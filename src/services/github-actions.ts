import { createAppAuth } from "@octokit/auth-app";
import { createHmac, timingSafeEqual } from "node:crypto";
import AdmZip from "adm-zip";
import sodium from "libsodium-wrappers";
import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { getWorkflowYaml, WORKFLOW_PATH } from "./github-workflow-template.js";

export interface GitHubRepoContext {
  owner: string;
  repo: string;
  defaultBranch: string;
  installationId: number;
  token: string;
  installationPermissions?: Record<string, string>;
}

export interface WorkflowDispatchInput {
  scanJobId: string;
  reportTitle: string;
  sourceRepo?: string;
  sourceInstallationId?: number;
  templateId?: string;
  sellerId?: string;
}

export interface GitHubRunLookup {
  runId: number | null;
  runAttempt?: number;
}

interface GitHubRun {
  id: number;
  run_attempt: number;
  created_at: string;
  event: string;
}

export interface PlatformWorkflowDispatchDiagnostics {
  owner: string;
  repo: string;
  workflowFile: string;
  workflowRef: string;
  installationId: number;
  appPermissions: Record<string, string>;
  installationPermissions: Record<string, string>;
  repoAccess: { ok: boolean; status: number; message?: string };
  workflowAccess: { ok: boolean; status: number; message?: string };
}

export type PlatformWorkflowConfigSyncCode =
  | "NOT_RUN"
  | "OK"
  | "WORKFLOW_CONFIG_INVALID"
  | "WORKFLOW_SECRET_SYNC_FAILED";

export interface PlatformWorkflowConfigSyncState {
  status: "unknown" | "ok" | "error";
  code: PlatformWorkflowConfigSyncCode;
  message?: string;
  checkedAt?: string;
  lastSyncAt?: string;
  workflowRepo: { owner: string; repo: string; ref: string };
  syncedSecrets: string[];
  syncedVariables: string[];
}

const platformWorkflowConfigSyncState: PlatformWorkflowConfigSyncState = {
  status: "unknown",
  code: "NOT_RUN",
  workflowRepo: { owner: "", repo: "", ref: "main" },
  syncedSecrets: [],
  syncedVariables: [],
};

const REQUIRED_PLATFORM_CONFIG_KEYS = [
  "CHUTES_API_KEY",
  "CHUTES_BASE_URL",
  "CHUTES_MODEL",
  "GITHUB_APP_ID",
  "GITHUB_APP_PRIVATE_KEY",
] as const;

const PLATFORM_WORKFLOW_SECRETS = ["AI_API_TOKEN", "GITHUB_APP_PRIVATE_KEY"] as const;
const PLATFORM_WORKFLOW_VARIABLES = [
  "AI_API_ENDPOINT",
  "COPILOT_DEFAULT_MODEL",
  "GITHUB_APP_ID",
] as const;

export class GitHubApiError extends Error {
  status: number;
  path: string;
  responseText: string;

  constructor(status: number, path: string, responseText: string) {
    super(`GitHub API ${status} ${path}: ${responseText}`);
    this.name = "GitHubApiError";
    this.status = status;
    this.path = path;
    this.responseText = responseText;
  }
}

interface GitHubActionsSecretPublicKey {
  key_id: string;
  key: string;
}

function setPlatformWorkflowConfigSyncState(
  patch: Partial<PlatformWorkflowConfigSyncState>
): PlatformWorkflowConfigSyncState {
  platformWorkflowConfigSyncState.status =
    patch.status ?? platformWorkflowConfigSyncState.status;
  platformWorkflowConfigSyncState.code =
    patch.code ?? platformWorkflowConfigSyncState.code;
  platformWorkflowConfigSyncState.message =
    patch.message ?? platformWorkflowConfigSyncState.message;
  platformWorkflowConfigSyncState.checkedAt =
    patch.checkedAt ?? platformWorkflowConfigSyncState.checkedAt;
  platformWorkflowConfigSyncState.lastSyncAt =
    patch.lastSyncAt ?? platformWorkflowConfigSyncState.lastSyncAt;
  platformWorkflowConfigSyncState.workflowRepo =
    patch.workflowRepo ?? platformWorkflowConfigSyncState.workflowRepo;
  platformWorkflowConfigSyncState.syncedSecrets = patch.syncedSecrets
    ? [...patch.syncedSecrets]
    : platformWorkflowConfigSyncState.syncedSecrets;
  platformWorkflowConfigSyncState.syncedVariables = patch.syncedVariables
    ? [...patch.syncedVariables]
    : platformWorkflowConfigSyncState.syncedVariables;

  return getPlatformWorkflowConfigSyncState();
}

function buildPlatformWorkflowRepoInfo(): { owner: string; repo: string; ref: string } {
  const env = getEnv();
  return {
    owner: env.GITHUB_PLATFORM_WORKFLOW_OWNER.trim(),
    repo: env.GITHUB_PLATFORM_WORKFLOW_REPO.trim(),
    ref: env.GITHUB_PLATFORM_WORKFLOW_REF.trim() || "main",
  };
}

function normalizeSecretValue(value: string): string {
  return value.replace(/\r\n/g, "\n");
}

function validatePlatformWorkflowSyncConfig(): {
  ok: boolean;
  missing: string[];
  values: Record<(typeof REQUIRED_PLATFORM_CONFIG_KEYS)[number], string>;
} {
  const env = getEnv();
  const values = {
    CHUTES_API_KEY: env.CHUTES_API_KEY.trim(),
    CHUTES_BASE_URL: env.CHUTES_BASE_URL.trim(),
    CHUTES_MODEL: env.CHUTES_MODEL.trim(),
    GITHUB_APP_ID: env.GITHUB_APP_ID.trim(),
    GITHUB_APP_PRIVATE_KEY: normalizeSecretValue(env.GITHUB_APP_PRIVATE_KEY),
  };

  const missing = REQUIRED_PLATFORM_CONFIG_KEYS.filter((key) => !values[key]);
  return { ok: missing.length === 0, missing, values };
}

async function getRepositoryActionsSecretPublicKey(
  context: GitHubRepoContext
): Promise<GitHubActionsSecretPublicKey> {
  return githubApi<GitHubActionsSecretPublicKey>(
    context.token,
    "GET",
    `/repos/${context.owner}/${context.repo}/actions/secrets/public-key`
  );
}

async function upsertRepositoryActionSecret(
  context: GitHubRepoContext,
  secretName: string,
  secretValue: string,
  publicKey: GitHubActionsSecretPublicKey
): Promise<void> {
  await sodium.ready;
  const encrypted = sodium.crypto_box_seal(
    Buffer.from(secretValue, "utf8"),
    Buffer.from(publicKey.key, "base64")
  );
  const encryptedValue = Buffer.from(encrypted).toString("base64");

  await githubApi(
    context.token,
    "PUT",
    `/repos/${context.owner}/${context.repo}/actions/secrets/${secretName}`,
    {
      encrypted_value: encryptedValue,
      key_id: publicKey.key_id,
    }
  );
}

async function upsertRepositoryActionVariable(
  context: GitHubRepoContext,
  variableName: string,
  variableValue: string
): Promise<void> {
  const variablePath = `/repos/${context.owner}/${context.repo}/actions/variables/${variableName}`;

  try {
    await githubApi(context.token, "PATCH", variablePath, {
      name: variableName,
      value: variableValue,
    });
    return;
  } catch (error) {
    if (!(error instanceof GitHubApiError) || error.status !== 404) {
      throw error;
    }
  }

  await githubApi(context.token, "POST", `/repos/${context.owner}/${context.repo}/actions/variables`, {
    name: variableName,
    value: variableValue,
  });
}

export function getPlatformWorkflowConfigSyncState(): PlatformWorkflowConfigSyncState {
  return {
    ...platformWorkflowConfigSyncState,
    workflowRepo: { ...platformWorkflowConfigSyncState.workflowRepo },
    syncedSecrets: [...platformWorkflowConfigSyncState.syncedSecrets],
    syncedVariables: [...platformWorkflowConfigSyncState.syncedVariables],
  };
}

export function isPlatformWorkflowConfigSyncReady(): boolean {
  return platformWorkflowConfigSyncState.status === "ok";
}

export async function syncPlatformWorkflowRuntimeConfigAtStartup(): Promise<PlatformWorkflowConfigSyncState> {
  const checkedAt = new Date().toISOString();
  const workflowRepo = buildPlatformWorkflowRepoInfo();
  setPlatformWorkflowConfigSyncState({
    checkedAt,
    workflowRepo,
    syncedSecrets: [],
    syncedVariables: [],
  });

  const validated = validatePlatformWorkflowSyncConfig();
  if (!validated.ok) {
    return setPlatformWorkflowConfigSyncState({
      status: "error",
      code: "WORKFLOW_CONFIG_INVALID",
      message: `Missing required platform workflow config: ${validated.missing.join(", ")}`,
      checkedAt,
      workflowRepo,
      syncedSecrets: [],
      syncedVariables: [],
    });
  }

  try {
    const workflowRepoContext = await getPlatformWorkflowContext();
    const publicKey = await getRepositoryActionsSecretPublicKey(workflowRepoContext);

    const secretValues: Record<(typeof PLATFORM_WORKFLOW_SECRETS)[number], string> = {
      AI_API_TOKEN: validated.values.CHUTES_API_KEY,
      GITHUB_APP_PRIVATE_KEY: validated.values.GITHUB_APP_PRIVATE_KEY,
    };

    const variableValues: Record<(typeof PLATFORM_WORKFLOW_VARIABLES)[number], string> = {
      AI_API_ENDPOINT: validated.values.CHUTES_BASE_URL,
      COPILOT_DEFAULT_MODEL: validated.values.CHUTES_MODEL,
      GITHUB_APP_ID: validated.values.GITHUB_APP_ID,
    };

    const syncedSecrets: string[] = [];
    const syncedVariables: string[] = [];

    for (const secretName of PLATFORM_WORKFLOW_SECRETS) {
      await upsertRepositoryActionSecret(
        workflowRepoContext,
        secretName,
        secretValues[secretName],
        publicKey
      );
      syncedSecrets.push(secretName);
    }

    for (const variableName of PLATFORM_WORKFLOW_VARIABLES) {
      await upsertRepositoryActionVariable(
        workflowRepoContext,
        variableName,
        variableValues[variableName]
      );
      syncedVariables.push(variableName);
    }

    const lastSyncAt = new Date().toISOString();
    return setPlatformWorkflowConfigSyncState({
      status: "ok",
      code: "OK",
      message: "Platform workflow config sync completed",
      checkedAt,
      lastSyncAt,
      workflowRepo: {
        owner: workflowRepoContext.owner,
        repo: workflowRepoContext.repo,
        ref: workflowRepoContext.defaultBranch,
      },
      syncedSecrets,
      syncedVariables,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(
      {
        err: error,
        workflowRepo,
        syncedSecrets: PLATFORM_WORKFLOW_SECRETS,
        syncedVariables: PLATFORM_WORKFLOW_VARIABLES,
      },
      "Failed syncing platform workflow runtime config"
    );
    return setPlatformWorkflowConfigSyncState({
      status: "error",
      code: "WORKFLOW_SECRET_SYNC_FAILED",
      message,
      checkedAt,
      workflowRepo,
      syncedSecrets: [],
      syncedVariables: [],
    });
  }
}

function parseRepo(sourceRepo: string): { owner: string; repo: string } {
  const [owner, repo] = sourceRepo.split("/");
  if (!owner || !repo) {
    throw new Error(`Invalid source_repo format: ${sourceRepo}`);
  }
  return { owner, repo };
}

async function githubApi<T>(
  token: string,
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const response = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new GitHubApiError(response.status, path, text);
  }

  if (response.status === 204) {
    return {} as T;
  }

  const json = (await response.json()) as T;
  return json;
}

async function resolveInstallationId(
  owner: string,
  explicitInstallationId?: number
): Promise<number> {
  if (explicitInstallationId) return explicitInstallationId;

  const env = getEnv();
  const auth = createAppAuth({
    appId: env.GITHUB_APP_ID,
    privateKey: env.GITHUB_APP_PRIVATE_KEY,
  });

  const appToken = await auth({ type: "app" });
  const installs = await githubApi<Array<{ id: number; account?: { login?: string } }>>(
    appToken.token,
    "GET",
    "/app/installations?per_page=100"
  );

  const matched = installs.find(
    (entry) => entry.account?.login?.toLowerCase() === owner.toLowerCase()
  );
  if (!matched) {
    throw new Error(`No GitHub App installation found for owner ${owner}`);
  }
  return matched.id;
}

async function getInstallationPermissions(
  installationId: number
): Promise<Record<string, string>> {
  const env = getEnv();
  const auth = createAppAuth({
    appId: env.GITHUB_APP_ID,
    privateKey: env.GITHUB_APP_PRIVATE_KEY,
  });
  const appToken = await auth({ type: "app" });

  const details = await githubApi<{ permissions?: Record<string, string> }>(
    appToken.token,
    "GET",
    `/app/installations/${installationId}`
  );
  return details.permissions || {};
}

async function getRepositoryDetails(
  token: string,
  owner: string,
  repo: string
): Promise<{ default_branch: string }> {
  try {
    return await githubApi<{ default_branch: string }>(
      token,
      "GET",
      `/repos/${owner}/${repo}`
    );
  } catch (error) {
    if (error instanceof GitHubApiError && error.status === 404) {
      throw new Error(
        `GitHub App installation cannot access repository ${owner}/${repo}. Verify repository name and app installation scope.`
      );
    }
    throw error;
  }
}

async function resolveWorkflowRef(
  token: string,
  owner: string,
  repo: string,
  fallbackBranch: string,
  requestedRef?: string
): Promise<string> {
  const ref = (requestedRef || "").trim();
  if (!ref) {
    return fallbackBranch || "main";
  }

  try {
    await githubApi(
      token,
      "GET",
      `/repos/${owner}/${repo}/branches/${encodeURIComponent(ref)}`
    );
    return ref;
  } catch (error) {
    if (error instanceof GitHubApiError && error.status === 404) {
      throw new Error(
        `Configured workflow ref "${ref}" was not found in ${owner}/${repo}.`
      );
    }
    throw error;
  }
}

export async function getRepoContext(
  sourceRepo: string,
  explicitInstallationId?: number
): Promise<GitHubRepoContext> {
  const env = getEnv();
  const { owner, repo } = parseRepo(sourceRepo);
  const installationId = await resolveInstallationId(owner, explicitInstallationId);

  const auth = createAppAuth({
    appId: env.GITHUB_APP_ID,
    privateKey: env.GITHUB_APP_PRIVATE_KEY,
  });
  const installToken = await auth({ type: "installation", installationId });

  const repoInfo = await getRepositoryDetails(installToken.token, owner, repo);

  return {
    owner,
    repo,
    defaultBranch: repoInfo.default_branch || "main",
    installationId,
    token: installToken.token,
  };
}

export async function getPlatformWorkflowContext(): Promise<GitHubRepoContext> {
  const env = getEnv();
  const owner = env.GITHUB_PLATFORM_WORKFLOW_OWNER.trim();
  const repo = env.GITHUB_PLATFORM_WORKFLOW_REPO.trim();

  if (!owner || !repo) {
    throw new Error(
      "Platform workflow repository is not configured. Set GITHUB_PLATFORM_WORKFLOW_OWNER and GITHUB_PLATFORM_WORKFLOW_REPO."
    );
  }

  const installationId = await resolveInstallationId(owner);
  const auth = createAppAuth({
    appId: env.GITHUB_APP_ID,
    privateKey: env.GITHUB_APP_PRIVATE_KEY,
  });
  const installToken = await auth({ type: "installation", installationId });
  const repoInfo = await getRepositoryDetails(installToken.token, owner, repo);
  const workflowRef = await resolveWorkflowRef(
    installToken.token,
    owner,
    repo,
    repoInfo.default_branch || "main",
    env.GITHUB_PLATFORM_WORKFLOW_REF
  );
  const installationPermissions = await getInstallationPermissions(installationId).catch(
    () => ({})
  );

  return {
    owner,
    repo,
    defaultBranch: workflowRef,
    installationId,
    token: installToken.token,
    installationPermissions,
  };
}

export async function getPlatformWorkflowDispatchDiagnostics(): Promise<PlatformWorkflowDispatchDiagnostics> {
  const env = getEnv();
  const owner = env.GITHUB_PLATFORM_WORKFLOW_OWNER.trim();
  const repo = env.GITHUB_PLATFORM_WORKFLOW_REPO.trim();
  const workflowFile = env.GITHUB_WORKFLOW_FILE.trim();
  const workflowRef = env.GITHUB_PLATFORM_WORKFLOW_REF.trim() || "main";

  if (!owner || !repo) {
    throw new Error(
      "Platform workflow repository is not configured. Set GITHUB_PLATFORM_WORKFLOW_OWNER and GITHUB_PLATFORM_WORKFLOW_REPO."
    );
  }

  const auth = createAppAuth({
    appId: env.GITHUB_APP_ID,
    privateKey: env.GITHUB_APP_PRIVATE_KEY,
  });
  const appToken = await auth({ type: "app" });
  const installationId = await resolveInstallationId(owner);

  const appDetails = await githubApi<{ permissions?: Record<string, string> }>(
    appToken.token,
    "GET",
    "/app"
  ).catch(() => ({ permissions: {} }));

  const installDetails = await githubApi<{ permissions?: Record<string, string> }>(
    appToken.token,
    "GET",
    `/app/installations/${installationId}`
  ).catch(() => ({ permissions: {} }));

  const installToken = await auth({ type: "installation", installationId });

  let repoAccess: { ok: boolean; status: number; message?: string } = {
    ok: false,
    status: 0,
  };
  try {
    await githubApi(
      installToken.token,
      "GET",
      `/repos/${owner}/${repo}`
    );
    repoAccess = { ok: true, status: 200 };
  } catch (error) {
    if (error instanceof GitHubApiError) {
      let message = "";
      try {
        message = JSON.parse(error.responseText || "{}")?.message || "";
      } catch {
        message = error.responseText || "";
      }
      repoAccess = { ok: false, status: error.status, message };
    } else {
      repoAccess = { ok: false, status: 0, message: String(error) };
    }
  }

  let workflowAccess: { ok: boolean; status: number; message?: string } = {
    ok: false,
    status: 0,
  };
  try {
    await githubApi(
      installToken.token,
      "GET",
      `/repos/${owner}/${repo}/actions/workflows/${encodeURIComponent(workflowFile)}`
    );
    workflowAccess = { ok: true, status: 200 };
  } catch (error) {
    if (error instanceof GitHubApiError) {
      let message = "";
      try {
        message = JSON.parse(error.responseText || "{}")?.message || "";
      } catch {
        message = error.responseText || "";
      }
      workflowAccess = { ok: false, status: error.status, message };
    } else {
      workflowAccess = { ok: false, status: 0, message: String(error) };
    }
  }

  return {
    owner,
    repo,
    workflowFile,
    workflowRef,
    installationId,
    appPermissions: appDetails.permissions || {},
    installationPermissions: installDetails.permissions || {},
    repoAccess,
    workflowAccess,
  };
}

export async function ensureWorkflowInRepo(
  context: GitHubRepoContext,
  options?: { force?: boolean }
): Promise<void> {
  const force = options?.force === true;
  const path = WORKFLOW_PATH;
  if (!force) {
    try {
      await githubApi(
        context.token,
        "GET",
        `/repos/${context.owner}/${context.repo}/contents/${path}?ref=${encodeURIComponent(context.defaultBranch)}`
      );
      return;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (!message.includes(" 404 ")) {
        throw err;
      }
    }
  }

  let existingSha: string | undefined;
  try {
    const existing = await githubApi<{ sha: string }>(
      context.token,
      "GET",
      `/repos/${context.owner}/${context.repo}/contents/${path}?ref=${encodeURIComponent(context.defaultBranch)}`
    );
    existingSha = existing.sha;
  } catch {
    existingSha = undefined;
  }

  const content = Buffer.from(getWorkflowYaml(), "utf-8").toString("base64");
  await githubApi(
    context.token,
    "PUT",
    `/repos/${context.owner}/${context.repo}/contents/${path}`,
    {
      message: existingSha
        ? "chore(scanner): update AgentDeploy security scan workflow"
        : "chore(scanner): seed AgentDeploy security scan workflow",
      content,
      branch: context.defaultBranch,
      sha: existingSha,
    }
  );
}

export async function dispatchWorkflowRun(
  context: GitHubRepoContext,
  input: WorkflowDispatchInput
): Promise<void> {
  const env = getEnv();
  const workflowFile = env.GITHUB_WORKFLOW_FILE;
  const permissions: Record<string, string> =
    context.installationPermissions ||
    (await getInstallationPermissions(context.installationId).catch(
      () => ({} as Record<string, string>)
    ));
  const actionsPermission = permissions.actions || "missing";
  const workflowsPermission = permissions.workflows || "missing";

  if (actionsPermission !== "write" || workflowsPermission !== "write") {
    logger.error(
      {
        installationId: context.installationId,
        repo: `${context.owner}/${context.repo}`,
        permissions,
      },
      "GitHub installation missing workflow dispatch permissions"
    );
    throw new Error(
      `GitHub installation missing required permissions for workflow dispatch. actions=${actionsPermission}, workflows=${workflowsPermission}. Reinstall/update the app installation for ${context.owner}.`
    );
  }

  const inputs: Record<string, string> = {
    scan_job_id: input.scanJobId,
    report_title: input.reportTitle,
  };

  if (input.sourceRepo) {
    inputs.source_repo = input.sourceRepo;
  }
  if (typeof input.sourceInstallationId === "number" && Number.isFinite(input.sourceInstallationId)) {
    inputs.source_installation_id = String(input.sourceInstallationId);
  }
  if (input.templateId) {
    inputs.template_id = input.templateId;
  }
  if (input.sellerId) {
    inputs.seller_id = input.sellerId;
  }

  const path = `/repos/${context.owner}/${context.repo}/actions/workflows/${encodeURIComponent(workflowFile)}/dispatches`;
  const payload = {
    ref: context.defaultBranch,
    inputs,
  };

  try {
    await githubApi(
      context.token,
      "POST",
      path,
      payload
    );
  } catch (error) {
    if (error instanceof GitHubApiError && error.status === 403) {
      const actionsPermissionOnFailure = permissions.actions || "missing";
      const workflowsPermissionOnFailure = permissions.workflows || "missing";

      logger.error(
        {
          status: error.status,
          path,
          responseText: error.responseText,
          installationId: context.installationId,
          repo: `${context.owner}/${context.repo}`,
          ref: payload.ref,
          inputs: payload.inputs,
          permissions,
        },
        "GitHub workflow dispatch forbidden"
      );

      throw new Error(
        `GitHub dispatch forbidden for ${context.owner}/${context.repo}. Required permissions likely missing. actions=${actionsPermissionOnFailure}, workflows=${workflowsPermissionOnFailure}. Request payload: ${JSON.stringify(
          payload
        )}`
      );
    }
    throw error;
  }
}

export async function cancelWorkflowRun(
  context: GitHubRepoContext,
  runId: number
): Promise<void> {
  await githubApi(
    context.token,
    "POST",
    `/repos/${context.owner}/${context.repo}/actions/runs/${runId}/cancel`
  );
}

export async function findRecentWorkflowRun(
  context: GitHubRepoContext,
  dispatchedAtMs: number
): Promise<GitHubRunLookup> {
  const env = getEnv();
  const workflowFile = env.GITHUB_WORKFLOW_FILE;

  for (let attempt = 0; attempt < 10; attempt++) {
    const runsResponse = await githubApi<{
      workflow_runs: GitHubRun[];
    }>(
      context.token,
      "GET",
      `/repos/${context.owner}/${context.repo}/actions/workflows/${encodeURIComponent(workflowFile)}/runs?event=workflow_dispatch&per_page=20`
    );

    const threshold = dispatchedAtMs - 2 * 60 * 1000;
    const match = runsResponse.workflow_runs.find((run: GitHubRun) => {
      const created = new Date(run.created_at).getTime();
      return created >= threshold;
    });

    if (match) {
      return { runId: match.id, runAttempt: match.run_attempt };
    }

    await new Promise((resolve) => setTimeout(resolve, 1500));
  }

  return { runId: null };
}

export async function getWorkflowRun(
  context: GitHubRepoContext,
  runId: number
): Promise<{ status: string; conclusion: string | null; runAttempt: number }> {
  const run = await githubApi<{ status: string; conclusion: string | null; run_attempt: number }>(
    context.token,
    "GET",
    `/repos/${context.owner}/${context.repo}/actions/runs/${runId}`
  );
  return {
    status: run.status,
    conclusion: run.conclusion,
    runAttempt: run.run_attempt,
  };
}

export async function downloadScanArtifacts(
  context: GitHubRepoContext,
  runId: number
): Promise<{
  reportArtifactName?: string;
  pdfBuffer?: Buffer;
  resultArtifactName?: string;
  resultJson?: string;
}> {
  const env = getEnv();
  const preferredReportArtifactName = env.GITHUB_SCAN_ARTIFACT_NAME.trim().toLowerCase();
  const resultFileName = env.GITHUB_SCAN_RESULT_FILE_NAME.trim().toLowerCase();
  const artifacts = await githubApi<{
    artifacts: Array<{ name: string; archive_download_url: string; expired: boolean; created_at?: string }>;
  }>(
    context.token,
    "GET",
    `/repos/${context.owner}/${context.repo}/actions/runs/${runId}/artifacts?per_page=100`
  );

  const activeArtifacts = artifacts.artifacts.filter((item) => !item.expired);
  const orderedArtifacts = activeArtifacts.sort((a, b) => {
    const aPreferred = a.name.trim().toLowerCase() === preferredReportArtifactName ? 1 : 0;
    const bPreferred = b.name.trim().toLowerCase() === preferredReportArtifactName ? 1 : 0;
    if (aPreferred !== bPreferred) {
      return bPreferred - aPreferred;
    }
    const aCreated = a.created_at ? new Date(a.created_at).getTime() : 0;
    const bCreated = b.created_at ? new Date(b.created_at).getTime() : 0;
    return bCreated - aCreated;
  });

  let pdfBuffer: Buffer | undefined;
  let reportArtifactName: string | undefined;
  let resultJson: string | undefined;
  let resultArtifactName: string | undefined;

  for (const artifact of orderedArtifacts) {
    const response = await fetch(artifact.archive_download_url, {
      headers: {
        Authorization: `Bearer ${context.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to download artifact zip: ${response.status}`);
    }

    const zipBuffer = Buffer.from(await response.arrayBuffer());
    const zip = new AdmZip(zipBuffer);
    const entries = zip.getEntries();

    if (!pdfBuffer) {
      const pdfEntry = entries.find((entry: AdmZip.IZipEntry) =>
        entry.entryName.toLowerCase().endsWith(".pdf")
      );
      if (pdfEntry) {
        pdfBuffer = pdfEntry.getData();
        reportArtifactName = artifact.name;
      }
    }

    if (!resultJson) {
      const resultEntry = entries.find((entry: AdmZip.IZipEntry) => {
        const normalized = entry.entryName.toLowerCase();
        const baseName = normalized.split("/").at(-1) || normalized;
        return baseName === resultFileName;
      });
      if (resultEntry) {
        resultJson = resultEntry.getData().toString("utf8");
        resultArtifactName = artifact.name;
      }
    }

    if (pdfBuffer && resultJson) {
      break;
    }
  }

  return {
    reportArtifactName,
    pdfBuffer,
    resultArtifactName,
    resultJson,
  };
}

function normalizePemLineEndings(value: string): string {
  return value.replace(/\r\n/g, "\n");
}

export function normalizeGitHubPrivateKey(privateKey: string): string {
  return normalizePemLineEndings(privateKey);
}

export function hasSellerRepoWorkflowWriteIssue(message: string): boolean {
  const lower = message.toLowerCase();
  return (
    lower.includes("resource not accessible by integration") ||
    (lower.includes("/contents/") && lower.includes(".github/workflows"))
  );
}

export function verifyGitHubWebhookSignature(
  rawBody: string,
  signatureHeader: string | null
): boolean {
  const env = getEnv();
  if (!env.GITHUB_WEBHOOK_SECRET) return false;
  if (!signatureHeader?.startsWith("sha256=")) return false;

  const expected = `sha256=${createHmac("sha256", env.GITHUB_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex")}`;
  const provided = signatureHeader.trim();
  if (expected.length !== provided.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
}

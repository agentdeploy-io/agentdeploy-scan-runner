import { Hono } from "hono";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { authMiddleware } from "../middleware/auth.js";
import { rateLimitMiddleware } from "../middleware/rate-limit.js";
import {
  appendScanJobEvent,
  createScanJob,
  getScanJob,
  getScanJobByGitHubRunId,
  isScanJobEventsLedgerAvailable,
  listAllActiveScanJobs,
  listActiveScanJobsForSeller,
  refreshScanJobEventsLedgerAvailability,
  updateTemplateScanFields,
  updateScanJob,
  uploadScanReportPdf,
  type ExtendedScanStatus,
  type ScanJobEntity,
} from "../services/directus.js";
import { logger } from "../logger.js";
import { getScanState, publishScanProgress } from "../services/redis.js";
import {
  admitTemplateScan,
  bindTemplateScanJob,
  clearTemplateBindingIfMatches,
  getActiveTemplateIds,
  releaseTemplateScanSlot,
} from "../services/scan-concurrency.js";
import {
  cancelScanJob,
  enqueueScanJob,
  getScanRunnerStats,
  isScanJobCancelled,
} from "../services/scan-runner.js";
import {
  cancelWorkflowRun,
  dispatchWorkflowRun,
  downloadScanArtifacts,
  ensureWorkflowInRepo,
  findRecentWorkflowRun,
  getWorkflowRun,
  GitHubApiError,
  getPlatformWorkflowContext,
  getRepoContext,
  verifyGitHubWebhookSignature,
} from "../services/github-actions.js";
import { getEnv } from "../env.js";
import { RATING_TO_COLOR, type ScanRating } from "../constants.js";

const MAX_LENGTH = {
  TEMPLATE_ID: 50,
  SELLER_ID: 100,
  SOURCE_REPO: 200,
  PURCHASE_ID: 100,
  BUYER_ID: 100,
  TARGET_REPO: 200,
} as const;

const scanRequestSchema = z.object({
  templateId: z
    .union([
      z.string().max(MAX_LENGTH.TEMPLATE_ID),
      z.number().int().nonnegative().max(999999999),
    ])
    .transform((val) => String(val)),
  sellerId: z.string().min(1).max(MAX_LENGTH.SELLER_ID),
  sourceRepo: z
    .string()
    .regex(/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/)
    .max(MAX_LENGTH.SOURCE_REPO),
  purchaseId: z.string().max(MAX_LENGTH.PURCHASE_ID).optional(),
  buyerId: z.string().max(MAX_LENGTH.BUYER_ID).optional(),
  targetRepo: z.string().max(MAX_LENGTH.TARGET_REPO).optional(),
  githubInstallationId: z.coerce.number().int().positive().optional(),
});

const scanCancelSchema = z.object({
  sellerId: z.string().min(1).max(MAX_LENGTH.SELLER_ID),
});

const scanWebhookSchema = z.object({
  action: z.string().optional(),
  repository: z
    .object({
      full_name: z.string().optional(),
    })
    .optional(),
  workflow_run: z
    .object({
      id: z.number(),
      run_attempt: z.number().optional(),
      status: z.string().nullable().optional(),
      conclusion: z.string().nullable().optional(),
      html_url: z.string().nullable().optional(),
      event: z.string().nullable().optional(),
      name: z.string().nullable().optional(),
    })
    .optional(),
});

const scanResultArtifactSchema = z.object({
  overallRating: z.enum(["A", "B", "C", "D", "F"]),
  overallScore: z.number().min(0).max(100),
  riskLevel: z.enum(["none", "low", "medium", "high", "critical"]),
  severityCounts: z.object({
    low: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    critical: z.number().int().nonnegative(),
  }),
  categoryRatings: z.object({
    secrets: z.enum(["A", "B", "C", "D", "F"]),
    promptInjection: z.enum(["A", "B", "C", "D", "F"]),
    dependencies: z.enum(["A", "B", "C", "D", "F"]),
    permissions: z.enum(["A", "B", "C", "D", "F"]),
    sast: z.enum(["A", "B", "C", "D", "F"]),
  }),
  summary: z.string().default(""),
  recommendations: z.array(z.string()).default([]),
});

export type ScanRequest = z.infer<typeof scanRequestSchema>;

export const scanRoute = new Hono();

type ScanJobPatch = Parameters<typeof updateScanJob>[1];

const ACTIVE_SCAN_STATUSES = new Set<ExtendedScanStatus>([
  "pending",
  "running",
  "analyzing",
  "workflow_seeding",
  "dispatching",
  "queued_in_github",
  "running_in_github",
  "artifact_processing",
  "delayed",
]);

const TERMINAL_STATUSES = new Set<ExtendedScanStatus>([
  "completed",
  "failed",
  "review_required",
  "approved",
  "rejected",
]);

function isActiveScanStatus(status: string): status is ExtendedScanStatus {
  return ACTIVE_SCAN_STATUSES.has(status as ExtendedScanStatus);
}

function statusToProgress(status: string): number {
  switch (status) {
    case "pending":
      return 5;
    case "workflow_seeding":
      return 15;
    case "dispatching":
      return 25;
    case "queued_in_github":
      return 35;
    case "running_in_github":
      return 70;
    case "artifact_processing":
      return 90;
    case "delayed":
      return 45;
    case "completed":
    case "review_required":
      return 100;
    case "failed":
      return 0;
    default:
      return 20;
  }
}

function stageForStatus(status: string): string {
  switch (status) {
    case "workflow_seeding":
      return "workflow_seeding";
    case "dispatching":
      return "dispatching";
    case "queued_in_github":
      return "queued_in_github";
    case "running_in_github":
      return "running_in_github";
    case "artifact_processing":
      return "artifact_processing";
    case "delayed":
      return "delayed";
    case "completed":
    case "review_required":
    case "approved":
    case "rejected":
      return "complete";
    case "failed":
      return "error";
    default:
      return "queued";
  }
}

async function publishStatusEvent(
  jobId: string,
  status: ExtendedScanStatus,
  message: string,
  data?: Record<string, unknown>
): Promise<void> {
  const eventType =
    status === "failed"
      ? "error"
      : status === "completed" || status === "review_required" || status === "approved" || status === "rejected"
        ? "complete"
        : "stage";
  await publishScanProgress(jobId, {
    jobId,
    event_type: eventType,
    stage: stageForStatus(status),
    message,
    progress: statusToProgress(status),
    data,
  }).catch((err) => logger.warn({ err, jobId }, "Failed to publish status event"));
}

function classifyDispatchError(err: unknown): {
  failureCode: string;
  status: ExtendedScanStatus;
} {
  const message = err instanceof Error ? err.message : String(err);
  const text = message.toLowerCase();

  if (err instanceof GitHubApiError) {
    const path = err.path.toLowerCase();
    if (
      (err.status === 401 || err.status === 403) &&
      path.includes("/actions/workflows/")
    ) {
      return { failureCode: "WORKFLOW_SEED_PERMISSION_DENIED", status: "failed" };
    }
  }

  if (text.includes("cancelled by user") || text.includes("canceled by user")) {
    return { failureCode: "CANCELED_BY_USER", status: "failed" };
  }
  if (text.includes("cannot access repository")) {
    return { failureCode: "WORKFLOW_SEED_PERMISSION_DENIED", status: "failed" };
  }
  if (
    text.includes("github installation missing required permissions for workflow dispatch") ||
    text.includes("github dispatch forbidden for") ||
    text.includes("actions=missing") ||
    text.includes("workflows=missing")
  ) {
    return { failureCode: "WORKFLOW_SEED_PERMISSION_DENIED", status: "failed" };
  }
  if (text.includes("rate limit") || text.includes("abuse")) {
    return { failureCode: "GITHUB_RATE_LIMITED", status: "delayed" };
  }
  if (text.includes("workflow") && text.includes("not found")) {
    return { failureCode: "WORKFLOW_NOT_FOUND", status: "failed" };
  }
  if (text.includes("resource not accessible by integration")) {
    return { failureCode: "WORKFLOW_SEED_PERMISSION_DENIED", status: "failed" };
  }
  return { failureCode: "DISPATCH_FAILED", status: "failed" };
}

function buildDispatchFailureReason(
  err: unknown,
  classified: { failureCode: string },
  workflowFile: string
): string {
  const raw = err instanceof Error ? err.message : String(err);
  const lower = raw.toLowerCase();

  if (classified.failureCode === "WORKFLOW_SEED_PERMISSION_DENIED") {
    const actionsMatch = raw.match(/actions=([a-z_]+)/i);
    const workflowsMatch = raw.match(/workflows=([a-z_]+)/i);
    if (actionsMatch || workflowsMatch) {
      const actions = actionsMatch?.[1] || "missing";
      const workflows = workflowsMatch?.[1] || "missing";
      return `GitHub App installation permissions are insufficient for workflow dispatch (actions=${actions}, workflows=${workflows}). Open the app installation for the workflow repository owner, accept updated permissions, and reinstall if required.`;
    }
    return "GitHub App cannot access the configured workflow repository/workflow path. Verify owner/repo/ref and reinstall the app with repository access.";
  }

  if (classified.failureCode === "WORKFLOW_NOT_FOUND") {
    return `GitHub workflow "${workflowFile}" was not found in the configured workflow repository/ref.`;
  }

  if (classified.failureCode === "GITHUB_RATE_LIMITED") {
    return "GitHub rate limiting or queue delay detected. Please retry shortly.";
  }

  if (lower.includes("forbidden")) {
    return "GitHub denied this request for the repository/integration. Verify app installation scope and permissions, then retry.";
  }

  return raw;
}

function throwIfCancelled(jobId: string): void {
  if (isScanJobCancelled(jobId)) {
    throw new Error("Scan cancelled by user");
  }
}

function isPublishableRating(rating: ScanRating): boolean {
  return rating === "A" || rating === "B";
}

function resolveRunRepoFullName(job: ScanJobEntity): string {
  const owner = job.github_repo_owner ? String(job.github_repo_owner).trim() : "";
  const repo = job.github_repo_name ? String(job.github_repo_name).trim() : "";
  if (owner && repo) {
    return `${owner}/${repo}`;
  }
  return String(job.source_repo);
}

async function finalizeSuccessfulGitHubRun(
  job: ScanJobEntity,
  githubRunId: string,
  githubRunAttempt?: number,
  workflowHtmlUrl?: string,
  providerEventId?: string
): Promise<{ status: ExtendedScanStatus; code?: string; artifactFileId?: string }> {
  const latest = await getScanJob(String(job.id)).catch(() => job);
  if (TERMINAL_STATUSES.has(String(latest.status) as ExtendedScanStatus)) {
    return { status: String(latest.status) as ExtendedScanStatus };
  }

  await updateScanJob(String(job.id), {
    status: "artifact_processing",
    github_run_attempt: githubRunAttempt,
  });

  await publishStatusEvent(
    String(job.id),
    "artifact_processing",
    "Processing report artifact from GitHub...",
    {
      templateId: String(job.template_id),
      githubRunId,
    }
  );

  try {
    const runRepo = resolveRunRepoFullName(job);
    const explicitInstallationId =
      runRepo.toLowerCase() === String(job.source_repo).toLowerCase() &&
      job.github_installation_id
        ? Number(job.github_installation_id)
        : undefined;
    const repoContext = await getRepoContext(runRepo, explicitInstallationId);

    const artifacts = await downloadScanArtifacts(repoContext, Number(githubRunId));
    if (!artifacts.pdfBuffer || !artifacts.resultJson) {
      await failScanJob(
        job,
        "failed",
        "ARTIFACT_NOT_FOUND",
        "GitHub run completed but required artifacts (report.pdf and scan-result.json) were not found.",
        providerEventId
      );
      return { status: "failed", code: "ARTIFACT_NOT_FOUND" };
    }

    const parsedResult = (() => {
      try {
        const parsed = JSON.parse(artifacts.resultJson || "{}");
        return scanResultArtifactSchema.parse(parsed);
      } catch {
        return null;
      }
    })();

    if (!parsedResult) {
      await failScanJob(
        job,
        "failed",
        "RESULT_PARSE_FAILED",
        "scan-result.json is missing required fields or has invalid format.",
        providerEventId
      );
      return { status: "failed", code: "RESULT_PARSE_FAILED" };
    }

    const overallRating = parsedResult.overallRating as ScanRating;
    const finalStatus: ExtendedScanStatus = isPublishableRating(overallRating)
      ? "completed"
      : "review_required";
    const templateScanStatus = isPublishableRating(overallRating) ? "clean" : "review_required";
    const completedAt = new Date().toISOString();
    const reportFileName = `security-report-${job.id}.pdf`;
    const uploaded = await uploadScanReportPdf(String(job.id), reportFileName, artifacts.pdfBuffer);

    await applyScanStateTransition(job, {
      status: finalStatus,
      message: "Scan complete. Report ready.",
      patch: {
        completed_at: completedAt,
        risk_level: parsedResult.riskLevel,
        overall_rating: overallRating,
        overall_score: Math.round(parsedResult.overallScore),
        rating_secrets: parsedResult.categoryRatings.secrets,
        rating_prompt_injection: parsedResult.categoryRatings.promptInjection,
        rating_dependencies: parsedResult.categoryRatings.dependencies,
        rating_permissions: parsedResult.categoryRatings.permissions,
        rating_sast: parsedResult.categoryRatings.sast,
        seller_color_light: RATING_TO_COLOR[overallRating],
        llm_summary: parsedResult.summary,
        llm_recommendations: parsedResult.recommendations as unknown,
        artifact_name: artifacts.reportArtifactName || undefined,
        artifact_file_id: uploaded.fileId,
        artifact_url_github: workflowHtmlUrl || undefined,
        failure_code: undefined,
        failure_reason: undefined,
        error_message: undefined,
        metadata: {
          ...(job.metadata || {}),
          reportUrl: uploaded.assetUrl,
          githubRunId,
          severityCounts: parsedResult.severityCounts,
          scanResultArtifactName: artifacts.resultArtifactName,
        },
      },
      eventData: {
        templateId: String(job.template_id),
        status: finalStatus,
        rating: overallRating,
        score: Math.round(parsedResult.overallScore),
        reportUrl: uploaded.assetUrl,
        artifactFileId: uploaded.fileId,
        githubRunId,
      },
      appendEvent: {
        eventSource: "github_webhook",
        eventType: "scan_terminal_success",
        providerEventId,
        payload: {
          status: finalStatus,
          githubRunId,
          artifactFileId: uploaded.fileId,
        },
      },
    });

    await updateTemplateScanFields(String(job.template_id), {
      scan_rating: overallRating,
      scan_score: Math.round(parsedResult.overallScore),
      scan_color_light: RATING_TO_COLOR[overallRating],
      last_scan_at: completedAt,
      last_scan_job_id: String(job.id),
      scan_status: templateScanStatus,
    });

    return {
      status: finalStatus,
      artifactFileId: uploaded.fileId,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await failScanJob(
      job,
      "failed",
      "ARTIFACT_DOWNLOAD_FAILED",
      message,
      providerEventId
    );
    return { status: "failed", code: "ARTIFACT_DOWNLOAD_FAILED" };
  }
}

async function reconcileJobStateFromGitHub(job: ScanJobEntity): Promise<void> {
  if (!job.github_run_id) return;
  const jobStatus = String(job.status);
  if (!isActiveScanStatus(jobStatus)) return;

  try {
    const runRepo = resolveRunRepoFullName(job);
    const explicitInstallationId =
      runRepo.toLowerCase() === String(job.source_repo).toLowerCase() &&
      job.github_installation_id
        ? Number(job.github_installation_id)
        : undefined;
    const repoContext = await getRepoContext(runRepo, explicitInstallationId);
    const run = await getWorkflowRun(repoContext, Number(job.github_run_id));
    const runStatus = String(run.status || "").toLowerCase();
    const runConclusion = String(run.conclusion || "").toLowerCase();

    if (runStatus === "queued" && jobStatus !== "queued_in_github") {
      await updateScanJob(String(job.id), {
        status: "queued_in_github",
        github_run_attempt: run.runAttempt,
      });
      await publishStatusEvent(
        String(job.id),
        "queued_in_github",
        "Scan queued in GitHub Actions",
        {
          templateId: String(job.template_id),
          githubRunId: String(job.github_run_id),
        }
      );
      return;
    }

    if (runStatus === "in_progress" && jobStatus !== "running_in_github") {
      await updateScanJob(String(job.id), {
        status: "running_in_github",
        github_run_attempt: run.runAttempt,
      });
      await publishStatusEvent(
        String(job.id),
        "running_in_github",
        "Running security scan in GitHub sandbox VM...",
        {
          templateId: String(job.template_id),
          githubRunId: String(job.github_run_id),
        }
      );
      return;
    }

    if (runStatus !== "completed") {
      return;
    }

    if (runConclusion !== "success") {
      await failScanJob(
        job,
        "failed",
        "WORKFLOW_RUN_FAILED",
        `GitHub workflow completed with conclusion: ${runConclusion || "unknown"}`
      );
      return;
    }

    await finalizeSuccessfulGitHubRun(
      job,
      String(job.github_run_id),
      run.runAttempt
    );
  } catch (err) {
    logger.warn(
      {
        err,
        jobId: String(job.id),
        githubRunId: String(job.github_run_id),
      },
      "Failed to reconcile scan job state from GitHub run"
    );
  }
}

interface ScanStateTransitionInput {
  status: ExtendedScanStatus;
  message: string;
  patch?: ScanJobPatch;
  eventData?: Record<string, unknown>;
  appendEvent?: {
    eventSource: "app" | "github_webhook" | "github_poll";
    eventType: string;
    providerEventId?: string;
    payload?: Record<string, unknown>;
  };
}

async function applyScanStateTransition(
  job: Pick<ScanJobEntity, "id" | "seller_id" | "template_id">,
  input: ScanStateTransitionInput
): Promise<void> {
  const jobId = String(job.id);
  const isTerminal = TERMINAL_STATUSES.has(input.status);
  const patch: ScanJobPatch = {
    ...(input.patch || {}),
    status: input.status,
  };

  if (isTerminal && !patch.completed_at) {
    patch.completed_at = new Date().toISOString();
  }

  await updateScanJob(jobId, patch).catch((err) => {
    logger.error({ err, jobId, status: input.status }, "Failed to apply scan state transition");
  });

  if (input.appendEvent) {
    await appendScanJobEvent({
      scanJobId: jobId,
      eventSource: input.appendEvent.eventSource,
      eventType: input.appendEvent.eventType,
      providerEventId: input.appendEvent.providerEventId,
      payload: input.appendEvent.payload || {},
    }).catch((err) => logger.warn({ err, jobId }, "Failed to append scan job event"));
  }

  await publishStatusEvent(jobId, input.status, input.message, input.eventData);

  if (isTerminal) {
    await clearTemplateBindingIfMatches(
      String(job.seller_id),
      String(job.template_id),
      jobId
    ).catch((err) => logger.warn({ err, jobId }, "Failed to clear template binding on terminal transition"));
  }
}

async function failScanJob(
  job: Pick<ScanJobEntity, "id" | "seller_id" | "template_id">,
  status: ExtendedScanStatus,
  failureCode: string,
  failureReason: string,
  deliveryId?: string
): Promise<void> {
  await applyScanStateTransition(job, {
    status,
    message: failureReason,
    patch: {
      failure_code: failureCode,
      failure_reason: failureReason,
      error_message: failureReason,
    },
    eventData: {
      templateId: String(job.template_id),
      failureCode,
      failureReason,
      status,
    },
    appendEvent: {
      eventSource: "app",
      eventType: `scan_failed:${failureCode}`,
      providerEventId: deliveryId,
      payload: { failureCode, failureReason, status },
    },
  });
}

function getActiveJobTtlMs(): number {
  const env = getEnv();
  const minutes = Number(env.SCAN_ACTIVE_JOB_TTL_MINUTES);
  const safeMinutes = Number.isFinite(minutes) ? Math.max(5, minutes) : 120;
  return safeMinutes * 60 * 1000;
}

function isStaleActiveJob(job: ScanJobEntity, nowMs: number, ttlMs: number): boolean {
  const startedAtMs = new Date(String(job.started_at || "")).getTime();
  if (!Number.isFinite(startedAtMs)) return true;
  return nowMs - startedAtMs > ttlMs;
}

async function reconcileStaleActiveJobsForSeller(sellerId: string): Promise<number> {
  const ttlMs = getActiveJobTtlMs();
  const ttlMinutes = Math.round(ttlMs / (60 * 1000));
  const nowMs = Date.now();
  const activeJobs = await listActiveScanJobsForSeller(sellerId).catch(() => []);
  const staleJobs = activeJobs.filter((job) => isStaleActiveJob(job, nowMs, ttlMs));

  for (const job of staleJobs) {
    const jobId = String(job.id);
    logger.warn(
      {
        sellerId,
        jobId,
        status: job.status,
        startedAt: job.started_at,
        ttlMinutes,
      },
      "Resetting stale active scan job"
    );
    await failScanJob(
      {
        id: jobId,
        seller_id: String(job.seller_id),
        template_id: String(job.template_id),
      },
      "failed",
      "STALE_ACTIVE_JOB",
      `Scan job exceeded ${ttlMinutes} minutes in an active state and was reset. Retry manually.`
    );
  }

  return staleJobs.length;
}

export interface ScanMaintenanceSweepResult {
  checked: number;
  staleReset: number;
  githubReconciled: number;
  errors: number;
}

export async function runScanMaintenanceSweep(maxJobs = 200): Promise<ScanMaintenanceSweepResult> {
  const result: ScanMaintenanceSweepResult = {
    checked: 0,
    staleReset: 0,
    githubReconciled: 0,
    errors: 0,
  };

  const jobs = await listAllActiveScanJobs(maxJobs);
  result.checked = jobs.length;
  if (jobs.length === 0) {
    return result;
  }

  const nowMs = Date.now();
  const ttlMs = getActiveJobTtlMs();
  const ttlMinutes = Math.round(ttlMs / (60 * 1000));

  for (const job of jobs) {
    const jobId = String(job.id);
    const sellerId = String(job.seller_id);
    const templateId = String(job.template_id);
    try {
      if (isStaleActiveJob(job, nowMs, ttlMs)) {
        result.staleReset += 1;
        await failScanJob(
          { id: jobId, seller_id: sellerId, template_id: templateId },
          "failed",
          "STALE_ACTIVE_JOB",
          `Scan job exceeded ${ttlMinutes} minutes in an active state and was reset. Retry manually.`
        );
        continue;
      }

      if (job.github_run_id) {
        result.githubReconciled += 1;
        await reconcileJobStateFromGitHub(job);
      }
    } catch (err) {
      result.errors += 1;
      logger.warn(
        { err, jobId, sellerId, templateId, githubRunId: job.github_run_id },
        "Scan maintenance sweep failed for active job"
      );
    }
  }

  return result;
}

async function dispatchGitHubScan(
  jobId: string,
  request: ScanRequest
): Promise<void> {
  const startedAtMs = Date.now();
  const env = getEnv();

  await updateScanJob(jobId, { status: "dispatching" });
  await publishStatusEvent(jobId, "dispatching", "Dispatching GitHub Actions run...", {
    templateId: request.templateId,
  });

  try {
    throwIfCancelled(jobId);
    const sourceRepoContext = await getRepoContext(request.sourceRepo, request.githubInstallationId);
    const workflowRepoContext = await getPlatformWorkflowContext();
    throwIfCancelled(jobId);

    await updateScanJob(jobId, {
      github_installation_id: sourceRepoContext.installationId,
      github_repo_owner: workflowRepoContext.owner,
      github_repo_name: workflowRepoContext.repo,
      status: "dispatching",
      metadata: {
        sourceRepo: request.sourceRepo,
        workflowRepo: `${workflowRepoContext.owner}/${workflowRepoContext.repo}`,
      },
    });

    const dispatchInput = {
      scanJobId: jobId,
      reportTitle: `Security Audit for ${request.sourceRepo}`,
      sourceRepo: request.sourceRepo,
      sourceInstallationId: sourceRepoContext.installationId,
      templateId: request.templateId,
      sellerId: request.sellerId,
      };

    throwIfCancelled(jobId);
    await updateScanJob(jobId, { status: "workflow_seeding" });
    await publishStatusEvent(
      jobId,
      "workflow_seeding",
      "Validating platform workflow availability...",
      {
        templateId: request.templateId,
        owner: workflowRepoContext.owner,
        repo: workflowRepoContext.repo,
      }
    );
    await ensureWorkflowInRepo(workflowRepoContext);

    await updateScanJob(jobId, { status: "dispatching" });
    await publishStatusEvent(jobId, "dispatching", "Dispatching GitHub Actions run...", {
      templateId: request.templateId,
      owner: workflowRepoContext.owner,
      repo: workflowRepoContext.repo,
    });

    await dispatchWorkflowRun(workflowRepoContext, dispatchInput);

    throwIfCancelled(jobId);
    const runLookup = await findRecentWorkflowRun(workflowRepoContext, startedAtMs);
    throwIfCancelled(jobId);
    if (!runLookup.runId) {
      await updateScanJob(jobId, {
        status: "delayed",
        failure_code: "GITHUB_RATE_LIMITED",
        failure_reason: "Workflow dispatched but run not visible yet. Waiting for GitHub sync.",
      });

      await appendScanJobEvent({
        scanJobId: jobId,
        eventSource: "github_poll",
        eventType: "dispatch_delayed",
        payload: {
          owner: workflowRepoContext.owner,
          repo: workflowRepoContext.repo,
        },
      }).catch((err) => logger.warn({ err, jobId }, "Failed to append dispatch delayed event"));

      await publishStatusEvent(
        jobId,
        "delayed",
        "GitHub accepted dispatch. Waiting for run to be scheduled...",
        { templateId: request.templateId }
      );
      return;
    }

    throwIfCancelled(jobId);
    await updateScanJob(jobId, {
      status: "queued_in_github",
      github_run_id: String(runLookup.runId),
      github_run_attempt: runLookup.runAttempt,
      github_workflow_id: env.GITHUB_WORKFLOW_FILE,
      failure_code: undefined,
      failure_reason: undefined,
      error_message: undefined,
    });

    await appendScanJobEvent({
      scanJobId: jobId,
      eventSource: "app",
      eventType: "dispatch_queued",
      payload: {
        githubRunId: runLookup.runId,
        githubRunAttempt: runLookup.runAttempt,
      },
    }).catch((err) => logger.warn({ err, jobId }, "Failed to append dispatch queued event"));

    await publishStatusEvent(jobId, "queued_in_github", "Scan queued in GitHub sandbox VM", {
      templateId: request.templateId,
      githubRunId: runLookup.runId,
    });
  } catch (err) {
    const classified = classifyDispatchError(err);
    const failureReason = buildDispatchFailureReason(err, classified, env.GITHUB_WORKFLOW_FILE);

    const jobEntity: Pick<ScanJobEntity, "id" | "seller_id" | "template_id"> = {
      id: jobId,
      seller_id: request.sellerId,
      template_id: request.templateId,
    };

    await failScanJob(
      jobEntity,
      classified.status,
      classified.failureCode,
      failureReason
    );

    logger.error(
      { err, jobId, sourceRepo: request.sourceRepo, failureCode: classified.failureCode, failureReason },
      "GitHub scan dispatch failed"
    );
  }
}

scanRoute.post("/scan/cancel/:jobId", authMiddleware, async (c) => {
  const jobId = c.req.param("jobId");
  if (!jobId) {
    return c.json(
      { error: { code: "INVALID_JOB_ID", message: "Job ID is required" } },
      400
    );
  }

  const body = await c.req.json().catch(() => null);
  const parsed = scanCancelSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: parsed.error.issues.map((i) => i.message).join(", "),
        },
      },
      400
    );
  }

  const sellerId = parsed.data.sellerId;

  const job = await getScanJob(jobId).catch(() => null);
  if (!job) {
    return c.json(
      { error: { code: "JOB_NOT_FOUND", message: "Scan job not found" } },
      404
    );
  }

  if (String(job.seller_id) !== String(sellerId)) {
    return c.json(
      { error: { code: "FORBIDDEN", message: "Scan job does not belong to seller" } },
      403
    );
  }

  if (!isActiveScanStatus(String(job.status))) {
    return c.json(
      {
        accepted: false,
        code: "SCAN_ALREADY_TERMINAL",
        message: "Scan already completed or failed",
        status: job.status,
      },
      200
    );
  }

  const cancelState = cancelScanJob(jobId);

  if (job.github_run_id) {
    try {
      const runRepo = resolveRunRepoFullName(job);
      const explicitInstallationId =
        runRepo.toLowerCase() === String(job.source_repo).toLowerCase() &&
        job.github_installation_id
          ? Number(job.github_installation_id)
          : undefined;
      const repoContext = await getRepoContext(runRepo, explicitInstallationId);
      await cancelWorkflowRun(repoContext, Number(job.github_run_id));
    } catch (error) {
      logger.warn(
        { error, jobId, githubRunId: job.github_run_id },
        "Failed to cancel GitHub run; continuing with local cancellation state"
      );
    }
  }

  await failScanJob(
    job,
    "failed",
    "CANCELED_BY_USER",
    "Scan cancelled by user"
  );

  return c.json({
    accepted: true,
    code: "SCAN_CANCELLED",
    message: "Scan cancelled",
    queued: cancelState.wasQueued,
    running: cancelState.wasRunning,
  });
});

scanRoute.post("/scan/retry/:jobId", authMiddleware, async (c) => {
  const previousJobId = c.req.param("jobId");
  if (!previousJobId) {
    return c.json(
      { error: { code: "INVALID_JOB_ID", message: "Job ID is required" } },
      400
    );
  }

  const body = await c.req.json().catch(() => null);
  const parsed = scanCancelSchema.safeParse(body);
  if (!parsed.success) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: parsed.error.issues.map((i) => i.message).join(", "),
        },
      },
      400
    );
  }

  const sellerId = parsed.data.sellerId;
  const previous = await getScanJob(previousJobId).catch(() => null);
  if (!previous) {
    return c.json(
      { error: { code: "JOB_NOT_FOUND", message: "Scan job not found" } },
      404
    );
  }

  if (String(previous.seller_id) !== String(sellerId)) {
    return c.json(
      { error: { code: "FORBIDDEN", message: "Scan job does not belong to seller" } },
      403
    );
  }

  if (!TERMINAL_STATUSES.has(String(previous.status) as ExtendedScanStatus)) {
    return c.json(
      {
        accepted: false,
        code: "SCAN_NOT_TERMINAL",
        message: "Only terminal scan jobs can be retried",
        status: previous.status,
      },
      409
    );
  }

  const retryRequest = {
    templateId: String(previous.template_id),
    sellerId: String(previous.seller_id),
    sourceRepo: String(previous.source_repo),
    purchaseId: previous.purchase_id ? String(previous.purchase_id) : undefined,
    buyerId: previous.buyer_id ? String(previous.buyer_id) : undefined,
    targetRepo: previous.target_repo ? String(previous.target_repo) : undefined,
    githubInstallationId:
      typeof previous.github_installation_id === "number" && Number.isFinite(previous.github_installation_id)
        ? Number(previous.github_installation_id)
        : undefined,
  };

  const response = await fetch(`${c.req.url.replace(`/scan/retry/${previousJobId}`, "/scan")}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Scanner-Key": c.req.header("X-Scanner-Key") || "",
    },
    body: JSON.stringify(retryRequest),
  });
  const payload = await response.json().catch(() => ({}));
  return c.json(payload, response.status as 200);
});

scanRoute.post("/scan", authMiddleware, rateLimitMiddleware, async (c) => {
  const body = await c.req.json();
  const parsed = scanRequestSchema.safeParse(body);

  if (!parsed.success) {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: parsed.error.issues.map((i) => i.message).join(", "),
        },
      },
      400
    );
  }

  const request = parsed.data;
  const env = getEnv();
  const requestId = uuidv4();

  if (env.SCAN_PROVIDER !== "github_actions_platform") {
    return c.json(
      {
        accepted: false,
        code: "PROVIDER_NOT_SUPPORTED",
        message: "Scanner is configured for a non-platform provider. Set SCAN_PROVIDER=github_actions_platform.",
      },
      503
    );
  }

  const ledgerAvailable = await refreshScanJobEventsLedgerAvailability().catch((err) => {
    logger.warn({ err, cached: isScanJobEventsLedgerAvailable() }, "Failed refreshing scan_job_events ledger availability before admission");
    return false;
  });
  if (!ledgerAvailable) {
    return c.json(
      {
        accepted: false,
        code: "SCAN_JOB_EVENTS_LEDGER_UNAVAILABLE",
        message:
          "scan_job_events ledger is unavailable (collection missing or permission denied). Fix Directus schema/RBAC before dispatching new scans.",
      },
      503
    );
  }

  await reconcileStaleActiveJobsForSeller(request.sellerId).catch((err) => {
    logger.warn({ err, sellerId: request.sellerId }, "Failed to reconcile stale active jobs before scan admission");
  });

  const reservationId = `reserved:${requestId}`;

  logger.info(
    { requestId, templateId: request.templateId, sellerId: request.sellerId },
    "📡 Scan request received - dispatching GitHub Actions run"
  );

  let admission = await admitTemplateScan(
    request.sellerId,
    request.templateId,
    reservationId
  );

  if (admission.state === "existing") {
    if (admission.jobId.startsWith("reserved:")) {
      return c.json(
        {
          accepted: true,
          code: "SCAN_ALREADY_RUNNING",
          status: "pending",
          message: "Scan for this template is already being queued",
        },
        202
      );
    }

    const existingJob = await getScanJob(admission.jobId).catch(() => null);
    if (existingJob && isActiveScanStatus(String(existingJob.status))) {
      return c.json(
        {
          accepted: true,
          code: "SCAN_ALREADY_RUNNING",
          jobId: String(existingJob.id),
          status: existingJob.status,
        },
        200
      );
    }

    await clearTemplateBindingIfMatches(
      request.sellerId,
      request.templateId,
      admission.jobId
    ).catch((err) => logger.warn({ err, templateId: request.templateId }, "Failed to clear stale binding"));

    admission = await admitTemplateScan(
      request.sellerId,
      request.templateId,
      reservationId
    );
  }

  if (admission.state === "limit") {
    const activeJobs = await listActiveScanJobsForSeller(request.sellerId);
    return c.json(
      {
        accepted: false,
        code: "MAX_ACTIVE_SCANS_REACHED",
        message: "Maximum 3 active template scans per user reached",
        activeTemplates: admission.templateIds,
        activeJobs: activeJobs.map((job) => ({
          jobId: String(job.id),
          templateId: String(job.template_id),
          status: job.status,
          startedAt: job.started_at,
          githubRunId: job.github_run_id,
        })),
      },
      429
    );
  }

  let scanJobId = "";
  try {
    const scanJob = await createScanJob({
      purchase_id: request.purchaseId,
      template_id: request.templateId,
      seller_id: request.sellerId,
      buyer_id: request.buyerId,
      source_repo: request.sourceRepo,
      target_repo: request.targetRepo,
      status: "pending",
      risk_level: "none",
      overall_rating: "A",
      overall_score: 100,
      rating_secrets: "A",
      rating_prompt_injection: "A",
      rating_dependencies: "A",
      rating_permissions: "A",
      rating_sast: "A",
      seller_color_light: "green",
      started_at: new Date().toISOString(),
      scan_provider: "github_actions_platform",
      github_installation_id: request.githubInstallationId,
      github_workflow_id: env.GITHUB_WORKFLOW_FILE,
      github_repo_owner: request.sourceRepo.split("/")[0],
      github_repo_name: request.sourceRepo.split("/")[1],
    });

    scanJobId = String(scanJob.id);
    await bindTemplateScanJob(request.sellerId, request.templateId, scanJobId);

    await appendScanJobEvent({
      scanJobId,
      eventSource: "app",
      eventType: "scan_requested",
      payload: {
        templateId: request.templateId,
        sourceRepo: request.sourceRepo,
      },
    }).catch((err) => logger.warn({ err, scanJobId }, "Failed to append scan requested event"));
  } catch (createErr) {
    await releaseTemplateScanSlot(request.sellerId, request.templateId).catch((err) => logger.warn({ err, templateId: request.templateId }, "Failed to release scan slot on error"));
    logger.error(
      { createErr, requestId, sellerId: request.sellerId, templateId: request.templateId },
      "Failed to create scan job"
    );

    return c.json(
      {
        error: {
          code: "SCAN_CREATE_FAILED",
          message: "Failed to create scan job",
        },
      },
      500
    );
  }

  const queued = enqueueScanJob(scanJobId, async () => {
    await dispatchGitHubScan(scanJobId, request);
  });

  if (!queued) {
    const failedJob: Pick<ScanJobEntity, "id" | "seller_id" | "template_id"> = {
      id: scanJobId,
      seller_id: request.sellerId,
      template_id: request.templateId,
    };

    await failScanJob(
      failedJob,
      "failed",
      "SCANNER_CAPACITY_REACHED",
      "Scanner queue is currently full. Please retry in a moment."
    );

    await clearTemplateBindingIfMatches(
      request.sellerId,
      request.templateId,
      scanJobId
    ).catch((err) => logger.warn({ err, scanJobId }, "Failed to clear binding on capacity limit"));

    return c.json(
      {
        accepted: false,
        code: "SCANNER_CAPACITY_REACHED",
        message: "Scanner queue is currently full. Please retry in a moment.",
        queue: getScanRunnerStats(),
      },
      503
    );
  }

  return c.json(
    {
      accepted: true,
      code: "SCAN_QUEUED",
      jobId: scanJobId,
      status: "pending",
      pollUrl: `/scan/status/${scanJobId}`,
      streamChannel: `scan:progress:${scanJobId}`,
      queue: getScanRunnerStats(),
    },
    202
  );
});

scanRoute.get("/scan/status/:jobId", authMiddleware, async (c) => {
  const jobId = c.req.param("jobId");

  if (!jobId) {
    return c.json(
      { error: { code: "INVALID_JOB_ID", message: "Job ID is required" } },
      400
    );
  }

  try {
    const initialJob = await getScanJob(jobId).catch(() => null);
    if (!initialJob) {
      return c.json(
        { error: { code: "JOB_NOT_FOUND", message: "Scan job not found" } },
        404
      );
    }

    await reconcileJobStateFromGitHub(initialJob);
    const job = await getScanJob(jobId);
    const metadata = (job.metadata || {}) as Record<string, unknown>;
    const reportUrlFromMetadata =
      typeof metadata.reportUrl === "string" ? metadata.reportUrl : undefined;

    if (!job) {
      return c.json(
        { error: { code: "JOB_NOT_FOUND", message: "Scan job not found" } },
        404
      );
    }

    return c.json({
      jobId: String(job.id),
      status: job.status,
      progress: statusToProgress(String(job.status)),
      overallRating: job.overall_rating,
      overallScore: job.overall_score,
      colorLight: job.seller_color_light,
      errorMessage: job.error_message,
      completedAt: job.completed_at,
      failureCode: job.failure_code,
      failureReason: job.failure_reason,
      githubRunId: job.github_run_id,
      githubRunAttempt: job.github_run_attempt,
      artifactName: job.artifact_name,
      artifactFileId: job.artifact_file_id,
      artifactUrl:
        reportUrlFromMetadata ||
        (job.artifact_file_id ? `/assets/${job.artifact_file_id}` : undefined),
      metadata,
    });
  } catch (err) {
    logger.error({ err, jobId }, "Failed to get scan job status");
    return c.json(
      {
        error: {
          code: "STATUS_FETCH_FAILED",
          message: "Failed to fetch job status",
        },
      },
      500
    );
  }
});

scanRoute.get("/scan/active/:sellerId", authMiddleware, async (c) => {
  const sellerId = c.req.param("sellerId");
  if (!sellerId) {
    return c.json(
      { error: { code: "INVALID_SELLER_ID", message: "sellerId is required" } },
      400
    );
  }

  try {
    await reconcileStaleActiveJobsForSeller(sellerId).catch((err) => {
      logger.warn({ err, sellerId }, "Failed to reconcile stale active jobs");
    });

    let jobs = await listActiveScanJobsForSeller(sellerId);
    if (jobs.length > 0) {
      await Promise.all(
        jobs.map(async (job) => {
          await reconcileJobStateFromGitHub(job).catch((err) => {
            logger.warn(
              { err, sellerId, jobId: String(job.id), githubRunId: job.github_run_id },
              "Failed to reconcile active job from GitHub during active listing"
            );
          });
        })
      );
      jobs = await listActiveScanJobsForSeller(sellerId);
    }

    const activeTemplateIds = await getActiveTemplateIds(sellerId);

    const withState = await Promise.all(
      jobs.map(async (job) => ({
        jobId: String(job.id),
        templateId: String(job.template_id),
        status: job.status,
        startedAt: job.started_at,
        githubRunId: job.github_run_id,
        latestEvent: await getScanState(String(job.id)),
      }))
    );

    return c.json({
      success: true,
      sellerId,
      activeTemplateIds,
      activeJobs: withState,
    });
  } catch (err) {
    logger.error({ err, sellerId }, "Failed to list active scan jobs");
    return c.json(
      {
        error: {
          code: "ACTIVE_SCAN_FETCH_FAILED",
          message: "Failed to fetch active scans",
        },
      },
      500
    );
  }
});

scanRoute.post("/github-webhook", async (c) => {
  const signature = c.req.header("X-Hub-Signature-256") || null;
  const deliveryId = c.req.header("X-GitHub-Delivery") || undefined;
  const eventName = c.req.header("X-GitHub-Event") || "";
  const rawBody = await c.req.text();

  if (!verifyGitHubWebhookSignature(rawBody, signature)) {
    return c.json(
      {
        error: {
          code: "WEBHOOK_SIGNATURE_INVALID",
          message: "Invalid webhook signature",
        },
      },
      401
    );
  }

  if (eventName !== "workflow_run") {
    return c.json({ success: true, ignored: true });
  }

  const parsedBody = (() => {
    try {
      return JSON.parse(rawBody || "{}");
    } catch {
      return null;
    }
  })();

  const parsed = scanWebhookSchema.safeParse(parsedBody);

  if (!parsed.success || !parsed.data.workflow_run?.id) {
    return c.json(
      {
        error: {
          code: "PROVIDER_EVENT_INVALID",
          message: "Invalid workflow_run webhook payload",
        },
      },
      400
    );
  }

  const payload = parsed.data;
  const workflowRun = payload.workflow_run;
  if (!workflowRun) {
    return c.json(
      {
        error: {
          code: "PROVIDER_EVENT_INVALID",
          message: "Missing workflow_run payload",
        },
      },
      400
    );
  }
  const githubRunId = String(workflowRun.id);

  const job = await getScanJobByGitHubRunId(githubRunId).catch(() => null);
  if (!job) {
    logger.info(
      { githubRunId, deliveryId, eventName },
      "No matching scan job found for webhook run id"
    );
    return c.json({ success: true, ignored: true, reason: "job_not_found" });
  }

  const inserted = await appendScanJobEvent({
    scanJobId: String(job.id),
    eventSource: "github_webhook",
    eventType: `workflow_run:${payload.action || "unknown"}`,
    payload: {
      action: payload.action,
      runStatus: workflowRun.status,
      runConclusion: workflowRun.conclusion,
      runAttempt: workflowRun.run_attempt,
      htmlUrl: workflowRun.html_url,
    },
    providerEventId: deliveryId,
  }).catch(() => true);

  if (!inserted) {
    return c.json({ success: true, duplicate: true });
  }

  const runStatus = (workflowRun.status || "").toLowerCase();
  const runConclusion = (workflowRun.conclusion || "").toLowerCase();

  if (runStatus === "queued" || payload.action === "requested") {
    await updateScanJob(String(job.id), {
      status: "queued_in_github",
      github_run_attempt: workflowRun.run_attempt,
    });
    await publishStatusEvent(
      String(job.id),
      "queued_in_github",
      "Scan queued in GitHub Actions",
      {
        templateId: String(job.template_id),
        githubRunId,
      }
    );

    return c.json({ success: true, status: "queued_in_github" });
  }

  if (runStatus === "in_progress") {
    await updateScanJob(String(job.id), {
      status: "running_in_github",
      github_run_attempt: workflowRun.run_attempt,
    });

    await publishStatusEvent(
      String(job.id),
      "running_in_github",
      "Running security scan in GitHub sandbox VM...",
      {
        templateId: String(job.template_id),
        githubRunId,
      }
    );

    return c.json({ success: true, status: "running_in_github" });
  }

  if (runStatus !== "completed" && payload.action !== "completed") {
    return c.json({ success: true, ignored: true, status: runStatus });
  }

  if (runConclusion !== "success") {
    await failScanJob(
      job,
      "failed",
      "WORKFLOW_RUN_FAILED",
      `GitHub workflow completed with conclusion: ${runConclusion || "unknown"}`,
      deliveryId
    );

    return c.json({ success: true, status: "failed" });
  }

  const finalized = await finalizeSuccessfulGitHubRun(
    job,
    githubRunId,
    workflowRun.run_attempt,
    workflowRun.html_url || undefined,
    deliveryId
  );
  return c.json({
    success: true,
    status: finalized.status,
    code: finalized.code,
    artifactFileId: finalized.artifactFileId,
  });
});

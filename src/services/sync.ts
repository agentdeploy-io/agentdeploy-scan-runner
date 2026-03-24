import { mkdir, readFile, readdir, rm, writeFile, stat, access } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { directusRequest } from "./directus.js";

// ─── GitHub Token Caching ───────────────────────────────────────────────

interface CachedToken {
  token: string;
  expiresAt: number;
}

const tokenCache = new Map<string, CachedToken>();
const TOKEN_TTL = 3600000; // 1 hour in milliseconds
const TOKEN_BUFFER = 60000; // 1 minute buffer before expiry

/**
 * Get a cached token or fetch a new one if expired
 */
async function getCachedInstallationToken(
  appId: string,
  privateKey: string,
  owner: string
): Promise<string> {
  const cacheKey = `${appId}:${owner}`;
  const cached = tokenCache.get(cacheKey);
  
  if (cached && Date.now() < cached.expiresAt) {
    logger.debug({ owner }, "Using cached GitHub installation token")
    return cached.token;
  }
  
  // Fetch new token
  const token = await getInstallationToken(appId, privateKey, owner);
  
  tokenCache.set(cacheKey, {
    token,
    expiresAt: Date.now() + TOKEN_TTL - TOKEN_BUFFER
  });
  
  logger.info({ owner }, "Fetched new GitHub installation token (cached for 1 hour)")
  return token;
}

export interface SyncResult {
  passoverId: string;
  buyerRepo: string;
  status: "synced" | "no_changes" | "failed";
  filesAdded: number;
  filesModified: number;
  filesDeleted: number;
  commitSha?: string;
  error?: string;
}

interface PassoverRecord {
  id: string;
  purchase_id: string;
  template_id: string;
  seller_id: string;
  buyer_id: string;
  seller_repo: string;
  buyer_repo: string;
  buyer_github_installation_id: number;
  status: string;
}

interface TemplateVersionRecord {
  id: number;
  template_id: string;
  version: string;
  commit_sha: string;
  files_hash: string;
  status: string;
}

interface PurchaseRecord {
  id: number;
  template_id: string;
  buyer_id: string;
  version_purchased: string;
  latest_version: string;
}

async function getInstallationToken(
  appId: string,
  privateKey: string,
  owner: string
): Promise<string> {
  const { createAppAuth } = await import("@octokit/auth-app");
  const auth = createAppAuth({ appId, privateKey });

  const installationAuth = await auth({
    type: "installation",
    installationId: undefined,
    owner,
  });

  return installationAuth.token;
}

async function getInstallationIdForRepo(
  buyerRepo: string
): Promise<number | null> {
  try {
    const record = await directusRequest<PassoverRecord>(
      `/items/code_passovers?filter[buyer_repo][_eq]=${encodeURIComponent(buyerRepo)}&limit=1&fields=buyer_github_installation_id`
    );
    return record?.buyer_github_installation_id ?? null;
  } catch {
    return null;
  }
}

async function cloneRepo(
  repoFullName: string,
  token: string,
  label: string
): Promise<string> {
  const [owner, repo] = repoFullName.split("/");
  if (!owner || !repo) throw new Error(`Invalid repo format: ${repoFullName}`);

  const hash = createHash("sha256")
    .update(repoFullName)
    .update(Date.now().toString())
    .digest("hex")
    .slice(0, 12);
  const tempDir = join(tmpdir(), `sync-${label}-${hash}`);
  await mkdir(tempDir, { recursive: true });

  const cloneUrl = `https://x-access-token:${token}@github.com/${owner}/${repo}.git`;

  execSync(`git clone --depth=1 ${cloneUrl} .`, {
    cwd: tempDir,
    timeout: 120_000,
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: "0",
      GIT_ASKPASS: "echo",
    },
  });

  logger.info({ repo: repoFullName, tempDir }, "Repo cloned for sync");
  return tempDir;
}

interface FileSnapshot {
  relativePath: string;
  content: string;
}

async function collectFiles(dir: string): Promise<Map<string, string>> {
  const files = new Map<string, string>();

  async function walk(currentDir: string) {
    const entries = await readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      const relativePath = fullPath.slice(dir.length + 1);

      if (entry.name === ".git" || entry.name === "node_modules") continue;
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }

      try {
        const fileStat = await stat(fullPath);
        if (fileStat.size > 5 * 1024 * 1024) continue; // Skip files > 5MB
        const content = await readFile(fullPath, "utf-8");
        files.set(relativePath, content);
      } catch {
        logger.debug({ path: relativePath }, "Skipping unreadable file");
      }
    }
  }

  await walk(dir);
  return files;
}

export async function syncToNewVersion(
  passoverId: string,
  newVersion: TemplateVersionRecord,
  dryRun: boolean = false
): Promise<SyncResult> {
  const env = getEnv();

  try {
    // 1. Fetch passover record
    const passover = await directusRequest<PassoverRecord>(
      `/items/code_passovers/${passoverId}`
    );

    if (!passover) {
      throw new Error(`Passover ${passoverId} not found`);
    }

    // 2. Fetch buyer's current purchase record
    const purchase = await directusRequest<PurchaseRecord>(
      `/items/purchases/${passover.purchase_id}`
    );

    // 3. Get GitHub App token for buyer's repo
    const buyerParts = passover.buyer_repo.split("/");
    const buyerOwner = buyerParts[0]!;
    const buyerToken = await getCachedInstallationToken(
      env.GITHUB_APP_ID,
      env.GITHUB_APP_PRIVATE_KEY,
      buyerOwner
    );

    // 4. Clone buyer's current repo
    const buyerDir = await cloneRepo(passover.buyer_repo, buyerToken, "buyer");

    try {
      // 5. Fetch source template at the new version's commit SHA
      const sellerParts = passover.seller_repo.split("/");
      const sellerOwner = sellerParts[0]!;
      const sellerRepoName = sellerParts[1]!;
      const sellerToken = await getCachedInstallationToken(
        env.GITHUB_APP_ID,
        env.GITHUB_APP_PRIVATE_KEY,
        sellerOwner
      );

      const sourceTarUrl = `https://api.github.com/repos/${sellerOwner}/${sellerRepoName}/tarball/${newVersion.commit_sha}`;
      const sourceRes = await fetch(sourceTarUrl, {
        headers: {
          Authorization: `Bearer ${sellerToken}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      });

      if (!sourceRes.ok) {
        throw new Error(`Failed to fetch source at ${newVersion.commit_sha}: ${sourceRes.status}`);
      }

      const sourceDir = join(tmpdir(), `sync-source-${Date.now()}`);
      await mkdir(sourceDir, { recursive: true });

      try {
        // Extract source tarball
        const tarballPath = join(sourceDir, "repo.tar.gz");
        const fileStream = (await import("node:fs")).createWriteStream(tarballPath);

        if (!sourceRes.body) throw new Error("No source response body");

        const reader = sourceRes.body.getReader();
        await new Promise<void>((resolve, reject) => {
          const pump = async () => {
            try {
              for (;;) {
                const { done, value } = await reader.read();
                if (done) { fileStream.end(); resolve(); return; }
                fileStream.write(value);
              }
            } catch (err) { reject(err); }
          };
          pump();
        });

        execSync(`tar -xzf "${tarballPath}" -C "${sourceDir}" --strip-components=1`, {
          timeout: 60_000,
        });
        await rm(tarballPath, { force: true });

        // 6. Collect files from both repos
        const buyerFiles = await collectFiles(buyerDir);
        const sourceFiles = await collectFiles(sourceDir);

        // 7. Compute diff
        let filesAdded = 0;
        let filesModified = 0;
        let filesDeleted = 0;

        // Files to add or modify (exist in source, may or may not exist in buyer)
        for (const [filePath, sourceContent] of sourceFiles) {
          const buyerContent = buyerFiles.get(filePath);
          if (buyerContent === undefined) {
            // New file - add it
            const fullPath = join(buyerDir, filePath);
            await mkdir(dirname(fullPath), { recursive: true });
            if (!dryRun) await writeFile(fullPath, sourceContent, "utf-8");
            filesAdded++;
          } else if (buyerContent !== sourceContent) {
            // Modified file - update it
            if (!dryRun) await writeFile(join(buyerDir, filePath), sourceContent, "utf-8");
            filesModified++;
          }
        }

        // Files to delete (exist in buyer but not in source)
        for (const filePath of buyerFiles.keys()) {
          if (!sourceFiles.has(filePath)) {
            const fullPath = join(buyerDir, filePath);
            if (!dryRun) await rm(fullPath, { force: true });
            filesDeleted++;
          }
        }

        if (filesAdded === 0 && filesModified === 0 && filesDeleted === 0) {
          logger.info({ passoverId, version: newVersion.version }, "No changes to sync");
          return {
            passoverId,
            buyerRepo: passover.buyer_repo,
            status: "no_changes",
            filesAdded: 0,
            filesModified: 0,
            filesDeleted: 0,
          };
        }

        if (dryRun) {
          return {
            passoverId,
            buyerRepo: passover.buyer_repo,
            status: "synced",
            filesAdded,
            filesModified,
            filesDeleted,
          };
        }

        // 8. Commit and push changes
        const commitMessage = `Update to ${newVersion.version} via AgentDeploy\n\nVersion: ${newVersion.version}\nSource: ${passover.seller_repo}@${newVersion.commit_sha.slice(0, 8)}\n\nGenerated by AgentDeploy Update System`;

        execSync("git add -A", { cwd: buyerDir });
        execSync(`git commit -m "${commitMessage.replace(/"/g, '\\"')}"`, {
          cwd: buyerDir,
          env: {
            ...process.env,
            GIT_AUTHOR_NAME: "AgentDeploy",
            GIT_AUTHOR_EMAIL: "updates@agentdeploy.io",
            GIT_COMMITTER_NAME: "AgentDeploy",
            GIT_COMMITTER_EMAIL: "updates@agentdeploy.io",
          },
        });

        execSync("git push origin HEAD", {
          cwd: buyerDir,
          timeout: 60_000,
          env: {
            ...process.env,
            GIT_TERMINAL_PROMPT: "0",
          },
        });

        // 9. Get the new commit SHA
        const newCommitSha = execSync("git rev-parse HEAD", {
          cwd: buyerDir,
        })
          .toString()
          .trim();

        // 10. Update purchase record with latest version
        try {
          await directusRequest(`/items/purchases/${passover.purchase_id}`, {
            method: "PATCH",
            body: JSON.stringify({
              latest_version: newVersion.version,
            }),
          });
        } catch (err) {
          logger.warn({ err, passoverId }, "Failed to update purchase latest_version");
        }

        // 11. Update passover status
        try {
          await directusRequest(`/items/code_passovers/${passoverId}`, {
            method: "PATCH",
            body: JSON.stringify({
              status: "synced",
              updated_at: new Date().toISOString(),
            }),
          });
        } catch (err) {
          logger.warn({ err, passoverId }, "Failed to update passover status");
        }

        logger.info(
          { passoverId, version: newVersion.version, filesAdded, filesModified, filesDeleted },
          "Sync completed"
        );

        return {
          passoverId,
          buyerRepo: passover.buyer_repo,
          status: "synced",
          filesAdded,
          filesModified,
          filesDeleted,
          commitSha: newCommitSha,
        };
      } finally {
        await rm(sourceDir, { recursive: true, force: true });
      }
    } finally {
      await cleanup(buyerDir);
    }
  } catch (err) {
    logger.error({ err, passoverId }, "Sync failed");
    return {
      passoverId,
      buyerRepo: "",
      status: "failed",
      filesAdded: 0,
      filesModified: 0,
      filesDeleted: 0,
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}

export async function syncAllBuyers(
  templateId: string,
  versionId: number,
  dryRun: boolean = false
): Promise<SyncResult[]> {
  try {
    // 1. Fetch the version record
    const version = await directusRequest<TemplateVersionRecord>(
      `/items/template_versions/${versionId}`
    );

    if (!version) {
      throw new Error(`Version ${versionId} not found`);
    }

    if (version.status !== "published") {
      throw new Error(`Version ${versionId} is not published (status: ${version.status})`);
    }

    // 2. Fetch all purchases for this template
    const purchases = await directusRequest<PurchaseRecord[]>(
      `/items/purchases?filter[template_id][_eq]=${templateId}&filter[status][_eq]=completed&limit=1000`
    );

    if (!purchases || purchases.length === 0) {
      logger.info({ templateId, versionId }, "No purchases found for template");
      return [];
    }

    // 3. Fetch passovers for each purchase
    const results: SyncResult[] = [];

    for (const purchase of purchases) {
      try {
        const passovers = await directusRequest<PassoverRecord[]>(
          `/items/code_passovers?filter[purchase_id][_eq]=${purchase.id}&filter[status][_eq]=completed&limit=1`
        );

        if (!passovers || passovers.length === 0) {
          logger.warn({ purchaseId: purchase.id }, "No completed passover found for purchase");
          results.push({
            passoverId: "",
            buyerRepo: "",
            status: "failed",
            filesAdded: 0,
            filesModified: 0,
            filesDeleted: 0,
            error: "No completed passover found",
          });
          continue;
        }

        const passover = passovers[0]!;
        const result = await syncToNewVersion(passover.id, version, dryRun);
        results.push(result);
      } catch (err) {
        logger.error({ err, purchaseId: purchase.id }, "Failed to sync purchase");
        results.push({
          passoverId: "",
          buyerRepo: "",
          status: "failed",
          filesAdded: 0,
          filesModified: 0,
          filesDeleted: 0,
          error: err instanceof Error ? err.message : "Unknown error",
        });
      }
    }

    // 4. Update template current_version if not dry run
    if (!dryRun) {
      try {
        await directusRequest(`/items/templates/${templateId}`, {
          method: "PATCH",
          body: JSON.stringify({
            current_version: version.version,
          }),
        });
      } catch (err) {
        logger.warn({ err, templateId }, "Failed to update template current_version");
      }
    }

    const synced = results.filter((r) => r.status === "synced").length;
    const failed = results.filter((r) => r.status === "failed").length;
    const noChanges = results.filter((r) => r.status === "no_changes").length;

    logger.info(
      { templateId, versionId, total: results.length, synced, failed, noChanges },
      "Sync-all completed"
    );

    return results;
  } catch (err) {
    logger.error({ err, templateId, versionId }, "Sync-all failed");
    throw err;
  }
}

async function cleanup(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}

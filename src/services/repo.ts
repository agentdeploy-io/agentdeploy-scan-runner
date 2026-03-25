import { createWriteStream } from "node:fs";
import { mkdir, readFile, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import {
  SCAN_INCLUDE_EXTENSIONS,
  SCAN_INCLUDE_FILES,
  SCAN_EXCLUDE_PATTERNS,
  SCAN_MAX_FILE_COUNT,
  SCAN_MAX_FILE_SIZE_BYTES,
} from "../constants.js";

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

/**
 * Clear cached token for a specific owner
 */
export function clearTokenCache(owner?: string): void {
  if (owner) {
    // Clear tokens for specific owner (need to iterate as we don't store appId in key)
    for (const [key, value] of tokenCache.entries()) {
      if (key.endsWith(`:${owner}`)) {
        tokenCache.delete(key);
      }
    }
  } else {
    tokenCache.clear();
  }
}

export interface RepoContents {
  tempDir: string;
  files: RepoFile[];
  totalSize: number;
}

export interface RepoFile {
  path: string;
  relativePath: string;
  size: number;
  content: string;
}

function shouldIncludeFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/");

  for (const pattern of SCAN_EXCLUDE_PATTERNS) {
    if (normalized.includes(pattern)) return false;
  }

  // Check if file is in the include list (specific filenames)
  const fileName = normalized.split("/").pop() || "";
  if (SCAN_INCLUDE_FILES.some((f) => fileName === f)) return true;

  const ext = normalized.slice(normalized.lastIndexOf("."));
  return SCAN_INCLUDE_EXTENSIONS.includes(ext);
}

async function getInstallationToken(
  appId: string,
  privateKey: string,
  owner: string
): Promise<string> {
  const { createAppAuth } = await import("@octokit/auth-app");
  const auth = createAppAuth({ appId, privateKey });

  // First, get the installation ID for the repo owner
  const appAuth = await auth({ type: "app" });
  const installationsRes = await fetch("https://api.github.com/app/installations", {
    headers: {
      Authorization: `Bearer ${appAuth.token}`,
      Accept: "application/vnd.github.v3+json",
    },
  });
  
  if (!installationsRes.ok) {
    throw new Error(`Failed to fetch installations: ${installationsRes.status}`);
  }
  
  const installations = await installationsRes.json();
  const installation = installations.find(
    (inst: any) => inst.account?.login?.toLowerCase() === owner.toLowerCase()
  );
  
  if (!installation) {
    throw new Error(`No installation found for owner: ${owner}`);
  }

  // Now get the installation token
  const installationAuth = await auth({
    type: "installation",
    installationId: installation.id,
    owner,
  });

  return installationAuth.token;
}

export async function fetchRepoContents(
  sourceRepo: string
): Promise<RepoContents> {
  const env = getEnv();
  const [owner, repo] = sourceRepo.split("/");

  if (!owner || !repo) {
    throw new Error(`Invalid source_repo format: ${sourceRepo}`);
  }

  const hash = createHash("sha256")
    .update(sourceRepo)
    .update(Date.now().toString())
    .digest("hex")
    .slice(0, 12);
  const workspaceRoot = env.SCAN_WORKDIR || tmpdir();
  await mkdir(workspaceRoot, { recursive: true });
  const tempDir = join(workspaceRoot, `scan-${hash}`);
  await mkdir(tempDir, { recursive: true });

  logger.info({ sourceRepo, tempDir, workspaceRoot }, "Fetching repository");

  const token = await getCachedInstallationToken(
    env.GITHUB_APP_ID,
    env.GITHUB_APP_PRIVATE_KEY,
    owner
  );

  const tarUrl = `https://api.github.com/repos/${owner}/${repo}/tarball/main`;
  const res = await fetch(tarUrl, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!res.ok) {
    const masterUrl = `https://api.github.com/repos/${owner}/${repo}/tarball/master`;
    const masterRes = await fetch(masterUrl, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });

    if (!masterRes.ok) {
      await rm(tempDir, { recursive: true, force: true });
      throw new Error(`Failed to fetch repo: ${res.status} ${res.statusText}`);
    }

    await extractTarball(masterRes, tempDir);
  } else {
    await extractTarball(res, tempDir);
  }

  const files = await collectFiles(tempDir);

  if (files.length > SCAN_MAX_FILE_COUNT) {
    logger.warn(
      { fileCount: files.length, max: SCAN_MAX_FILE_COUNT },
      "File count exceeds limit"
    );
  }

  const totalSize = files.reduce((sum, f) => sum + f.size, 0);

  return { tempDir, files, totalSize };
}

async function extractTarball(
  res: Response,
  destDir: string
): Promise<void> {
  const tarballPath = join(destDir, "repo.tar.gz");
  const fileStream = createWriteStream(tarballPath);

  if (!res.body) throw new Error("No response body");

  const reader = res.body.getReader();

  await new Promise<void>((resolve, reject) => {
    const pump = async () => {
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) {
            fileStream.end();
            resolve();
            return;
          }
          fileStream.write(value);
        }
      } catch (err) {
        reject(err);
      }
    };
    pump();
  });

  const { execSync } = await import("node:child_process");
  execSync(`tar -xzf "${tarballPath}" -C "${destDir}" --strip-components=1`, {
    timeout: 60_000,
  });

  await rm(tarballPath, { force: true });
}

async function collectFiles(dir: string): Promise<RepoFile[]> {
  const files: RepoFile[] = [];

  async function walk(currentDir: string) {
    const entries = await readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      const relativePath = fullPath.slice(dir.length + 1);

      if (entry.isDirectory()) {
        if (!SCAN_EXCLUDE_PATTERNS.some((p) => {
          // Match directory patterns like "node_modules/" or ".git/"
          if (p.endsWith("/")) {
            return relativePath.startsWith(p) || relativePath.startsWith(p.slice(0, -1));
          }
          return false;
        })) {
          await walk(fullPath);
        }
        continue;
      }

      if (!shouldIncludeFile(relativePath)) continue;
      
      // Check if file matches exclude patterns
      const fileName = entry.name;
      if (SCAN_EXCLUDE_PATTERNS.some((p) => {
        // Match exact filenames like "package-lock.json"
        if (!p.includes("*")) {
          return fileName === p || relativePath === p;
        }
        // Match glob patterns like "*.lock"
        if (p.startsWith("*.")) {
          return fileName.endsWith(p.slice(1));
        }
        return false;
      })) continue;

      const fileStat = await stat(fullPath);
      if (fileStat.size > SCAN_MAX_FILE_SIZE_BYTES) continue;

      try {
        const content = await readFile(fullPath, "utf-8");
        files.push({
          path: fullPath,
          relativePath,
          size: fileStat.size,
          content,
        });
      } catch {
        logger.debug({ path: relativePath }, "Skipping unreadable file");
      }
    }
  }

  await walk(dir);
  return files;
}

export async function cleanupRepo(tempDir: string): Promise<void> {
  await rm(tempDir, { recursive: true, force: true });
  logger.info({ tempDir }, "Repo temp dir cleaned up");
}

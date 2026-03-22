import { createWriteStream } from "node:fs";
import { mkdir, readFile, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { SCAN_MAX_FILE_COUNT, SCAN_MAX_FILE_SIZE_BYTES, SCAN_INCLUDE_EXTENSIONS, SCAN_EXCLUDE_PATTERNS, } from "../constants.js";
function shouldIncludeFile(filePath) {
    const normalized = filePath.replace(/\\/g, "/");
    for (const pattern of SCAN_EXCLUDE_PATTERNS) {
        if (normalized.includes(pattern))
            return false;
    }
    const ext = normalized.slice(normalized.lastIndexOf("."));
    return SCAN_INCLUDE_EXTENSIONS.includes(ext);
}
async function getInstallationToken(appId, privateKey, owner) {
    const { createAppAuth } = await import("@octokit/auth-app");
    const auth = createAppAuth({ appId, privateKey });
    const installationAuth = await auth({
        type: "installation",
        installationId: undefined,
        owner,
    });
    return installationAuth.token;
}
export async function fetchRepoContents(sourceRepo) {
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
    const tempDir = join(tmpdir(), `scan-${hash}`);
    await mkdir(tempDir, { recursive: true });
    logger.info({ sourceRepo, tempDir }, "Fetching repository");
    const token = await getInstallationToken(env.GITHUB_APP_ID, env.GITHUB_APP_PRIVATE_KEY, owner);
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
    }
    else {
        await extractTarball(res, tempDir);
    }
    const files = await collectFiles(tempDir);
    if (files.length > SCAN_MAX_FILE_COUNT) {
        logger.warn({ fileCount: files.length, max: SCAN_MAX_FILE_COUNT }, "File count exceeds limit");
    }
    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
    return { tempDir, files, totalSize };
}
async function extractTarball(res, destDir) {
    const tarballPath = join(destDir, "repo.tar.gz");
    const fileStream = createWriteStream(tarballPath);
    if (!res.body)
        throw new Error("No response body");
    const reader = res.body.getReader();
    await new Promise((resolve, reject) => {
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
            }
            catch (err) {
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
async function collectFiles(dir) {
    const files = [];
    async function walk(currentDir) {
        const entries = await readdir(currentDir, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = join(currentDir, entry.name);
            const relativePath = fullPath.slice(dir.length + 1);
            if (entry.isDirectory()) {
                if (!SCAN_EXCLUDE_PATTERNS.some((p) => relativePath.startsWith(p.replace("/", "")))) {
                    await walk(fullPath);
                }
                continue;
            }
            if (!shouldIncludeFile(relativePath))
                continue;
            const fileStat = await stat(fullPath);
            if (fileStat.size > SCAN_MAX_FILE_SIZE_BYTES)
                continue;
            try {
                const content = await readFile(fullPath, "utf-8");
                files.push({
                    path: fullPath,
                    relativePath,
                    size: fileStat.size,
                    content,
                });
            }
            catch {
                logger.debug({ path: relativePath }, "Skipping unreadable file");
            }
        }
    }
    await walk(dir);
    return files;
}
export async function cleanupRepo(tempDir) {
    await rm(tempDir, { recursive: true, force: true });
    logger.info({ tempDir }, "Repo temp dir cleaned up");
}

import { writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { execSync } from "node:child_process";
import { logger } from "../logger.js";
import { SCAN_MAX_BUNDLED_LINES } from "../constants.js";
import type { RepoContents, RepoFile } from "./repo.js";

export interface BundleResult {
  content: string;
  lineCount: number;
  exceededThreshold: boolean;
  fileCount: number;
}

export async function bundleRepo(repo: RepoContents): Promise<BundleResult> {
  logger.info(
    { fileCount: repo.files.length },
    "Bundling repository files"
  );

  const bundleLines: string[] = [];
  let fileCount = 0;

  for (const file of repo.files) {
    const header = `\n${"=".repeat(80)}\nFILE: ${file.relativePath}\nLINES: ${file.content.split("\n").length}\n${"=".repeat(80)}\n`;
    bundleLines.push(header);
    bundleLines.push(file.content);
    fileCount++;
  }

  const content = bundleLines.join("\n");
  const lineCount = content.split("\n").length;
  const exceededThreshold = lineCount > SCAN_MAX_BUNDLED_LINES;

  if (exceededThreshold) {
    logger.warn(
      { lineCount, threshold: SCAN_MAX_BUNDLED_LINES },
      "Bundle exceeds line threshold"
    );
  }

  logger.info({ lineCount, fileCount }, "Bundle created");

  return { content, lineCount, exceededThreshold, fileCount };
}

export async function bundleWithCli(
  repoPath: string,
  outputPath: string
): Promise<BundleResult> {
  try {
    execSync(
      `npx ai-code-bundler bundle --input "${repoPath}" --output "${outputPath}" --format analysis`,
      { timeout: 120_000, stdio: "pipe" }
    );

    const content = await readFile(outputPath, "utf-8");
    const lineCount = content.split("\n").length;
    const exceededThreshold = lineCount > SCAN_MAX_BUNDLED_LINES;

    return { content, lineCount, exceededThreshold, fileCount: 0 };
  } catch (err) {
    logger.warn({ err }, "ai-code-bundler failed, using fallback bundling");
    throw err;
  }
}

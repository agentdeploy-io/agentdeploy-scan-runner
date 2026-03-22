import { readFile } from "node:fs/promises";
import { execSync } from "node:child_process";
import { logger } from "../logger.js";
import { SCAN_MAX_BUNDLED_LINES } from "../constants.js";
export async function bundleRepo(repo) {
    logger.info({ fileCount: repo.files.length }, "Bundling repository files");
    const bundleLines = [];
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
        logger.warn({ lineCount, threshold: SCAN_MAX_BUNDLED_LINES }, "Bundle exceeds line threshold");
    }
    logger.info({ lineCount, fileCount }, "Bundle created");
    return { content, lineCount, exceededThreshold, fileCount };
}
export async function bundleWithCli(repoPath, outputPath) {
    try {
        execSync(`npx ai-code-bundler bundle --input "${repoPath}" --output "${outputPath}" --format analysis`, { timeout: 120_000, stdio: "pipe" });
        const content = await readFile(outputPath, "utf-8");
        const lineCount = content.split("\n").length;
        const exceededThreshold = lineCount > SCAN_MAX_BUNDLED_LINES;
        return { content, lineCount, exceededThreshold, fileCount: 0 };
    }
    catch (err) {
        logger.warn({ err }, "ai-code-bundler failed, using fallback bundling");
        throw err;
    }
}

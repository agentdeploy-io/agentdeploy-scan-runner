import type { RepoContents } from "./repo.js";
export interface BundleResult {
    content: string;
    lineCount: number;
    exceededThreshold: boolean;
    fileCount: number;
}
export declare function bundleRepo(repo: RepoContents): Promise<BundleResult>;
export declare function bundleWithCli(repoPath: string, outputPath: string): Promise<BundleResult>;

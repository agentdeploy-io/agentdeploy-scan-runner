/**
 * Clear cached token for a specific owner
 */
export declare function clearTokenCache(owner?: string): void;
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
export declare function fetchRepoContents(sourceRepo: string): Promise<RepoContents>;
export declare function cleanupRepo(tempDir: string): Promise<void>;

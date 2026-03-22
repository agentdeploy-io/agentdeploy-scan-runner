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
interface TemplateVersionRecord {
    id: number;
    template_id: string;
    version: string;
    commit_sha: string;
    files_hash: string;
    status: string;
}
export declare function syncToNewVersion(passoverId: string, newVersion: TemplateVersionRecord, dryRun?: boolean): Promise<SyncResult>;
export declare function syncAllBuyers(templateId: string, versionId: number, dryRun?: boolean): Promise<SyncResult[]>;
export {};

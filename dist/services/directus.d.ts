import type { ScanStatus, ScanRating, RiskLevel, ColorLight, ScanCategory, ScanSeverity } from "../constants.js";
interface ScanJobRecord {
    purchase_id?: string;
    template_id: string;
    seller_id: string;
    buyer_id?: string;
    source_repo: string;
    target_repo?: string;
    status: ScanStatus;
    risk_level: RiskLevel;
    overall_rating: ScanRating;
    overall_score: number;
    rating_secrets: ScanRating;
    rating_prompt_injection: ScanRating;
    rating_dependencies: ScanRating;
    rating_permissions: ScanRating;
    rating_sast: ScanRating;
    seller_color_light: ColorLight;
    started_at: string;
    completed_at?: string;
    error_message?: string;
    llm_summary?: string;
    llm_recommendations?: Record<string, unknown>;
    bundled_line_count?: number;
    exceeded_line_threshold?: boolean;
    metadata?: Record<string, unknown>;
}
interface ScanFindingRecord {
    scan_job_id: string;
    severity: ScanSeverity;
    category: ScanCategory | string;
    tool: string;
    rule_id: string;
    file_path?: string;
    line_start?: number;
    line_end?: number;
    title: string;
    description: string;
    recommendation: string;
    evidence?: Record<string, unknown>;
    status: "open";
}
export interface DirectusErrorBody {
    error?: {
        code?: string;
        message?: string;
        collection?: string;
        action?: string;
        role?: string;
    };
}
export declare class DirectusForbiddenError extends Error {
    readonly collection?: string;
    readonly action?: string;
    readonly role?: string;
    readonly fields?: string[];
    readonly statusCode = 403;
    constructor(message: string, options?: {
        collection?: string;
        action?: string;
        role?: string;
        fields?: string[];
    });
}
export declare function directusRequest<T>(path: string, options?: RequestInit): Promise<T>;
export declare function createScanJob(record: ScanJobRecord): Promise<{
    id: string;
}>;
export declare function updateScanJob(id: string, patch: Partial<ScanJobRecord>): Promise<void>;
export declare function createScanFindings(findings: ScanFindingRecord[]): Promise<void>;
export declare function updateTemplateScanFields(templateId: string, fields: {
    scan_rating: ScanRating;
    scan_score: number;
    scan_color_light: ColorLight;
    last_scan_at: string;
    last_scan_job_id: string;
    scan_status: string;
}): Promise<void>;
export declare function updateSellerSecurityFields(sellerId: string, fields: {
    security_rating: ScanRating;
    security_score: number;
    security_color_light: ColorLight;
    last_security_scan: string;
    scan_compliant: boolean;
}): Promise<void>;
export declare function getScanJob(id: string): Promise<ScanJobRecord & {
    id: string;
}>;
export declare function getSellerTemplates(sellerId: string): Promise<Array<{
    id: string;
    scan_rating?: ScanRating;
    scan_score?: number;
}>>;
export {};

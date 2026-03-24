/**
 * Get circuit breaker status for a provider
 */
export declare function getCircuitBreakerStatus(provider: string): {
    state: string;
    failures: number;
} | undefined;
export interface ScanFinding {
    severity: "low" | "medium" | "high" | "critical";
    category: "secrets" | "prompt_injection" | "dependencies" | "permissions" | "sast";
    ruleId: string;
    tool: string;
    filePath: string;
    lineStart?: number;
    lineEnd?: number;
    title: string;
    description: string;
    recommendation: string;
    evidence?: Record<string, unknown>;
}
export interface LlmScanResult {
    findings: ScanFinding[];
    ratings: Record<string, {
        rating: string;
        score: number;
        findings: number;
    }>;
    summary: string;
    recommendations: string[];
}
export declare function analyzeWithLLM(bundledCode: string): Promise<LlmScanResult>;

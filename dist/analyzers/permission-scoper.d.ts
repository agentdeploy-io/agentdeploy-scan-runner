import type { ScanFinding } from "../services/llm.js";
export declare function analyzePermissions(files: Array<{
    relativePath: string;
    content: string;
}>): ScanFinding[];

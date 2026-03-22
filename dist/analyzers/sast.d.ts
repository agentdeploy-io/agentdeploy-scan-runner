import type { ScanFinding } from "../services/llm.js";
export declare function analyzeSast(files: Array<{
    relativePath: string;
    content: string;
}>): ScanFinding[];

import type { ScanFinding } from "../services/llm.js";
export declare function analyzeDependencies(files: Array<{
    relativePath: string;
    content: string;
}>): ScanFinding[];

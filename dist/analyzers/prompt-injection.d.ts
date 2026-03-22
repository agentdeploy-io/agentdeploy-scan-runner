import type { ScanFinding } from "../services/llm.js";
export declare function analyzePromptInjection(files: Array<{
    relativePath: string;
    content: string;
}>): ScanFinding[];

import type { ScanFinding } from "./llm.js";
export declare function scanForSecrets(files: Array<{
    relativePath: string;
    content: string;
}>): ScanFinding[];

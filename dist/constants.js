export const SCAN_MAX_BUNDLED_LINES = 200000;
export const SCAN_MAX_FILE_COUNT = 1000;
export const SCAN_MAX_FILE_SIZE_BYTES = 1048576; // 1MB per file
export const SCAN_LLM_MAX_TOKENS = 16384;
export const SCAN_LLM_MODEL = "gpt-4";
export const SCAN_LLM_TEMPERATURE = 0.1;
export const SCAN_TIMEOUT_MS = 300000;
export const SCAN_RATE_LIMIT_PER_MINUTE = 10;
export const SCAN_FINDINGS_MAX = 100;
export const SCAN_RATING_THRESHOLDS = {
    A: 90,
    B: 70,
    C: 50,
    D: 25,
};
export const SCAN_MINIMUM_RATING_FOR_DEPLOY = "C";
export const SCAN_RATING_ORDER = ["A", "B", "C", "D", "F"];
export const SCAN_CATEGORY_WEIGHTS = {
    secrets: 0.3,
    prompt_injection: 0.25,
    dependencies: 0.2,
    permissions: 0.15,
    sast: 0.1,
};
export const SCAN_INCLUDE_EXTENSIONS = [
    ".ts",
    ".js",
    ".py",
    ".go",
    ".rs",
    ".yml",
    ".yaml",
    ".toml",
];
export const SCAN_INCLUDE_FILES = [
    "package.json",
    "tsconfig.json",
    "docker-compose.yml",
    "Dockerfile",
];
export const SCAN_EXCLUDE_PATTERNS = [
    ".git/",
    "node_modules/",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "*.min.js",
    "*.min.css",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.svg",
    "*.ico",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    "*.mp4",
    "*.mp3",
    "*.zip",
    "*.tar",
    "*.gz",
    "*.pdf",
    "*.exe",
    "*.bin",
    ".DS_Store",
    "Thumbs.db",
];
export const RATING_TO_COLOR = {
    A: "green",
    B: "yellow",
    C: "orange",
    D: "red",
    F: "red_flashing",
};
export const RATING_TO_LABEL = {
    A: "Verified Secure",
    B: "Good Standing",
    C: "Needs Attention",
    D: "Under Review",
    F: "Suspended",
};
export const FINDING_TOOL_MAP = {
    secrets: "gitleaks",
    prompt_injection: "llm-scanner",
    dependencies: "osv-scanner",
    permissions: "custom",
    sast: "semgrep",
};

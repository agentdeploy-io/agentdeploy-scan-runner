import { z } from "zod";

// Transform to strip trailing double-quote from env values
// Handles cases like: GLM_API_KEY="some-key-with-trailing-quote"
const stripTrailingQuote = z.string().transform((s) => {
  const stripped = s.replace(/"$/g, '');
  if (stripped !== s) {
    // Log warning for security audit (will be visible during server startup)
    console.warn(`[ENV_TRANSFORM] Stripped trailing quote from environment variable`);
  }
  return stripped;
});

// Create a schema that validates min length before transform
const nonEmptyStringWithQuoteStrip = z.string().min(1).transform((s) => {
  const stripped = s.replace(/"$/g, '');
  if (stripped !== s) {
    console.warn(`[ENV_TRANSFORM] Stripped trailing quote from environment variable`);
  }
  return stripped;
});

const envSchema = z.object({
  // Auth (optional for local dev, required in production)
  SCANNER_API_KEY: stripTrailingQuote.optional().default(""),
  SCAN_WS_TOKEN_SECRET: stripTrailingQuote.optional().default(""),
  SCAN_MAX_ACTIVE_TEMPLATES_PER_USER: z.coerce.number().int().min(1).max(10).default(3),
  SCAN_MAX_PARALLEL_JOBS_PER_INSTANCE: z.coerce.number().int().min(1).max(100).default(6),
  SCAN_MAX_QUEUE_JOBS_PER_INSTANCE: z.coerce.number().int().min(1).max(10000).default(500),
  SCAN_ACTIVE_JOB_TTL_MINUTES: z.coerce.number().int().min(5).max(24 * 60).default(120),
  SCAN_MAINTENANCE_INTERVAL_SECONDS: z.coerce.number().int().min(15).max(1800).default(30),
  SCAN_ENFORCE_WORKFLOW_SYNC_GATE: z.coerce.boolean().default(false),
  SCAN_ENFORCE_LEDGER_GATE: z.coerce.boolean().default(false),
  SCAN_WORKFLOW_CONFIG_SYNC_MODE: z
    .enum(["manual", "startup_sync"])
    .default("manual"), // manual = no auto secret sync (SECURE)
  SCAN_WORKDIR: z.string().optional().default(""),
  SCAN_PROVIDER: z
    .enum(["github_actions_platform"])
    .default("github_actions_platform"),
  SCAN_STATE_TTL_SECONDS: z.coerce.number().int().min(60).max(60 * 60 * 24 * 14).default(60 * 60 * 24),
  GITHUB_WEBHOOK_SECRET: stripTrailingQuote.optional().default(""),
  GITHUB_WORKFLOW_FILE: z.string().optional().default("agent-security-scan.yml"),
  GITHUB_WORKFLOW_NAME: z.string().optional().default("Agentic Security Scan"),
  GITHUB_SCAN_ARTIFACT_NAME: z.string().optional().default("Certified-Security-Report"),
  GITHUB_SCAN_RESULT_FILE_NAME: z.string().optional().default("scan-result.json"),
  GITHUB_PLATFORM_WORKFLOW_OWNER: z.string().optional().default(""),
  GITHUB_PLATFORM_WORKFLOW_REPO: z.string().optional().default(""),
  GITHUB_PLATFORM_WORKFLOW_REF: z.string().optional().default("main"),

  // Directus
  DIRECTUS_URL: z.string().url(),
  DIRECTUS_ADMIN_TOKEN: nonEmptyStringWithQuoteStrip,

  // ─── LLM Providers (each is independent, OpenAI-compatible) ───
  // Primary model to use
  SCANNER_LLM_MODEL: z.string().optional().default("minimax/minimax-m2.5:free"),

  // Fallback order (comma-separated provider names)
  SCANNER_LLM_FALLBACK_ORDER: z.string().optional().default("openrouter,chutes,glm,novita"),

  // OpenRouter (openrouter.ai)
  OPENROUTER_API_KEY: stripTrailingQuote.optional().default(""),
  OPENROUTER_BASE_URL: z.string().optional().default("https://openrouter.ai/api/v1"),

  // Chutes (chutes.ai)
  CHUTES_API_KEY: stripTrailingQuote.optional().default(""),
  CHUTES_BASE_URL: z.string().optional().default("https://llm.chutes.ai/v1"),
  CHUTES_MODEL: z.string().optional().default("minimax/minimax-m2.5:free"),

  // GLM / Z.AI (bigmodel.cn)
  GLM_API_KEY: stripTrailingQuote.optional().default(""),
  GLM_BASE_URL: z.string().optional().default("https://open.bigmodel.cn/api/v4"),
  GLM_MODEL: z.string().optional().default("glm-4-flash"),

  // Novita (novita.ai)
  NOVITA_API_KEY: stripTrailingQuote.optional().default(""),
  NOVITA_BASE_URL: z.string().optional().default("https://api.novita.ai/v3/openai"),
  NOVITA_MODEL: z.string().optional().default("minimax/minimax-m2.5:free"),

  // Legacy OpenAI direct
  OPENAI_API_KEY: stripTrailingQuote.optional().default(""),

  // GitHub App
  GITHUB_APP_ID: z.string().min(1),
  GITHUB_APP_PRIVATE_KEY: nonEmptyStringWithQuoteStrip,

  // Server
  FRONTEND_URL: z.string().url().default("http://localhost:2000"),
  PORT: z.coerce.number().default(3001),
});

export type Env = z.infer<typeof envSchema>;

let _env: Env | null = null;

export function getEnv(): Env {
  if (_env) return _env;

  const result = envSchema.safeParse(process.env);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join(".")}: ${i.message}`)
      .join(", ");
    throw new Error(`Invalid environment: ${issues}`);
  }

  _env = result.data;
  return _env;
}

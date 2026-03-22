import { z } from "zod";

const envSchema = z.object({
  // Auth (optional for local dev, required in production)
  SCANNER_API_KEY: z.string().optional().default(""),

  // Directus
  DIRECTUS_URL: z.string().url(),
  DIRECTUS_ADMIN_TOKEN: z.string().min(1),

  // ─── LLM Providers (each is independent, OpenAI-compatible) ───
  // Primary model to use
  SCANNER_LLM_MODEL: z.string().optional().default("minimax/minimax-m2.5:free"),

  // Fallback order (comma-separated provider names)
  SCANNER_LLM_FALLBACK_ORDER: z.string().optional().default("openrouter,chutes,glm,novita"),

  // OpenRouter (openrouter.ai)
  OPENROUTER_API_KEY: z.string().optional().default(""),
  OPENROUTER_BASE_URL: z.string().optional().default("https://openrouter.ai/api/v1"),

  // Chutes (chutes.ai)
  CHUTES_API_KEY: z.string().optional().default(""),
  CHUTES_BASE_URL: z.string().optional().default("https://llm.chutes.ai/v1"),
  CHUTES_MODEL: z.string().optional().default("minimax/minimax-m2.5:free"),

  // GLM / Z.AI (bigmodel.cn)
  GLM_API_KEY: z.string().optional().default(""),
  GLM_BASE_URL: z.string().optional().default("https://open.bigmodel.cn/api/v4"),
  GLM_MODEL: z.string().optional().default("glm-4-flash"),

  // Novita (novita.ai)
  NOVITA_API_KEY: z.string().optional().default(""),
  NOVITA_BASE_URL: z.string().optional().default("https://api.novita.ai/v3/openai"),
  NOVITA_MODEL: z.string().optional().default("minimax/minimax-m2.5:free"),

  // Legacy OpenAI direct
  OPENAI_API_KEY: z.string().optional().default(""),

  // GitHub App
  GITHUB_APP_ID: z.string().min(1),
  GITHUB_APP_PRIVATE_KEY: z.string().min(1),

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

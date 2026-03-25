import OpenAI from "openai";
import { z } from "zod";
import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { safeLogContext } from "../lib/redact.js";
import {
  SCAN_LLM_MAX_TOKENS,
  SCAN_LLM_TEMPERATURE,
  SCAN_TIMEOUT_MS,
} from "../constants.js";

// ─── Circuit Breaker ───────────────────────────────────────────────────

interface CircuitBreakerState {
  failures: number;
  lastFailure: number;
  state: "closed" | "open" | "half-open";
}

const circuitBreakers = new Map<string, CircuitBreakerState>();

const CIRCUIT_FAILURE_THRESHOLD = 5;
const CIRCUIT_RESET_TIMEOUT = 60000; // 1 minute

/**
 * Check if a provider should be tried based on circuit breaker state
 */
function shouldTryProvider(provider: string): boolean {
  const cb = circuitBreakers.get(provider);
  if (!cb) return true;
  
  if (cb.state === "closed") return true;
  
  if (cb.state === "open" && Date.now() - cb.lastFailure > CIRCUIT_RESET_TIMEOUT) {
    cb.state = "half-open";
    logger.info({ provider }, "Circuit breaker entering half-open state")
    return true;
  }
  
  return cb.state === "half-open";
}

/**
 * Record a successful call - reset the circuit breaker
 */
function recordSuccess(provider: string): void {
  const cb = circuitBreakers.get(provider);
  if (cb) {
    cb.failures = 0;
    cb.state = "closed";
    logger.debug({ provider }, "Circuit breaker closed")
  }
}

/**
 * Record a failure - potentially open the circuit
 */
function recordFailure(provider: string): void {
  let cb = circuitBreakers.get(provider);
  if (!cb) {
    cb = { failures: 0, lastFailure: 0, state: "closed" };
    circuitBreakers.set(provider, cb);
  }
  cb.failures++;
  cb.lastFailure = Date.now();
  
  if (cb.failures >= CIRCUIT_FAILURE_THRESHOLD) {
    cb.state = "open";
    logger.warn({ provider, failures: cb.failures }, "Circuit breaker opened - provider temporarily disabled")
  }
}

/**
 * Get circuit breaker status for a provider
 */
export function getCircuitBreakerStatus(provider: string): { state: string; failures: number } | undefined {
  const cb = circuitBreakers.get(provider);
  if (!cb) return undefined;
  return { state: cb.state, failures: cb.failures };
}

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

const findingSchema = z.object({
  severity: z.enum(["low", "medium", "high", "critical"]),
  category: z.enum(["secrets", "prompt_injection", "dependencies", "permissions", "sast"]),
  ruleId: z.string(),
  filePath: z.string(),
  lineStart: z.number().optional(),
  lineEnd: z.number().optional(),
  title: z.string(),
  description: z.string(),
  recommendation: z.string(),
  evidence: z.string().optional(),
});

const llmResponseSchema = z.object({
  findings: z.array(findingSchema),
  ratings: z.object({
    secrets: z.object({ rating: z.enum(["A", "B", "C", "D", "F"]), score: z.number(), findings: z.number() }),
    prompt_injection: z.object({ rating: z.enum(["A", "B", "C", "D", "F"]), score: z.number(), findings: z.number() }),
    dependencies: z.object({ rating: z.enum(["A", "B", "C", "D", "F"]), score: z.number(), findings: z.number() }),
    permissions: z.object({ rating: z.enum(["A", "B", "C", "D", "F"]), score: z.number(), findings: z.number() }),
    sast: z.object({ rating: z.enum(["A", "B", "C", "D", "F"]), score: z.number(), findings: z.number() }),
  }),
  summary: z.string(),
  recommendations: z.array(z.string()),
});

export interface LlmScanResult {
  findings: ScanFinding[];
  ratings: Record<string, { rating: string; score: number; findings: number }>;
  summary: string;
  recommendations: string[];
}

// ─── Provider definitions ───────────────────────────────────────────

interface LLMProvider {
  name: string;
  apiKey: string;
  baseUrl: string;
  model: string;
}

function parseJsonFromAssistantContent(content: string): unknown {
  const trimmed = content.trim();
  if (!trimmed) {
    throw new Error("Empty LLM response");
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    // Some providers return JSON wrapped in markdown fences.
    const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (fenced?.[1]) {
      return JSON.parse(fenced[1].trim());
    }

    // Last fallback: attempt to parse the first JSON object in the content.
    const firstBrace = trimmed.indexOf("{");
    const lastBrace = trimmed.lastIndexOf("}");
    if (firstBrace !== -1 && lastBrace > firstBrace) {
      const candidate = trimmed.slice(firstBrace, lastBrace + 1);
      return JSON.parse(candidate);
    }

    throw new Error("LLM response was not valid JSON");
  }
}

function normalizeLetterGrade(value: unknown): string {
  if (typeof value !== "string") return "C";
  const raw = value.trim().toUpperCase();
  const first = raw[0];
  if (first === "A" || first === "B" || first === "C" || first === "D" || first === "F") {
    return first;
  }
  if (first === "E") return "F";
  return "C";
}

function normalizeNumericScore(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 50;
  return Math.max(0, Math.min(100, Math.round(parsed)));
}

function normalizeNumericFindings(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return Math.round(parsed);
}

function normalizeLlmPayload(raw: unknown): unknown {
  if (!raw || typeof raw !== "object") return raw;
  const payload = raw as Record<string, unknown>;
  const ratingsRaw = payload.ratings;
  if (!ratingsRaw || typeof ratingsRaw !== "object") return payload;

  const ratings = ratingsRaw as Record<string, unknown>;
  const categories = ["secrets", "prompt_injection", "dependencies", "permissions", "sast"] as const;

  for (const category of categories) {
    const nodeRaw = ratings[category];
    if (!nodeRaw || typeof nodeRaw !== "object") continue;
    const node = nodeRaw as Record<string, unknown>;
    node.rating = normalizeLetterGrade(node.rating);
    node.score = normalizeNumericScore(node.score);
    node.findings = normalizeNumericFindings(node.findings);
  }

  return payload;
}

function getAvailableProviders(env: ReturnType<typeof getEnv>): LLMProvider[] {
  const providers: LLMProvider[] = [];

  if (env.OPENROUTER_API_KEY) {
    providers.push({
      name: "openrouter",
      apiKey: env.OPENROUTER_API_KEY,
      baseUrl: env.OPENROUTER_BASE_URL,
      model: env.SCANNER_LLM_MODEL || "minimax/minimax-m2.5:free",
    });
  }

  if (env.CHUTES_API_KEY) {
    providers.push({
      name: "chutes",
      apiKey: env.CHUTES_API_KEY,
      baseUrl: env.CHUTES_BASE_URL,
      model: env.CHUTES_MODEL || "minimax/minimax-m2.5:free",
    });
  }

  if (env.GLM_API_KEY) {
    providers.push({
      name: "glm",
      apiKey: env.GLM_API_KEY,
      baseUrl: env.GLM_BASE_URL,
      model: env.GLM_MODEL || "glm-4-flash",
    });
  }

  if (env.NOVITA_API_KEY) {
    providers.push({
      name: "novita",
      apiKey: env.NOVITA_API_KEY,
      baseUrl: env.NOVITA_BASE_URL,
      model: env.NOVITA_MODEL || "minimax/minimax-m2.5:free",
    });
  }

  if (env.OPENAI_API_KEY) {
    providers.push({
      name: "openai",
      apiKey: env.OPENAI_API_KEY,
      baseUrl: "https://api.openai.com/v1",
      model: env.SCANNER_LLM_MODEL || "gpt-4o-mini",
    });
  }

  return providers;
}

/**
 * Order providers according to SCANNER_LLM_FALLBACK_ORDER.
 * Providers not in the order list are appended at the end.
 */
function orderProviders(
  providers: LLMProvider[],
  fallbackOrder: string
): LLMProvider[] {
  const order = fallbackOrder
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const ordered: LLMProvider[] = [];
  const remaining = new Set(providers.map((p) => p.name));

  for (const name of order) {
    const provider = providers.find((p) => p.name === name);
    if (provider) {
      ordered.push(provider);
      remaining.delete(name);
    }
  }

  // Append any providers not explicitly ordered
  for (const p of providers) {
    if (remaining.has(p.name)) {
      ordered.push(p);
    }
  }

  return ordered;
}

// ─── System prompt ──────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a security-focused code reviewer for AI agent templates. Your task is to analyze bundled repository code and identify security vulnerabilities, focusing on risks specific to AI agent deployments.

Analyze across these categories:

1. SECRET SCANNING: Look for hardcoded API keys (OPENAI_API_KEY, SLACK_TOKEN, etc.), OAuth tokens, database credentials, JWT secrets, webhook secrets, and any other sensitive values that should be in environment variables.

2. PROMPT INJECTION AUDIT: Examine system prompts, agent.md files, configuration files for:
   - Missing input validation before LLM calls
   - Instructions that could be overridden by user input
   - Missing output validation before external API calls
   - Recursive prompt patterns
   - Overly permissive agent instructions

3. DEPENDENCY ANALYSIS: Review package.json, requirements.txt, go.mod for:
   - Known vulnerable packages
   - Suspicious or typosquatted package names
   - Missing version pinning
   - MCP server configurations pointing to untrusted sources

4. PERMISSION SCOPING: Check for:
   - OAuth scopes exceeding what the agent needs
   - Docker capabilities beyond requirement (privileged, host networking)
   - Filesystem mounts that are broader than needed
   - Unrestricted network egress

5. STATIC ANALYSIS: Scan for:
   - eval() or Function() with variable input
   - Child_process exec with unsanitized input
   - SQL query construction with string concatenation
   - Unsafe deserialization (JSON.parse of user input without validation)
   - Prototype pollution vectors

Respond ONLY with valid JSON:
{
  "findings": [{"severity":"low|medium|high|critical","category":"secrets|prompt_injection|dependencies|permissions|sast","ruleId":"LLM-XXX","filePath":"path","lineStart":1,"lineEnd":1,"title":"Title","description":"Desc","recommendation":"Fix","evidence":"Code"}],
  "ratings": {"secrets":{"rating":"A","score":95,"findings":0},"prompt_injection":{"rating":"A","score":95,"findings":0},"dependencies":{"rating":"A","score":95,"findings":0},"permissions":{"rating":"A","score":95,"findings":0},"sast":{"rating":"A","score":95,"findings":0}},
  "summary": "Overall assessment",
  "recommendations": ["rec1", "rec2"]
}`;

// ─── Main entry point ──────────────────────────────────────────────

export async function analyzeWithLLM(
  bundledCode: string
): Promise<LlmScanResult> {
  const env = getEnv();

  const allProviders = getAvailableProviders(env);
  if (allProviders.length === 0) {
    logger.warn("No LLM providers configured — returning deterministic-only results");
    return {
      findings: [],
      ratings: {
        secrets: { rating: "C", score: 50, findings: 0 },
        prompt_injection: { rating: "C", score: 50, findings: 0 },
        dependencies: { rating: "C", score: 50, findings: 0 },
        permissions: { rating: "C", score: 50, findings: 0 },
        sast: { rating: "C", score: 50, findings: 0 },
      },
      summary: "No LLM provider configured. Scan used deterministic checks only.",
      recommendations: ["Configure OPENROUTER_API_KEY, CHUTES_API_KEY, GLM_API_KEY, or NOVITA_API_KEY for LLM analysis."],
    };
  }

  const providers = orderProviders(allProviders, env.SCANNER_LLM_FALLBACK_ORDER);

  const truncatedCode =
    bundledCode.length > 100_000
      ? bundledCode.slice(0, 100_000) + "\n\n[... truncated for length ...]"
      : bundledCode;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  let lastError: unknown;

  for (const provider of providers) {
    // Check circuit breaker before trying provider
    if (!shouldTryProvider(provider.name)) {
      logger.info({ provider: provider.name }, "Circuit breaker open - skipping provider")
      continue;
    }

    try {
      logger.info(
        { provider: provider.name, model: provider.model, codeLength: truncatedCode.length },
        "Trying LLM provider"
      );

      const client = new OpenAI({
        apiKey: provider.apiKey,
        baseURL: provider.baseUrl,
        ...(provider.name === "openrouter"
          ? {
              defaultHeaders: {
                "HTTP-Referer": env.FRONTEND_URL,
                "X-Title": "AgentDeploy Scanner",
              },
            }
          : {}),
      });

      const response = await client.chat.completions.create(
        {
          model: provider.model,
          temperature: SCAN_LLM_TEMPERATURE,
          max_tokens: SCAN_LLM_MAX_TOKENS,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            {
              role: "user",
              content: `Analyze this bundled code for security vulnerabilities:\n\n${truncatedCode}`,
            },
          ],
          response_format: { type: "json_object" },
        },
        { signal: controller.signal }
      );

      const content = response.choices[0]?.message?.content;
      if (!content) {
        throw new Error("Empty LLM response");
      }

      const parsed = parseJsonFromAssistantContent(content);
      const normalized = normalizeLlmPayload(parsed);
      const validated = llmResponseSchema.parse(normalized);

      const findings: ScanFinding[] = validated.findings.map((f: z.infer<typeof findingSchema>) => ({
        ...f,
        tool: `llm-${provider.name}`,
        evidence: f.evidence ? { snippet: f.evidence } : undefined,
      }));

      // Record success for circuit breaker
      recordSuccess(provider.name)

      logger.info(
        { provider: provider.name, findings: findings.length },
        "LLM analysis complete"
      );

      clearTimeout(timeout);

      return {
        findings,
        ratings: validated.ratings,
        summary: validated.summary,
        recommendations: validated.recommendations,
      };
    } catch (err) {
      lastError = err;
      
      // Record failure for circuit breaker
      recordFailure(provider.name)
      
      if (err instanceof DOMException && err.name === "AbortError") {
        logger.error(safeLogContext({ provider: provider.name }), "LLM provider timed out — skipping remaining");
        break;
      }
      logger.warn(
        safeLogContext({ provider: provider.name, error: err instanceof Error ? err.message : String(err) }),
        "LLM provider failed, trying next"
      );
    }
  }

  clearTimeout(timeout);

  if (lastError instanceof DOMException && lastError.name === "AbortError") {
    throw new Error("LLM analysis timed out on all providers");
  }

  logger.error(safeLogContext({ lastError: lastError instanceof Error ? { message: lastError.message, name: lastError.name } : String(lastError) }), "All LLM providers failed");
  throw lastError instanceof Error ? lastError : new Error("All LLM providers failed");
}

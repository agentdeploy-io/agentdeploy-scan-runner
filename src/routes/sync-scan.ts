import { Hono } from "hono";
import { z } from "zod";
import { authMiddleware } from "../middleware/auth.js";
import { rateLimitMiddleware } from "../middleware/rate-limit.js";
import { fetchRepoContents, cleanupRepo } from "../services/repo.js";
import { bundleRepo } from "../services/bundler.js";
import { analyzeWithLLM } from "../services/llm.js";
import { scanForSecrets } from "../services/secrets.js";
import { analyzePromptInjection } from "../analyzers/prompt-injection.js";
import { analyzeDependencies } from "../analyzers/dependency-check.js";
import { analyzePermissions } from "../analyzers/permission-scoper.js";
import { analyzeSast } from "../analyzers/sast.js";
import { calculateCategoryRating, aggregateRatings } from "../services/rating.js";
import {
  createScanJob,
  updateScanJob,
  createScanFindings,
  updateTemplateScanFields,
  updateSellerSecurityFields,
  getSellerTemplates,
} from "../services/directus.js";
import { logger } from "../logger.js";
import { RATING_TO_COLOR } from "../constants.js";
import type { ScanFinding } from "../services/llm.js";
import { publishScanProgress, type ScanProgressEvent } from "../services/redis.js";

const syncScanRequestSchema = z.object({
  templateId: z.string().min(1),
  sellerId: z.string().min(1),
  sourceRepo: z.string().regex(/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/),
  purchaseId: z.string().optional(),
  buyerId: z.string().optional(),
  targetRepo: z.string().optional(),
});

export const syncScanRoute = new Hono();

function mapRatingToRisk(
  rating: string
): "none" | "low" | "medium" | "high" | "critical" {
  switch (rating) {
    case "A":
      return "none";
    case "B":
      return "low";
    case "C":
      return "medium";
    case "D":
      return "high";
    case "F":
      return "critical";
    default:
      return "medium";
  }
}

function findWorstRating(
  templates: Array<{ scan_rating?: string }>,
  currentRating: string
): "A" | "B" | "C" | "D" | "F" {
  const order = ["A", "B", "C", "D", "F"];
  let worst = order.indexOf(currentRating);

  for (const t of templates) {
    if (t.scan_rating) {
      const idx = order.indexOf(t.scan_rating);
      if (idx > worst) worst = idx;
    }
  }

  return (order[worst] ?? "F") as "A" | "B" | "C" | "D" | "F";
}

/**
 * POST /sync-scan
 * Synchronous scan endpoint for backward compatibility.
 * Only enabled when ?sync=true query param is present.
 * WARNING: This endpoint may timeout for large repositories.
 */
syncScanRoute.post(
  "/sync-scan",
  authMiddleware,
  rateLimitMiddleware,
  async (c) => {
    const syncParam = c.req.query("sync");
    if (syncParam !== "true") {
      return c.json(
        {
          error: {
            code: "SYNC_NOT_ENABLED",
            message:
              "Synchronous scan is disabled. Use async scan or add ?sync=true query parameter.",
          },
        },
        400
      );
    }

    logger.warn(
      { sync: true },
      "⚠️ Synchronous scan requested - may timeout for large repositories"
    );

    const body = await c.req.json();
    const parsed = syncScanRequestSchema.safeParse(body);

    if (!parsed.success) {
      return c.json(
        {
          error: {
            code: "VALIDATION_ERROR",
            message: parsed.error.issues.map((i) => i.message).join(", "),
          },
        },
        400
      );
    }

    const { templateId, sellerId, sourceRepo, purchaseId, buyerId, targetRepo } =
      parsed.data;

    const startedAt = Date.now();

    const scanJob = await createScanJob({
      purchase_id: purchaseId,
      template_id: templateId,
      seller_id: sellerId,
      buyer_id: buyerId,
      source_repo: sourceRepo,
      target_repo: targetRepo,
      status: "running",
      risk_level: "none",
      overall_rating: "A",
      overall_score: 100,
      rating_secrets: "A",
      rating_prompt_injection: "A",
      rating_dependencies: "A",
      rating_permissions: "A",
      rating_sast: "A",
      seller_color_light: "green",
      started_at: new Date().toISOString(),
    });

    const scanJobId = String(scanJob.id);
    const publishProgress = (
      event: Omit<ScanProgressEvent, "timestamp" | "jobId">
    ) =>
      publishScanProgress(scanJobId, {
        ...event,
        jobId: scanJobId,
        data: {
          templateId: String(templateId),
          ...(event.data ?? {}),
        },
      }).catch(() => {});

    try {
      await updateScanJob(scanJob.id, { status: "running" });
      await publishProgress({
        event_type: "stage",
        stage: "auth",
        message: "Scan job created",
        progress: 10,
      }).catch(() => {});

      await publishProgress({
        event_type: "stage",
        stage: "clone",
        message: "Fetching repository...",
        progress: 15,
      }).catch(() => {});
      const repo = await fetchRepoContents(sourceRepo);
      await publishProgress({
        event_type: "stage",
        stage: "clone",
        message: "Repository fetched",
        progress: 25,
      }).catch(() => {});

      await publishProgress({
        event_type: "stage",
        stage: "semgrep",
        message: "Bundling repository files...",
        progress: 30,
      }).catch(() => {});
      const bundle = await bundleRepo(repo);

      if (bundle.exceededThreshold) {
        await updateScanJob(scanJob.id, {
          status: "review_required",
          bundled_line_count: bundle.lineCount,
          exceeded_line_threshold: true,
          error_message:
            "Bundled code exceeds line threshold. Manual review required.",
        });

        await cleanupRepo(repo.tempDir);

        return c.json({
          scanJobId: scanJob.id,
          status: "review_required",
          exceededLineThreshold: true,
          bundledLineCount: bundle.lineCount,
        });
      }

      await updateScanJob(scanJob.id, { status: "analyzing" });

      // Run security tools with progress updates
      await publishProgress({
        event_type: "stage",
        stage: "gitleaks",
        message: "Scanning for secrets...",
        progress: 45,
      }).catch(() => {});
      const secretsFindings = await scanForSecrets(repo.files);

      await publishProgress({
        event_type: "stage",
        stage: "trufflehog",
        message: "Analyzing prompt injection risks...",
        progress: 55,
      }).catch(() => {});
      const promptFindings = await analyzePromptInjection(repo.files);

      await publishProgress({
        event_type: "stage",
        stage: "analysis",
        message: "Checking dependencies...",
        progress: 65,
      }).catch(() => {});
      const depFindings = await analyzeDependencies(repo.files);

      await publishProgress({
        event_type: "stage",
        stage: "analysis",
        message: "Analyzing permissions...",
        progress: 75,
      }).catch(() => {});
      const permFindings = await analyzePermissions(repo.files);

      await publishProgress({
        event_type: "stage",
        stage: "semgrep",
        message: "Running static analysis...",
        progress: 85,
      }).catch(() => {});
      const sastFindings = await analyzeSast(repo.files);

      const allFindings: ScanFinding[] = [];

      allFindings.push(...secretsFindings);
      allFindings.push(...promptFindings);
      allFindings.push(...depFindings);
      allFindings.push(...permFindings);
      allFindings.push(...sastFindings);

      let llmResult;
      try {
        await publishProgress({
          event_type: "stage",
          stage: "analysis",
          message: "Running LLM security analysis...",
          progress: 90,
        }).catch(() => {});
        llmResult = await analyzeWithLLM(bundle.content);
        allFindings.push(...llmResult.findings);
        await publishProgress({
          event_type: "stage",
          stage: "analysis",
          message: "LLM analysis complete",
          progress: 95,
        }).catch(() => {});
      } catch (err) {
        logger.warn({ err }, "LLM analysis failed, using deterministic results only");
        llmResult = {
          findings: [] as ScanFinding[],
          ratings: {},
          summary:
            "LLM analysis unavailable; results based on deterministic scanning.",
          recommendations: [] as string[],
        };
        await publishProgress({
          event_type: "stage",
          stage: "analysis",
          message: "LLM analysis unavailable, using deterministic results",
          progress: 95,
        }).catch(() => {});
      }

      const categoryMap: Record<string, ScanFinding[]> = {};
      for (const finding of allFindings) {
        if (!categoryMap[finding.category]) categoryMap[finding.category] = [];
        categoryMap[finding.category]!.push(finding);
      }

      const categoryRatings: Record<
        string,
        ReturnType<typeof calculateCategoryRating>
      > = {};
      for (const [category, catFindings] of Object.entries(categoryMap)) {
        categoryRatings[category] = calculateCategoryRating(catFindings);
      }

      const result = aggregateRatings(categoryRatings);

      await createScanFindings(
        allFindings.map((f) => ({
          scan_job_id: scanJob.id,
          severity: f.severity,
          category: f.category,
          tool: f.tool,
          rule_id: f.ruleId,
          file_path: f.filePath,
          line_start: f.lineStart,
          line_end: f.lineEnd,
          title: f.title,
          description: f.description,
          recommendation: f.recommendation,
          evidence: f.evidence,
          status: "open" as const,
        }))
      );

      const completedAt = new Date().toISOString();
      const isDeployable =
        result.overallRating === "D" || result.overallRating === "F"
          ? "review_required"
          : "completed";

      await publishProgress({
        event_type: "stage",
        stage: "persist",
        message: "Saving results...",
        progress: 95,
      }).catch(() => {});

      await updateScanJob(scanJob.id, {
        status: isDeployable,
        risk_level: mapRatingToRisk(result.overallRating),
        overall_rating: result.overallRating,
        overall_score: result.overallScore,
        rating_secrets:
          (categoryRatings.secrets?.rating ?? "A") as typeof result.overallRating,
        rating_prompt_injection:
          (categoryRatings.prompt_injection?.rating ??
            "A") as typeof result.overallRating,
        rating_dependencies:
          (categoryRatings.dependencies?.rating ??
            "A") as typeof result.overallRating,
        rating_permissions:
          (categoryRatings.permissions?.rating ??
            "A") as typeof result.overallRating,
        rating_sast:
          (categoryRatings.sast?.rating ?? "A") as typeof result.overallRating,
        seller_color_light: result.colorLight,
        completed_at: completedAt,
        llm_summary: llmResult.summary,
        llm_recommendations: { recommendations: llmResult.recommendations },
        bundled_line_count: bundle.lineCount,
        exceeded_line_threshold: bundle.exceededThreshold,
        metadata: {
          ratings: result.ratings,
          overall: {
            rating: result.overallRating,
            score: result.overallScore,
            color_light: result.colorLight,
            weakest_category: result.weakestCategory,
          },
          findings_count: allFindings.length,
          bundled_line_count: bundle.lineCount,
          exceeded_line_threshold: bundle.exceededThreshold,
        },
      });

      await updateTemplateScanFields(templateId, {
        scan_rating: result.overallRating,
        scan_score: result.overallScore,
        scan_color_light: result.colorLight,
        last_scan_at: completedAt,
        last_scan_job_id: scanJob.id,
        scan_status: isDeployable === "review_required" ? "failed" : "passed",
      });

      const sellerTemplates = await getSellerTemplates(sellerId);
      const worstRating = findWorstRating(sellerTemplates, result.overallRating);

      await updateSellerSecurityFields(sellerId, {
        security_rating: worstRating,
        security_score: result.overallScore,
        security_color_light: RATING_TO_COLOR[worstRating],
        last_security_scan: completedAt,
        scan_compliant:
          worstRating === "A" ||
          worstRating === "B" ||
          worstRating === "C",
      });

      await cleanupRepo(repo.tempDir);

      logger.info(
        {
          scanJobId: scanJob.id,
          overallRating: result.overallRating,
          findings: allFindings.length,
          durationMs: Date.now() - startedAt,
        },
        "Synchronous scan completed"
      );

      await publishProgress({
        event_type: "complete",
        stage: "complete",
        message: "Scan complete",
        progress: 100,
        data: {
          rating: result.overallRating,
          score: result.overallScore,
          status: isDeployable,
        },
      }).catch(() => {});

      return c.json({
        scanJobId: scanJob.id,
        status: isDeployable,
        overallRating: result.overallRating,
        overallScore: result.overallScore,
        colorLight: result.colorLight,
        weakestCategory: result.weakestCategory,
        ratings: result.ratings,
        findingsCount: allFindings.length,
        summary: llmResult.summary,
        recommendations: llmResult.recommendations,
        bundledLineCount: bundle.lineCount,
        exceededLineThreshold: bundle.exceededThreshold,
      });
    } catch (err) {
      logger.error({ err, scanJobId: scanJob.id }, "Synchronous scan failed");

      await updateScanJob(scanJob.id, {
        status: "failed",
        error_message: err instanceof Error ? err.message : "Unknown error",
        completed_at: new Date().toISOString(),
      });

      return c.json(
        { error: { code: "SCAN_FAILED", message: "Scan execution failed" } },
        500
      );
    }
  }
);

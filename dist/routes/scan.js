import { Hono } from "hono";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
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
import { createScanJob, updateScanJob, createScanFindings, updateTemplateScanFields, updateSellerSecurityFields, getSellerTemplates, DirectusForbiddenError, } from "../services/directus.js";
import { logger } from "../logger.js";
import { safeLogContext } from "../lib/redact.js";
import { RATING_TO_COLOR } from "../constants.js";
import { publishScanProgress } from "../services/redis.js";
// Input length limits to prevent DoS
const MAX_LENGTH = {
    TEMPLATE_ID: 50,
    SELLER_ID: 100,
    SOURCE_REPO: 200,
    PURCHASE_ID: 100,
    BUYER_ID: 100,
    TARGET_REPO: 200,
};
// Pre-process templateId to validate length after transformation
const templateIdSchema = z.union([
    z.string().max(MAX_LENGTH.TEMPLATE_ID, `templateId must be at most ${MAX_LENGTH.TEMPLATE_ID} characters`),
    z.number().max(999999999, "templateId too large"),
]).transform((val) => {
    const str = String(val);
    if (typeof val === 'number') {
        logger.warn(safeLogContext({ originalValue: val, convertedValue: str }), 'templateId type conversion: number -> string');
    }
    return str;
});
const scanRequestSchema = z.object({
    templateId: templateIdSchema,
    sellerId: z.string()
        .min(1, "sellerId is required")
        .max(MAX_LENGTH.SELLER_ID, `sellerId must be at most ${MAX_LENGTH.SELLER_ID} characters`),
    sourceRepo: z.string()
        .regex(/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/, "sourceRepo must be in format: owner/repo")
        .max(MAX_LENGTH.SOURCE_REPO, `sourceRepo must be at most ${MAX_LENGTH.SOURCE_REPO} characters`),
    purchaseId: z.string()
        .optional()
        .refine((val) => !val || val.length <= MAX_LENGTH.PURCHASE_ID, {
        message: `purchaseId must be at most ${MAX_LENGTH.PURCHASE_ID} characters`,
    }),
    buyerId: z.string()
        .optional()
        .refine((val) => !val || val.length <= MAX_LENGTH.BUYER_ID, {
        message: `buyerId must be at most ${MAX_LENGTH.BUYER_ID} characters`,
    }),
    targetRepo: z.string()
        .optional()
        .refine((val) => !val || val.length <= MAX_LENGTH.TARGET_REPO, {
        message: `targetRepo must be at most ${MAX_LENGTH.TARGET_REPO} characters`,
    }),
});
export const scanRoute = new Hono();
/**
 * Async scan processing function - runs in background
 */
async function processScanAsync(jobId, templateId, sellerId, sourceRepo, purchaseId, buyerId, targetRepo) {
    const startedAt = Date.now();
    try {
        logger.info({ jobId, templateId }, "🔍 Async scan processing started");
        // Update status to processing
        await updateScanJob(jobId, { status: "running" });
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "auth",
            message: "Scan job processing started",
            progress: 10,
        }).catch(() => { });
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "clone",
            message: "Fetching repository...",
            progress: 15,
        }).catch(() => { });
        const repo = await fetchRepoContents(sourceRepo);
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "clone",
            message: "Repository fetched",
            progress: 25,
        }).catch(() => { });
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "semgrep",
            message: "Bundling repository files...",
            progress: 30,
        }).catch(() => { });
        const bundle = await bundleRepo(repo);
        if (bundle.exceededThreshold) {
            await updateScanJob(jobId, {
                status: "review_required",
                bundled_line_count: bundle.lineCount,
                exceeded_line_threshold: true,
                error_message: "Bundled code exceeds line threshold. Manual review required.",
                completed_at: new Date().toISOString(),
            });
            await cleanupRepo(repo.tempDir);
            await publishScanProgress(templateId, {
                event_type: "complete",
                stage: "complete",
                message: "Scan complete: review_required (exceeded line threshold)",
                progress: 100,
                data: { status: "review_required", exceededLineThreshold: true },
            }).catch(() => { });
            logger.info({ jobId, templateId }, "✅ Async scan completed (review_required - line threshold)");
            return;
        }
        await updateScanJob(jobId, { status: "analyzing" });
        // Run security tools with progress updates
        // First: scan for secrets (sequential - must complete before other analysis)
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "gitleaks",
            message: "Scanning for secrets...",
            progress: 45,
        }).catch(() => { });
        const secretsFindings = await scanForSecrets(repo.files);
        // Second: run all analyzers in parallel for 5x speed improvement
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "analysis",
            message: "Running security analyzers in parallel...",
            progress: 55,
        }).catch(() => { });
        const [promptFindings, depFindings, permFindings, sastFindings] = await Promise.all([
            analyzePromptInjection(repo.files),
            analyzeDependencies(repo.files),
            analyzePermissions(repo.files),
            analyzeSast(repo.files),
        ]);
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "analysis",
            message: "All security analyzers complete",
            progress: 85,
        }).catch(() => { });
        const allFindings = [];
        allFindings.push(...secretsFindings);
        allFindings.push(...promptFindings);
        allFindings.push(...depFindings);
        allFindings.push(...permFindings);
        allFindings.push(...sastFindings);
        let llmResult;
        try {
            await publishScanProgress(templateId, {
                event_type: "stage",
                stage: "analysis",
                message: "Running LLM security analysis...",
                progress: 90,
            }).catch(() => { });
            llmResult = await analyzeWithLLM(bundle.content);
            allFindings.push(...llmResult.findings);
            await publishScanProgress(templateId, {
                event_type: "stage",
                stage: "analysis",
                message: "LLM analysis complete",
                progress: 95,
            }).catch(() => { });
        }
        catch (err) {
            logger.warn({ err, jobId }, "LLM analysis failed, using deterministic results only");
            llmResult = {
                findings: [],
                ratings: {},
                summary: "LLM analysis unavailable; results based on deterministic scanning.",
                recommendations: [],
            };
            await publishScanProgress(templateId, {
                event_type: "stage",
                stage: "analysis",
                message: "LLM analysis unavailable, using deterministic results",
                progress: 95,
            }).catch(() => { });
        }
        const categoryMap = {};
        for (const finding of allFindings) {
            if (!categoryMap[finding.category])
                categoryMap[finding.category] = [];
            categoryMap[finding.category].push(finding);
        }
        const categoryRatings = {};
        for (const [category, catFindings] of Object.entries(categoryMap)) {
            categoryRatings[category] = calculateCategoryRating(catFindings);
        }
        const result = aggregateRatings(categoryRatings);
        await createScanFindings(allFindings.map((f) => ({
            scan_job_id: jobId,
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
            status: "open",
        })));
        const completedAt = new Date().toISOString();
        const isDeployable = result.overallRating === "D" || result.overallRating === "F"
            ? "review_required"
            : "completed";
        await publishScanProgress(templateId, {
            event_type: "stage",
            stage: "persist",
            message: "Saving results...",
            progress: 95,
        }).catch(() => { });
        await updateScanJob(jobId, {
            status: isDeployable,
            risk_level: mapRatingToRisk(result.overallRating),
            overall_rating: result.overallRating,
            overall_score: result.overallScore,
            rating_secrets: (categoryRatings.secrets?.rating ?? "A"),
            rating_prompt_injection: (categoryRatings.prompt_injection?.rating ?? "A"),
            rating_dependencies: (categoryRatings.dependencies?.rating ?? "A"),
            rating_permissions: (categoryRatings.permissions?.rating ?? "A"),
            rating_sast: (categoryRatings.sast?.rating ?? "A"),
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
                duration_ms: Date.now() - startedAt,
            },
        });
        await updateTemplateScanFields(templateId, {
            scan_rating: result.overallRating,
            scan_score: result.overallScore,
            scan_color_light: result.colorLight,
            last_scan_at: completedAt,
            last_scan_job_id: jobId,
            scan_status: isDeployable === "review_required" ? "failed" : "passed",
        });
        const sellerTemplates = await getSellerTemplates(sellerId);
        const worstRating = findWorstRating(sellerTemplates, result.overallRating);
        try {
            logger.info({ sellerId, worstRating, score: result.overallScore }, "📝 Updating seller security fields after scan");
            await updateSellerSecurityFields(sellerId, {
                security_rating: worstRating,
                security_score: result.overallScore,
                security_color_light: RATING_TO_COLOR[worstRating],
                last_security_scan: completedAt,
                scan_compliant: worstRating === "A" ||
                    worstRating === "B" ||
                    worstRating === "C",
            });
            logger.info({ sellerId }, "✅ Seller security fields updated successfully");
        }
        catch (error) {
            if (error instanceof DirectusForbiddenError) {
                logger.error({
                    sellerId,
                    templateId,
                    jobId,
                    collection: error.collection,
                    action: error.action,
                    role: error.role,
                    fields: ["security_rating", "security_score", "security_color_light", "last_security_scan", "scan_compliant"],
                    errorMessage: error.message,
                }, "❌ 403 Forbidden: Cannot update seller - Missing Directus RBAC permission");
                // Continue without failing the entire scan - seller update is non-critical
                logger.warn({ sellerId, templateId }, "⚠️  Scan completed but seller security fields were not updated due to permission error");
            }
            else {
                logger.error({ sellerId, templateId, jobId, error }, "❌ Failed to update seller security fields");
                throw error;
            }
        }
        await cleanupRepo(repo.tempDir);
        logger.info({
            jobId,
            templateId,
            overallRating: result.overallRating,
            findings: allFindings.length,
            durationMs: Date.now() - startedAt,
        }, "✅ Async scan completed successfully");
        await publishScanProgress(templateId, {
            event_type: "complete",
            stage: "complete",
            message: "Scan complete",
            progress: 100,
            data: {
                rating: result.overallRating,
                score: result.overallScore,
                status: isDeployable,
            },
        }).catch(() => { });
    }
    catch (err) {
        logger.error({ err, jobId, templateId }, "❌ Async scan failed");
        await updateScanJob(jobId, {
            status: "failed",
            error_message: err instanceof Error ? err.message : "Unknown error",
            completed_at: new Date().toISOString(),
        });
        await publishScanProgress(templateId, {
            event_type: "error",
            stage: "error",
            message: `Scan failed: ${err instanceof Error ? err.message : "Unknown error"}`,
            progress: 0,
        }).catch(() => { });
    }
}
scanRoute.post("/scan", authMiddleware, rateLimitMiddleware, async (c) => {
    const body = await c.req.json();
    const parsed = scanRequestSchema.safeParse(body);
    if (!parsed.success) {
        return c.json({
            error: {
                code: "VALIDATION_ERROR",
                message: parsed.error.issues.map((i) => i.message).join(", "),
            },
        }, 400);
    }
    const { templateId, sellerId, sourceRepo, purchaseId, buyerId, targetRepo } = parsed.data;
    // Generate unique job ID
    const jobId = uuidv4();
    logger.info({ jobId, templateId, sellerId }, "📡 Scan request received - creating async job");
    // Create scan job in queued state
    const scanJob = await createScanJob({
        purchase_id: purchaseId,
        template_id: templateId,
        seller_id: sellerId,
        buyer_id: buyerId,
        source_repo: sourceRepo,
        target_repo: targetRepo,
        status: "pending",
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
    // Start async processing (don't await)
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    processScanAsync(jobId, templateId, sellerId, sourceRepo, purchaseId, buyerId, targetRepo);
    // Return 202 Accepted immediately
    logger.info({ jobId, templateId }, "✅ Scan job queued - returning 202 Accepted");
    return c.json({
        jobId: scanJob.id,
        status: "queued",
        pollUrl: `/scan/status/${scanJob.id}`,
    }, 202);
});
/**
 * GET /scan/status/:jobId
 * Poll for scan job status
 */
scanRoute.get("/scan/status/:jobId", authMiddleware, async (c) => {
    const jobId = c.req.param("jobId");
    if (!jobId) {
        return c.json({ error: { code: "INVALID_JOB_ID", message: "Job ID is required" } }, 400);
    }
    try {
        const { getScanJob } = await import("../services/directus.js");
        const job = await getScanJob(jobId);
        if (!job) {
            return c.json({ error: { code: "JOB_NOT_FOUND", message: "Scan job not found" } }, 404);
        }
        // Build response based on job status
        const response = {
            jobId: job.id,
            status: job.status,
        };
        // Add progress based on status
        if (job.status === "pending") {
            response.progress = 10;
        }
        else if (job.status === "running") {
            response.progress = 50;
        }
        else if (job.status === "analyzing") {
            response.progress = 75;
        }
        else if (job.status === "completed" || job.status === "review_required") {
            response.progress = 100;
            response.overallRating = job.overall_rating;
            response.overallScore = job.overall_score;
            response.colorLight = job.seller_color_light;
            response.completedAt = job.completed_at;
            response.metadata = job.metadata;
        }
        else if (job.status === "failed") {
            response.progress = 0;
            response.errorMessage = job.error_message;
            response.completedAt = job.completed_at;
        }
        return c.json(response);
    }
    catch (err) {
        logger.error({ err, jobId }, "Failed to get scan job status");
        return c.json({ error: { code: "STATUS_FETCH_FAILED", message: "Failed to fetch job status" } }, 500);
    }
});
function mapRatingToRisk(rating) {
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
function findWorstRating(templates, currentRating) {
    const order = ["A", "B", "C", "D", "F"];
    let worst = order.indexOf(currentRating);
    for (const t of templates) {
        if (t.scan_rating) {
            const idx = order.indexOf(t.scan_rating);
            if (idx > worst)
                worst = idx;
        }
    }
    return (order[worst] ?? "F");
}

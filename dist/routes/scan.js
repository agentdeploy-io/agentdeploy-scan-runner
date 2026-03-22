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
import { createScanJob, updateScanJob, createScanFindings, updateTemplateScanFields, updateSellerSecurityFields, getSellerTemplates, } from "../services/directus.js";
import { logger } from "../logger.js";
import { RATING_TO_COLOR } from "../constants.js";
const scanRequestSchema = z.object({
    templateId: z.string().min(1),
    sellerId: z.string().min(1),
    sourceRepo: z.string().regex(/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/),
    purchaseId: z.string().optional(),
    buyerId: z.string().optional(),
    targetRepo: z.string().optional(),
});
export const scanRoute = new Hono();
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
    try {
        await updateScanJob(scanJob.id, { status: "running" });
        const repo = await fetchRepoContents(sourceRepo);
        const bundle = await bundleRepo(repo);
        if (bundle.exceededThreshold) {
            await updateScanJob(scanJob.id, {
                status: "review_required",
                bundled_line_count: bundle.lineCount,
                exceeded_line_threshold: true,
                error_message: "Bundled code exceeds line threshold. Manual review required.",
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
        const allFindings = [];
        allFindings.push(...scanForSecrets(repo.files));
        allFindings.push(...analyzePromptInjection(repo.files));
        allFindings.push(...analyzeDependencies(repo.files));
        allFindings.push(...analyzePermissions(repo.files));
        allFindings.push(...analyzeSast(repo.files));
        let llmResult;
        try {
            llmResult = await analyzeWithLLM(bundle.content);
            allFindings.push(...llmResult.findings);
        }
        catch (err) {
            logger.warn({ err }, "LLM analysis failed, using deterministic results only");
            llmResult = {
                findings: [],
                ratings: {},
                summary: "LLM analysis unavailable; results based on deterministic scanning.",
                recommendations: [],
            };
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
            status: "open",
        })));
        const completedAt = new Date().toISOString();
        const isDeployable = result.overallRating === "D" || result.overallRating === "F"
            ? "review_required"
            : "completed";
        await updateScanJob(scanJob.id, {
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
            scan_compliant: worstRating === "A" ||
                worstRating === "B" ||
                worstRating === "C",
        });
        await cleanupRepo(repo.tempDir);
        logger.info({
            scanJobId: scanJob.id,
            overallRating: result.overallRating,
            findings: allFindings.length,
        }, "Scan completed");
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
    }
    catch (err) {
        logger.error({ err, scanJobId: scanJob.id }, "Scan failed");
        await updateScanJob(scanJob.id, {
            status: "failed",
            error_message: err instanceof Error ? err.message : "Unknown error",
            completed_at: new Date().toISOString(),
        });
        return c.json({ error: { code: "SCAN_FAILED", message: "Scan execution failed" } }, 500);
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

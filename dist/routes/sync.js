import { Hono } from "hono";
import { z } from "zod";
import { authMiddleware } from "../middleware/auth.js";
import { rateLimitMiddleware } from "../middleware/rate-limit.js";
import { syncToNewVersion, syncAllBuyers } from "../services/sync.js";
import { logger } from "../logger.js";
const syncRequestSchema = z.object({
    passoverId: z.string().min(1),
    versionId: z.number().int().positive(),
    dryRun: z.boolean().optional().default(false),
});
const syncAllRequestSchema = z.object({
    templateId: z.string().min(1),
    versionId: z.number().int().positive(),
    dryRun: z.boolean().optional().default(false),
});
export const syncRoute = new Hono();
/**
 * POST /sync
 * Sync a single buyer's repo to a new template version.
 * Called when a buyer purchases an update.
 */
syncRoute.post("/sync", authMiddleware, rateLimitMiddleware, async (c) => {
    const body = await c.req.json();
    const parsed = syncRequestSchema.safeParse(body);
    if (!parsed.success) {
        return c.json({
            error: {
                code: "VALIDATION_ERROR",
                message: parsed.error.issues.map((i) => i.message).join(", "),
            },
        }, 400);
    }
    const { passoverId, versionId, dryRun } = parsed.data;
    // Fetch the version record from Directus
    const env = await import("../env.js");
    const { directusRequest } = await import("../services/directus.js");
    let version;
    try {
        version = await directusRequest(`/items/template_versions/${versionId}`);
    }
    catch {
        return c.json({ error: { code: "VERSION_NOT_FOUND", message: `Version ${versionId} not found` } }, 404);
    }
    if (!version) {
        return c.json({ error: { code: "VERSION_NOT_FOUND", message: `Version ${versionId} not found` } }, 404);
    }
    if (version.status !== "published") {
        return c.json({
            error: {
                code: "VERSION_NOT_PUBLISHED",
                message: `Version ${versionId} is not published (status: ${version.status})`,
            },
        }, 400);
    }
    try {
        logger.info({ passoverId, versionId, dryRun }, "Starting single sync");
        const result = await syncToNewVersion(passoverId, version, dryRun);
        return c.json({
            success: true,
            result,
        });
    }
    catch (err) {
        logger.error({ err, passoverId, versionId }, "Sync failed");
        return c.json({ error: { code: "SYNC_FAILED", message: err instanceof Error ? err.message : "Sync failed" } }, 500);
    }
});
/**
 * POST /sync-all
 * Push a courtesy update to all buyers of a template version.
 * Called when a seller triggers a courtesy push.
 */
syncRoute.post("/sync-all", authMiddleware, rateLimitMiddleware, async (c) => {
    const body = await c.req.json();
    const parsed = syncAllRequestSchema.safeParse(body);
    if (!parsed.success) {
        return c.json({
            error: {
                code: "VALIDATION_ERROR",
                message: parsed.error.issues.map((i) => i.message).join(", "),
            },
        }, 400);
    }
    const { templateId, versionId, dryRun } = parsed.data;
    try {
        logger.info({ templateId, versionId, dryRun }, "Starting sync-all");
        const results = await syncAllBuyers(templateId, versionId, dryRun);
        const summary = {
            total: results.length,
            synced: results.filter((r) => r.status === "synced").length,
            noChanges: results.filter((r) => r.status === "no_changes").length,
            failed: results.filter((r) => r.status === "failed").length,
            totalFilesAdded: results.reduce((sum, r) => sum + r.filesAdded, 0),
            totalFilesModified: results.reduce((sum, r) => sum + r.filesModified, 0),
            totalFilesDeleted: results.reduce((sum, r) => sum + r.filesDeleted, 0),
        };
        return c.json({
            success: true,
            summary,
            results,
        });
    }
    catch (err) {
        logger.error({ err, templateId, versionId }, "Sync-all failed");
        return c.json({
            error: {
                code: "SYNC_ALL_FAILED",
                message: err instanceof Error ? err.message : "Sync-all failed",
            },
        }, 500);
    }
});

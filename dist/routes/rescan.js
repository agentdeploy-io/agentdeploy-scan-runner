import { Hono } from "hono";
import { z } from "zod";
import { authMiddleware } from "../middleware/auth.js";
import { rateLimitMiddleware } from "../middleware/rate-limit.js";
import { getScanJob } from "../services/directus.js";
import { logger } from "../logger.js";
const rescanRequestSchema = z.object({
    scanJobId: z.string().min(1),
});
export const rescanRoute = new Hono();
rescanRoute.post("/rescan", authMiddleware, rateLimitMiddleware, async (c) => {
    const body = await c.req.json();
    const parsed = rescanRequestSchema.safeParse(body);
    if (!parsed.success) {
        return c.json({
            error: {
                code: "VALIDATION_ERROR",
                message: parsed.error.issues.map((i) => i.message).join(", "),
            },
        }, 400);
    }
    const { scanJobId } = parsed.data;
    try {
        const previousScan = await getScanJob(scanJobId);
        logger.info({ previousScanId: scanJobId, templateId: previousScan.template_id }, "Initiating rescan");
        const scanRequest = {
            templateId: previousScan.template_id,
            sellerId: previousScan.seller_id,
            sourceRepo: previousScan.source_repo,
            purchaseId: previousScan.purchase_id,
            buyerId: previousScan.buyer_id,
            targetRepo: previousScan.target_repo,
        };
        const scanResponse = await fetch(`${c.req.url.replace("/rescan", "/scan")}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Scanner-Key": c.req.header("X-Scanner-Key") ?? "",
            },
            body: JSON.stringify(scanRequest),
        });
        const result = await scanResponse.json();
        return c.json(result, scanResponse.status);
    }
    catch (err) {
        logger.error({ err, scanJobId }, "Rescan failed");
        return c.json({ error: { code: "RESCAN_FAILED", message: "Rescan execution failed" } }, 500);
    }
});

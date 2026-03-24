import { Hono } from "hono";
import { getRedisClient } from "../services/redis.js";
import { directusRequest } from "../services/directus.js";
import { logger } from "../logger.js";
export const healthRoute = new Hono();
healthRoute.get("/health", async (c) => {
    const checks = {};
    let healthy = true;
    // Check Redis
    try {
        const redis = await getRedisClient();
        await redis.ping();
        checks.redis = "ok";
    }
    catch (err) {
        logger.error({ err }, "Health check: Redis ping failed");
        checks.redis = "error";
        healthy = false;
    }
    // Check Directus
    try {
        await directusRequest("/server/info");
        checks.directus = "ok";
    }
    catch (err) {
        logger.error({ err }, "Health check: Directus ping failed");
        checks.directus = "error";
        healthy = false;
    }
    return c.json({
        status: healthy ? "healthy" : "unhealthy",
        timestamp: new Date().toISOString(),
        checks,
    }, healthy ? 200 : 503);
});

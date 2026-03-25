import { SCAN_RATE_LIMIT_PER_MINUTE } from "../constants.js";
import { getRedisClient } from "../services/redis.js";
import { logger } from "../logger.js";
const RATE_LIMIT_WINDOW = 60; // 1 minute in seconds
/**
 * Check if a request should be rate limited using Redis-based sliding window
 * @param key Unique identifier for the rate limit (e.g., API key, IP)
 * @returns true if allowed, false if rate limited
 */
async function checkRateLimit(key) {
    try {
        const redis = await getRedisClient();
        const now = Date.now();
        const windowKey = `ratelimit:${key}`;
        // Remove old entries outside the window
        const removed = await redis.zRemRangeByScore(windowKey, 0, now - RATE_LIMIT_WINDOW * 1000);
        // Count requests in current window
        const count = await redis.zCard(windowKey);
        if (count >= SCAN_RATE_LIMIT_PER_MINUTE) {
            logger.warn({ key, count, limit: SCAN_RATE_LIMIT_PER_MINUTE }, 'Rate limit exceeded');
            return false;
        }
        // Add current request with timestamp as score
        const requestId = `${now}-${Math.random().toString(36).slice(2)}`;
        await redis.zAdd(windowKey, { score: now, value: requestId });
        // Set expiry on the key (window + buffer)
        await redis.expire(windowKey, RATE_LIMIT_WINDOW + 10);
        return true;
    }
    catch (err) {
        // If Redis fails, allow the request but log an error
        logger.error({ err, key }, 'Rate limit check failed, allowing request');
        return true;
    }
}
/**
 * Get remaining requests in the current window for a key
 */
export async function getRateLimitRemaining(key) {
    try {
        const redis = await getRedisClient();
        const now = Date.now();
        const windowKey = `ratelimit:${key}`;
        // Remove old entries
        await redis.zRemRangeByScore(windowKey, 0, now - RATE_LIMIT_WINDOW * 1000);
        const count = await redis.zCard(windowKey);
        return Math.max(0, SCAN_RATE_LIMIT_PER_MINUTE - count);
    }
    catch (err) {
        logger.error({ err, key }, 'Failed to get rate limit remaining');
        return SCAN_RATE_LIMIT_PER_MINUTE;
    }
}
/**
 * Get seconds until the rate limit window resets
 */
export async function getRateLimitReset(key) {
    try {
        const redis = await getRedisClient();
        const windowKey = `ratelimit:${key}`;
        // Get the oldest entry in the window using zRangeWithScores
        const results = await redis.zRangeWithScores(windowKey, 0, 0);
        if (results.length > 0 && results[0]) {
            // Return the time when the oldest request will expire
            return Math.ceil((results[0].score + RATE_LIMIT_WINDOW * 1000 - Date.now()) / 1000);
        }
        return 0;
    }
    catch (err) {
        logger.error({ err, key }, 'Failed to get rate limit reset');
        return 0;
    }
}
export async function rateLimitMiddleware(c, next) {
    const key = c.req.header("X-Scanner-Key") ||
        c.req.header("X-Forwarded-For") ||
        "anonymous";
    const allowed = await checkRateLimit(key);
    if (!allowed) {
        const retryAfter = await getRateLimitReset(key);
        return c.json({
            error: {
                code: "RATE_LIMITED",
                message: "Rate limit exceeded",
            },
            retryAfterSeconds: retryAfter,
        }, 429);
    }
    // Add rate limit headers
    const remaining = await getRateLimitRemaining(key);
    c.res.headers.set("X-RateLimit-Limit", String(SCAN_RATE_LIMIT_PER_MINUTE));
    c.res.headers.set("X-RateLimit-Remaining", String(remaining));
    await next();
}

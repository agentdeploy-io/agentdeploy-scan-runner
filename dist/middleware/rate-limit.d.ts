import type { Context, Next } from "hono";
/**
 * Get remaining requests in the current window for a key
 */
export declare function getRateLimitRemaining(key: string): Promise<number>;
/**
 * Get seconds until the rate limit window resets
 */
export declare function getRateLimitReset(key: string): Promise<number>;
export declare function rateLimitMiddleware(c: Context, next: Next): Promise<(Response & import("hono").TypedResponse<{
    error: {
        code: string;
        message: string;
    };
    retryAfterSeconds: number;
}, 429, "json">) | undefined>;

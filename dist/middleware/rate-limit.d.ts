import type { Context, Next } from "hono";
export declare function rateLimitMiddleware(c: Context, next: Next): Promise<(Response & import("hono").TypedResponse<{
    error: {
        code: string;
        message: string;
    };
    retryAfterSeconds: number;
}, 429, "json">) | undefined>;

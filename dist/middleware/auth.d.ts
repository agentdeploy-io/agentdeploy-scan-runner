import type { Context, Next } from "hono";
export declare function authMiddleware(c: Context, next: Next): Promise<(Response & import("hono").TypedResponse<{
    error: {
        code: string;
        message: string;
    };
}, 503, "json">) | (Response & import("hono").TypedResponse<{
    error: {
        code: string;
        message: string;
    };
}, 401, "json">) | undefined>;

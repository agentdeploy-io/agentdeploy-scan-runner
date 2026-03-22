import { getEnv } from "../env.js";
export async function authMiddleware(c, next) {
    const env = getEnv();
    // If no SCANNER_API_KEY is set, allow all requests (local dev mode)
    if (!env.SCANNER_API_KEY) {
        await next();
        return;
    }
    const key = c.req.header("X-Scanner-Key") ||
        c.req.header("Authorization")?.replace("Bearer ", "");
    if (!key || key !== env.SCANNER_API_KEY) {
        return c.json({ error: { code: "UNAUTHORIZED", message: "Invalid API key" } }, 401);
    }
    await next();
}

import { timingSafeEqual } from "node:crypto";
import type { Context, Next } from "hono";
import { getEnv } from "../env.js";

export async function authMiddleware(c: Context, next: Next) {
  const env = getEnv();

  if (!env.SCANNER_API_KEY) {
    return c.json(
      { error: { code: "SCANNER_AUTH_NOT_CONFIGURED", message: "SCANNER_API_KEY is not configured" } },
      503
    );
  }

  const key =
    c.req.header("X-Scanner-Key") ||
    c.req.header("Authorization")?.replace("Bearer ", "");

  if (!key) {
    return c.json({ error: { code: "UNAUTHORIZED", message: "Missing API key" } }, 401);
  }

  const expected = Buffer.from(env.SCANNER_API_KEY, "utf8");
  const provided = Buffer.from(key, "utf8");

  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return c.json({ error: { code: "UNAUTHORIZED", message: "Invalid API key" } }, 401);
  }

  await next();
}

import type { Context, Next } from "hono";
import { SCAN_RATE_LIMIT_PER_MINUTE } from "../constants.js";

const requestCounts = new Map<string, { count: number; resetAt: number }>();

export async function rateLimitMiddleware(c: Context, next: Next) {
  const key =
    c.req.header("X-Scanner-Key") ||
    c.req.header("X-Forwarded-For") ||
    "anonymous";

  const now = Date.now();
  const record = requestCounts.get(key);

  if (!record || now > record.resetAt) {
    requestCounts.set(key, {
      count: 1,
      resetAt: now + 60_000,
    });
    await next();
    return;
  }

  if (record.count >= SCAN_RATE_LIMIT_PER_MINUTE) {
    const retryAfter = Math.ceil((record.resetAt - now) / 1000);
    return c.json(
      {
        error: {
          code: "RATE_LIMITED",
          message: "Rate limit exceeded",
        },
        retryAfterSeconds: retryAfter,
      },
      429
    );
  }

  record.count++;
  await next();
}

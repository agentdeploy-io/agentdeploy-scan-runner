import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { getEnv } from "./env.js";
import { logger } from "./logger.js";
import { redactSecrets, safeLogContext } from "./lib/redact.js";
import { scanRoute } from "./routes/scan.js";
import { rescanRoute } from "./routes/rescan.js";
import { healthRoute } from "./routes/health.js";
import { syncRoute } from "./routes/sync.js";
import { syncScanRoute } from "./routes/sync-scan.js";

const env = getEnv();

const app = new Hono();

// Allowed origins for CSRF protection
const ALLOWED_ORIGINS = [
  'https://agentdeploy.xyz',
  'https://www.agentdeploy.xyz',
  env.FRONTEND_URL,
].filter((origin): origin is string => Boolean(origin));

// CSRF protection: validate origin header for state-changing requests
app.use('*', async (c, next) => {
  // Only check POST, PUT, DELETE requests
  const method = c.req.method;
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    return next();
  }

  const origin = c.req.header('Origin');
  const referer = c.req.header('Referer');

  // If there's an origin header, validate it
  if (origin) {
    if (!ALLOWED_ORIGINS.includes(origin)) {
      logger.warn(safeLogContext({ origin, method, path: c.req.path }), 'Blocked request with invalid origin');
      return c.json(
        { error: { code: 'FORBIDDEN', message: 'Invalid origin' } },
        403
      );
    }
  } else if (referer) {
    // Check referer as fallback
    const refererUrl = new URL(referer);
    const refererOrigin = refererUrl.origin;
    if (!ALLOWED_ORIGINS.includes(refererOrigin)) {
      logger.warn(safeLogContext({ referer, method, path: c.req.path }), 'Blocked request with invalid referer');
      return c.json(
        { error: { code: 'FORBIDDEN', message: 'Invalid origin' } },
        403
      );
    }
  }

  await next();
});

app.use(
  "*",
  cors({
    origin: env.FRONTEND_URL,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "X-Scanner-Key"],
  })
);

app.route("/", healthRoute);
app.route("/", scanRoute);
app.route("/", rescanRoute);
app.route("/", syncRoute);
app.route("/", syncScanRoute);

app.onError((err, c) => {
  // Redact secrets from error before logging
  const safeErr = err instanceof Error
    ? { name: err.name, message: err.message, stack: err.stack }
    : err;
  logger.error(safeLogContext({ err: safeErr }), "Unhandled error");
  return c.json(
    { error: { code: "INTERNAL", message: "Internal server error" } },
    500
  );
});

const port = env.PORT;
logger.info({ port }, "Scanner service starting");

serve({ fetch: app.fetch, port });

export { app };

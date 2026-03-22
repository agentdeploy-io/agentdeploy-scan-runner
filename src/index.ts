import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { getEnv } from "./env.js";
import { logger } from "./logger.js";
import { scanRoute } from "./routes/scan.js";
import { rescanRoute } from "./routes/rescan.js";
import { healthRoute } from "./routes/health.js";
import { syncRoute } from "./routes/sync.js";

const env = getEnv();

const app = new Hono();

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

app.onError((err, c) => {
  logger.error({ err }, "Unhandled error");
  return c.json(
    { error: { code: "INTERNAL", message: "Internal server error" } },
    500
  );
});

const port = env.PORT;
logger.info({ port }, "Scanner service starting");

serve({ fetch: app.fetch, port });

export { app };

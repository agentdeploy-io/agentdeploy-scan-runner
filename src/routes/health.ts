import { Hono } from "hono";
import { getEnv } from "../env.js";
import { resolveScanWsSecret } from "../lib/scan-ws-token.js";
import { getRedisClient } from "../services/redis.js";
import { getScanRunnerStats } from "../services/scan-runner.js";
import { directusRequest } from "../services/directus.js";
import { isScanJobEventsLedgerAvailable } from "../services/directus.js";
import { refreshScanJobEventsLedgerAvailability } from "../services/directus.js";
import { logger } from "../logger.js";
export const healthRoute = new Hono();

healthRoute.get("/health", async (c) => {
  const checks: Record<string, string> = {};
  let status: "healthy" | "degraded" | "unhealthy" = "healthy";
  let healthy = true;

  // Check Redis
  try {
    const redis = await getRedisClient();
    await redis.ping();
    checks.redis = "ok";
  } catch (err) {
    logger.error({ err }, "Health check: Redis ping failed");
    checks.redis = "error";
    healthy = false;
  }

  // Check Directus
  try {
    await directusRequest("/server/info");
    checks.directus = "ok";
  } catch (err) {
    logger.error({ err }, "Health check: Directus ping failed");
    checks.directus = "error";
    healthy = false;
  }

  // Check websocket auth secret resolution
  try {
    const env = getEnv();
    const secret = resolveScanWsSecret(env.SCAN_WS_TOKEN_SECRET, env.SCANNER_API_KEY);
    if (!secret) {
      checks.ws_auth = "error";
      healthy = false;
    } else {
      checks.ws_auth = "ok";
    }
  } catch (err) {
    logger.error({ err }, "Health check: WS auth secret resolution failed");
    checks.ws_auth = "error";
    healthy = false;
  }

  try {
    const env = getEnv();
    const requiresPlatformRepoConfig = env.SCAN_PROVIDER === "github_actions_platform";
    const hasGitHubConfig = Boolean(
      env.GITHUB_APP_ID &&
        env.GITHUB_APP_PRIVATE_KEY &&
        env.GITHUB_WORKFLOW_FILE &&
        env.GITHUB_SCAN_ARTIFACT_NAME &&
        (!requiresPlatformRepoConfig ||
          (env.GITHUB_PLATFORM_WORKFLOW_OWNER && env.GITHUB_PLATFORM_WORKFLOW_REPO))
    );
    checks.github = hasGitHubConfig ? "ok" : "error";
    if (!hasGitHubConfig) healthy = false;
  } catch {
    checks.github = "error";
    healthy = false;
  }

  let ledgerAvailable = isScanJobEventsLedgerAvailable();
  try {
    ledgerAvailable = await refreshScanJobEventsLedgerAvailability();
  } catch (err) {
    logger.error({ err }, "Health check: scan_job_events ledger probe failed");
    ledgerAvailable = false;
  }

  checks.scan_job_events_ledger = ledgerAvailable ? "ok" : "error";
  if (!ledgerAvailable) {
    status = "degraded";
    healthy = false;
  }

  if (!healthy && status !== "degraded") {
    status = "unhealthy";
  }

  return c.json(
    {
      status,
      timestamp: new Date().toISOString(),
      checks,
      scanRunner: getScanRunnerStats(),
      provider: getEnv().SCAN_PROVIDER,
    },
    status === "healthy" ? 200 : 503
  );
});

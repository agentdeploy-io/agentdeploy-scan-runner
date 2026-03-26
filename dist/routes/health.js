import { Hono } from "hono";
import { getEnv } from "../env.js";
import { resolveScanWsSecret } from "../lib/scan-ws-token.js";
import { getRedisClient } from "../services/redis.js";
import { getScanRunnerStats } from "../services/scan-runner.js";
import { directusRequest } from "../services/directus.js";
import { logger } from "../logger.js";
import { getPlatformWorkflowConfigSyncState } from "../services/github-actions.js";
export const healthRoute = new Hono();
healthRoute.get("/health", async (c) => {
    const checks = {};
    let healthy = true;
    // Check Redis
    try {
        const redis = await getRedisClient();
        await redis.ping();
        checks.redis = "ok";
    }
    catch (err) {
        logger.error({ err }, "Health check: Redis ping failed");
        checks.redis = "error";
        healthy = false;
    }
    // Check Directus
    try {
        await directusRequest("/server/info");
        checks.directus = "ok";
    }
    catch (err) {
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
        }
        else {
            checks.ws_auth = "ok";
        }
    }
    catch (err) {
        logger.error({ err }, "Health check: WS auth secret resolution failed");
        checks.ws_auth = "error";
        healthy = false;
    }
    try {
        const env = getEnv();
        const requiresPlatformRepoConfig = env.SCAN_PROVIDER === "github_actions_platform";
        const hasGitHubConfig = Boolean(env.GITHUB_APP_ID &&
            env.GITHUB_APP_PRIVATE_KEY &&
            env.GITHUB_WORKFLOW_FILE &&
            env.GITHUB_SCAN_ARTIFACT_NAME &&
            (!requiresPlatformRepoConfig ||
                (env.GITHUB_PLATFORM_WORKFLOW_OWNER && env.GITHUB_PLATFORM_WORKFLOW_REPO)));
        checks.github = hasGitHubConfig ? "ok" : "error";
        if (!hasGitHubConfig)
            healthy = false;
    }
    catch {
        checks.github = "error";
        healthy = false;
    }
    const workflowConfigSync = getPlatformWorkflowConfigSyncState();
    if (getEnv().SCAN_PROVIDER === "github_actions_platform") {
        checks.workflow_config_sync = workflowConfigSync.status === "ok" ? "ok" : "error";
        if (workflowConfigSync.status !== "ok") {
            healthy = false;
        }
    }
    else {
        checks.workflow_config_sync = "ok";
    }
    return c.json({
        status: healthy ? "healthy" : "unhealthy",
        timestamp: new Date().toISOString(),
        checks,
        scanRunner: getScanRunnerStats(),
        provider: getEnv().SCAN_PROVIDER,
        workflowConfig: {
            status: workflowConfigSync.status,
            code: workflowConfigSync.code,
            message: workflowConfigSync.message,
            owner: workflowConfigSync.workflowRepo.owner,
            repo: workflowConfigSync.workflowRepo.repo,
            ref: workflowConfigSync.workflowRepo.ref,
            checkedAt: workflowConfigSync.checkedAt,
            lastSyncAt: workflowConfigSync.lastSyncAt,
            syncedSecrets: workflowConfigSync.syncedSecrets,
            syncedVariables: workflowConfigSync.syncedVariables,
        },
    }, healthy ? 200 : 503);
});

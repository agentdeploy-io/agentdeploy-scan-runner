import { createAdaptorServer } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { getEnv } from "./env.js";
import { logger } from "./logger.js";
import { safeLogContext } from "./lib/redact.js";
import { runScanMaintenanceSweep, scanRoute } from "./routes/scan.js";
import { healthRoute } from "./routes/health.js";
import { syncRoute } from "./routes/sync.js";
import { getPlatformWorkflowConfigSyncState, getPlatformWorkflowDispatchDiagnostics, syncPlatformWorkflowRuntimeConfigAtStartup, } from "./services/github-actions.js";
import { attachScanWebSocketServer } from "./services/scan-ws-server.js";
const env = getEnv();
const app = new Hono();
// Allowed origins for CSRF protection
const ALLOWED_ORIGINS = [
    'https://agentdeploy.xyz',
    'https://www.agentdeploy.xyz',
    env.FRONTEND_URL,
].filter((origin) => Boolean(origin));
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
            return c.json({ error: { code: 'FORBIDDEN', message: 'Invalid origin' } }, 403);
        }
    }
    else if (referer) {
        // Check referer as fallback
        const refererUrl = new URL(referer);
        const refererOrigin = refererUrl.origin;
        if (!ALLOWED_ORIGINS.includes(refererOrigin)) {
            logger.warn(safeLogContext({ referer, method, path: c.req.path }), 'Blocked request with invalid referer');
            return c.json({ error: { code: 'FORBIDDEN', message: 'Invalid origin' } }, 403);
        }
    }
    await next();
});
app.use("*", cors({
    origin: env.FRONTEND_URL,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization", "X-Scanner-Key"],
}));
app.route("/", healthRoute);
app.route("/", scanRoute);
app.route("/", syncRoute);
app.onError((err, c) => {
    // Redact secrets from error before logging
    const safeErr = err instanceof Error
        ? { name: err.name, message: err.message, stack: err.stack }
        : err;
    logger.error(safeLogContext({ err: safeErr }), "Unhandled error");
    return c.json({ error: { code: "INTERNAL", message: "Internal server error" } }, 500);
});
const port = env.PORT;
logger.info({ port }, "Scanner service starting");
async function runPlatformWorkflowStartupPreflight() {
    if (env.SCAN_PROVIDER !== "github_actions_platform") {
        return;
    }
    // SECURE: Skip automatic secret sync - secrets are configured manually in workflow repo
    if (env.SCAN_WORKFLOW_CONFIG_SYNC_MODE === "manual") {
        logger.info({ mode: env.SCAN_WORKFLOW_CONFIG_SYNC_MODE }, "Workflow config sync set to manual - skipping automatic secret sync (SECURE MODE)");
    }
    try {
        const diagnostics = await getPlatformWorkflowDispatchDiagnostics();
        const appActions = diagnostics.appPermissions.actions || "missing";
        const appWorkflows = diagnostics.appPermissions.workflows || "missing";
        const installActions = diagnostics.installationPermissions.actions || "missing";
        const installWorkflows = diagnostics.installationPermissions.workflows || "missing";
        const issues = [];
        if (appActions !== "write")
            issues.push(`app.actions=${appActions}`);
        if (appWorkflows !== "write")
            issues.push(`app.workflows=${appWorkflows}`);
        if (installActions !== "write")
            issues.push(`installation.actions=${installActions}`);
        if (installWorkflows !== "write")
            issues.push(`installation.workflows=${installWorkflows}`);
        if (!diagnostics.repoAccess.ok)
            issues.push(`repoAccess=${diagnostics.repoAccess.status}`);
        if (!diagnostics.workflowAccess.ok)
            issues.push(`workflowAccess=${diagnostics.workflowAccess.status}`);
        const logPayload = {
            owner: diagnostics.owner,
            repo: diagnostics.repo,
            workflowFile: diagnostics.workflowFile,
            workflowRef: diagnostics.workflowRef,
            installationId: diagnostics.installationId,
            appPermissions: diagnostics.appPermissions,
            installationPermissions: diagnostics.installationPermissions,
            repoAccess: diagnostics.repoAccess,
            workflowAccess: diagnostics.workflowAccess,
        };
        if (issues.length > 0) {
            logger.error({ ...logPayload, issues }, "Platform workflow dispatch preflight failed");
        }
        else {
            logger.info(logPayload, "Platform workflow dispatch preflight passed");
        }
    }
    catch (err) {
        logger.error({ err }, "Platform workflow dispatch preflight check failed");
    }
    if (env.SCAN_WORKFLOW_CONFIG_SYNC_MODE === "manual") {
        logger.info({ mode: env.SCAN_WORKFLOW_CONFIG_SYNC_MODE }, "Skipping workflow config sync in manual mode - secrets must be configured manually in workflow repo");
        return;
    }
    const syncState = await syncPlatformWorkflowRuntimeConfigAtStartup();
    const syncPayload = {
        code: syncState.code,
        message: syncState.message,
        workflowRepo: syncState.workflowRepo,
        checkedAt: syncState.checkedAt,
        lastSyncAt: syncState.lastSyncAt,
        syncedSecrets: syncState.syncedSecrets,
        syncedVariables: syncState.syncedVariables,
    };
    if (syncState.status === "ok") {
        logger.info(syncPayload, "Platform workflow runtime config sync passed");
        return;
    }
    logger.error(syncPayload, "Platform workflow runtime config sync failed");
}
const server = createAdaptorServer({ fetch: app.fetch });
attachScanWebSocketServer(server);
let maintenanceTimer = null;
function startScanMaintenanceLoop() {
    if (env.SCAN_PROVIDER !== "github_actions_platform") {
        return;
    }
    if (maintenanceTimer) {
        return;
    }
    const intervalMs = env.SCAN_MAINTENANCE_INTERVAL_SECONDS * 1000;
    maintenanceTimer = setInterval(() => {
        void runScanMaintenanceSweep().then((result) => {
            if (result.errors > 0 || result.staleReset > 0) {
                logger.warn(result, "Scan maintenance sweep detected stale/errors");
            }
        }).catch((err) => {
            logger.error({ err }, "Scan maintenance sweep failed");
        });
    }, intervalMs);
    if (typeof maintenanceTimer.unref === "function") {
        maintenanceTimer.unref();
    }
    logger.info({ intervalSeconds: env.SCAN_MAINTENANCE_INTERVAL_SECONDS }, "Started scan maintenance reconciliation loop");
}
async function startServer() {
    await runPlatformWorkflowStartupPreflight();
    const syncState = getPlatformWorkflowConfigSyncState();
    if (env.SCAN_PROVIDER === "github_actions_platform" && syncState.status !== "ok") {
        logger.warn({
            code: syncState.code,
            message: syncState.message,
            workflowRepo: syncState.workflowRepo,
        }, "Scanner started with platform workflow sync errors; scan dispatch will be gated");
    }
    server.listen(port, () => {
        logger.info({ port }, "Scanner HTTP+WS server listening");
    });
    startScanMaintenanceLoop();
}
void startServer();
export { app };

import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { safeLogContext } from "../lib/redact.js";
export class DirectusForbiddenError extends Error {
    collection;
    action;
    role;
    fields;
    statusCode = 403;
    constructor(message, options) {
        super(message);
        this.name = "DirectusForbiddenError";
        this.collection = options?.collection;
        this.action = options?.action;
        this.role = options?.role;
        this.fields = options?.fields;
    }
}
let sellerSecurityUpdateForbidden = false;
let scanJobEventsLedgerUnavailable = false;
export function isScanJobEventsLedgerAvailable() {
    return !scanJobEventsLedgerUnavailable;
}
export async function refreshScanJobEventsLedgerAvailability() {
    try {
        await directusRequest("/items/scan_job_events?limit=1&fields=id");
        scanJobEventsLedgerUnavailable = false;
        return true;
    }
    catch (error) {
        if (error instanceof Error && /scan_job_events|forbidden|permission|field|collection/i.test(error.message)) {
            scanJobEventsLedgerUnavailable = true;
            return false;
        }
        throw error;
    }
}
function authHeaders(extra) {
    const env = getEnv();
    return {
        Authorization: `Bearer ${env.DIRECTUS_ADMIN_TOKEN}`,
        ...extra,
    };
}
export async function directusRequest(path, options = {}) {
    const env = getEnv();
    const url = `${env.DIRECTUS_URL}${path}`;
    const headers = {
        ...authHeaders(),
        ...options.headers,
    };
    if (options.body && !(options.body instanceof FormData) && !headers["Content-Type"]) {
        headers["Content-Type"] = "application/json";
    }
    const res = await fetch(url, {
        ...options,
        headers,
    });
    if (!res.ok) {
        const bodyText = await res.text();
        let errorBody = null;
        try {
            errorBody = JSON.parse(bodyText);
        }
        catch {
            // ignore
        }
        const errorCode = errorBody?.error?.code || errorBody?.errors?.[0]?.extensions?.code;
        const errorMessage = errorBody?.error?.message || errorBody?.errors?.[0]?.message || bodyText;
        const collection = errorBody?.error?.collection || errorBody?.errors?.[0]?.extensions?.collection;
        const action = errorBody?.error?.action || errorBody?.errors?.[0]?.extensions?.action;
        const role = errorBody?.error?.role;
        const errorContext = {
            status: res.status,
            path,
            method: options.method || "GET",
            errorCode,
            errorMessage,
            collection,
            action,
            role,
        };
        if (res.status === 403) {
            const fallbackCollection = extractCollectionFromPath(path);
            const fallbackAction = extractActionFromMethod(options.method || "GET");
            logger.error(safeLogContext({ ...errorContext, collection: collection || fallbackCollection, action: action || fallbackAction }), "Directus 403 Forbidden - Permission denied");
            throw new DirectusForbiddenError(errorMessage || `You do not have permission to ${fallbackAction} ${fallbackCollection}`, {
                collection: collection || fallbackCollection,
                action: action || fallbackAction,
                role,
            });
        }
        logger.error(safeLogContext(errorContext), "Directus request failed");
        throw new Error(`Directus ${res.status}: ${path} - ${errorMessage}`);
    }
    if (res.status === 204) {
        return {};
    }
    const json = (await res.json());
    return json.data;
}
function extractCollectionFromPath(path) {
    const match = path.match(/^\/items\/([^/]+)/);
    return match?.[1];
}
function extractActionFromMethod(method) {
    switch (method.toUpperCase()) {
        case "GET":
            return "read";
        case "POST":
            return "create";
        case "PATCH":
        case "PUT":
            return "update";
        case "DELETE":
            return "delete";
        default:
            return method.toLowerCase();
    }
}
export async function createScanJob(record) {
    const result = await directusRequest("/items/scan_jobs", {
        method: "POST",
        body: JSON.stringify(record),
    });
    const id = String(result.id);
    logger.info({ scanJobId: id }, "Scan job created");
    return { id };
}
export async function updateScanJob(id, patch) {
    await directusRequest(`/items/scan_jobs/${id}`, {
        method: "PATCH",
        body: JSON.stringify(patch),
    });
    logger.info({ scanJobId: id }, "Scan job updated");
}
export async function createScanFindings(findings) {
    if (findings.length === 0)
        return;
    await directusRequest("/items/scan_findings", {
        method: "POST",
        body: JSON.stringify(findings),
    });
    logger.info({ count: findings.length }, "Scan findings created");
}
export async function updateTemplateScanFields(templateId, fields) {
    await directusRequest(`/items/templates/${templateId}`, {
        method: "PATCH",
        body: JSON.stringify(fields),
    });
    logger.info({ templateId }, "Template scan fields updated");
}
export async function updateSellerSecurityFields(sellerId, fields) {
    if (sellerSecurityUpdateForbidden) {
        logger.warn({ sellerId }, "Skipping seller security update (permission previously denied for sellers.update)");
        return false;
    }
    const fieldNames = Object.keys(fields);
    const normalizedFields = {
        security_rating: fields.security_rating,
        security_score: String(fields.security_score),
        security_color_light: fields.security_color_light,
        last_security_scan: fields.last_security_scan,
        scan_compliant: String(fields.scan_compliant),
    };
    logger.info({ sellerId, fields: fieldNames, fieldValues: normalizedFields }, "Updating seller security fields");
    try {
        const sellerRows = await directusRequest(`/items/sellers?filter[user_id][_eq]=${encodeURIComponent(sellerId)}&fields=id&limit=1`);
        const sellerRecord = sellerRows[0];
        if (!sellerRecord?.id) {
            logger.warn({ sellerId }, "Skipping seller security update (no sellers row found for user_id)");
            return false;
        }
        await directusRequest(`/items/sellers/${sellerRecord.id}`, {
            method: "PATCH",
            body: JSON.stringify(normalizedFields),
        });
        logger.info({ sellerId, sellerRecordId: sellerRecord.id, fields: fieldNames }, "Seller security fields updated");
        return true;
    }
    catch (error) {
        if (error instanceof DirectusForbiddenError) {
            sellerSecurityUpdateForbidden = true;
            logger.error({
                sellerId,
                fields: fieldNames,
                collection: error.collection,
                action: error.action,
                role: error.role,
                errorMessage: error.message,
            }, "❌ Permission denied when updating seller security fields");
            return false;
        }
        logger.error({ sellerId, fields: fieldNames, error }, "Failed to update seller security fields");
        throw error;
    }
}
export async function getScanJob(id) {
    return await directusRequest(`/items/scan_jobs/${id}`);
}
export async function getScanJobByGitHubRunId(githubRunId) {
    const query = new URLSearchParams({
        "filter[github_run_id][_eq]": githubRunId,
        sort: "-started_at",
        limit: "1",
    });
    const rows = await directusRequest(`/items/scan_jobs?${query.toString()}`).catch(() => []);
    return rows[0] || null;
}
export async function listActiveScanJobsForSeller(sellerId) {
    const activeStatuses = [
        "pending",
        "running",
        "analyzing",
        "workflow_seeding",
        "dispatching",
        "queued_in_github",
        "running_in_github",
        "artifact_processing",
        "delayed",
    ].join(",");
    const query = new URLSearchParams({
        "filter[seller_id][_eq]": sellerId,
        "filter[status][_in]": activeStatuses,
        sort: "-started_at",
        limit: "20",
        fields: "id,template_id,seller_id,status,started_at,completed_at,overall_rating,overall_score,github_run_id,artifact_file_id",
    });
    try {
        return await directusRequest(`/items/scan_jobs?${query.toString()}`);
    }
    catch (error) {
        logger.error({ error, sellerId }, "Failed to list active scan jobs for seller");
        return [];
    }
}
export async function listAllActiveScanJobs(limit = 200) {
    const activeStatuses = [
        "pending",
        "running",
        "analyzing",
        "workflow_seeding",
        "dispatching",
        "queued_in_github",
        "running_in_github",
        "artifact_processing",
        "delayed",
    ].join(",");
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(1000, Math.trunc(limit))) : 200;
    const query = new URLSearchParams({
        "filter[status][_in]": activeStatuses,
        sort: "-started_at",
        limit: String(safeLimit),
        fields: "id,template_id,seller_id,status,started_at,completed_at,overall_rating,overall_score,github_run_id,artifact_file_id,source_repo,github_installation_id,github_repo_owner,github_repo_name",
    });
    try {
        return await directusRequest(`/items/scan_jobs?${query.toString()}`);
    }
    catch (error) {
        logger.error({ error, limit: safeLimit }, "Failed to list active scan jobs");
        return [];
    }
}
export async function getSellerTemplates(sellerId) {
    try {
        return await directusRequest(`/items/templates?filter[seller_id][_eq]=${sellerId}&fields=id,scan_rating,scan_score`);
    }
    catch {
        logger.warn({ sellerId }, "Could not fetch seller templates");
        return [];
    }
}
export async function uploadScanReportPdf(scanJobId, fileName, pdfBuffer) {
    const env = getEnv();
    const url = `${env.DIRECTUS_URL}/files`;
    const formData = new FormData();
    const blob = new Blob([new Uint8Array(pdfBuffer)], { type: "application/pdf" });
    formData.append("file", blob, fileName);
    formData.append("title", `Scan Report ${scanJobId}`);
    const res = await fetch(url, {
        method: "POST",
        headers: authHeaders(),
        body: formData,
    });
    if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`Directus file upload failed (${res.status}): ${body}`);
    }
    const json = (await res.json());
    const fileId = String(json.data?.id || "");
    if (!fileId) {
        throw new Error("Directus file upload did not return an id");
    }
    return {
        fileId,
        assetUrl: `${env.DIRECTUS_URL}/assets/${fileId}`,
    };
}
function isDuplicateEventError(error) {
    if (!(error instanceof Error))
        return false;
    return /RECORD_NOT_UNIQUE|duplicate/i.test(error.message);
}
export async function appendScanJobEvent(input) {
    if (scanJobEventsLedgerUnavailable) {
        return true;
    }
    try {
        await directusRequest("/items/scan_job_events", {
            method: "POST",
            body: JSON.stringify({
                scan_job_id: input.scanJobId,
                event_source: input.eventSource,
                event_type: input.eventType,
                payload: input.payload || {},
                provider_event_id: input.providerEventId,
            }),
        });
        return true;
    }
    catch (error) {
        if (isDuplicateEventError(error)) {
            logger.info({ scanJobId: input.scanJobId, providerEventId: input.providerEventId }, "Duplicate scan_job_events record ignored");
            return false;
        }
        // Missing table/field should not break runtime flow during rollout.
        if (error instanceof Error && /scan_job_events|field/i.test(error.message)) {
            scanJobEventsLedgerUnavailable = true;
            logger.warn({ scanJobId: input.scanJobId, error: error.message }, "Disabling scan_job_events ledger writes for this process (collection missing or forbidden)");
            return true;
        }
        throw error;
    }
}

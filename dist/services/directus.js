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
export async function directusRequest(path, options = {}) {
    const env = getEnv();
    const url = `${env.DIRECTUS_URL}${path}`;
    const res = await fetch(url, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${env.DIRECTUS_ADMIN_TOKEN}`,
            ...options.headers,
        },
    });
    if (!res.ok) {
        const body = await res.text();
        let errorBody = null;
        try {
            errorBody = JSON.parse(body);
        }
        catch {
            // Body is not JSON, ignore
        }
        const errorContext = {
            status: res.status,
            path,
            method: options.method || "GET",
            // Don't log full responseBody - it might contain sensitive data
            errorCode: errorBody?.error?.code,
            errorMessage: errorBody?.error?.message,
            collection: errorBody?.error?.collection,
            action: errorBody?.error?.action,
            role: errorBody?.error?.role,
        };
        // Handle 403 Forbidden with detailed permission error
        if (res.status === 403) {
            const collection = extractCollectionFromPath(path);
            const action = extractActionFromMethod(options.method || "GET");
            logger.error(safeLogContext({ ...errorContext, collection, action }), "Directus 403 Forbidden - Permission denied");
            throw new DirectusForbiddenError(errorBody?.error?.message || `You do not have permission to ${action} ${collection}`, {
                collection,
                action,
                role: errorBody?.error?.role,
            });
        }
        // Handle other errors - redact secrets from context
        logger.error(safeLogContext(errorContext), "Directus request failed");
        throw new Error(`Directus ${res.status}: ${path} - ${errorBody?.error?.message || body}`);
    }
    const json = (await res.json());
    return json.data;
}
/**
 * Extract collection name from Directus API path
 * e.g., /items/sellers/123 -> sellers
 */
function extractCollectionFromPath(path) {
    const match = path.match(/^\/items\/([^/]+)/);
    return match?.[1];
}
/**
 * Extract action type from HTTP method
 */
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
    logger.info({ scanJobId: result.id }, "Scan job created");
    return result;
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
    const fieldNames = Object.keys(fields);
    logger.info({ sellerId, fields: fieldNames, fieldValues: fields }, "Updating seller security fields");
    try {
        await directusRequest(`/items/sellers/${sellerId}`, {
            method: "PATCH",
            body: JSON.stringify(fields),
        });
        logger.info({ sellerId, fields: fieldNames }, "Seller security fields updated");
    }
    catch (error) {
        if (error instanceof DirectusForbiddenError) {
            logger.error({
                sellerId,
                fields: fieldNames,
                collection: error.collection,
                action: error.action,
                role: error.role,
                errorMessage: error.message,
            }, "❌ Permission denied when updating seller security fields");
            throw new Error(`Permission denied: Cannot update seller fields. Missing permission for ${error.collection}.${error.action}. ` +
                `Required fields: ${fieldNames.join(", ")}. ` +
                `Contact admin to grant update permission on sellers collection.`);
        }
        logger.error({ sellerId, fields: fieldNames, error }, "Failed to update seller security fields");
        throw error;
    }
}
export async function getScanJob(id) {
    return await directusRequest(`/items/scan_jobs/${id}`);
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

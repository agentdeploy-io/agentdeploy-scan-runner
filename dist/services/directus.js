import { getEnv } from "../env.js";
import { logger } from "../logger.js";
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
        logger.error({ status: res.status, path, body }, "Directus request failed");
        throw new Error(`Directus ${res.status}: ${path}`);
    }
    const json = (await res.json());
    return json.data;
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
    await directusRequest(`/items/sellers/${sellerId}`, {
        method: "PATCH",
        body: JSON.stringify(fields),
    });
    logger.info({ sellerId }, "Seller security fields updated");
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

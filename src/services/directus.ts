import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import type {
  ScanStatus,
  ScanRating,
  RiskLevel,
  ColorLight,
  ScanCategory,
  ScanSeverity,
} from "../constants.js";

interface ScanJobRecord {
  purchase_id?: string;
  template_id: string;
  seller_id: string;
  buyer_id?: string;
  source_repo: string;
  target_repo?: string;
  status: ScanStatus;
  risk_level: RiskLevel;
  overall_rating: ScanRating;
  overall_score: number;
  rating_secrets: ScanRating;
  rating_prompt_injection: ScanRating;
  rating_dependencies: ScanRating;
  rating_permissions: ScanRating;
  rating_sast: ScanRating;
  seller_color_light: ColorLight;
  started_at: string;
  completed_at?: string;
  error_message?: string;
  llm_summary?: string;
  llm_recommendations?: Record<string, unknown>;
  bundled_line_count?: number;
  exceeded_line_threshold?: boolean;
  metadata?: Record<string, unknown>;
}

interface ScanFindingRecord {
  scan_job_id: string;
  severity: ScanSeverity;
  category: ScanCategory | string;
  tool: string;
  rule_id: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  title: string;
  description: string;
  recommendation: string;
  evidence?: Record<string, unknown>;
  status: "open";
}

export async function directusRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
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

  const json = (await res.json()) as { data: T };
  return json.data;
}

export async function createScanJob(
  record: ScanJobRecord
): Promise<{ id: string }> {
  const result = await directusRequest<{ id: string }>("/items/scan_jobs", {
    method: "POST",
    body: JSON.stringify(record),
  });
  logger.info({ scanJobId: result.id }, "Scan job created");
  return result;
}

export async function updateScanJob(
  id: string,
  patch: Partial<ScanJobRecord>
): Promise<void> {
  await directusRequest(`/items/scan_jobs/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  logger.info({ scanJobId: id }, "Scan job updated");
}

export async function createScanFindings(
  findings: ScanFindingRecord[]
): Promise<void> {
  if (findings.length === 0) return;

  await directusRequest("/items/scan_findings", {
    method: "POST",
    body: JSON.stringify(findings),
  });
  logger.info({ count: findings.length }, "Scan findings created");
}

export async function updateTemplateScanFields(
  templateId: string,
  fields: {
    scan_rating: ScanRating;
    scan_score: number;
    scan_color_light: ColorLight;
    last_scan_at: string;
    last_scan_job_id: string;
    scan_status: string;
  }
): Promise<void> {
  await directusRequest(`/items/templates/${templateId}`, {
    method: "PATCH",
    body: JSON.stringify(fields),
  });
  logger.info({ templateId }, "Template scan fields updated");
}

export async function updateSellerSecurityFields(
  sellerId: string,
  fields: {
    security_rating: ScanRating;
    security_score: number;
    security_color_light: ColorLight;
    last_security_scan: string;
    scan_compliant: boolean;
  }
): Promise<void> {
  await directusRequest(`/items/sellers/${sellerId}`, {
    method: "PATCH",
    body: JSON.stringify(fields),
  });
  logger.info({ sellerId }, "Seller security fields updated");
}

export async function getScanJob(
  id: string
): Promise<ScanJobRecord & { id: string }> {
  return await directusRequest<ScanJobRecord & { id: string }>(
    `/items/scan_jobs/${id}`
  );
}

export async function getSellerTemplates(
  sellerId: string
): Promise<Array<{ id: string; scan_rating?: ScanRating; scan_score?: number }>> {
  try {
    return await directusRequest<
      Array<{ id: string; scan_rating?: ScanRating; scan_score?: number }>
    >(`/items/templates?filter[seller_id][_eq]=${sellerId}&fields=id,scan_rating,scan_score`);
  } catch {
    logger.warn({ sellerId }, "Could not fetch seller templates");
    return [];
  }
}

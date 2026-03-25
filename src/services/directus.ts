import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { safeLogContext } from "../lib/redact.js";
import type {
  ColorLight,
  RiskLevel,
  ScanCategory,
  ScanRating,
  ScanSeverity,
  ScanStatus,
} from "../constants.js";

export type ExtendedScanStatus =
  | ScanStatus
  | "workflow_seeding"
  | "dispatching"
  | "queued_in_github"
  | "running_in_github"
  | "artifact_processing"
  | "delayed";

interface ScanJobRecord {
  purchase_id?: string;
  template_id: string;
  seller_id: string;
  buyer_id?: string;
  source_repo: string;
  target_repo?: string;
  status: ExtendedScanStatus;
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
  llm_recommendations?: unknown;
  bundled_line_count?: number;
  exceeded_line_threshold?: boolean;
  metadata?: Record<string, unknown>;
  scan_provider?: "github_actions" | "github_actions_platform" | "local";
  github_installation_id?: number;
  github_workflow_id?: string;
  github_run_id?: string;
  github_run_attempt?: number;
  github_repo_owner?: string;
  github_repo_name?: string;
  artifact_name?: string;
  artifact_url_github?: string;
  artifact_file_id?: string;
  failure_code?: string;
  failure_reason?: string;
}

export interface ScanJobEntity extends ScanJobRecord {
  id: string | number;
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

export interface DirectusErrorBody {
  error?: {
    code?: string;
    message?: string;
    collection?: string;
    action?: string;
    role?: string;
  };
  errors?: Array<{
    message?: string;
    extensions?: {
      code?: string;
      collection?: string;
      action?: string;
    };
  }>;
}

export class DirectusForbiddenError extends Error {
  public readonly collection?: string;
  public readonly action?: string;
  public readonly role?: string;
  public readonly fields?: string[];
  public readonly statusCode = 403;

  constructor(
    message: string,
    options?: {
      collection?: string;
      action?: string;
      role?: string;
      fields?: string[];
    }
  ) {
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

function authHeaders(extra?: HeadersInit): HeadersInit {
  const env = getEnv();
  return {
    Authorization: `Bearer ${env.DIRECTUS_ADMIN_TOKEN}`,
    ...extra,
  };
}

export async function directusRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const env = getEnv();
  const url = `${env.DIRECTUS_URL}${path}`;

  const headers: HeadersInit = {
    ...authHeaders(),
    ...options.headers,
  };

  if (options.body && !(options.body instanceof FormData) && !(headers as Record<string, string>)["Content-Type"]) {
    (headers as Record<string, string>)["Content-Type"] = "application/json";
  }

  const res = await fetch(url, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const bodyText = await res.text();
    let errorBody: DirectusErrorBody | null = null;

    try {
      errorBody = JSON.parse(bodyText) as DirectusErrorBody;
    } catch {
      // ignore
    }

    const errorCode = errorBody?.error?.code || errorBody?.errors?.[0]?.extensions?.code;
    const errorMessage =
      errorBody?.error?.message || errorBody?.errors?.[0]?.message || bodyText;
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
      logger.error(
        safeLogContext({ ...errorContext, collection: collection || fallbackCollection, action: action || fallbackAction }),
        "Directus 403 Forbidden - Permission denied"
      );

      throw new DirectusForbiddenError(
        errorMessage || `You do not have permission to ${fallbackAction} ${fallbackCollection}`,
        {
          collection: collection || fallbackCollection,
          action: action || fallbackAction,
          role,
        }
      );
    }

    logger.error(safeLogContext(errorContext), "Directus request failed");
    throw new Error(`Directus ${res.status}: ${path} - ${errorMessage}`);
  }

  if (res.status === 204) {
    return {} as T;
  }

  const json = (await res.json()) as { data: T };
  return json.data;
}

function extractCollectionFromPath(path: string): string | undefined {
  const match = path.match(/^\/items\/([^/]+)/);
  return match?.[1];
}

function extractActionFromMethod(method: string): string {
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

export async function createScanJob(record: ScanJobRecord): Promise<{ id: string }> {
  const result = await directusRequest<{ id: string | number }>("/items/scan_jobs", {
    method: "POST",
    body: JSON.stringify(record),
  });
  const id = String(result.id);
  logger.info({ scanJobId: id }, "Scan job created");
  return { id };
}

export async function updateScanJob(id: string, patch: Partial<ScanJobRecord>): Promise<void> {
  await directusRequest(`/items/scan_jobs/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  logger.info({ scanJobId: id }, "Scan job updated");
}

export async function createScanFindings(findings: ScanFindingRecord[]): Promise<void> {
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
): Promise<boolean> {
  if (sellerSecurityUpdateForbidden) {
    logger.warn(
      { sellerId },
      "Skipping seller security update (permission previously denied for sellers.update)"
    );
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
  logger.info(
    { sellerId, fields: fieldNames, fieldValues: normalizedFields },
    "Updating seller security fields"
  );

  try {
    const sellerRows = await directusRequest<Array<{ id: string | number }>>(
      `/items/sellers?filter[user_id][_eq]=${encodeURIComponent(sellerId)}&fields=id&limit=1`
    );
    const sellerRecord = sellerRows[0];

    if (!sellerRecord?.id) {
      logger.warn(
        { sellerId },
        "Skipping seller security update (no sellers row found for user_id)"
      );
      return false;
    }

    await directusRequest(`/items/sellers/${sellerRecord.id}`, {
      method: "PATCH",
      body: JSON.stringify(normalizedFields),
    });
    logger.info(
      { sellerId, sellerRecordId: sellerRecord.id, fields: fieldNames },
      "Seller security fields updated"
    );
    return true;
  } catch (error) {
    if (error instanceof DirectusForbiddenError) {
      sellerSecurityUpdateForbidden = true;
      logger.error(
        {
          sellerId,
          fields: fieldNames,
          collection: error.collection,
          action: error.action,
          role: error.role,
          errorMessage: error.message,
        },
        "❌ Permission denied when updating seller security fields"
      );
      return false;
    }
    logger.error(
      { sellerId, fields: fieldNames, error },
      "Failed to update seller security fields"
    );
    throw error;
  }
}

export async function getScanJob(id: string): Promise<ScanJobEntity> {
  return await directusRequest<ScanJobEntity>(`/items/scan_jobs/${id}`);
}

export async function getScanJobByGitHubRunId(
  githubRunId: string
): Promise<ScanJobEntity | null> {
  const query = new URLSearchParams({
    "filter[github_run_id][_eq]": githubRunId,
    sort: "-started_at",
    limit: "1",
  });

  const rows = await directusRequest<ScanJobEntity[]>(
    `/items/scan_jobs?${query.toString()}`
  ).catch(() => []);
  return rows[0] || null;
}

export async function listActiveScanJobsForSeller(
  sellerId: string
): Promise<ScanJobEntity[]> {
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
    fields:
      "id,template_id,seller_id,status,started_at,completed_at,overall_rating,overall_score,github_run_id,artifact_file_id",
  });

  try {
    return await directusRequest<ScanJobEntity[]>(`/items/scan_jobs?${query.toString()}`);
  } catch (error) {
    logger.error({ error, sellerId }, "Failed to list active scan jobs for seller");
    return [];
  }
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

export async function uploadScanReportPdf(
  scanJobId: string,
  fileName: string,
  pdfBuffer: Buffer
): Promise<{ fileId: string; assetUrl: string }> {
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

  const json = (await res.json()) as { data?: { id?: string } };
  const fileId = String(json.data?.id || "");
  if (!fileId) {
    throw new Error("Directus file upload did not return an id");
  }

  return {
    fileId,
    assetUrl: `${env.DIRECTUS_URL}/assets/${fileId}`,
  };
}

interface AppendScanJobEventInput {
  scanJobId: string;
  eventSource: "app" | "github_webhook" | "github_poll";
  eventType: string;
  payload?: Record<string, unknown>;
  providerEventId?: string;
}

function isDuplicateEventError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return /RECORD_NOT_UNIQUE|duplicate/i.test(error.message);
}

export async function appendScanJobEvent(input: AppendScanJobEventInput): Promise<boolean> {
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
  } catch (error) {
    if (isDuplicateEventError(error)) {
      logger.info(
        { scanJobId: input.scanJobId, providerEventId: input.providerEventId },
        "Duplicate scan_job_events record ignored"
      );
      return false;
    }

    // Missing table/field should not break runtime flow during rollout.
    if (error instanceof Error && /scan_job_events|field/i.test(error.message)) {
      scanJobEventsLedgerUnavailable = true;
      logger.warn(
        { scanJobId: input.scanJobId, error: error.message },
        "Disabling scan_job_events ledger writes for this process (collection missing or forbidden)"
      );
      return true;
    }

    throw error;
  }
}

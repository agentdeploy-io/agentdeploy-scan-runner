import { getEnv } from "../env.js";
import { logger } from "../logger.js";
import { redactSecrets, safeLogContext } from "../lib/redact.js";
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

export interface DirectusErrorBody {
  error?: {
    code?: string;
    message?: string;
    collection?: string;
    action?: string;
    role?: string;
  };
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
    let errorBody: DirectusErrorBody | null = null;

    try {
      errorBody = JSON.parse(body) as DirectusErrorBody;
    } catch {
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

      logger.error(
        safeLogContext({ ...errorContext, collection, action }),
        "Directus 403 Forbidden - Permission denied"
      );

      throw new DirectusForbiddenError(
        errorBody?.error?.message || `You do not have permission to ${action} ${collection}`,
        {
          collection,
          action,
          role: errorBody?.error?.role,
        }
      );
    }

    // Handle other errors - redact secrets from context
    logger.error(safeLogContext(errorContext), "Directus request failed");
    throw new Error(`Directus ${res.status}: ${path} - ${errorBody?.error?.message || body}`);
  }

  const json = (await res.json()) as { data: T };
  return json.data;
}

/**
 * Extract collection name from Directus API path
 * e.g., /items/sellers/123 -> sellers
 */
function extractCollectionFromPath(path: string): string | undefined {
  const match = path.match(/^\/items\/([^/]+)/);
  return match?.[1];
}

/**
 * Extract action type from HTTP method
 */
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
  const fieldNames = Object.keys(fields);
  logger.info(
    { sellerId, fields: fieldNames, fieldValues: fields },
    "Updating seller security fields"
  );

  try {
    await directusRequest(`/items/sellers/${sellerId}`, {
      method: "PATCH",
      body: JSON.stringify(fields),
    });
    logger.info({ sellerId, fields: fieldNames }, "Seller security fields updated");
  } catch (error) {
    if (error instanceof DirectusForbiddenError) {
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
      throw new Error(
        `Permission denied: Cannot update seller fields. Missing permission for ${error.collection}.${error.action}. ` +
        `Required fields: ${fieldNames.join(", ")}. ` +
        `Contact admin to grant update permission on sellers collection.`
      );
    }
    logger.error(
      { sellerId, fields: fieldNames, error },
      "Failed to update seller security fields"
    );
    throw error;
  }
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

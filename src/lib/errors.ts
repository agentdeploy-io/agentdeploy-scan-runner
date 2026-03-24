/**
 * Standardized error response format for the scanner service.
 * All error responses should follow this structure for consistency.
 */

export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    requestId?: string;
  };
}

/**
 * Creates a standardized error response object.
 * @param code - Machine-readable error code (e.g., 'SCAN_FAILED', 'VALIDATION_ERROR')
 * @param message - Human-readable error message
 * @param requestId - Optional request ID for correlation
 * @returns Standardized error response object
 */
export function createErrorResponse(
  code: string,
  message: string,
  requestId?: string
): ErrorResponse {
  return {
    error: {
      code,
      message,
      ...(requestId && { requestId }),
    },
  };
}

/**
 * Common error codes for the scanner service
 */
export const ErrorCodes = {
  VALIDATION_ERROR: "VALIDATION_ERROR",
  SCAN_FAILED: "SCAN_FAILED",
  NOT_FOUND: "NOT_FOUND",
  UNAUTHORIZED: "UNAUTHORIZED",
  INTERNAL_ERROR: "INTERNAL_ERROR",
  RATE_LIMITED: "RATE_LIMITED",
  DIRECTUS_ERROR: "DIRECTUS_ERROR",
  REDIS_ERROR: "REDIS_ERROR",
  BUNDLE_ERROR: "BUNDLE_ERROR",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];
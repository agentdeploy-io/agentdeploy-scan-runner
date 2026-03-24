import type { Context } from "hono";
import { randomUUID } from "crypto";

const REQUEST_ID_HEADER = "x-request-id";

/**
 * Request ID middleware for tracing requests through the system.
 * Generates or propagates a request ID from the incoming request.
 */
export function requestIdMiddleware(c: Context, next: () => Promise<void>): Promise<void> {
  const id = c.req.header(REQUEST_ID_HEADER) || randomUUID();
  
  // Set request ID in context for use in handlers
  c.set("requestId", id);
  
  // Propagate request ID in response headers
  c.res.headers.set(REQUEST_ID_HEADER, id);
  
  return next();
}

/**
 * Get the request ID from the context.
 * Returns the request ID or undefined if not set.
 */
export function getRequestId(c: Context): string | undefined {
  return c.get("requestId");
}
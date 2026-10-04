/**
 * API client for talking to the Go backend.
 *
 * Endpoints: GET /api/v1/health, POST /api/v1/scans, GET /api/v1/scans/{id}.
 * The backend URL comes from VITE_BACKEND_URL (see .env.example).
 *
 * Errors from the backend look like:
 *   { "error": { "code": "target_not_allowlisted", "message": "..." } }
 * They are parsed into ApiError so the UI can branch on `code` instead of
 * showing raw JSON.
 */

import type { ScanRequest, ScanResponse } from "./types";

const BACKEND_URL =
  import.meta.env.VITE_BACKEND_URL ?? "http://localhost:8080";

/** Error codes the backend currently returns, plus our own client-side ones. */
export type ApiErrorCode =
  | "target_not_allowlisted"
  | "scan_capacity_reached"
  | "scan_failed"
  | "invalid_request"
  | "invalid_json"
  | "unsupported_media_type"
  | "not_found"
  | "storage_failed"
  | "database_unavailable"
  | "network_error"
  | "unknown";

class ApiError extends Error {
  status: number;
  code: ApiErrorCode;

  constructor(message: string, status: number, code: ApiErrorCode = "unknown") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** Turns a failed Response into an ApiError, using the backend's JSON body when present. */
async function toApiError(res: Response, fallback: string): Promise<ApiError> {
  let code: ApiErrorCode = "unknown";
  let message = `${fallback} (HTTP ${res.status})`;
  try {
    const body = await res.json();
    if (body?.error?.code) code = body.error.code as ApiErrorCode;
    if (body?.error?.message) message = String(body.error.message);
  } catch {
    // Not JSON (proxy error page, etc.): keep the fallback message.
  }
  return new ApiError(message, res.status, code);
}

/**
 * GET /api/v1/health
 * Used to show "backend unreachable" instead of a silent failure.
 */
export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BACKEND_URL}/api/v1/health`);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * POST /api/v1/scans
 * Sends passive findings already computed in the browser, plus scan mode
 * and consent. For active/combined scans the backend runs its probes, and
 * only for hosts in its allowlist (otherwise: 403 target_not_allowlisted).
 */
export async function submitScan(
  request: ScanRequest,
  authToken?: string,
): Promise<ScanResponse> {
  let res: Response;
  try {
    res = await fetch(`${BACKEND_URL}/api/v1/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      },
      body: JSON.stringify(request),
    });
  } catch {
    throw new ApiError(
      "Could not reach the backend. Check that it is running and that its CORS settings allow this origin.",
      0,
      "network_error",
    );
  }

  if (!res.ok) throw await toApiError(res, "Scan request failed");
  return res.json();
}

/**
 * GET /api/v1/scans/{scan_id}
 * Fetches a stored (sanitized) scan result.
 */
export async function getScanResult(scanId: string): Promise<ScanResponse> {
  const res = await fetch(`${BACKEND_URL}/api/v1/scans/${scanId}`);
  if (!res.ok) throw await toApiError(res, `Failed to fetch scan ${scanId}`);
  return res.json();
}

export { ApiError };
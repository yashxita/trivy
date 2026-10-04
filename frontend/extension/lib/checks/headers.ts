import type { HeaderFinding, Severity } from "../../shared/types";

interface HeaderRule {
  name: string;
  severityIfMissing: Severity;
  /** Only report this header when the page itself is served over HTTPS. */
  httpsOnly?: boolean;
}

/**
 * Mirrors the backend's header policy (validate/policy.go):
 *  - HSTS is ignored on non-HTTPS pages (browsers ignore it there too).
 *  - access-control-allow-origin is NOT checked here. A wildcard alone is
 *    not a confirmed vulnerability, and the backend discards it. The
 *    active CORS probe covers real misconfigurations.
 * Everything reported here is a heuristic from the browser's view of the
 * response headers, not a confirmed vulnerability.
 */
const HEADER_RULES: HeaderRule[] = [
  { name: "content-security-policy", severityIfMissing: "Medium" },
  { name: "strict-transport-security", severityIfMissing: "Medium", httpsOnly: true },
  { name: "x-frame-options", severityIfMissing: "Medium" },
  { name: "x-content-type-options", severityIfMissing: "Low" },
  { name: "referrer-policy", severityIfMissing: "Low" },
  { name: "permissions-policy", severityIfMissing: "Low" },
];

/**
 * Pure function: given the raw response headers for the main document
 * request, returns a HeaderFinding for every header that is missing.
 * Called from background.ts, the only place with access to raw response
 * headers via the webRequest API.
 */
export function evaluateHeaders(
  pageUrl: string,
  headers: { name: string; value: string }[],
): HeaderFinding[] {
  const lookup = new Map(headers.map((h) => [h.name.toLowerCase(), h.value]));
  const isHttps = pageUrl.startsWith("https://");
  const findings: HeaderFinding[] = [];

  for (const rule of HEADER_RULES) {
    if (rule.httpsOnly && !isHttps) continue;
    if (lookup.has(rule.name)) continue;

    findings.push({
      category: "header",
      pageUrl,
      header: rule.name,
      value: null,
      status: "missing",
      severity: rule.severityIfMissing,
      confidence: "heuristic",
      evidence: "Browser reported this response header as missing",
    });
  }

  return findings;
}
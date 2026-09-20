import type { SensitiveUrlFinding } from "../../shared/types";

/**
 * Parameter names that commonly carry sensitive values. Not exhaustive —
 * tune this list as you test against real sites.
 */
const SENSITIVE_PARAM_PATTERNS: { pattern: RegExp; reason: string }[] = [
  { pattern: /token/i, reason: 'matched pattern "token"' },
  { pattern: /session/i, reason: 'matched pattern "session"' },
  { pattern: /api[_-]?key/i, reason: 'matched pattern "api_key"' },
  { pattern: /password/i, reason: 'matched pattern "password"' },
  { pattern: /secret/i, reason: 'matched pattern "secret"' },
  { pattern: /email/i, reason: 'matched pattern "email"' },
  { pattern: /^auth$/i, reason: 'matched pattern "auth"' },
];

/** Masks a parameter value, keeping the URL structure intact for evidence. */
function redactUrl(url: URL, paramName: string): string {
  const clone = new URL(url.href);
  clone.searchParams.set(paramName, "***");
  return clone.href;
}

/**
 * Collects parameter names via forEach rather than for...of over
 * .entries() — per FRONTEND_CHANGES_NEEDED.md's cross-browser note,
 * don't assume every browser exposes URLSearchParams.entries() as an
 * iterable; forEach is the one iteration method guaranteed everywhere.
 */
function collectParamNames(url: URL): string[] {
  const names: string[] = [];
  url.searchParams.forEach((_value, key) => {
    if (!names.includes(key)) names.push(key);
  });
  return names;
}

/**
 * Checks the current page URL for sensitive-looking query parameters.
 * IMPORTANT: redaction happens here, before this ever reaches a message,
 * a log, or the network. The raw value never leaves this function.
 */
export function checkSensitiveUrl(): SensitiveUrlFinding[] {
  const findings: SensitiveUrlFinding[] = [];
  let url: URL;
  try {
    url = new URL(window.location.href);
  } catch {
    return findings;
  }

  for (const paramName of collectParamNames(url)) {
    const match = SENSITIVE_PARAM_PATTERNS.find(({ pattern }) =>
      pattern.test(paramName),
    );
    if (!match) continue;

    findings.push({
      category: "sensitive_url",
      pageUrl: window.location.href,
      url: redactUrl(url, paramName),
      parameterName: paramName,
      matchReason: match.reason,
      severity: "High",
    });
  }

  return findings;
}

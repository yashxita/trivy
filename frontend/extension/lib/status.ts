import type { Finding, FindingCategory } from "../shared/types";

/**
 * How a finding is shown to the person: a status colour plus a word and a
 * symbol, so the meaning never depends on colour alone.
 *
 *   vuln    High or Critical severity
 *   review  Medium or Low severity (a signal worth checking)
 *   info    Info severity
 *   clear   a check that ran and found nothing (never means "secure")
 */
export type Status = "vuln" | "review" | "info" | "clear";

export const STATUS_LABEL: Record<Status, string> = {
  vuln: "Vulnerable",
  review: "Review",
  info: "Info",
  clear: "Clear",
};

export const STATUS_TAG: Record<Status, string> = {
  vuln: "VULNERABLE",
  review: "REVIEW",
  info: "INFO",
  clear: "CLEAR",
};

export function statusOf(f: Finding): Exclude<Status, "clear"> {
  if (f.severity === "Critical" || f.severity === "High") return "vuln";
  if (f.severity === "Info") return "info";
  return "review";
}

/** Passive checks the popup reports as "Clear" when they ran and found nothing. */
export const PASSIVE_CHECKS: { category: FindingCategory; name: string }[] = [
  { category: "header", name: "Security headers" },
  { category: "insecure_form", name: "Forms" },
  { category: "unencrypted_credentials", name: "Password forms" },
  { category: "mixed_content", name: "Mixed content" },
  { category: "sensitive_url", name: "URL parameters" },
  { category: "insecure_cookie", name: "Cookies" },
  { category: "exposed_secret", name: "Secret-shaped strings" },
  { category: "vulnerable_library", name: "Library versions" },
  { category: "sensitive_storage", name: "Browser storage" },
  { category: "dom_xss_taint", name: "DOM XSS signals" },
];
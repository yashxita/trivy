import type {
  InsecureFormFinding,
  UnencryptedCredentialsFinding,
} from "../../shared/types";

const SENSITIVE_AUTOCOMPLETE_TYPES = new Set([
  "password",
  "cc-number",
  "cc-csc",
  "cc-exp",
]);

/** Heuristic only: a matching field name does not prove a CSRF defense works. */
const CSRF_FIELD_SELECTOR =
  'input[name*="csrf" i], input[name*="xsrf" i], input[name*="token" i]';

/**
 * Scans every <form> on the page. Two outputs, matching the backend policy:
 *
 * 1. insecureForms
 *    - A real `insecure_form` finding ONLY when an HTTPS page submits to an
 *      HTTP action (same rule the backend keeps in policy.go).
 *    - A low-confidence REVIEW SIGNAL (severity Info, isActionInsecure=false)
 *      for a POST form with no visible CSRF field. This is "worth a look",
 *      not a verified vulnerability. The backend discards it on active
 *      scans, so it is effectively local-only.
 *    - GET forms never produce a CSRF signal.
 *
 * 2. credentialFindings
 *    - `unencrypted_credentials` whenever a password field is submitted to
 *      an http:// action, regardless of the page's own scheme.
 */
export function checkForms(): {
  insecureForms: InsecureFormFinding[];
  credentialFindings: UnencryptedCredentialsFinding[];
} {
  const pageUrl = window.location.href;
  const pageIsHttps = window.location.protocol === "https:";
  const insecureForms: InsecureFormFinding[] = [];
  const credentialFindings: UnencryptedCredentialsFinding[] = [];

  const forms = Array.from(document.querySelectorAll("form"));

  for (const form of forms) {
    // Resolve relative action URLs against the page. Skip forms whose
    // action isn't a plain http(s) URL (javascript:, mailto:, malformed).
    let actionUrl: string;
    try {
      const resolved = new URL(
        form.getAttribute("action") ?? window.location.href,
        window.location.href,
      );
      if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
        continue;
      }
      actionUrl = resolved.href;
    } catch {
      continue;
    }

    const actionIsHttp = actionUrl.startsWith("http://");
    // Backend rule: HTTPS page -> HTTP action.
    const isActionInsecure = pageIsHttps && actionIsHttp;

    const hasPasswordField =
      form.querySelector('input[type="password"]') !== null;

    const autocompleteOnSensitive = Array.from(
      form.querySelectorAll<HTMLInputElement>("input"),
    ).some((input) => {
      const attr = (input.getAttribute("autocomplete") ?? "").toLowerCase();
      return SENSITIVE_AUTOCOMPLETE_TYPES.has(input.type) && !attr.includes("off");
    });

    const hasCsrfToken = form.querySelector(CSRF_FIELD_SELECTOR) !== null;

    const method: "GET" | "POST" =
      form.getAttribute("method")?.toUpperCase() === "POST" ? "POST" : "GET";

    if (isActionInsecure) {
      insecureForms.push({
        category: "insecure_form",
        pageUrl,
        formAction: actionUrl,
        method,
        hasPasswordField,
        isActionInsecure: true,
        autocompleteOnSensitive,
        hasCsrfToken,
        severity: hasPasswordField ? "High" : "Medium",
        confidence: "likely",
        evidence: "HTTPS page contains a form whose action uses HTTP",
      });
    } else if (method === "POST" && !hasCsrfToken) {
      // Review signal only; GET forms are skipped by the method check.
      insecureForms.push({
        category: "insecure_form",
        pageUrl,
        formAction: actionUrl,
        method,
        hasPasswordField,
        isActionInsecure: false,
        autocompleteOnSensitive,
        hasCsrfToken: false,
        severity: "Info",
        confidence: "heuristic",
        evidence:
          "State-changing form has no visible CSRF field. It may be protected another way (SameSite cookies, custom header); verify before treating as an issue.",
      });
    }

    // Separate, stronger warning: password submitted over plain HTTP.
    if (hasPasswordField && actionIsHttp) {
      credentialFindings.push({
        category: "unencrypted_credentials",
        pageUrl,
        formAction: actionUrl,
        hasPasswordField: true,
        isHttp: true,
        severity: "High",
        confidence: "likely",
        evidence: "Password form action uses HTTP",
      });
    }
  }

  return { insecureForms, credentialFindings };
}
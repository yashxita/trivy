import type { Finding, FindingCategory } from "../shared/types";

interface RemediationInfo {
  remediation: string;
  references: string;
}

const REMEDIATION_MAP: Record<FindingCategory, RemediationInfo> = {
  header: {
    remediation: "Add or correct this response header on the server. Most missing-header issues are a one-line config change (e.g. a CSP or HSTS directive in your web server or framework).",
    references: "OWASP A05 · CWE-693",
  },
  insecure_form: {
    remediation: "Serve the form over HTTPS, add a CSRF token, and disable autocomplete on sensitive fields.",
    references: "OWASP A05 · CWE-352",
  },
  unencrypted_credentials: {
    remediation: "Serve this form exclusively over HTTPS. Credentials submitted over plain HTTP can be read by anyone on the network path.",
    references: "OWASP A02 · CWE-319",
  },
  mixed_content: {
    remediation: "Update the resource URL to HTTPS. Browsers may block or warn on mixed content, and scripts/iframes loaded over HTTP can be tampered with in transit.",
    references: "OWASP A02 · CWE-319",
  },
  sensitive_url: {
    remediation: "Move this value out of the URL and into a request body, header, or server-side session instead. URLs are logged by proxies, browser history, and referrer headers.",
    references: "OWASP A01 · CWE-598",
  },
  insecure_cookie: {
    remediation: "Set the Secure, HttpOnly, and SameSite flags on this cookie to limit how it can be read or transmitted.",
    references: "OWASP A05 · CWE-614",
  },
  exposed_secret: {
    remediation: "Remove this value from client-side code and rotate the credential immediately — anything shipped to the browser is public.",
    references: "OWASP A02 · CWE-798",
  },
  vulnerable_library: {
    remediation: "Upgrade to a patched version of this library. Check the linked CVE for the exact fixed version.",
    references: "OWASP A06 · CWE-1104",
  },
  sensitive_storage: {
    remediation: "Avoid storing tokens or credentials in localStorage/sessionStorage — prefer an HttpOnly cookie or in-memory storage that clears on tab close.",
    references: "OWASP A02 · CWE-922",
  },
  reflected_input: {
    remediation: "Encode or sanitize this parameter before reflecting it back in the response.",
    references: "OWASP A03 · CWE-79",
  },
  sql_injection: {
    remediation: "Use parameterized queries for this parameter — never build SQL by concatenating user input.",
    references: "OWASP A03 · CWE-89",
  },
  cors_misconfig: {
    remediation: "Restrict Access-Control-Allow-Origin to a known allowlist, and never combine a wildcard origin with Access-Control-Allow-Credentials: true.",
    references: "OWASP A05 · CWE-942",
  },
  dom_xss_taint: {
    remediation: "Sanitize or HTML-escape this value before writing it into the DOM — or use a safe API (textContent, DOMPurify) instead of innerHTML/outerHTML/insertAdjacentHTML.",
    references: "OWASP A03 · CWE-79",
  },
  discovered_endpoint: {
    remediation: "This is a reconnaissance finding, not a vulnerability by itself — it lists an endpoint the page called that a static crawl wouldn't see. Review it for auth/rate-limiting the same way you would any other API route.",
    references: "OWASP A01",
  },
};

export function getRemediation(category: FindingCategory): RemediationInfo {
  return REMEDIATION_MAP[category];
}

/** Short human label + evidence line, used as the finding's title and subtitle. */
export function describeFinding(f: Finding): { title: string; evidence: string } {
  switch (f.category) {
    case "header":
      return {
        title: `Missing/weak header: ${f.header}`,
        evidence: f.value ? `Current value: ${f.value}` : "Header not present in response",
      };
    case "insecure_form":
      return { title: "Insecure form configuration", evidence: `Action: ${f.formAction}` };
    case "unencrypted_credentials":
      return { title: "Credentials submitted over HTTP", evidence: `Action: ${f.formAction}` };
    case "mixed_content":
      return { title: `Mixed content: ${f.resourceType}`, evidence: f.resourceUrl };
    case "sensitive_url":
      return { title: `Sensitive value in URL: ${f.parameterName}`, evidence: f.url };
    case "insecure_cookie":
      return { title: `Insecure cookie: ${f.cookieName}`, evidence: `Missing: ${[f.missingSecure && "Secure", f.missingHttpOnly && "HttpOnly", f.missingSameSite && "SameSite"].filter(Boolean).join(", ")}` };
    case "exposed_secret":
      return { title: `Exposed secret: ${f.secretType}`, evidence: `Found in ${f.location}` };
    case "vulnerable_library":
      return { title: `Vulnerable library: ${f.libraryName} ${f.detectedVersion}`, evidence: f.knownCve ?? "No CVE on file" };
    case "sensitive_storage":
      return { title: `Sensitive data in ${f.storageType}`, evidence: `Key: ${f.keyName} — ${f.reason}` };
    case "reflected_input":
      return { title: `Reflected input: ${f.parameterName}`, evidence: `Marker: ${f.markerValue}` };
    case "sql_injection":
      return { title: `Possible SQL injection: ${f.parameterName}`, evidence: f.evidenceSnippet };
    case "cors_misconfig":
      return { title: "CORS misconfiguration", evidence: `Origin ${f.requestOrigin} reflected as ${f.reflectedAcaoValue}` };
    case "dom_xss_taint":
      return { title: `DOM XSS: ${f.source ?? "unknown source"}`, evidence: f.evidence ?? "" };
    case "discovered_endpoint":
      return { title: `${f.method} ${f.testedUrl}`, evidence: f.evidence ?? "" };
    default:
      return { title: "Unknown finding", evidence: "" };
  }
}

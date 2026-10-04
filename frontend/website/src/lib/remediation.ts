import type { Finding, FindingCategory } from "../shared/types";

interface RemediationInfo {
  remediation: string;
  references: string;
}

const REMEDIATION_MAP: Record<FindingCategory, RemediationInfo> = {
  header: {
    remediation:
      "Confirm the header is really absent on the final response (a CDN or proxy may add it). If it is, add it in your web server or framework config. Most are a one-line change.",
    references: "OWASP A05 · CWE-693",
  },
  insecure_form: {
    remediation:
      "Verify first: check whether this form is already protected (SameSite cookies, a custom request header, or a token the scanner couldn't see). If it submits to HTTP, serve the action over HTTPS.",
    references: "OWASP A05 · CWE-352",
  },
  unencrypted_credentials: {
    remediation:
      "Serve this form exclusively over HTTPS. Credentials submitted over plain HTTP can be read by anyone on the network path.",
    references: "OWASP A02 · CWE-319",
  },
  mixed_content: {
    remediation:
      "Update the resource URL to HTTPS. Scripts and iframes loaded over HTTP can be tampered with in transit; browsers may block them.",
    references: "OWASP A02 · CWE-319",
  },
  sensitive_url: {
    remediation:
      "Verify whether this parameter really carries a secret or personal data. If so, move it out of the URL into a request body, header, or server-side session. URLs end up in logs, history, and referrers.",
    references: "OWASP A01 · CWE-598",
  },
  insecure_cookie: {
    remediation:
      "Check whether this cookie is sensitive (session, auth). If so, set Secure, HttpOnly, and SameSite to limit how it can be read or sent.",
    references: "OWASP A05 · CWE-614",
  },
  exposed_secret: {
    remediation:
      "Verify first: confirm whether the matched text is a live credential or just a placeholder or public identifier. Only if it is live, remove it from client-side code and rotate it.",
    references: "OWASP A02 · CWE-798",
  },
  vulnerable_library: {
    remediation:
      "Verify first: confirm which version is actually loaded in the page, and check whether the relevant advisory applies to how you use the library. If it does, upgrade to a patched release.",
    references: "OWASP A06 · CWE-1104",
  },
  sensitive_storage: {
    remediation:
      "Verify first: check what this entry actually holds. If it is a token or credential, prefer an HttpOnly cookie or in-memory storage over localStorage/sessionStorage.",
    references: "OWASP A02 · CWE-922",
  },
  reflected_input: {
    remediation:
      "Review where the value appears in the response. If it lands in HTML or script context unencoded, encode it for that context.",
    references: "OWASP A03 · CWE-79",
  },
  sql_injection: {
    remediation:
      "Verify first: a database error signature is a strong hint but not proof. Review how this parameter reaches the query and use parameterized queries.",
    references: "OWASP A03 · CWE-89",
  },
  cors_misconfig: {
    remediation:
      "Restrict Access-Control-Allow-Origin to a known allowlist, and never combine a reflected or wildcard origin with Access-Control-Allow-Credentials: true.",
    references: "OWASP A05 · CWE-942",
  },
  dom_xss_taint: {
    remediation:
      "Verify first: a value reaching a DOM sink is a signal, not proof. Check whether it is escaped elsewhere. If not, use textContent or a sanitizer such as DOMPurify instead of innerHTML.",
    references: "OWASP A03 · CWE-79",
  },
  discovered_endpoint: {
    remediation:
      "Reconnaissance only, not a vulnerability by itself. Review this endpoint for authentication and rate limiting like any other API route.",
    references: "OWASP A01",
  },
};

export function getRemediation(
  category: FindingCategory,
  finding?: Finding,
): RemediationInfo {
  if (
    finding?.category === "insecure_form" &&
    finding.isActionInsecure
  ) {
    return {
      remediation:
        "Serve the form action over HTTPS. An HTTPS page that submits to an HTTP URL exposes the submitted data in transit.",
      references: "OWASP A02 · CWE-319",
    };
  }
  return REMEDIATION_MAP[category];
}

/** The backend replaces some values with these; never show them as if they were data. */
export function isRedacted(value?: string | null): boolean {
  return !value || value.includes("[redacted]") || value.includes("redacted.invalid");
}

/** Plain-language confidence label for the badge. */
export function confidenceLabel(f: Finding): string {
  switch (f.confidence) {
    case "confirmed":
      return "Confirmed";
    case "likely":
      return "Likely";
    case "heuristic":
      return "Needs verification";
    case "informational":
      return "Informational";
    default:
      return "";
  }
}

/** Joins non-empty lines. */
function lines(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join("\n");
}

/** Short human label + evidence text, used as the finding's title and detail. */
export function describeFinding(f: Finding): { title: string; evidence: string } {
  switch (f.category) {
    case "header":
      return {
        title: `${f.status === "weak" ? "Weak" : "Missing"} header: ${f.header}`,
        evidence: lines(
          f.evidence ?? "Browser reported this response header as missing",
          f.value && !isRedacted(f.value) && `Current value: ${f.value}`,
        ),
      };
    case "insecure_form":
      return {
        title: f.isActionInsecure
          ? "HTTPS page submits a form to HTTP"
          : "Review: possible missing CSRF defense",
        evidence: lines(f.evidence, `Form action: ${f.formAction}`),
      };
    case "unencrypted_credentials":
      return {
        title: "Password submitted over HTTP",
        evidence: lines(f.evidence, `Form action: ${f.formAction}`),
      };
    case "mixed_content":
      return {
        title: `Mixed content: ${f.resourceType}`,
        evidence: lines(f.evidence, f.resourceUrl),
      };
    case "sensitive_url":
      return {
        title: `Sensitive-looking URL parameter: ${f.parameterName}`,
        evidence: lines(f.evidence, f.url),
      };
    case "insecure_cookie": {
      const missing = [
        f.missingSecure && "Secure",
        f.missingHttpOnly && "HttpOnly",
        f.missingSameSite && "SameSite",
      ].filter(Boolean);
      return {
        title: `Cookie missing attributes: ${f.cookieName}`,
        evidence: lines(f.evidence, missing.length > 0 && `Missing: ${missing.join(", ")}`),
      };
    }
    case "exposed_secret":
      return {
        title: `Secret-shaped value (${f.secretType}), unverified`,
        evidence: lines(
          f.evidence ?? "Matches a secret-shaped pattern; validity has not been verified",
          f.location && `Where: ${f.location}`,
        ),
      };
    case "vulnerable_library":
      return {
        title: `Possibly outdated library: ${f.libraryName} ${f.detectedVersion}`,
        evidence:
          f.evidence ??
          "Version detected from the page; verify the loaded code and whether the advisory applies",
      };
    case "sensitive_storage":
      return {
        title: `Storage entry may hold credentials (${f.storageType})`,
        evidence: lines(
          f.evidence,
          f.reason,
          f.keyName && !isRedacted(f.keyName) && `Key: ${f.keyName}`,
        ),
      };
    case "reflected_input":
      return {
        title: `Reflected input: ${f.parameterName}`,
        evidence: f.evidence ?? "A test marker was reflected in the response",
      };
    case "sql_injection":
      return {
        title: `Possible database error signature: ${f.parameterName}`,
        evidence:
          f.evidence ?? "A database error signature appeared after a quote probe",
      };
    case "cors_misconfig":
      return {
        title: "CORS: untrusted Origin accepted",
        evidence: lines(
          f.evidence,
          f.reflectedAcaoValue &&
            !isRedacted(f.reflectedAcaoValue) &&
            `Access-Control-Allow-Origin: ${f.reflectedAcaoValue}`,
          f.allowsCredentials && "Credentials are also allowed",
        ),
      };
    case "dom_xss_taint":
      return {
        title: "Possible DOM XSS: value reached a DOM sink",
        evidence: f.evidence ?? "",
      };
    case "discovered_endpoint":
      return {
        title: `${f.method} ${f.testedUrl}`,
        evidence: f.evidence ?? "",
      };
    default:
      return { title: "Unknown finding", evidence: "" };
  }
}
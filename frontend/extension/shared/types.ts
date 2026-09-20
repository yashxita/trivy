/**
 * Shared types for Trivy.
 *
 * This file is the single source of truth for the shape of a "Finding" and
 * a "Scan". Both the extension (popup, content script, background worker)
 * and the website import from here, so nothing drifts out of sync.
 *
 * IMPORTANT FOR BACKEND: this file is also the reference for the JSON your
 * Go server receives on POST /api/v1/scans and returns on the response.
 * See API_CONTRACT.md at the repo root for the full endpoint list, request/
 * response examples, and field-by-field notes on what the backend should
 * validate, recompute, or store per category.
 *
 * If you (backend) change a field name or add a field, update this file in
 * the same PR so frontend and backend never silently disagree on shape.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export type ScanMode = "passive" | "active" | "combined";

/**
 * One entry per check category. This is the discriminant field on Finding —
 * switch on `category` to know which extra fields are present.
 */
export type FindingCategory =
  | "header"
  | "insecure_form"
  | "unencrypted_credentials"
  | "mixed_content"
  | "sensitive_url"
  | "insecure_cookie"
  | "exposed_secret"
  | "vulnerable_library"
  | "sensitive_storage"
  // active-scan categories (computed on the Go backend, not the extension)
  | "reflected_input"
  | "sql_injection"
  | "cors_misconfig"
  // client-side (DOM) findings — new, see FRONTEND_CHANGES_NEEDED.md
  | "dom_xss_taint"
  | "discovered_endpoint";

// ---------------------------------------------------------------------------
// Base finding shape — every category extends this
// ---------------------------------------------------------------------------

interface FindingBase {
  /** Which check produced this finding. Switch on this field. */
  category: FindingCategory;
  /** The page the finding was found on. Always the full page URL. */
  pageUrl: string;
  /**
   * Severity as computed by the frontend. The backend should NOT trust this
   * blindly — see API_CONTRACT.md for which categories must be recomputed
   * server-side (mixed_content, unencrypted_credentials especially).
   */
  severity: Severity;
  /**
   * Common optional fields the backend attaches to (or expects on) any
   * finding, matching the Go model.Finding struct exactly. Not every
   * category uses every field — e.g. "confidence" is mostly set by
   * backend-produced active-scan findings, while "affectedPages" /
   * "sampleUrls" appear when the backend rolls up the same issue found
   * across a crawl of multiple pages into one finding.
   */
  confidence?: "heuristic" | "likely" | "confirmed";
  /** Where this finding came from — "http" for backend probes, "dom" for frontend-observed findings. */
  source?: string;
  /** Free-text evidence description. Always prefer this over inventing a new typed field. */
  evidence?: string;
  testedUrl?: string;
  affectedPages?: number;
  sampleUrls?: string[];
}

export interface HeaderFinding extends FindingBase {
  category: "header";
  header: string; // e.g. "Content-Security-Policy"
  value: string | null; // actual header value, or null if missing
  status: "missing" | "weak" | "ok";
}

export interface InsecureFormFinding extends FindingBase {
  category: "insecure_form";
  formAction: string;
  method: "GET" | "POST";
  hasPasswordField: boolean;
  isActionInsecure: boolean;
  autocompleteOnSensitive: boolean;
  hasCsrfToken: boolean;
}

export interface UnencryptedCredentialsFinding extends FindingBase {
  category: "unencrypted_credentials";
  formAction: string;
  hasPasswordField: true;
  isHttp: true;
}

export interface MixedContentFinding extends FindingBase {
  category: "mixed_content";
  resourceUrl: string;
  resourceType: "script" | "image" | "stylesheet" | "iframe" | "font";
}

export interface SensitiveUrlFinding extends FindingBase {
  category: "sensitive_url";
  /** Already redacted before this object is created. Never the raw value. */
  url: string;
  parameterName: string;
  matchReason: string;
}

export interface InsecureCookieFinding extends FindingBase {
  category: "insecure_cookie";
  cookieName: string;
  missingSecure: boolean;
  missingHttpOnly: boolean;
  missingSameSite: boolean;
}

export interface ExposedSecretFinding extends FindingBase {
  category: "exposed_secret";
  /** What kind of secret matched (jwt, api_key, generic_token, etc). Never the value itself. */
  secretType: string;
  location: string; // e.g. "inline <script> tag" or script src URL
}

export interface VulnerableLibraryFinding extends FindingBase {
  category: "vulnerable_library";
  libraryName: string;
  detectedVersion: string;
  knownCve?: string;
}

export interface SensitiveStorageFinding extends FindingBase {
  category: "sensitive_storage";
  storageType: "localStorage" | "sessionStorage";
  keyName: string;
  reason: string; // e.g. "value matches JWT pattern"
}

/** Active-scan findings. These are produced by the Go backend, not the extension. */
export interface ReflectedInputFinding extends FindingBase {
  category: "reflected_input";
  parameterName: string;
  markerValue: string;
}

export interface SqlInjectionFinding extends FindingBase {
  category: "sql_injection";
  parameterName: string;
  evidenceSnippet: string;
}

export interface CorsMisconfigFinding extends FindingBase {
  category: "cors_misconfig";
  requestOrigin: string;
  reflectedAcaoValue: string;
  allowsCredentials: boolean;
}

/**
 * Client-side DOM XSS taint finding — a controllable source (URL query
 * value, hash, or form input) was observed reaching a dangerous DOM sink
 * without escaping. Computed entirely in the browser; the mechanism is
 * documented in lib/checks/domTaint.ts. Uses only the common optional
 * fields (source, evidence, confidence) rather than a dedicated "sink"
 * field, because the backend's Go struct doesn't declare one — anything
 * not in that struct is silently dropped on an active/combined scan's
 * round trip through the backend, so the sink name is folded into the
 * evidence text instead to survive that round trip.
 */
export interface DomXssTaintFinding extends FindingBase {
  category: "dom_xss_taint";
}

/**
 * A request the page itself made (via fetch/XHR) that isn't visible as a
 * plain HTML link or form — the SPA-endpoint-discovery finding from
 * FRONTEND_CHANGES_NEEDED.md. Only names/shapes are captured, never
 * values — see lib/requestCapture.ts.
 */
export interface DiscoveredEndpointFinding extends FindingBase {
  category: "discovered_endpoint";
  method: string;
  testedUrl: string;
}

/** Union of every possible finding shape. Use this type when handling a findings array. */
export type Finding =
  | HeaderFinding
  | InsecureFormFinding
  | UnencryptedCredentialsFinding
  | MixedContentFinding
  | SensitiveUrlFinding
  | InsecureCookieFinding
  | ExposedSecretFinding
  | VulnerableLibraryFinding
  | SensitiveStorageFinding
  | ReflectedInputFinding
  | SqlInjectionFinding
  | CorsMisconfigFinding
  | DomXssTaintFinding
  | DiscoveredEndpointFinding;

// ---------------------------------------------------------------------------
// Scan request / response — the POST /api/v1/scans contract
// ---------------------------------------------------------------------------

export interface ScanRequest {
  target: string; // full URL being scanned
  scanMode: ScanMode;
  /** Required (and must be true) if scanMode is "active" or "combined". */
  consent: boolean;
  /** Passive findings already computed in-browser, sent up for active-mode correlation and optional storage. */
  findings: Finding[];
  /**
   * Only present for active/combined scans — carries the user's rate
   * limit settings from the options page so the backend's active probe
   * engine can honor them, per the report's rate-limiting requirement.
   */
  rateLimit?: {
    requestsPerSecond: number;
    maxConcurrency: number;
  };
  /** Paths the active scanner must never touch, from the user's settings. */
  excludedPaths?: string[];
}

export interface Coverage {
  pagesDiscovered: number;
  pagesScanned: number;
  requestsMade: number;
  formsDiscovered: number;
  parametersTested: number;
  bodyParametersTested: number;
  activeProbes: number;
  truncated: boolean;
  warnings?: string[];
}

export interface ScanResponse {
  /** Always present — the backend now persists every scan under this id. */
  scanId: string;
  /** Combined list: the passive findings echoed back plus any active findings the backend computed. */
  findings: Finding[];
  /** Optional summary counts, handy for the popup/dashboard to avoid recomputing. */
  summary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  /** Present on active/combined scans — what the backend's crawl actually covered. */
  coverage?: Coverage;
}

// ---------------------------------------------------------------------------
// Settings — mirrors the options page, stored via extension storage API
// ---------------------------------------------------------------------------

export interface ScanSettings {
  scanMode: ScanMode;
  requestsPerSecond: number;
  maxConcurrency: number;
  excludedPaths: string[];
  enabledCategories: Partial<Record<FindingCategory, boolean>>;
  includeSessionCookies: boolean;
}

export const DEFAULT_SETTINGS: ScanSettings = {
  scanMode: "passive",
  requestsPerSecond: 3,
  maxConcurrency: 2,
  excludedPaths: ["/logout", "/delete", "/checkout"],
  enabledCategories: {},
  includeSessionCookies: false,
};

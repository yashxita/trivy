import { useEffect, useState } from "react";
import { loadSettings } from "../../lib/settings";
import { isExtensionMessage, type ExtensionMessage } from "../../lib/messages";
import type { Coverage, Finding, ScanMode } from "../../shared/types";

type ScanState = "idle" | "running" | "done" | "error";

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

export default function App() {
  const [scanMode, setScanMode] = useState<ScanMode>("passive");
  const [consent, setConsent] = useState(false);
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [pageUrl, setPageUrl] = useState<string>("");

  useEffect(() => {
    loadSettings().then((settings) => setScanMode(settings.scanMode));

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url ?? "";
      setPageUrl(url);
      if (url) {
        const domain = safeDomain(url);
        chrome.storage.local.get([`consent:${domain}`], (result) => {
          setConsent(Boolean(result[`consent:${domain}`]));
        });
      }
    });
  }, []);

  useEffect(() => {
    function handleMessage(message: unknown) {
      if (isExtensionMessage(message) && message.type === "SCAN_PROGRESS") {
        setProgress(message.percent);
      }
    }
    chrome.runtime.onMessage.addListener(handleMessage);
    return () => chrome.runtime.onMessage.removeListener(handleMessage);
  }, []);

  function handleConsentChange(checked: boolean) {
    setConsent(checked);
    const domain = safeDomain(pageUrl);
    if (domain) {
      chrome.storage.local.set({ [`consent:${domain}`]: checked });
    }
  }

  function runScan() {
    setScanState("running");
    setProgress(0);
    setErrorMessage(null);
    setErrorCode(null);

    const message: ExtensionMessage = { type: "RUN_SCAN", scanMode, consent };
    chrome.runtime.sendMessage(message, (response: ExtensionMessage) => {
      if (!response) {
        setScanState("error");
        setErrorMessage("No response from background worker.");
        return;
      }
      if (response.type === "SCAN_COMPLETE") {
        setFindings(
          [...response.result.findings].sort(
            (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
          ),
        );
        setCoverage(response.result.coverage ?? null);
        setScanState("done");
      } else if (response.type === "SCAN_ERROR") {
        setScanState("error");
        setErrorMessage(response.message);
        setErrorCode(response.code ?? null);
      }
    });
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(findings, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    chrome.downloads.download({
      url,
      filename: `trivy-scan-${safeDomain(pageUrl)}.json`,
    });
  }

  const needsConsent = scanMode !== "passive";
  const mainFindings = findings.filter((f) => f.severity !== "Info");
  const infoFindings = findings.filter((f) => f.severity === "Info");

  return (
    <main className="popup">
      <header className="popup__header">
        <span className="popup__title">Trivy</span>
        <button
          type="button"
          className="settings-button"
          aria-label="Open settings"
          onClick={() => chrome.runtime.openOptionsPage()}
        >
          ⚙
        </button>
      </header>
      <p className="popup__target">scanning: {safeDomain(pageUrl) || "—"}</p>

      <div className="glass-panel">
        <div className="mode-toggle" role="radiogroup" aria-label="Scan mode">
          {(["passive", "active", "combined"] as ScanMode[]).map((mode) => (
            <button
              key={mode}
              type="button"
              role="radio"
              aria-checked={scanMode === mode}
              className={`mode-toggle__option ${scanMode === mode ? "mode-toggle__option--active" : ""}`}
              onClick={() => setScanMode(mode)}
            >
              {mode}
            </button>
          ))}
        </div>

        {needsConsent && (
          <label className="consent">
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => handleConsentChange(e.target.checked)}
            />
            I'm authorized to test this domain
          </label>
        )}

        <button
          type="button"
          className="run-button"
          disabled={
            scanState === "running" || (needsConsent && !consent) || !pageUrl
          }
          onClick={runScan}
        >
          {scanState === "running" ? `Scanning… ${progress}%` : "▶ Run scan"}
        </button>

        {scanState === "running" && (
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
        )}

        {errorMessage && (
          <ScanError
            message={errorMessage}
            code={errorCode}
            host={safeHost(pageUrl)}
          />
        )}
      </div>

      {scanState === "done" && (
        <div className="glass-panel">
          {coverage && (
            <p className="coverage-line">
              {coverage.pagesScanned}/{coverage.pagesDiscovered} pages · {coverage.requestsMade} requests
              {coverage.truncated ? " · truncated" : ""}
            </p>
          )}

          <h2 className="findings-heading">Findings ({mainFindings.length})</h2>
          {mainFindings.length === 0 ? (
            <p className="empty-state">No issues found.</p>
          ) : (
            <ul className="findings-list">
              {mainFindings.map((f, i) => (
                <li key={i} className={`finding finding--${f.severity.toLowerCase()}`} title={f.evidence}>
                  <span className="finding__dot" />
                  <span className="finding__label">{describeFinding(f)}</span>
                  <span className="finding__severity">{f.severity}</span>
                </li>
              ))}
            </ul>
          )}

          {infoFindings.length > 0 && (
            <>
              <h2 className="findings-heading findings-heading--info">Info ({infoFindings.length})</h2>
              <ul className="findings-list">
                {infoFindings.map((f, i) => (
                  <li key={i} className="finding finding--info" title={f.evidence}>
                    <span className="finding__dot" />
                    <span className="finding__label">{describeFinding(f)}</span>
                    <span className="finding__severity">Info</span>
                  </li>
                ))}
              </ul>
            </>
          )}

          <div className="actions">
            <button type="button" onClick={exportJson}>
              ⬇ Export JSON
            </button>
            <button
              type="button"
              onClick={() => chrome.tabs.create({ url: "https://app.trivy.io/dashboard" })}
            >
              Open dashboard ↗
            </button>
          </div>
        </div>
      )}
    </main>
  );
}

function safeDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** host includes the port (e.g. localhost:3000), which is what the backend allowlist matches on. */
function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function ScanError({
  message,
  code,
  host,
}: {
  message: string;
  code: string | null;
  host: string;
}) {
  if (code === "target_not_allowlisted") {
    return (
      <div className="callout" role="alert">
        <strong>Active scanning isn't enabled for {host || "this host"}</strong>
        <p>
          The backend only runs active probes against hosts it has been told to
          allow. Passive scans still work on this site.
        </p>
        <p>
          Ask the backend owner to add <code>{host || "the host"}</code> to{" "}
          <code>TRIVY_INTRUSIVE_ALLOWED_HOSTS</code>. The match is exact,
          including the port.
        </p>
      </div>
    );
  }
  if (code === "scan_capacity_reached") {
    return (
      <div className="callout" role="alert">
        <strong>The backend is busy</strong>
        <p>Too many active scans are already running. Wait a few seconds and try again.</p>
      </div>
    );
  }
  return <p className="error-text">{message}</p>;
}

function describeFinding(f: Finding): string {
  switch (f.category) {
    case "header":
      return `${f.status === "weak" ? "Weak" : "Missing"} header: ${f.header}`;
    case "insecure_form":
      return f.isActionInsecure
        ? "HTTPS page submits a form to HTTP"
        : "Review: possible missing CSRF defense";
    case "unencrypted_credentials":
      return "Password submitted over HTTP";
    case "mixed_content":
      return `Mixed content: ${f.resourceType}`;
    case "sensitive_url":
      return `Sensitive-looking URL parameter: ${f.parameterName}`;
    case "insecure_cookie":
      return `Cookie missing attributes: ${f.cookieName}`;
    case "exposed_secret":
      return `Secret-shaped value (${f.secretType}), unverified`;
    case "vulnerable_library":
      return `Possibly outdated library: ${f.libraryName} ${f.detectedVersion}`;
    case "sensitive_storage":
      return `Storage entry may hold credentials (${f.storageType})`;
    case "reflected_input":
      return `Reflected input: ${f.parameterName}`;
    case "sql_injection":
      return `Possible database error signature: ${f.parameterName}`;
    case "cors_misconfig":
      return "CORS: untrusted Origin accepted";
    case "dom_xss_taint":
      return "Possible DOM XSS: value reached a DOM sink";
    case "discovered_endpoint":
      return `${f.method} ${f.testedUrl}`;
    default:
      return "Unknown finding";
  }
}
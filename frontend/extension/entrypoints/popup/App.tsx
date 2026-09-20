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

        {errorMessage && <p className="error-text">{errorMessage}</p>}
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
                <li key={i} className={`finding finding--${f.severity.toLowerCase()}`}>
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
                  <li key={i} className="finding finding--info">
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

function describeFinding(f: Finding): string {
  switch (f.category) {
    case "header":
      return `Missing/weak header: ${f.header}`;
    case "insecure_form":
      return "Insecure form configuration";
    case "unencrypted_credentials":
      return "Credentials submitted over HTTP";
    case "mixed_content":
      return `Mixed content: ${f.resourceType}`;
    case "sensitive_url":
      return `Sensitive value in URL: ${f.parameterName}`;
    case "insecure_cookie":
      return `Insecure cookie: ${f.cookieName}`;
    case "exposed_secret":
      return `Exposed secret: ${f.secretType}`;
    case "vulnerable_library":
      return `Vulnerable library: ${f.libraryName} ${f.detectedVersion}`;
    case "sensitive_storage":
      return `Sensitive data in ${f.storageType}`;
    case "reflected_input":
      return `Reflected input: ${f.parameterName}`;
    case "sql_injection":
      return `Possible SQL injection: ${f.parameterName}`;
    case "cors_misconfig":
      return "CORS misconfiguration";
    case "dom_xss_taint":
      return f.evidence ?? `DOM XSS: value from ${f.source ?? "unknown source"}`;
    case "discovered_endpoint":
      return `${f.method} ${f.testedUrl}`;
    default:
      return "Unknown finding";
  }
}

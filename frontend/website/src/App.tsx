import { useEffect, useState } from "react";
import { submitScan } from "./shared/api-client";
import type { Coverage, Finding } from "./shared/types";
import { describeFinding, getRemediation } from "./lib/remediation";
import SeverityBarChart from "./components/SeverityBarChart";
import CategoryBarChart from "./components/CategoryBarChart";
import CoverageRing from "./components/CoverageRing";

type ScanState = "idle" | "running" | "done" | "error";
type Theme = "light" | "dark";

interface PastScan {
  id: string;
  target: string;
  timestamp: number;
  findings: Finding[];
  coverage: Coverage | null;
}

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

const CHECK_PILLS = [
  "Reflected XSS",
  "SQL injection",
  "CORS misconfig",
  "DOM XSS taint",
  "SPA endpoint discovery",
];

function severityCounts(findings: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.severity === "Critical") counts.critical++;
    else if (f.severity === "High") counts.high++;
    else if (f.severity === "Medium") counts.medium++;
    else if (f.severity === "Low") counts.low++;
  }
  return counts;
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem("trivy-theme") as Theme | null) ?? "light",
  );
  const [target, setTarget] = useState("");
  const [consent, setConsent] = useState(false);
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [selected, setSelected] = useState(0);
  const [pastScans, setPastScans] = useState<PastScan[]>([]);
  const [viewingPastId, setViewingPastId] = useState<string | null>(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("trivy-theme", theme);
  }, [theme]);

  const counts = severityCounts(findings);

  async function runScan() {
    if (!consent || !target) return;
    setScanState("running");
    setErrorMessage(null);
    setViewingPastId(null);

    try {
      const result = await submitScan({
        target,
        scanMode: "active",
        consent,
        findings: [],
      });
      const sorted = [...result.findings].sort(
        (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
      );
      setFindings(sorted);
      setCoverage(result.coverage ?? null);
      setSelected(0);
      setScanState("done");

      // Session-only history — cleared on page reload, never sent anywhere.
      // This is something the extension deliberately doesn't do (no
      // persistent scan history), but the dashboard can hold a working
      // set for the current session without any backend storage decision.
      setPastScans((prev) => [
        {
          id: result.scanId || `${Date.now()}`,
          target,
          timestamp: Date.now(),
          findings: sorted,
          coverage: result.coverage ?? null,
        },
        ...prev,
      ].slice(0, 10));
    } catch (err) {
      setScanState("error");
      setErrorMessage(err instanceof Error ? err.message : "Scan failed.");
    }
  }

  function viewPastScan(scan: PastScan) {
    setFindings(scan.findings);
    setCoverage(scan.coverage);
    setSelected(0);
    setViewingPastId(scan.id);
    setScanState("done");
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(findings, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trivy-scan-${safeDomain(target)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const selectedFinding = findings[selected];
  const mainFindings = findings.filter((f) => f.severity !== "Info");
  const infoFindings = findings.filter((f) => f.severity === "Info");

  return (
    <div className="page">
      <nav className="nav">
        <span className="nav__brand">🛡 Trivy</span>
        <button
          type="button"
          className="theme-toggle"
          aria-label="Toggle dark mode"
          onClick={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
        >
          {theme === "light" ? "🌙" : "☀️"}
        </button>
      </nav>

      <header className="hero">
        <h1 className="hero__title">Scan any site for security issues</h1>
        <p className="hero__subtitle">
          Point Trivy at a URL and get a live active security scan, run
          server-side, with fuller visualizations and session history than
          the browser extension's popup can show.
        </p>
        <p className="hero__note">
          Passive checks (headers, cookies, DOM) need the browser extension —
          only it can read the live page you're viewing. This dashboard runs
          the same active engine, on demand, against any URL.
        </p>

        <div className="check-pills">
          {CHECK_PILLS.map((c) => (
            <span key={c} className="check-pill">{c}</span>
          ))}
        </div>

        <div className="glass-panel scan-form">
          <div className="scan-form__row">
            <input
              type="url"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="target-input"
              onKeyDown={(e) => e.key === "Enter" && runScan()}
            />
            <button
              type="button"
              className="run-button"
              disabled={scanState === "running" || !consent || !target}
              onClick={runScan}
            >
              {scanState === "running" ? "Scanning…" : "▶ Run scan"}
            </button>
          </div>
          <label className="consent">
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
            />
            I'm authorized to run active security tests against this domain
          </label>
          {errorMessage && <p className="error-text">{errorMessage}</p>}
        </div>
      </header>

      <div className="layout">
        <aside className="sidebar">
          <h2 className="sidebar__heading">Recent scans</h2>
          {pastScans.length === 0 ? (
            <p className="empty-state empty-state--sidebar">
              Scans from this session will show up here.
            </p>
          ) : (
            <ul className="past-scans-list">
              {pastScans.map((scan) => (
                <li
                  key={scan.id}
                  className={`past-scan ${viewingPastId === scan.id ? "past-scan--active" : ""}`}
                  onClick={() => viewPastScan(scan)}
                >
                  <span className="past-scan__target">{safeDomain(scan.target)}</span>
                  <span className="past-scan__meta">
                    {scan.findings.length} findings · {formatTime(scan.timestamp)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </aside>

        <main className="main-content">
          {scanState === "done" && (
            <section className="results fade-in">
              <div className="glass-panel viz-grid">
                <div className="viz-cell">
                  <h3>Severity</h3>
                  <SeverityBarChart findings={findings} />
                </div>
                <div className="viz-cell">
                  <h3>By category</h3>
                  <CategoryBarChart findings={findings} />
                </div>
                {coverage && (
                  <div className="viz-cell viz-cell--coverage">
                    <h3>Coverage</h3>
                    <CoverageRing coverage={coverage} />
                  </div>
                )}
              </div>

              <div className="summary-cards">
                <div className="summary-card summary-card--critical">
                  <span className="summary-card__num">{counts.critical}</span>
                  <span className="summary-card__label">Critical</span>
                </div>
                <div className="summary-card summary-card--high">
                  <span className="summary-card__num">{counts.high}</span>
                  <span className="summary-card__label">High</span>
                </div>
                <div className="summary-card summary-card--medium">
                  <span className="summary-card__num">{counts.medium}</span>
                  <span className="summary-card__label">Medium</span>
                </div>
                <div className="summary-card summary-card--low">
                  <span className="summary-card__num">{counts.low}</span>
                  <span className="summary-card__label">Low</span>
                </div>
              </div>

              <div className="results-panel">
                <div className="glass-panel findings-column">
                  <div className="findings-column__header">
                    <h2>Findings ({mainFindings.length})</h2>
                    <button type="button" onClick={exportJson}>⬇ Export JSON</button>
                  </div>
                  {mainFindings.length === 0 ? (
                    <p className="empty-state">No issues found for this target.</p>
                  ) : (
                    <ul className="findings-list">
                      {mainFindings.map((f, i) => {
                        const { title } = describeFinding(f);
                        const globalIndex = findings.indexOf(f);
                        return (
                          <li
                            key={i}
                            className={`finding finding--${f.severity.toLowerCase()} ${globalIndex === selected ? "finding--selected" : ""}`}
                            onClick={() => setSelected(globalIndex)}
                          >
                            <span className="finding__dot" />
                            <span className="finding__label">{title}</span>
                            <span className="finding__severity">{f.severity}</span>
                          </li>
                        );
                      })}
                    </ul>
                  )}

                  {infoFindings.length > 0 && (
                    <>
                      <h2 className="info-heading">Info ({infoFindings.length})</h2>
                      <ul className="findings-list">
                        {infoFindings.map((f, i) => {
                          const { title } = describeFinding(f);
                          const globalIndex = findings.indexOf(f);
                          return (
                            <li
                              key={i}
                              className={`finding finding--info ${globalIndex === selected ? "finding--selected" : ""}`}
                              onClick={() => setSelected(globalIndex)}
                            >
                              <span className="finding__dot" />
                              <span className="finding__label">{title}</span>
                              <span className="finding__severity">Info</span>
                            </li>
                          );
                        })}
                      </ul>
                    </>
                  )}
                </div>

                {selectedFinding && (
                  <div className="glass-panel detail-panel">
                    <DetailView finding={selectedFinding} />
                  </div>
                )}
              </div>
            </section>
          )}
        </main>
      </div>

      <footer className="footer">Findings are pointers for further review, not proof of exploitability.</footer>
    </div>
  );
}

function DetailView({ finding }: { finding: Finding }) {
  const { title, evidence } = describeFinding(finding);
  const { remediation, references } = getRemediation(finding.category);

  return (
    <>
      <div className="detail-panel__header">
        <h3>{title}</h3>
        <span className={`severity-badge severity-badge--${finding.severity.toLowerCase()}`}>
          {finding.severity}
        </span>
      </div>
      <p className="detail-panel__meta">{finding.pageUrl} · {finding.category}</p>

      <h4>Evidence</h4>
      <div className="evidence-block">{evidence}</div>

      <h4>Fix</h4>
      <p className="detail-panel__fix">{remediation}</p>

      <p className="detail-panel__refs">refs: {references}</p>
    </>
  );
}

function safeDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "scan";
  }
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

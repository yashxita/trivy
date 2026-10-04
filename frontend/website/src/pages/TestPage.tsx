import { useEffect, useMemo, useState, type FormEvent } from "react";
import { ApiError, submitScan } from "../shared/api-client";
import type { Coverage, Finding } from "../shared/types";
import { confidenceLabel, describeFinding, getRemediation } from "../lib/remediation";
import { ACTIVE_CHECKS, STATUS_LABEL, STATUS_TAG, statusOf, type Status } from "../lib/status";
import SeverityBarChart from "../components/SeverityBarChart";
import CategoryBarChart from "../components/CategoryBarChart";
import CoverageRing from "../components/CoverageRing";
import { ArrowIcon, ChevronIcon, CurveArrow } from "../components/Bits";

type ScanState = "idle" | "running" | "done" | "error";
type Filter = "all" | Status;

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

export default function TestPage({
  target,
  setTarget,
  onBack,
  onAlert,
}: {
  target: string;
  setTarget: (v: string) => void;
  onBack: () => void;
  onAlert: (alert: boolean) => void;
}) {
  const [consent, setConsent] = useState(false);
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [scannedTarget, setScannedTarget] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [openIndex, setOpenIndex] = useState<number | null>(0);
  const [pastScans, setPastScans] = useState<PastScan[]>([]);
  const [viewingPastId, setViewingPastId] = useState<string | null>(null);

  async function runScan() {
    if (!consent || !target) return;
    setScanState("running");
    setErrorMessage(null);
    setErrorCode(null);
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
      setScannedTarget(target);
      setFilter("all");
      setOpenIndex(0);
      setScanState("done");

      // Session-only history: cleared on reload, never sent anywhere.
      setPastScans((prev) =>
        [
          {
            id: result.scanId || `${Date.now()}`,
            target,
            timestamp: Date.now(),
            findings: sorted,
            coverage: result.coverage ?? null,
          },
          ...prev,
        ].slice(0, 10),
      );
    } catch (err) {
      setScanState("error");
      setErrorMessage(err instanceof Error ? err.message : "Scan failed.");
      setErrorCode(err instanceof ApiError ? err.code : null);
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    void runScan();
  }

  function viewPastScan(scan: PastScan) {
    setFindings(scan.findings);
    setCoverage(scan.coverage);
    setScannedTarget(scan.target);
    setFilter("all");
    setOpenIndex(0);
    setViewingPastId(scan.id);
    setScanState("done");
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `trivy-scan-${safeDomain(scannedTarget || target)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const counts = useMemo(() => {
    const c: Record<Status, number> = { vuln: 0, review: 0, info: 0, clear: 0 };
    for (const f of findings) c[statusOf(f)] += 1;
    return c;
  }, [findings]);

  // "Clear" only when active probes actually ran, and only for checks that found nothing.
  const clearChecks = useMemo(() => {
    if (scanState !== "done" || !coverage || coverage.activeProbes <= 0) return [];
    const seen = new Set(findings.map((f) => f.category));
    return ACTIVE_CHECKS.filter((c) => !seen.has(c.category));
  }, [findings, coverage, scanState]);

  const allCounts: Record<Status, number> = { ...counts, clear: clearChecks.length };
  const visible = findings.filter((f) => filter === "all" || filter === statusOf(f));
  const showClear = filter === "all" || filter === "clear";
  const alert = scanState === "done" && counts.vuln > 0;
  const host = safeHost(scannedTarget || target);

  useEffect(() => {
    onAlert(alert);
  }, [alert, onAlert]);

  return (
    <div className="test">
      <header className="hero hero--test">
        <div className="hero__main">
          <h1>
            {scanState === "running" ? (
              <>
                Scanning <em>{host || "page"}</em>
              </>
            ) : scanState === "done" ? (
              counts.vuln > 0 ? (
                <>
                  <span className="pill-red">{counts.vuln} vulnerable</span>
                  <br />
                  {counts.review} to review
                </>
              ) : counts.review > 0 ? (
                <>
                  {counts.review} to <em>review</em>
                </>
              ) : (
                <>
                  Nothing <em>found</em>
                </>
              )
            ) : scanState === "error" ? (
              <>
                Scan <em>stopped</em>
              </>
            ) : (
              <>
                Test a <em>page</em>
              </>
            )}
          </h1>

          <form className="scanbar" onSubmit={submit}>
            <label htmlFor="test-target" className="sr-only">
              Target URL
            </label>
            <input
              id="test-target"
              type="url"
              placeholder="https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            <button type="submit" className="btn" disabled={scanState === "running" || !consent || !target}>
              {scanState === "running" ? "Scanning…" : "Scan target"} <ArrowIcon />
            </button>
          </form>

          <label className="switch-row">
            <input type="checkbox" role="switch" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
            <span className="switch" aria-hidden="true" />
            I'm authorized to run active security tests against this domain
          </label>

          {errorMessage && <ScanError message={errorMessage} code={errorCode} host={safeHost(target)} />}

          <p className="quiet">
            Passive checks (headers, cookies, DOM) need the browser extension, since only it can read the page you are
            viewing. This page runs the active engine on demand.
          </p>
        </div>

        <aside className="recent glass" aria-label="Recent scans">
          <h2 className="label">Recent scans</h2>
          {pastScans.length === 0 ? (
            <p className="quiet">Scans from this session show up here.</p>
          ) : (
            <ul className="recent__list">
              {pastScans.map((s) => (
                <li key={s.id}>
                  <button
                    type="button"
                    className={`recent__item ${viewingPastId === s.id ? "recent__item--on" : ""}`}
                    onClick={() => viewPastScan(s)}
                  >
                    <b>{safeDomain(s.target)}</b>
                    <span>
                      {s.findings.length} findings · {formatTime(s.timestamp)}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <button type="button" className="ghost" onClick={onBack}>
            Back to overview
          </button>
        </aside>
      </header>

      {scanState === "done" && (
        <section className="results" aria-label="Scan results">
          <div className="results__head">
            <p className="eyebrow">04 · Review</p>
            <div className="note-arrow">
              <CurveArrow kind="note" />
              <span className="cap">Open a card for evidence and what to do</span>
            </div>
          </div>

          <div className="stats">
            {(["vuln", "review", "info", "clear"] as Status[]).map((s) => (
              <div key={s} className={`stat stat--${s}`}>
                <b>{allCounts[s]}</b>
                <span>{STATUS_LABEL[s]}</span>
              </div>
            ))}
          </div>

          <div className="viz glass">
            <div className="viz__cell">
              <h3>Severity</h3>
              <SeverityBarChart findings={findings} />
            </div>
            <div className="viz__cell">
              <h3>By category</h3>
              <CategoryBarChart findings={findings} />
            </div>
            {coverage && (
              <div className="viz__cell">
                <h3>Coverage</h3>
                <CoverageRing coverage={coverage} />
              </div>
            )}
          </div>

          <div className="toolbar">
            <div className="filters" role="group" aria-label="Filter results">
              {(["all", "vuln", "review", "info", "clear"] as Filter[]).map((f) => (
                <button
                  key={f}
                  type="button"
                  aria-pressed={filter === f}
                  className={`filter ${filter === f ? "filter--on" : ""}`}
                  onClick={() => {
                    setFilter(f);
                    setOpenIndex(null);
                  }}
                >
                  {f === "all" ? "All" : STATUS_LABEL[f]}
                </button>
              ))}
            </div>
            <button type="button" className="ghost" onClick={exportJson}>
              Export JSON
            </button>
          </div>

          <ul className="findings">
            {visible.map((f, i) => (
              <FindingCard
                key={`${f.category}-${i}`}
                finding={f}
                open={openIndex === i}
                onToggle={() => setOpenIndex(openIndex === i ? null : i)}
              />
            ))}
            {showClear &&
              clearChecks.map((c) => (
                <li key={c.category} className="finding finding--clear">
                  <div className="finding__row finding__row--static">
                    <span className="tag tag--clear">{STATUS_TAG.clear}</span>
                    <span className="finding__text">
                      <b>{c.name}</b>
                      <span>Nothing found</span>
                    </span>
                  </div>
                </li>
              ))}
            {visible.length === 0 && !(showClear && clearChecks.length > 0) && (
              <li className="quiet">Nothing in this view.</li>
            )}
          </ul>
          {showClear && clearChecks.length > 0 && (
            <p className="footnote">Clear means a check found nothing. It does not prove the page is secure.</p>
          )}
          <p className="footnote">Findings are pointers for further review, not proof of exploitability.</p>
        </section>
      )}
    </div>
  );
}

function FindingCard({ finding, open, onToggle }: { finding: Finding; open: boolean; onToggle: () => void }) {
  const status = statusOf(finding);
  const { title, evidence } = describeFinding(finding);
  const { remediation, references } = getRemediation(finding.category, finding);
  const confidence = confidenceLabel(finding);
  const samples = (finding.sampleUrls ?? []).slice(0, 5);
  const lead = remediation.startsWith("Verify first:") ? "Verify first:" : "";
  const rest = lead ? remediation.slice(lead.length).trim() : remediation;
  const sub =
    finding.affectedPages && finding.affectedPages > 1
      ? `Seen on ${finding.affectedPages} pages`
      : (evidence.split("\n")[0] ?? "");

  return (
    <li className={`finding finding--${status} ${open ? "finding--open" : ""}`}>
      <button type="button" className="finding__row" aria-expanded={open} onClick={onToggle}>
        <span className={`tag tag--${status}`}>{STATUS_TAG[status]}</span>
        <span className="finding__text">
          <b>{title}</b>
          <span>{sub}</span>
        </span>
        {confidence && <span className="conf conf--row">{confidence}</span>}
        <ChevronIcon />
      </button>
      {open && (
        <div className="finding__body">
          <div>
            <div className="label">Evidence</div>
            <div className="evidence">{evidence || "No evidence text provided."}</div>
            <p className="meta">
              <PageLabel url={finding.pageUrl} /> · {finding.category}
            </p>
            {finding.affectedPages !== undefined && finding.affectedPages > 1 && (
              <>
                <div className="label">Seen on {finding.affectedPages} pages</div>
                <ul className="samples">
                  {samples.map((u) => (
                    <li key={u}>
                      <PageLabel url={u} />
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
          <div>
            <div className="label">What to do</div>
            <div className="todo">
              {lead && <b>{lead} </b>}
              {rest}
            </div>
            <p className="meta">refs: {references}</p>
          </div>
        </div>
      )}
    </li>
  );
}

function PageLabel({ url }: { url: string }) {
  const origin = redactedPathOrigin(url);
  if (origin) {
    return (
      <>
        {origin} <span className="redacted-chip">path hidden by server</span>
      </>
    );
  }
  return <>{url}</>;
}

/** Returns the origin when the backend replaced the URL path with /redacted, else null. */
function redactedPathOrigin(url: string): string | null {
  try {
    const u = new URL(url);
    return u.pathname === "/redacted" ? u.origin : null;
  } catch {
    return null;
  }
}

function ScanError({ message, code, host }: { message: string; code: string | null; host: string }) {
  if (code === "target_not_allowlisted") {
    return (
      <div className="callout" role="alert">
        <strong>Active scanning isn't enabled for {host || "this host"}</strong>
        <p>
          Active scans are intrusive, so the backend only runs them against hosts it has been told to allow. Nothing
          was sent to this target.
        </p>
        <p>
          Ask the backend owner to add <code>{host || "the host"}</code> to <code>TRIVY_INTRUSIVE_ALLOWED_HOSTS</code>.
          The match is exact, including the port. Only scan sites you are authorized to test.
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
  return (
    <p className="error-text" role="alert">
      {message}
    </p>
  );
}

function safeDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "scan";
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
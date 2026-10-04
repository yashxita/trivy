import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { loadSettings } from "../../lib/settings";
import { isExtensionMessage, type ExtensionMessage } from "../../lib/messages";
import {
  confidenceLabel,
  describeFinding,
  getRemediation,
} from "../../lib/remediation";
import {
  PASSIVE_CHECKS,
  STATUS_LABEL,
  STATUS_TAG,
  statusOf,
  type Status,
} from "../../lib/status";
import {
  DEFAULT_SETTINGS,
  type Coverage,
  type Finding,
  type ScanMode,
  type ScanSettings,
} from "../../shared/types";

type ScanState = "idle" | "running" | "done" | "error";
type Filter = "all" | Status;
type Theme = "dark" | "light";

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Info: 4,
};

const MODES: ScanMode[] = ["passive", "active", "combined"];

export default function App() {
  const [theme, toggleTheme] = useTheme();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [settings, setSettings] = useState<ScanSettings>(DEFAULT_SETTINGS);
  const [scanMode, setScanMode] = useState<ScanMode>("passive");
  const [consent, setConsent] = useState(false);
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [pageUrl, setPageUrl] = useState<string>("");
  const [openStep, setOpenStep] = useState<number>(1);
  const [filter, setFilter] = useState<Filter>("all");
  const [openFinding, setOpenFinding] = useState<number | null>(null);

  useEffect(() => {
    loadSettings().then((s) => {
      setSettings(s);
      setScanMode(s.scanMode);
    });

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
    setFilter("all");
    setOpenFinding(null);
    setOpenStep(3);

    const message: ExtensionMessage = { type: "RUN_SCAN", scanMode, consent };
    chrome.runtime.sendMessage(message, (response: ExtensionMessage) => {
      if (!response) {
        setScanState("error");
        setErrorMessage("No response from background worker.");
        setOpenStep(3);
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
        setOpenStep(4);
      } else if (response.type === "SCAN_ERROR") {
        setScanState("error");
        setErrorMessage(response.message);
        setErrorCode(response.code ?? null);
        setOpenStep(3);
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
  const host = safeHost(pageUrl);

  const counts = useMemo(() => {
    const c: Record<Status, number> = { vuln: 0, review: 0, info: 0, clear: 0 };
    for (const f of findings) c[statusOf(f)] += 1;
    return c;
  }, [findings]);

  const clearChecks = useMemo(() => {
    if (scanState !== "done") return [];
    const seen = new Set(findings.map((f) => f.category));
    return PASSIVE_CHECKS.filter(
      (c) => settings.enabledCategories[c.category] !== false && !seen.has(c.category),
    );
  }, [findings, scanState, settings.enabledCategories]);

  const allCounts: Record<Status, number> = { ...counts, clear: clearChecks.length };

  const visibleFindings = findings.filter(
    (f) => filter === "all" || filter === statusOf(f),
  );
  const showClear = filter === "all" || filter === "clear";

  const alert = scanState === "done" && counts.vuln > 0;

  // After a scan, bring the results into view.
  useEffect(() => {
    if (scanState === "done") {
      const target = document.getElementById("step-4");
      const box = scrollRef.current;
      if (target && box) box.scrollTop = target.offsetTop - 4;
    }
  }, [scanState]);

  return (
    <main className={`popup ${alert ? "popup--alert" : ""}`}>
      <div className="bg" aria-hidden="true">
        <div className="bg__streaks" />
        <div className="bg__arc" />
        <div className="bg__orb bg__orb--glow" />
        <div className="bg__orb bg__orb--glass" />
        <div className="bg__haze" />
      </div>

      <header className="top">
        <div className="brand">
          <Logo />
          Trivy
        </div>
        <div className="top__right">
          <span className="host-chip" title={pageUrl}>
            <span className="host-chip__dot" />
            {host || "no page"}
          </span>
          <button
            type="button"
            className="icon-button"
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            onClick={toggleTheme}
          >
            {theme === "dark" ? <SunIcon /> : <MoonIcon />}
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label="Open settings"
            onClick={() => chrome.runtime.openOptionsPage()}
          >
            <GearIcon />
          </button>
        </div>
      </header>

      <div className="scroll" ref={scrollRef}>
      <section className="hero" aria-live="polite">
        <Hero scanState={scanState} counts={counts} host={host} />
      </section>

      <div className="steps">
        <Step
          n={1}
          title="Target"
          summary={`${host || "no page"} · ${scanMode}`}
          open={openStep === 1}
          onToggle={() => setOpenStep(openStep === 1 ? 0 : 1)}
        >
          <div className="field" title={pageUrl}>
            <GlobeIcon />
            <span className="field__text">{pageUrl || "Open a web page, then reopen Trivy"}</span>
          </div>
          <div className="segmented" role="radiogroup" aria-label="Scan mode">
            {MODES.map((mode) => (
              <button
                key={mode}
                type="button"
                role="radio"
                aria-checked={scanMode === mode}
                className={`segmented__option ${scanMode === mode ? "segmented__option--on" : ""}`}
                onClick={() => setScanMode(mode)}
              >
                {mode.charAt(0).toUpperCase() + mode.slice(1)}
              </button>
            ))}
          </div>
        </Step>

        <Step
          n={2}
          title="Limits"
          summary={limitsSummary(settings, scanMode, consent)}
          open={openStep === 2}
          onToggle={() => setOpenStep(openStep === 2 ? 0 : 2)}
        >
          {needsConsent ? (
            <label className="switch-row">
              <input
                type="checkbox"
                role="switch"
                checked={consent}
                onChange={(e) => handleConsentChange(e.target.checked)}
              />
              <span className="switch" aria-hidden="true" />
              I'm authorized to test this domain
            </label>
          ) : (
            <p className="quiet">Passive scans send no probes.</p>
          )}
          <button
            type="button"
            className="ghost-button"
            onClick={() => chrome.runtime.openOptionsPage()}
          >
            Edit limits in settings
          </button>
        </Step>

        <Step
          n={3}
          title="Run"
          summary={runSummary(scanState, progress)}
          open={openStep === 3}
          onToggle={() => setOpenStep(openStep === 3 ? 0 : 3)}
        >
          {scanState === "running" && (
            <div
              className="progress"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={progress}
            >
              <div className="progress__fill" style={{ width: `${progress}%` }} />
            </div>
          )}
          {scanState === "idle" && <p className="quiet">Ready when you are.</p>}
          {scanState === "done" && coverage && (
            <p className="quiet mono">
              {coverage.pagesScanned}/{coverage.pagesDiscovered} pages · {coverage.requestsMade} requests
              {coverage.truncated ? " · truncated" : ""}
            </p>
          )}
          {scanState === "done" && !coverage && <p className="quiet">Scan finished.</p>}
          {errorMessage && <ScanError message={errorMessage} code={errorCode} host={host} />}
        </Step>

        <Step
          n={4}
          title="Review"
          summary={reviewSummary(scanState, counts)}
          open={openStep === 4}
          onToggle={() => setOpenStep(openStep === 4 ? 0 : 4)}
        >
          {scanState !== "done" ? (
            <p className="quiet">Results appear here after a scan.</p>
          ) : (
            <>
              <div className="stats">
                {(["vuln", "review", "info", "clear"] as Status[]).map((s) => (
                  <div key={s} className={`stat stat--${s}`}>
                    <b>{allCounts[s]}</b>
                    <span>{STATUS_LABEL[s]}</span>
                  </div>
                ))}
              </div>

              <div className="filters" role="group" aria-label="Filter results">
                {(["all", "vuln", "review", "info", "clear"] as Filter[]).map((f) => (
                  <button
                    key={f}
                    type="button"
                    aria-pressed={filter === f}
                    className={`filter ${filter === f ? "filter--on" : ""}`}
                    onClick={() => {
                      setFilter(f);
                      setOpenFinding(null);
                    }}
                  >
                    {f === "all" ? "All" : STATUS_LABEL[f]}
                  </button>
                ))}
              </div>

              <ul className="findings">
                {visibleFindings.map((f, i) => (
                  <FindingCard
                    key={`${f.category}-${i}`}
                    finding={f}
                    open={openFinding === i}
                    onToggle={() => setOpenFinding(openFinding === i ? null : i)}
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
                {visibleFindings.length === 0 && !(showClear && clearChecks.length > 0) && (
                  <li className="quiet">Nothing in this view.</li>
                )}
              </ul>
              {showClear && clearChecks.length > 0 && (
                <p className="footnote">
                  Clear means a check found nothing. It does not prove the page is secure.
                </p>
              )}

              <div className="actions">
                <button type="button" className="ghost-button" onClick={exportJson}>
                  Export JSON
                </button>
                <button
                  type="button"
                  className="ghost-button"
                  onClick={() => chrome.tabs.create({ url: "https://app.trivy.io/dashboard" })}
                >
                  Open dashboard
                </button>
              </div>
            </>
          )}
        </Step>
      </div>
      </div>

      <div className="cta-bar">
        <button
          type="button"
          className="cta"
          disabled={
            scanState === "running" || (needsConsent && !consent) || !pageUrl
          }
          onClick={runScan}
        >
          <span>{ctaLabel(scanState, scanMode, progress)}</span>
          <span className="cta__go">
            <ArrowIcon />
          </span>
        </button>
      </div>
    </main>
  );
}

/* ---------- pieces ---------- */

function Hero({
  scanState,
  counts,
  host,
}: {
  scanState: ScanState;
  counts: Record<Status, number>;
  host: string;
}) {
  if (scanState === "running") {
    return (
      <h1>
        Scanning <em>{host || "page"}</em>
      </h1>
    );
  }
  if (scanState === "error") {
    return (
      <h1>
        Scan <em>stopped</em>
      </h1>
    );
  }
  if (scanState === "done") {
    if (counts.vuln > 0) {
      return (
        <h1>
          <span className="pill-red">{counts.vuln} vulnerable</span>
          <br />
          {counts.review} to review
        </h1>
      );
    }
    if (counts.review > 0) {
      return (
        <h1>
          {counts.review} to <em>review</em>
        </h1>
      );
    }
    return (
      <h1>
        Nothing <em>found</em>
      </h1>
    );
  }
  return (
    <h1>
      Scan this page
      <br />
      in <em>4 steps</em>
    </h1>
  );
}

function Step({
  n,
  title,
  summary,
  open,
  onToggle,
  children,
}: {
  n: number;
  title: string;
  summary: string;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  const id = `step-${n}`;
  return (
    <section id={id} className={`step ${open ? "step--open" : ""}`}>
      <h2 className="step__head">
        <button
          type="button"
          className="step__toggle"
          aria-expanded={open}
          aria-controls={`${id}-body`}
          onClick={onToggle}
        >
          <span className="step__num">[{n}]</span>
          <span className="step__text">
            <b>{title}</b>
            <span>{summary}</span>
          </span>
          <ChevronIcon />
        </button>
      </h2>
      {open && (
        <div className="step__body" id={`${id}-body`}>
          {children}
        </div>
      )}
    </section>
  );
}

function FindingCard({
  finding,
  open,
  onToggle,
}: {
  finding: Finding;
  open: boolean;
  onToggle: () => void;
}) {
  const status = statusOf(finding);
  const { title, evidence } = describeFinding(finding);
  const todo = getRemediation(finding.category, finding).remediation;
  const lead = todo.startsWith("Verify first:") ? "Verify first:" : "";
  const rest = lead ? todo.slice(lead.length).trim() : todo;
  const confidence = confidenceLabel(finding);
  const sub =
    finding.affectedPages && finding.affectedPages > 1
      ? `Seen on ${finding.affectedPages} pages`
      : (evidence.split("\n")[0] ?? "");

  return (
    <li className={`finding finding--${status} ${open ? "finding--open" : ""}`}>
      <button
        type="button"
        className="finding__row"
        aria-expanded={open}
        onClick={onToggle}
      >
        <span className={`tag tag--${status}`}>{STATUS_TAG[status]}</span>
        <span className="finding__text">
          <b>{title}</b>
          <span>{sub}</span>
        </span>
        <ChevronIcon />
      </button>
      {open && (
        <div className="finding__body">
          {confidence && <span className="conf">Confidence: {confidence}</span>}
          {evidence && (
            <>
              <div className="label">Evidence</div>
              <div className="evidence">{evidence}</div>
            </>
          )}
          <div className="label">What to do</div>
          <div className="todo">
            {lead && <b>{lead} </b>}
            {rest}
          </div>
        </div>
      )}
    </li>
  );
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
  return (
    <p className="error-text" role="alert">
      {message}
    </p>
  );
}

/* ---------- helpers ---------- */

function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() =>
    window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark",
  );

  useEffect(() => {
    chrome.storage.local.get(["theme"], (result) => {
      if (result.theme === "dark" || result.theme === "light") {
        setTheme(result.theme);
      }
    });
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  function toggle() {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setTheme(next);
    chrome.storage.local.set({ theme: next });
  }

  return [theme, toggle];
}

function limitsSummary(s: ScanSettings, mode: ScanMode, consent: boolean): string {
  if (mode === "passive") return "Passive: no probes sent";
  if (!consent) return "Confirm you may test this host";
  const skip = s.excludedPaths[0] ? ` · skips ${s.excludedPaths[0]}` : "";
  return `${s.requestsPerSecond} req/s · ${s.maxConcurrency} at once${skip}`;
}

function runSummary(state: ScanState, progress: number): string {
  if (state === "running") return `Scanning… ${progress}%`;
  if (state === "done") return "Finished";
  if (state === "error") return "Stopped";
  return "Ready";
}

function reviewSummary(state: ScanState, counts: Record<Status, number>): string {
  if (state !== "done") return "No results yet";
  return `${counts.vuln} vulnerable · ${counts.review} to review`;
}

function ctaLabel(state: ScanState, mode: ScanMode, progress: number): string {
  if (state === "running") return `Scanning… ${progress}%`;
  if (state === "done" || state === "error") return "Scan again";
  return `Run ${mode} scan`;
}

function safeDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** host includes the port, which is what the backend allowlist matches on. */
function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

/* ---------- icons ---------- */

function Logo() {
  return (
    <svg width="28" height="28" viewBox="0 0 8 8" shapeRendering="crispEdges" aria-hidden="true">
      <rect width="8" height="8" rx="2" fill="var(--acc)" />
      <path fill="var(--onacc)" d="M2 1h4v1h1v3H6v1H5v1H3V6H2V5H1V2h1z" />
      <path fill="var(--acc)" d="M3 3h2v1H3z" />
    </svg>
  );
}

const iconProps = {
  width: 18,
  height: 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2.2,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

function ChevronIcon() {
  return (
    <svg className="chev" {...iconProps}>
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}
function ArrowIcon() {
  return (
    <svg {...iconProps} strokeWidth={2.6}>
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  );
}
function GlobeIcon() {
  return (
    <svg {...iconProps} width={14} height={14}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18" />
    </svg>
  );
}
function SunIcon() {
  return (
    <svg {...iconProps}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  );
}
function MoonIcon() {
  return (
    <svg {...iconProps}>
      <path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" />
    </svg>
  );
}
function GearIcon() {
  return (
    <svg {...iconProps} strokeWidth={2}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3.9a7 7 0 0 0-2-1.2L14.2 3h-4l-.4 2.6a7 7 0 0 0-2 1.2l-2.3-.9-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.3-.9a7 7 0 0 0 2 1.2l.4 2.6h4l.4-2.6a7 7 0 0 0 2-1.2l2.3.9 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z" />
    </svg>
  );
}
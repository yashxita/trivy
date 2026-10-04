import type { FormEvent, ReactNode } from "react";
import { ArrowIcon, CurveArrow } from "../components/Bits";

interface Props {
  target: string;
  setTarget: (v: string) => void;
  onStart: () => void;
}

interface CheckCard {
  n: string;
  title: ReactNode;
  text: string;
  runs: string;
  art: ReactNode;
}

const svgProps = {
  width: 120,
  height: 84,
  viewBox: "0 0 120 84",
  fill: "none",
  strokeWidth: 4,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

const CHECKS: CheckCard[] = [
  {
    n: "01",
    title: (
      <>
        Is it wearing a <em>seatbelt</em>?
      </>
    ),
    text: "Headers like CSP and frame options tell the browser how to protect your page.",
    runs: "Extension",
    art: (
      <svg {...svgProps}>
        <rect x="10" y="12" width="100" height="62" rx="10" className="s-mu" />
        <path d="M10 28h100" className="s-mu" />
        <path d="M60 28l22 8v16c0 12-9 18-22 22-13-4-22-10-22-22V36z" className="s-ac" />
        <path d="M50 50l8 8 14-16" className="s-grn" />
      </svg>
    ),
  },
  {
    n: "02",
    title: (
      <>
        Where does it <em>post</em>?
      </>
    ),
    text: "Flags password forms that send over HTTP, and state-changing forms worth a CSRF review.",
    runs: "Extension",
    art: (
      <svg {...svgProps}>
        <rect x="14" y="10" width="92" height="20" rx="10" className="s-mu" />
        <rect x="14" y="40" width="92" height="20" rx="10" className="s-mu" />
        <path d="M28 50h30" strokeDasharray="1 9" className="s-ac" />
        <path d="M92 74l16-14M98 60h10v10" className="s-red" />
      </svg>
    ),
  },
  {
    n: "03",
    title: (
      <>
        Who can <em>touch</em> it?
      </>
    ),
    text: "Cookies missing Secure, HttpOnly or SameSite are easier to steal or misuse.",
    runs: "Extension",
    art: (
      <svg {...svgProps}>
        <path d="M60 8a34 34 0 1 0 34 34 14 14 0 0 1-16-16 14 14 0 0 1-18-18z" className="s-ac" />
        <circle cx="46" cy="40" r="3" className="s-ac f-ac" />
        <circle cx="62" cy="56" r="3" className="s-ac f-ac" />
        <circle cx="72" cy="40" r="3" className="s-ac f-ac" />
      </svg>
    ),
  },
  {
    n: "04",
    title: (
      <>
        A <em>half-locked</em> page
      </>
    ),
    text: "An HTTPS page that still loads scripts or images over plain HTTP.",
    runs: "Extension",
    art: (
      <svg {...svgProps}>
        <rect x="34" y="38" width="52" height="38" rx="8" className="s-ac" />
        <path d="M44 38V26a16 16 0 0 1 32 0" className="s-ac" />
        <path d="M60 50v12" className="s-ac" />
        <path d="M94 14l-10 14 10 10-10 14" className="s-red" />
      </svg>
    ),
  },
  {
    n: "05",
    title: (
      <>
        Keys left <em>outside</em>
      </>
    ),
    text: "Secret-shaped strings in scripts. Matches are unverified, so you confirm them.",
    runs: "Extension",
    art: (
      <svg {...svgProps}>
        <circle cx="38" cy="42" r="14" className="s-ac" />
        <path d="M52 42h46M82 42v12M94 42v8" className="s-ac" />
        <path d="M14 14l-6 8 6 8M106 14l6 8-6 8" className="s-mu" />
      </svg>
    ),
  },
  {
    n: "06",
    title: (
      <>
        Old parts <em>inside</em>
      </>
    ),
    text: "Library versions found by pattern that may be out of date.",
    runs: "Extension",
    art: (
      <svg {...svgProps}>
        <rect x="16" y="46" width="44" height="28" rx="6" className="s-ac" />
        <rect x="40" y="14" width="44" height="28" rx="6" className="s-mu" />
        <circle cx="90" cy="56" r="16" className="s-amb" />
        <path d="M90 48v9l6 4" className="s-amb" />
      </svg>
    ),
  },
  {
    n: "07",
    title: (
      <>
        Stuff in the <em>drawer</em>
      </>
    ),
    text: "Token-like keys sitting in localStorage and sessionStorage.",
    runs: "Extension",
    art: (
      <svg {...svgProps}>
        <ellipse cx="60" cy="20" rx="30" ry="10" className="s-ac" />
        <path d="M30 20v40c0 6 13 10 30 10s30-4 30-10V20" className="s-ac" />
        <path d="M30 40c0 6 13 10 30 10s30-4 30-10" className="s-mu" />
      </svg>
    ),
  },
  {
    n: "08",
    title: (
      <>
        Poke it, <em>politely</em>
      </>
    ),
    text: "Allowlisted hosts only: reflected input, database error hints and CORS behaviour, with your consent.",
    runs: "Website and extension",
    art: (
      <svg {...svgProps}>
        <circle cx="60" cy="42" r="30" className="s-ac" />
        <circle cx="60" cy="42" r="16" className="s-red" />
        <path d="M60 6v16M60 62v16M24 42h16M80 42h16" className="s-ac" />
      </svg>
    ),
  },
];

function Diagram({ nodes }: { nodes: { t: string; s?: string; hot?: boolean }[] }) {
  const xs = [6, 162, 318];
  return (
    <svg viewBox="0 0 420 110" width="100%" fill="none" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {nodes.map((n, i) => (
        <g key={n.t}>
          <rect x={xs[i]} y="30" width="96" height="50" rx="14" strokeWidth="2.5" className={n.hot ? "s-ac" : "s-mu"} />
          <text x={(xs[i] ?? 0) + 48} y={n.s ? 52 : 60} textAnchor="middle" className="svg-text">
            {n.t}
          </text>
          {n.s && (
            <text x={(xs[i] ?? 0) + 48} y="68" textAnchor="middle" className="svg-text svg-text--hot">
              {n.s}
            </text>
          )}
          {i < 2 && (
            <>
              <path d={`M${(xs[i] ?? 0) + 100} 55h52`} strokeWidth="3.5" className="s-red" />
              <path d={`M${(xs[i] ?? 0) + 142} 46l12 9-12 9`} strokeWidth="3.5" className="s-red" />
            </>
          )}
        </g>
      ))}
    </svg>
  );
}

const EXPLAINERS = [
  {
    key: "A",
    title: "Cross-site scripting",
    sub: "Your page repeats what strangers type",
    nodes: [{ t: "crafted link" }, { t: "your page", s: "prints it raw", hot: true }, { t: "visitor", s: "runs script" }],
    text: "If a page puts unescaped input into the DOM, a link can run script as the visitor. Trivy flags where input reaches risky spots.",
    check: "add a harmless marker to the URL and see whether it appears unescaped in the page source.",
  },
  {
    key: "B",
    title: "SQL injection",
    sub: "A question that answers back too much",
    nodes: [{ t: "odd input '" }, { t: "your query", hot: true }, { t: "database" }],
    text: "When user input is glued into a database query, odd characters can change the query. A database error in the response is a hint, not proof.",
    check: "on a test copy, confirm the code uses parameterised queries.",
  },
  {
    key: "C",
    title: "CSRF",
    sub: "A form that obeys anyone",
    nodes: [{ t: "other site" }, { t: "your browser", s: "sends cookie" }, { t: "your app", hot: true }],
    text: "A missing token field is only a signal. SameSite cookies or a custom header may already protect the form.",
    check: "look for SameSite on the session cookie and a token or header on the request.",
  },
];

export default function Landing({ target, setTarget, onStart }: Props) {
  function submit(e: FormEvent) {
    e.preventDefault();
    onStart();
  }

  return (
    <div className="landing">
      <header className="hero hero--landing">
        <div>
          <h1>
            Find the <em className="em-red">holes</em> before someone else does.
          </h1>
          <p className="lead">
            Trivy looks at your page the way an attacker would, then tells you how to check each finding yourself.
          </p>
          <div className="hero__actions">
            <button type="button" className="btn" onClick={onStart}>
              Start testing <ArrowIcon />
            </button>
            <span className="note-arrow">
              <CurveArrow kind="note" />
              <span className="cap">Takes a few seconds</span>
            </span>
          </div>
        </div>
      </header>

      <div className="flow" aria-label="How Trivy works">
        <span className="flow__pill"><i>01</i>Look</span>
        <CurveArrow kind="right" />
        <span className="flow__pill"><i>02</i>Understand</span>
        <CurveArrow kind="left" />
        <span className="flow__pill"><i>03</i>Test</span>
      </div>

      <section className="section" id="checks">
        <p className="eyebrow">01 · Look</p>
        <h2>
          Eight things we <em>look at</em>
        </h2>
        <p className="sub">
          Each check is a small question about your page. We tell you how sure we are, and how to confirm it.
        </p>
        <div className="card-grid">
          {CHECKS.map((c) => (
            <article key={c.n} className="check-card">
              <span className="check-card__n">[{c.n}]</span>
              <div className="check-card__art">{c.art}</div>
              <h3>{c.title}</h3>
              <p>{c.text}</p>
              <span className="check-card__tag">RUNS IN · {c.runs.toUpperCase()}</span>
            </article>
          ))}
        </div>
      </section>

      <div className="between">
        <CurveArrow kind="down-left" />
        <span className="cap">Next: what do these mean?</span>
      </div>

      <section className="section" id="learn">
        <p className="eyebrow">02 · Understand</p>
        <h2>
          Serious words, <em>plain</em> pictures
        </h2>
        <p className="sub">Open one. Each shows how the attack works and how you check your own site.</p>
        <div className="explainers">
          {EXPLAINERS.map((x, i) => (
            <details key={x.key} className="explainer" open={i === 0}>
              <summary>
                <span className="num">[{x.key}]</span>
                <span className="explainer__title">
                  {x.title}
                  <small>{x.sub}</small>
                </span>
                <svg className="chev" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M6 9l6 6 6-6" />
                </svg>
              </summary>
              <div className="explainer__body">
                <div className="diagram">
                  <Diagram nodes={x.nodes} />
                </div>
                <div>
                  <p>{x.text}</p>
                  <div className="fix">
                    <b>Check it yourself:</b> {x.check}
                  </div>
                </div>
              </div>
            </details>
          ))}
        </div>
      </section>

      <section className="section">
        <p className="eyebrow">Reading your results</p>
        <h2>
          Red, amber, <em>green</em>
        </h2>
        <p className="sub">Every result carries a word and a symbol as well as a colour, so it reads the same without colour.</p>
        <div className="legend">
          <div className="legend__card legend__card--vuln">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" className="s-red" aria-hidden="true">
              <path d="M32 6l22 8v16c0 14-9 22-22 28-13-6-22-14-22-28V14z" />
              <path d="M23 23l18 18M41 23L23 41" />
            </svg>
            <span className="tag tag--vuln">VULNERABLE</span>
            <h3>Confirmed or likely problem</h3>
            <p>For example a password form that posts over HTTP. Fix these first, after you verify.</p>
          </div>
          <div className="legend__card legend__card--review">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" className="s-amb" aria-hidden="true">
              <path d="M32 6l22 8v16c0 14-9 22-22 28-13-6-22-14-22-28V14z" />
              <path d="M32 20v14M32 41v2" />
            </svg>
            <span className="tag tag--review">REVIEW</span>
            <h3>Worth a second look</h3>
            <p>A signal such as a missing header. It may be covered another way, so check before you act.</p>
          </div>
          <div className="legend__card legend__card--clear">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" className="s-grn" aria-hidden="true">
              <path d="M32 6l22 8v16c0 14-9 22-22 28-13-6-22-14-22-28V14z" />
              <path d="M22 32l8 8 14-16" />
            </svg>
            <span className="tag tag--clear">CLEAR</span>
            <h3>Nothing found</h3>
            <p>A check ran and found nothing. That is not proof the page is secure. Re-run after you change it.</p>
          </div>
        </div>
      </section>

      <div className="between">
        <CurveArrow kind="down-right" />
        <span className="cap">Next: try it</span>
      </div>

      <section className="cta" id="test">
        <p className="eyebrow">03 · Test</p>
        <h2>
          Point it at a <em>page</em>
        </h2>
        <form className="scanbar scanbar--center" onSubmit={submit}>
          <label htmlFor="landing-target" className="sr-only">
            Target URL
          </label>
          <input
            id="landing-target"
            type="url"
            placeholder="https://example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
          <button type="submit" className="btn">
            Scan target
          </button>
        </form>
      </section>
    </div>
  );
}
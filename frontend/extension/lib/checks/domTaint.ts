import type { Finding } from "../../shared/types";

/**
 * Non-destructive DOM XSS taint tracker.
 *
 * Rather than injecting synthetic payloads into the live page — which
 * would be an active, potentially disruptive technique, and risky to run
 * automatically on a page the person may not want mutated — this tracks
 * real attacker-controllable values already present on the page (the
 * current URL's query values, the hash fragment, and the most recently
 * typed form input) and watches whether any of them ever reach a
 * dangerous DOM sink (innerHTML, outerHTML, insertAdjacentHTML, or a
 * javascript: URL assignment) without being escaped first. Nothing is
 * written to the page and no payload is ever injected; this only
 * observes writes the page itself was already going to make.
 *
 * "Confidence: heuristic" (matching the backend's own vocabulary for its
 * probe results) because a value reaching a sink unescaped is a strong
 * signal but not by itself proof of an exploitable path — the person
 * still has to look at the evidence.
 */

interface TaintHit {
  pageUrl: string;
  source: string;
  sink: string;
  evidence: string;
}

const hits: TaintHit[] = [];
const seenKeys = new Set<string>();
let lastFormInput: { name: string; value: string } | null = null;
let initialized = false;

function currentSources(): { name: string; value: string }[] {
  const sources: { name: string; value: string }[] = [];
  try {
    const url = new URL(window.location.href);
    url.searchParams.forEach((value, key) => {
      if (value.length > 3) sources.push({ name: `url_query:${key}`, value });
    });
  } catch {
    // malformed URL — nothing to track
  }
  if (window.location.hash.length > 4) {
    sources.push({ name: "url_hash", value: window.location.hash.slice(1) });
  }
  if (lastFormInput && lastFormInput.value.length > 3) {
    sources.push({
      name: `form_input:${lastFormInput.name || "unnamed"}`,
      value: lastFormInput.value,
    });
  }
  return sources;
}

function looksUnescaped(written: string, value: string): boolean {
  if (!written.includes(value)) return false;
  return /[<>"']|javascript:/i.test(value);
}

function truncate(s: string): string {
  return s.length > 160 ? `${s.slice(0, 160)}…` : s;
}

function record(sink: string, written: string): void {
  for (const { name, value } of currentSources()) {
    if (!looksUnescaped(written, value)) continue;
    const key = `${window.location.href}|${name}|${sink}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    hits.push({
      pageUrl: window.location.href,
      source: name,
      sink,
      evidence: `Value from ${name} reached ${sink} without escaping: ${truncate(written)}`,
    });
  }
}

/** Hooks the dangerous sinks and starts watching for SPA navigation. Safe to call once. */
export function initDomTaintTracking(): void {
  if (initialized) return;
  initialized = true;

  document.addEventListener(
    "input",
    (e) => {
      const target = e.target as HTMLInputElement | HTMLTextAreaElement | null;
      if (target && "value" in target) {
        lastFormInput = { name: target.name || target.id || "", value: target.value };
      }
    },
    true,
  );

  const innerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
  if (innerHTMLDesc?.set) {
    const originalSet = innerHTMLDesc.set;
    Object.defineProperty(Element.prototype, "innerHTML", {
      ...innerHTMLDesc,
      set(value: string) {
        record("innerHTML", String(value));
        originalSet.call(this, value);
      },
    });
  }

  const outerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, "outerHTML");
  if (outerHTMLDesc?.set) {
    const originalSet = outerHTMLDesc.set;
    Object.defineProperty(Element.prototype, "outerHTML", {
      ...outerHTMLDesc,
      set(value: string) {
        record("outerHTML", String(value));
        originalSet.call(this, value);
      },
    });
  }

  const originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function (position, text) {
    record("insertAdjacentHTML", String(text));
    return originalInsertAdjacentHTML.call(this, position, text);
  };

  // Script-like URL assignments (href/src set to a javascript: URL) —
  // caught via attribute observation rather than patching every element
  // type's property setter individually.
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type !== "attributes") continue;
      if (m.attributeName !== "href" && m.attributeName !== "src") continue;
      const el = m.target as Element;
      const val = el.getAttribute(m.attributeName) ?? "";
      if (val.trim().toLowerCase().startsWith("javascript:")) {
        record(`${m.attributeName}=javascript:`, val);
      }
    }
  });
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["href", "src"],
    subtree: true,
  });

  // SPA route changes don't reload the page, so re-check sources whenever
  // the URL changes via pushState/replaceState/popstate — currentSources()
  // reads location live, so nothing else needs to happen on this event
  // beyond keeping the sink hooks (already installed) active.
  const wrapHistoryMethod = (method: "pushState" | "replaceState") => {
    const original = history[method].bind(history);
    (history as unknown as Record<string, unknown>)[method] = (...args: unknown[]) => {
      const result = (original as (...a: unknown[]) => unknown)(...args);
      window.dispatchEvent(new Event("trivy:spa-navigation"));
      return result;
    };
  };
  wrapHistoryMethod("pushState");
  wrapHistoryMethod("replaceState");
}

/** Returns whatever taint hits have been observed on this page so far. */
export function getDomTaintFindings(): Finding[] {
  return hits.map(
    (h): Finding => ({
      category: "dom_xss_taint",
      pageUrl: h.pageUrl,
      severity: "High",
      confidence: "heuristic",
      source: h.source,
      evidence: h.evidence,
    }),
  );
}

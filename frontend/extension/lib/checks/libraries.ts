import type { VulnerableLibraryFinding } from "../../shared/types";

interface LibraryRule {
  name: string;
  /** Reads the version off a page global, if the library exposes one. */
  detectFromWindow?: () => string | undefined;
  /** Matches the version out of a <script src> URL as a fallback. */
  srcPattern?: RegExp;
  /** Returns true if the detected version is known-vulnerable. */
  isVulnerable: (version: string) => boolean;
  knownCve?: string;
}

function versionLessThan(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff < 0;
  }
  return false;
}

// Small starter reference table — expand as needed. This is the kind of
// dataset that in a fuller build would come from an external feed (similar
// to what Retire.js maintains) rather than being hand-maintained here.
const LIBRARY_RULES: LibraryRule[] = [
  {
    name: "jQuery",
    detectFromWindow: () => (window as any).jQuery?.fn?.jquery,
    srcPattern: /jquery[.-]([\d.]+)(?:\.min)?\.js/i,
    isVulnerable: (v) => versionLessThan(v, "3.5.0"),
    knownCve: "CVE-2020-11022",
  },
  {
    name: "Lodash",
    detectFromWindow: () => (window as any)._?.VERSION,
    srcPattern: /lodash[.-]([\d.]+)(?:\.min)?\.js/i,
    isVulnerable: (v) => versionLessThan(v, "4.17.21"),
    knownCve: "CVE-2021-23337",
  },
  {
    name: "Angular.js",
    detectFromWindow: () => (window as any).angular?.version?.full,
    srcPattern: /angular[.-]([\d.]+)(?:\.min)?\.js/i,
    isVulnerable: (v) => versionLessThan(v, "1.8.0"),
    knownCve: "CVE-2020-7676",
  },
];

export function checkVulnerableLibraries(): VulnerableLibraryFinding[] {
  const pageUrl = window.location.href;
  const findings: VulnerableLibraryFinding[] = [];
  const scriptSrcs = Array.from(
    document.querySelectorAll<HTMLScriptElement>("script[src]"),
  ).map((s) => s.src);

  for (const rule of LIBRARY_RULES) {
    let version = rule.detectFromWindow?.();

    if (!version && rule.srcPattern) {
      for (const src of scriptSrcs) {
        const match = src.match(rule.srcPattern);
        if (match?.[1]) {
          version = match[1];
          break;
        }
      }
    }

    if (!version) continue;
    if (!rule.isVulnerable(version)) continue;

    findings.push({
      category: "vulnerable_library",
      pageUrl,
      libraryName: rule.name,
      detectedVersion: version,
      knownCve: rule.knownCve,
      severity: "High",
    });
  }

  return findings;
}

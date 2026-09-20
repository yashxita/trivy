import type { Finding, FindingCategory } from "../shared/types";

const CATEGORY_LABELS: Record<FindingCategory, string> = {
  header: "Security headers",
  insecure_form: "Insecure forms",
  unencrypted_credentials: "Unencrypted credentials",
  mixed_content: "Mixed content",
  sensitive_url: "Sensitive URL data",
  insecure_cookie: "Insecure cookies",
  exposed_secret: "Exposed secrets",
  vulnerable_library: "Vulnerable libraries",
  sensitive_storage: "Sensitive storage",
  reflected_input: "Reflected input",
  sql_injection: "SQL injection",
  cors_misconfig: "CORS misconfig",
  dom_xss_taint: "DOM XSS taint",
  discovered_endpoint: "Discovered endpoints",
};

export default function CategoryBarChart({ findings }: { findings: Finding[] }) {
  const byCategory = new Map<FindingCategory, number>();
  for (const f of findings) {
    byCategory.set(f.category, (byCategory.get(f.category) ?? 0) + 1);
  }
  const rows = Array.from(byCategory.entries()).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...rows.map(([, count]) => count));

  if (rows.length === 0) {
    return <p className="empty-state">No categories to break down yet.</p>;
  }

  return (
    <div className="bar-chart">
      {rows.map(([category, count]) => (
        <div key={category} className="bar-chart__row">
          <span className="bar-chart__label bar-chart__label--wide">
            {CATEGORY_LABELS[category] ?? category}
          </span>
          <div className="bar-chart__track">
            <div
              className="bar-chart__fill bar-chart__fill--accent"
              style={{ width: `${(count / max) * 100}%` }}
            />
          </div>
          <span className="bar-chart__count">{count}</span>
        </div>
      ))}
    </div>
  );
}

import type { Finding } from "../shared/types";

const SEVERITY_ORDER: Finding["severity"][] = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_VAR: Record<Finding["severity"], string> = {
  Critical: "var(--critical)",
  High: "var(--high)",
  Medium: "var(--medium)",
  Low: "var(--low)",
  Info: "var(--info)",
};

export default function SeverityBarChart({ findings }: { findings: Finding[] }) {
  const counts = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    count: findings.filter((f) => f.severity === sev).length,
  }));
  const max = Math.max(1, ...counts.map((c) => c.count));

  return (
    <div className="bar-chart">
      {counts.map(({ severity, count }) => (
        <div key={severity} className="bar-chart__row">
          <span className="bar-chart__label">{severity}</span>
          <div className="bar-chart__track">
            <div
              className="bar-chart__fill"
              style={{
                width: `${(count / max) * 100}%`,
                background: SEVERITY_VAR[severity],
              }}
            />
          </div>
          <span className="bar-chart__count">{count}</span>
        </div>
      ))}
    </div>
  );
}

import type { Coverage } from "../shared/types";

export default function CoverageRing({ coverage }: { coverage: Coverage }) {
  const size = 120;
  const stroke = 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const ratio =
    coverage.pagesDiscovered > 0
      ? Math.min(1, coverage.pagesScanned / coverage.pagesDiscovered)
      : coverage.pagesScanned > 0
        ? 1
        : 0;
  const dashOffset = circumference * (1 - ratio);

  return (
    <div className="coverage-ring">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--glass-border)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--accent)"
          strokeWidth={stroke}
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset 0.5s ease" }}
        />
        <text
          x="50%"
          y="50%"
          textAnchor="middle"
          dominantBaseline="middle"
          className="coverage-ring__text"
        >
          {Math.round(ratio * 100)}%
        </text>
      </svg>
      <div className="coverage-ring__stats">
        <div>
          <strong>{coverage.pagesScanned}</strong>/{coverage.pagesDiscovered} pages
        </div>
        <div>{coverage.requestsMade} requests made</div>
        <div>{coverage.formsDiscovered} forms discovered</div>
        <div>{coverage.parametersTested} params tested</div>
        <div>{coverage.activeProbes} active probes run</div>
        {coverage.truncated && <div className="coverage-ring__truncated">Scan truncated</div>}
      </div>
    </div>
  );
}

import type { SVGProps } from "react";

export function Logo({ size = 30 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 8 8" shapeRendering="crispEdges" aria-hidden="true">
      <rect width="8" height="8" rx="2" fill="var(--acc)" />
      <path fill="var(--onacc)" d="M2 1h4v1h1v3H6v1H5v1H3V6H2V5H1V2h1z" />
      <path fill="var(--acc)" d="M3 3h2v1H3z" />
    </svg>
  );
}

/** Decorative glow, orbs and streaks. `alert` turns the glow red. */
export function Background({ alert = false }: { alert?: boolean }) {
  return (
    <div className={`bg ${alert ? "bg--alert" : ""}`} aria-hidden="true">
      <div className="bg__streaks" />
      <div className="bg__arc" />
      <div className="bg__orb bg__orb--glow" />
      <div className="bg__orb bg__orb--glass" />
      <div className="bg__orb bg__orb--small" />
      <div className="bg__haze bg__haze--a" />
      <div className="bg__haze bg__haze--b" />
    </div>
  );
}

const base: SVGProps<SVGSVGElement> = {
  width: 20,
  height: 20,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2.2,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};

export const ChevronIcon = () => (
  <svg className="chev" {...base}>
    <path d="M6 9l6 6 6-6" />
  </svg>
);
export const ArrowIcon = () => (
  <svg {...base} strokeWidth={2.6}>
    <path d="M5 12h14M13 6l6 6-6 6" />
  </svg>
);
export const SunIcon = () => (
  <svg {...base}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
  </svg>
);
export const MoonIcon = () => (
  <svg {...base}>
    <path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z" />
  </svg>
);

/** Hand-drawn style curved arrows used to connect sections. */
export function CurveArrow({ kind }: { kind: "right" | "left" | "down-left" | "down-right" | "note" }) {
  const common = {
    fill: "none",
    strokeWidth: 3.5,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    className: "s-ac",
    "aria-hidden": true,
  };
  if (kind === "right")
    return (
      <svg width="86" height="40" viewBox="0 0 86 40" {...common}>
        <path d="M6 28C26 4 52 4 76 20" />
        <path d="M62 10l15 11-17 6" />
      </svg>
    );
  if (kind === "left")
    return (
      <svg width="86" height="40" viewBox="0 0 86 40" {...common}>
        <path d="M6 12C26 36 52 36 76 20" />
        <path d="M62 30l15-10-17-7" />
      </svg>
    );
  if (kind === "down-left")
    return (
      <svg width="140" height="120" viewBox="0 0 140 120" {...common} strokeWidth={4}>
        <path d="M30 8C110 14 120 60 60 96" />
        <path d="M52 78l10 20 22-8" />
      </svg>
    );
  if (kind === "down-right")
    return (
      <svg width="140" height="120" viewBox="0 0 140 120" {...common} strokeWidth={4}>
        <path d="M110 8C30 14 20 60 80 96" />
        <path d="M88 78l-10 20-22-8" />
      </svg>
    );
  return (
    <svg width="70" height="40" viewBox="0 0 70 40" {...common}>
      <path d="M66 6C42 2 20 10 10 30" />
      <path d="M6 20l4 12 12-6" />
    </svg>
  );
}
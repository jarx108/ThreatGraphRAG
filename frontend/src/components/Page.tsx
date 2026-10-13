import type { CSSProperties, ReactNode } from "react";
import { CheckIcon } from "./Icons";

/** Header of a pillar tab: what the rubric asks for and where it is shown. */
export function PageHero({ eyebrow, title, color, children, checklist }: {
  eyebrow: string;
  title: string;
  color: string;
  children: ReactNode;
  checklist?: string[];
}) {
  return (
    <div className="hero" style={{ "--tab": color } as CSSProperties}>
      <div className="eyebrow">{eyebrow}</div>
      <h1>{title}</h1>
      <p>{children}</p>
      {checklist && (
        <div className="checklist">
          {checklist.map((c) => <span key={c} className="check"><CheckIcon size={13} />{c}</span>)}
        </div>
      )}
    </div>
  );
}

export function Kpi({ label, value, foot, color }: { label: string; value: ReactNode; foot?: ReactNode; color: string }) {
  return (
    <div className="card kpi" style={{ "--m": color } as CSSProperties}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {foot && <div className="kpi-foot">{foot}</div>}
    </div>
  );
}

export function Section({ title, sub, children, right }: { title: string; sub?: ReactNode; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h3 className="card-title">{title}</h3>
          {sub && <div className="card-sub">{sub}</div>}
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

/** Two horizontal bars comparing the systems on one metric. */
export function CompareRow({ label, a, b, fmt, higherIsBetter = true, max = 1 }: {
  label: string; a: number | null; b: number | null; fmt: (v: number | null) => string;
  higherIsBetter?: boolean; max?: number;
}) {
  const better = a === null || b === null || Math.abs(a - b) < 1e-9 ? null : (a > b) === higherIsBetter ? 0 : 1;
  const w = (v: number | null) => `${v === null ? 0 : Math.max(2, Math.min(100, (v / max) * 100))}%`;
  return (
    <div className="cmp-row">
      <div className="cmp-label">{label}</div>
      <div className="cmp-bars">
        {[a, b].map((v, i) => (
          <div key={i} className={`cmp-bar ${i === 0 ? "baseline" : "threatgraph"} ${better === i ? "win" : ""}`}>
            <span style={{ width: w(v) }} />
            <em>{fmt(v)}</em>
          </div>
        ))}
      </div>
    </div>
  );
}

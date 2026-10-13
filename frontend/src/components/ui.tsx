import { useEffect, useState, type ReactNode } from "react";
import { attackUrl, SYSTEM_LABEL } from "../format";
import type { SystemKey } from "../types";

export function SystemBadge({ system }: { system: SystemKey }) {
  return (
    <span className={`badge ${system}`}>
      <span className="dot" style={{ background: "currentColor", marginRight: 0 }} />
      {SYSTEM_LABEL[system]}
    </span>
  );
}

export function AttackChip({ id }: { id: string }) {
  const url = attackUrl(id);
  return url ? (
    <a className="chip" href={url} target="_blank" rel="noreferrer" title="Open on attack.mitre.org">{id}</a>
  ) : (
    <span className="chip">{id}</span>
  );
}

export function Switch({ checked, onChange, children }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
  return (
    <label className="switch">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="track" />
      {children}
    </label>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: {
  value: T;
  options: { value: T; label: ReactNode }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="segmented" role="radiogroup">
      {options.map((o) => (
        <button key={o.value} type="button" role="radio" aria-checked={value === o.value}
          className={value === o.value ? "on" : ""} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Bar({ value, system, mini }: { value: number | null; system?: SystemKey; mini?: boolean }) {
  if (value === null) return null;
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <div className={`bar ${system ?? ""} ${mini ? "mini" : ""}`}>
      <span style={{ width: `${pct}%` }} />
    </div>
  );
}

export function Notice({ kind = "info", children }: { kind?: "info" | "warn" | "bad" | "good"; children: ReactNode }) {
  return <div className={`notice ${kind}`}>{children}</div>;
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

export function Spinner() {
  return <span className="spinner" />;
}

/** Seconds elapsed since `since` (ms timestamp), ticking every 250ms while set. */
export function useElapsed(since: number | null): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (since === null) return;
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(t);
  }, [since]);
  return since === null ? 0 : Math.max(0, (now - since) / 1000);
}

export function Toast({ message, onDone }: { message: string | null; onDone: () => void }) {
  useEffect(() => {
    if (!message) return;
    const t = setTimeout(onDone, 2200);
    return () => clearTimeout(t);
  }, [message, onDone]);
  return message ? <div className="toast">{message}</div> : null;
}

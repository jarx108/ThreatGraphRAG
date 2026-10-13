import type { Summary, SystemKey } from "./types";

export const SYSTEM_LABEL: Record<SystemKey, string> = {
  baseline: "Text-only RAG",
  threatgraph: "GraphRAG",
};
export const SYSTEM_ORDER: SystemKey[] = ["baseline", "threatgraph"];

export const pct = (v: number | null | undefined, digits = 0) =>
  v === null || v === undefined ? "N/A" : `${(v * 100).toFixed(digits)}%`;

export const num = (v: number | null | undefined, digits = 2) =>
  v === null || v === undefined ? "N/A" : v.toFixed(digits);

/** Format a benchmark metric (fractions as %, latency in seconds). */
export function fmtMetric(key: string, s: Summary | number | null | undefined): string {
  const v = s === null || s === undefined ? null : typeof s === "number" ? s : s.mean;
  if (v === null) return "N/A";
  return key === "total_latency_seconds" ? `${v.toFixed(1)} s` : pct(v, 0);
}

/** Index of the better value (0 or 1), or null for ties / missing values. */
export function winner(a: number | null | undefined, b: number | null | undefined, higherIsBetter: boolean) {
  if (a === null || a === undefined || b === null || b === undefined) return null;
  if (Math.abs(a - b) < 1e-9) return null;
  return (a > b) === higherIsBetter ? 0 : 1;
}

export function fmtDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

const ATTACK_PATHS: Record<string, string> = { G: "groups", T: "techniques", S: "software", M: "mitigations", C: "campaigns" };

export function attackUrl(id: string): string | null {
  const kind = ATTACK_PATHS[id[0]];
  if (!kind || !/^[GTSMC]\d{4}(\.\d{3})?$/.test(id)) return null;
  return `https://attack.mitre.org/${kind}/${id.replace(".", "/")}/`;
}

export const CATEGORY_LABEL: Record<string, string> = {
  group_technique_mitigation: "Group → Technique → Mitigation",
  group_software_technique: "Group → Software → Technique",
  group_software_technique_mitigation: "Group → Software → Technique → Mitigation",
};

export const LABEL_COLOR: Record<string, string> = {
  ThreatGroup: "#f472b6", Technique: "#60a5fa", Software: "#a78bfa", Mitigation: "#34d399",
  Campaign: "#fbbf24", Chunk: "#94a3b8", Document: "#fb923c",
};

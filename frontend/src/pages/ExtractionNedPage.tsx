import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { api, errorText } from "../api";
import { TABS } from "../tabs";
import { LinkIcon, PlayIcon } from "../components/Icons";
import { CompareRow, Kpi, PageHero, Section } from "../components/Page";
import { AttackChip, Notice, Spinner } from "../components/ui";
import { LABEL_COLOR, pct } from "../format";
import type { ExtractionNed, ExtractResult, Mention } from "../types";

const NED_EXAMPLE = "Which mitigations defend against techniques used by Cozy Bear and Fancy Bear, and does Mimikatz do credential dumping?";
const VARIANTS = ["canonical name", "alias", "alias (lower case)", "ATT&CK ID", "overall"];

function Highlighted({ text, mentions }: { text: string; mentions: Mention[] }) {
  const parts: ReactNode[] = [];
  let at = 0;
  mentions.forEach((m, i) => {
    if (m.start > at) parts.push(text.slice(at, m.start));
    parts.push(
      <mark key={i} className="ned-mark" style={{ "--m": LABEL_COLOR[m.entity_type] } as CSSProperties}>
        {text.slice(m.start, m.end)}
        <span className="ned-tag">{m.attack_id} · {m.canonical_name}</span>
      </mark>,
    );
    at = m.end;
  });
  parts.push(text.slice(at));
  return <div className="ned-text">{parts}</div>;
}

export function ExtractionNedPage() {
  const [info, setInfo] = useState<ExtractionNed | null>(null);
  const [text, setText] = useState("");
  const [result, setResult] = useState<ExtractResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nedText, setNedText] = useState(NED_EXAMPLE);
  const [mentions, setMentions] = useState<Mention[] | null>(null);

  useEffect(() => {
    api.extractionNed().then((d) => { setInfo(d); if (d.samples[0]) setText(d.samples[0].text); })
      .catch((e) => setError(errorText(e)));
    api.ned(NED_EXAMPLE).then((r) => setMentions(r.mentions)).catch(() => undefined);
  }, []);

  async function runExtract() {
    setBusy(true); setError(null); setResult(null);
    try { setResult(await api.extract(text)); } catch (e) { setError(errorText(e)); } finally { setBusy(false); }
  }
  async function runNed() {
    try { setMentions((await api.ned(nedText)).mentions); } catch (e) { setError(errorText(e)); }
  }

  const ex = info?.extraction;
  const ned = info?.ned;
  return (
    <div className="stack" style={{ gap: 26 }}>
      <PageHero eyebrow="Pillar 3 · 25%" title="LLM Extraction & Entity Disambiguation" color={TABS[3].color}
        checklist={["Pydantic schema", "Ollama schema-constrained JSON", "NED to canonical graph nodes"]}>
        A local LLM ({info?.model ?? "…"} via {info?.provider ?? "…"}) reads threat-intel text and returns entities and
        relationships. Ollama is forced to follow the Pydantic model's JSON Schema while generating, and the result is
        validated again afterwards. Named Entity Disambiguation then links each mention, e.g. “Cozy Bear”, to its
        canonical node (APT29, G0016), so there are no duplicates.
      </PageHero>
      {error && <Notice kind="bad">{error}</Notice>}

      <Section title="Try extraction" sub="Pick a real MITRE description or paste your own text.">
        <div className="row" style={{ gap: 8, marginBottom: 10 }}>
          {info?.samples.map((s) => (
            <button key={s.attack_id} className={`btn ${text === s.text ? "primary" : ""}`} onClick={() => { setText(s.text); setResult(null); }}>
              {s.name} <span className="chip">{s.attack_id}</span>
            </button>
          ))}
        </div>
        <textarea value={text} onChange={(e) => setText(e.target.value)} style={{ minHeight: 120 }} />
        <div className="row spread" style={{ marginTop: 10 }}>
          <span className="muted">Prompt: <code>prompts/extraction_prompt.txt</code> · temperature 0 · schema: <code>schemas.ExtractionResult</code></span>
          <button className="btn primary" disabled={busy || !text.trim()} onClick={runExtract}>
            {busy ? <><Spinner /> Extracting…</> : <><PlayIcon size={14} /> Extract</>}
          </button>
        </div>
        {result && (
          <div className="stack" style={{ gap: 14, marginTop: 16 }}>
            <div className="row" style={{ gap: 8 }}>
              <span className="badge good">{result.entities.length} entities</span>
              <span className="badge good">{result.relationships.length} relationships</span>
              <span className={`badge ${result.rejected.length ? "warn" : ""}`}>{result.rejected.length} rejected by validation</span>
              {result.schema_enforced && <span className="badge">schema enforced in decoding</span>}
              <span className="badge">{result.cached ? "cached · " : ""}{result.latency_seconds.toFixed(1)} s</span>
            </div>
            <div className="grid-2">
              <div className="table-wrap">
                <table className="data compact">
                  <thead><tr><th>Mention</th><th>→ Canonical node (NED)</th><th>How</th></tr></thead>
                  <tbody>
                    {result.entities.map((e, i) => (
                      <tr key={i}>
                        <td><span style={{ color: LABEL_COLOR[e.type] }}>{e.mention}</span><div className="muted">{e.type}</div></td>
                        <td>{e.resolved ? <>{e.canonical_name} <AttackChip id={e.attack_id!} /></> : <span className="muted">not in ATT&amp;CK</span>}</td>
                        <td>{e.method ? <span className="badge">{e.method}{e.similarity ? ` ${e.similarity.toFixed(2)}` : ""}</span> : "–"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="table-wrap">
                <table className="data compact">
                  <thead><tr><th>Relationship</th><th>Conf.</th><th>MITRE</th></tr></thead>
                  <tbody>
                    {result.relationships.map((r, i) => (
                      <tr key={i} title={r.evidence_text}>
                        <td>{r.source_id ?? r.source} <span className="fact-edge">{r.predicate}</span> {r.target_id ?? r.target}</td>
                        <td>{r.confidence.toFixed(2)}</td>
                        <td>{r.verified === null ? <span className="muted">unresolved</span> : r.verified
                          ? <span className="badge good">confirmed</span> : <span className="badge">new</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </Section>

      <Section title="Try entity disambiguation" sub="Links names, aliases and ATT&CK IDs in any text to graph nodes. Deterministic, no LLM.">
        <div className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
          <input type="text" value={nedText} onChange={(e) => setNedText(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runNed()} />
          <button className="btn primary" onClick={runNed}><LinkIcon size={14} /> Link</button>
        </div>
        {mentions && (mentions.length ? <Highlighted text={nedText} mentions={mentions} />
          : <div className="muted" style={{ marginTop: 12 }}>No ATT&amp;CK entities found.</div>)}
      </Section>

      {ned && (
        <Section title="NED accuracy" sub={`${ned.n_cases.toLocaleString()} mentions of ${ned.n_entities.toLocaleString()} entities, built from MITRE's own names and aliases (${ned.ambiguous_aliases_excluded} ambiguous aliases excluded).`}
          right={<div className="legend-row"><span className="legend"><span className="sw baseline" />Exact-name lookup</span><span className="legend"><span className="sw threatgraph" />ThreatGraph NED</span></div>}>
          {VARIANTS.map((v) => (
            <CompareRow key={v} label={v === "overall" ? "Overall" : v[0].toUpperCase() + v.slice(1)}
              a={ned.baseline_exact_name[v].accuracy} b={ned.threatgraph_ned[v].accuracy} fmt={(x) => pct(x, 1)} />
          ))}
        </Section>
      )}

      {ex && (
        <Section title="Extraction quality" sub={`${ex.sample_size_succeeded}/${ex.sample_size_requested} MITRE descriptions processed by ${ex.model}; extracted triples compared after NED.`}>
          <div className="grid-4">
            <Kpi label="Precision (verified)" value={pct(ex.false_positive_breakdown?.adjusted_precision, 1)}
              foot="extracted facts that MITRE also asserts" color="#34d399" />
            <Kpi label="Recall" value={pct(ex.metrics.recall, 1)} foot={`of ${ex.metrics.n_gold} gold triples`} color="#60a5fa" />
            <Kpi label="Strict precision / F1" value={`${pct(ex.metrics.precision, 1)} / ${pct(ex.metrics.f1, 1)}`}
              foot="against the 60-triple gold sample only" color="#a78bfa" />
            <Kpi label="Not in MITRE ATT&CK" value={ex.false_positive_breakdown?.n_hallucinated ?? "N/A"}
              foot={`of ${ex.metrics.n_predicted} extracted facts`} color="#fb7185" />
          </div>
        </Section>
      )}
    </div>
  );
}

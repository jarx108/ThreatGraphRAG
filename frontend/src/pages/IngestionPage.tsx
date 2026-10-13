import { useEffect, useState, type CSSProperties } from "react";
import { api, errorText } from "../api";
import { TABS } from "../tabs";
import { Kpi, PageHero, Section } from "../components/Page";
import { Notice, Spinner } from "../components/ui";
import { LABEL_COLOR, pct } from "../format";
import type { Ingestion } from "../types";

// Node positions of the ontology diagram (labels/edge counts come from Neo4j).
const POS: Record<string, [number, number]> = {
  Campaign: [80, 50], ThreatGroup: [340, 50], Software: [620, 50],
  Mitigation: [210, 260], Technique: [620, 260],
};

function SchemaDiagram({ data }: { data: Ingestion }) {
  const counts = Object.fromEntries(data.labels.map((l) => [l.label, l.n]));
  const edges = data.relationships.filter((r) => r.source === "mitre_attack_stix" && POS[r.src] && POS[r.tgt]);
  return (
    <svg viewBox="0 0 700 310" className="schema-svg" role="img" aria-label="Graph schema">
      <defs>
        <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0L10 5L0 10z" fill="#8a94a8" />
        </marker>
      </defs>
      {edges.map((e) => {
        const [x1, y1] = POS[e.src], [x2, y2] = POS[e.tgt];
        if (e.src === e.tgt) return null;
        const dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy);
        const pad = 46, sx = x1 + (dx / len) * pad, sy = y1 + (dy / len) * pad * 0.6;
        const ex = x2 - (dx / len) * pad, ey = y2 - (dy / len) * pad * 0.6;
        const mx = (sx + ex) / 2, my = (sy + ey) / 2;
        return (
          <g key={`${e.src}-${e.rel}-${e.tgt}`}>
            <line x1={sx} y1={sy} x2={ex} y2={ey} stroke="#56607a" strokeWidth="1.6" markerEnd="url(#arr)" />
            <text x={mx} y={my - 6} className="schema-edge">{e.rel} · {e.n.toLocaleString()}</text>
          </g>
        );
      })}
      {Object.entries(POS).map(([label, [x, y]]) => (
        <g key={label}>
          <rect x={x - 62} y={y - 24} width="124" height="48" rx="12"
            fill={`${LABEL_COLOR[label]}22`} stroke={LABEL_COLOR[label]} strokeWidth="1.5" />
          <text x={x} y={y - 3} className="schema-node" fill={LABEL_COLOR[label]}>{label}</text>
          <text x={x} y={y + 14} className="schema-count">{(counts[label] ?? 0).toLocaleString()} nodes</text>
        </g>
      ))}
    </svg>
  );
}

export function IngestionPage() {
  const [data, setData] = useState<Ingestion | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.ingestion().then(setData).catch((e) => setError(errorText(e))); }, []);

  const stixEdges = data?.relationships.filter((r) => r.source === "mitre_attack_stix").reduce((a, r) => a + r.n, 0) ?? 0;
  const ti = data?.text_ingestion;
  const ex = data?.stix_edge_example;

  return (
    <div className="stack" style={{ gap: 26 }}>
      <PageHero eyebrow="Pillar 1 · 25%" title="Schema & Data Ingestion" color={TABS[1].color}
        checklist={["Structured data (STIX ontology)", "Unstructured text (LLM extraction)", "Provenance, timestamps & confidence on every edge"]}>
        Two sources feed one Neo4j property graph. The structured MITRE ATT&amp;CK STIX bundle is parsed directly.
        Free-text threat descriptions go through the LLM extraction pipeline, and the facts it extracts are stored
        as a separate, clearly labelled source and cross-checked against MITRE.
      </PageHero>
      {error && <Notice kind="bad">{error}</Notice>}
      {!data && !error && <div className="muted"><Spinner /> Loading…</div>}

      {data && (
        <>
          <div className="grid-2">
            <div className="card source-card" style={{ "--m": "#60a5fa" } as CSSProperties}>
              <div className="eyebrow-sm">Source 1 · structured</div>
              <h3 className="card-title">MITRE ATT&amp;CK STIX 2.1 · v{data.attack_version}</h3>
              <div className="grid-2 tight">
                <Kpi label="Entities" color="#60a5fa"
                  value={data.labels.filter((l) => POS[l.label]).reduce((a, l) => a + l.n, 0).toLocaleString()} />
                <Kpi label="Relationships" color="#60a5fa" value={stixEdges.toLocaleString()} />
              </div>
              <div className="card-sub" style={{ marginTop: 10 }}>Pinned by SHA-256; parsed by <code>ingestion/stix_loader.py</code>, loaded by <code>graph/populate.py</code>.</div>
            </div>
            <div className="card source-card" style={{ "--m": "#fbbf24" } as CSSProperties}>
              <div className="eyebrow-sm">Source 2 · unstructured text</div>
              <h3 className="card-title">LLM-extracted facts ({ti?.model ?? "not run yet"})</h3>
              {ti ? (
                <>
                  <div className="grid-3 tight">
                    <Kpi label="Documents" color="#fbbf24" value={ti.documents_processed} />
                    <Kpi label="Edges written" color="#fbbf24" value={ti.edges_written} />
                    <Kpi label="Confirmed by MITRE" color="#34d399" value={pct(ti.verified_share)} />
                  </div>
                  <div className="card-sub" style={{ marginTop: 10 }}>Mean LLM confidence {ti.mean_confidence?.toFixed(2)} · written by <code>ingestion/text_ingest.py</code></div>
                </>
              ) : <Notice kind="warn">Run <code>make ingest-text</code> to add this source.</Notice>}
            </div>
          </div>

          <Section title="Graph schema (labelled property graph)" sub="Node labels and MITRE-asserted relationship types with live counts from Neo4j.">
            <SchemaDiagram data={data} />
            <div className="grid-2" style={{ marginTop: 12 }}>
              <div>
                <div className="stat-label" style={{ marginBottom: 6 }}>Ontology mapping (STIX object → node label)</div>
                <table className="data compact">
                  <tbody>
                    {data.stix_mapping.map((m) => (
                      <tr key={m.stix_type}><td><code>{m.stix_type}</code></td><td style={{ color: LABEL_COLOR[m.label] }}>{m.label}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div>
                <div className="stat-label" style={{ marginBottom: 6 }}>Why a property graph instead of RDF?</div>
                <div className="muted">Provenance, timestamps and confidence are needed <em>on each edge</em>. A labelled
                  property graph stores them as relationship properties directly, while RDF needs reification or RDF-star.
                  Every node keeps its ATT&amp;CK ID and attack.mitre.org URL, and every edge keeps its STIX relationship ID, so the graph still maps back to the STIX ontology. Text
                  chunks link to entities via <code>DESCRIBES</code>, and every entity links to its source
                  document via <code>MENTIONED_IN</code>.</div>
              </div>
            </div>
          </Section>

          {ex && (
            <Section title="Edge provenance: one real relationship" sub="Every MITRE edge carries these properties (graph/populate.py).">
              <div className="edge-title">
                <span className="chip">{String(ex.subject)}</span>
                <span className="fact-edge">{String(ex.predicate)}</span>
                <span className="chip">{String(ex.object)}</span>
              </div>
              <table className="data compact props">
                <tbody>
                  {(["source", "source_version", "stix_relationship_id", "created", "modified", "confidence", "evidence_text"] as const).map((k) => (
                    <tr key={k}><td><code>r.{k}</code></td><td>{String(ex[k] ?? "")}</td></tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}

          {data.llm_edge_examples.length > 0 && (
            <Section title="Facts extracted from unstructured text" sub="Stored with source = 'llm_extraction', the model, the LLM's confidence, the evidence sentence, and whether MITRE confirms the same fact.">
              <div className="table-wrap">
                <table className="data compact">
                  <thead><tr><th>Fact</th><th>Confidence</th><th>MITRE</th><th>Evidence (from the text)</th></tr></thead>
                  <tbody>
                    {data.llm_edge_examples.map((e, i) => (
                      <tr key={i}>
                        <td className="nowrap">{e.subject} <span className="fact-edge">{e.predicate}</span> {e.object}</td>
                        <td>{e.confidence?.toFixed(2)}</td>
                        <td>{e.verified ? <span className="badge good">confirmed</span> : <span className="badge">new</span>}</td>
                        <td className="muted">{e.evidence_text}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          <Section title="All relationship types" sub="Counts per source; 'structural' = text-chunk and document links.">
            <div className="table-wrap">
              <table className="data compact">
                <thead><tr><th>Pattern</th><th>Source</th><th style={{ textAlign: "right" }}>Edges</th></tr></thead>
                <tbody>
                  {data.relationships.map((r) => (
                    <tr key={`${r.src}${r.rel}${r.tgt}${r.source}`}>
                      <td>({r.src})-[<span className="fact-edge">{r.rel}</span>]→({r.tgt})</td>
                      <td><span className="badge">{r.source}</span></td>
                      <td style={{ textAlign: "right" }}>{r.n.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        </>
      )}
    </div>
  );
}

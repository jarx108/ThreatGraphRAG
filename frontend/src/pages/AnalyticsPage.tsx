import { useEffect, useState, type CSSProperties } from "react";
import { api, errorText } from "../api";
import { TABS } from "../tabs";
import { PlayIcon } from "../components/Icons";
import { Kpi, PageHero, Section } from "../components/Page";
import { AttackChip, Notice, Spinner } from "../components/ui";
import { fmtDate, LABEL_COLOR, pct } from "../format";
import type { Analytics } from "../types";

const RANK_LABELS = ["ThreatGroup", "Software", "Technique", "Mitigation"];

export function AnalyticsPage() {
  const [data, setData] = useState<Analytics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  useEffect(() => { api.analytics().then(setData).catch((e) => setError(errorText(e))); }, []);

  async function rerun() {
    setRunning(true); setError(null);
    try { setData(await api.runAnalytics()); } catch (e) { setError(errorText(e)); } finally { setRunning(false); }
  }

  const t = data?.topology;
  const maxCommunity = Math.max(1, ...(data?.louvain?.largest.map((c) => c.size) ?? [1]));
  return (
    <div className="stack" style={{ gap: 26 }}>
      <PageHero eyebrow="Pillar 2 · 25%" title="Graph Analytics & Reasoning" color={TABS[2].color}
        checklist={["PageRank", "Louvain communities", "Weakly connected components", "Path calculations"]}>
        The Neo4j Graph Data Science library runs over the MITRE-verified graph. Each node gets its PageRank,
        community, component and degree written back as properties, and GraphRAG reads these at question time.
        The exact statements are in <code>cypher/gds_analytics.cypher</code>.
      </PageHero>
      {error && <Notice kind="bad">{error}</Notice>}
      {data && !data.available && <Notice kind="warn">No analytics yet. Run them below (needs the GDS plugin).</Notice>}

      {data?.available && t && (
        <>
          <div className="grid-4">
            <Kpi label="Nodes · edges" value={`${data.projection!.nodes.toLocaleString()} · ${data.projection!.relationships.toLocaleString()}`}
              foot={data.projection!.relationship_types.join(", ")} color="#a78bfa" />
            <Kpi label="Mean degree" value={t.mean_degree} foot={`max ${t.max_degree} · density ${t.density.toFixed(4)}`} color="#60a5fa" />
            <Kpi label="Connected components" value={t.components}
              foot={`largest covers ${pct(t.largest_component_share, 1)} of nodes`} color="#2fd7c3" />
            <Kpi label="Louvain communities" value={data.louvain!.communities}
              foot={`modularity ${data.louvain!.modularity}`} color="#f472b6" />
          </div>

          <Section title="Most central entities (PageRank)" sub={`GDS ${data.gds_version} · ${data.pagerank!.iterations} iterations, ${data.pagerank!.converged ? "converged" : "not converged"}`}>
            <div className="grid-4">
              {RANK_LABELS.map((label) => (
                <div key={label} className="rank-col" style={{ "--m": LABEL_COLOR[label] } as CSSProperties}>
                  <div className="rank-head">{label}</div>
                  {(data.pagerank!.top_by_label[label] ?? []).slice(0, 6).map((n, i) => {
                    const top = data.pagerank!.top_by_label[label][0].pagerank;
                    return (
                      <div key={n.attack_id} className="rank-row">
                        <span className="rank-i">{i + 1}</span>
                        <div className="rank-body">
                          <div className="rank-name">{n.name} <AttackChip id={n.attack_id} /></div>
                          <div className="rank-bar"><span style={{ width: `${(n.pagerank / top) * 100}%` }} /></div>
                        </div>
                        <span className="rank-v">{n.pagerank.toFixed(1)}</span>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
          </Section>

          <Section title="Communities (Louvain)" sub="Each bar is one community; the colours show what it is made of.">
            <div className="stack" style={{ gap: 12 }}>
              {data.louvain!.largest.map((c) => (
                <div key={c.community} className="comm-row">
                  <div className="comm-meta"><strong>#{c.community}</strong><span className="muted">{c.size} nodes</span></div>
                  <div className="comm-bar" style={{ width: `${(c.size / maxCommunity) * 100}%` }}>
                    {([["ThreatGroup", c.groups], ["Software", c.software], ["Technique", c.techniques],
                       ["Mitigation", c.mitigations], ["Campaign", c.campaigns]] as const).map(([l, n]) => n > 0 && (
                      <span key={l} title={`${l}: ${n}`} style={{ flex: n, background: LABEL_COLOR[l] }} />
                    ))}
                  </div>
                  <div className="comm-members muted">{c.top_members.slice(0, 4).map((m) => m.name).join(" · ")}</div>
                </div>
              ))}
              <div className="pill-row">
                {["ThreatGroup", "Software", "Technique", "Mitigation", "Campaign"].map((l) => (
                  <span key={l} className="legend"><span style={{ background: LABEL_COLOR[l] }} />{l}</span>
                ))}
              </div>
            </div>
          </Section>

          <div className="grid-2">
            <Section title="Path reasoning: mitigation coverage" sub="Counts Group→Technique←Mitigation paths for APT29 (G0016). GraphRAG adds this ranking to its prompt.">
              <table className="data compact">
                <thead><tr><th>Mitigation</th><th>Covers</th><th style={{ width: "40%" }} /></tr></thead>
                <tbody>
                  {data.examples!.mitigation_coverage_G0016.slice(0, 8).map((m) => (
                    <tr key={m.attack_id}>
                      <td>{m.mitigation} <AttackChip id={m.attack_id} /></td>
                      <td className="nowrap">{m.covered} / {m.total}</td>
                      <td><div className="rank-bar" style={{ "--m": "#34d399" } as CSSProperties}><span style={{ width: `${(m.covered / m.total) * 100}%` }} /></div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
            <Section title="Path reasoning: shortest connection" sub="Cypher shortestPath between APT29 (G0016) and APT28 (G0007).">
              {data.examples!.shortest_path_G0016_G0007.map((p, i) => (
                <div key={i} className="path">
                  {p.path.map((n, j) => (
                    <span key={j} className="path-step">{j > 0 && <span className="path-arrow">→</span>}<span className="chip">{n}</span></span>
                  ))}
                  <div className="muted" style={{ marginTop: 8 }}>{p.hops} hops over USES / MITIGATES / ATTRIBUTED_TO edges.</div>
                </div>
              ))}
            </Section>
          </div>
        </>
      )}

      <div className="card">
        <div className="row spread">
          <div>
            <h3 className="card-title">Re-run GDS analytics</h3>
            <div className="card-sub">{data?.computed_at ? `Last run ${fmtDate(data.computed_at)}. ` : ""}Projects the graph, runs PageRank, Louvain, WCC and degree (concurrency 1, deterministic), and writes the results back.</div>
          </div>
          <button className="btn primary" disabled={running} onClick={rerun}>
            {running ? <><Spinner /> Running…</> : <><PlayIcon size={14} /> Run analytics</>}
          </button>
        </div>
      </div>
    </div>
  );
}

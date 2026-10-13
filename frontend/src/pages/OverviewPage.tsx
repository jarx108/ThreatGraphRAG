import type { CSSProperties } from "react";
import { TABS } from "../tabs";
import { ArrowIcon } from "../components/Icons";
import { Kpi, PageHero } from "../components/Page";
import { fmtMetric, LABEL_COLOR, pct } from "../format";
import { href } from "../router";
import type { Overview } from "../types";

const PIPELINE = [
  { tab: 1, title: "Ingest", text: "MITRE ATT&CK STIX (structured) and free-text descriptions (unstructured) become one Neo4j graph; every edge records its source, timestamps and confidence." },
  { tab: 2, title: "Analyze", text: "Neo4j GDS runs PageRank, Louvain and WCC over the graph and writes the scores back onto the nodes." },
  { tab: 3, title: "Extract & link", text: "A local LLM (Ollama) extracts facts as Pydantic-validated JSON; NED links names like \"Cozy Bear\" to the canonical node." },
  { tab: 4, title: "Answer", text: "GraphRAG follows the multi-hop path the question asks for, adds GDS scores, and answers with traceable ATT&CK citations." },
];

export function OverviewPage({ data }: { data: Overview | null }) {
  const b = data?.headline.benchmark;
  const entities = data?.nodes.filter((n) => !["Chunk", "Document"].includes(n.label)) ?? [];
  const nEntities = entities.reduce((a, n) => a + n.n, 0);
  const nEdges = data?.edges_by_source.reduce((a, e) => a + (e.source === "structural" ? 0 : e.n), 0) ?? 0;

  return (
    <div className="stack" style={{ gap: 26 }}>
      <PageHero eyebrow="Introduction & problem statement" title="Multi-hop questions need a graph, not just text" color={TABS[0].color}>
        Security analysts ask questions that span several connected facts, e.g. <em>“which mitigations address
        the techniques that the malware used by APT29 implements?”</em> A text-only RAG system retrieves the few
        passages most similar to the question and has to hope they happen to contain every link in that chain.
        When they don't, it answers incompletely or cites IDs that aren't in its evidence. ThreatGraph stores
        MITRE ATT&amp;CK as a knowledge graph and lets the LLM answer from the exact multi-hop subgraph, with
        a citation for every fact.
      </PageHero>

      <div className="grid-2">
        <div className="card">
          <h3 className="card-title">Why cyber threat intelligence?</h3>
          <ul className="plain-list">
            <li><strong>Naturally a graph.</strong> Groups use software, software implements techniques, mitigations counter techniques.</li>
            <li><strong>Errors are costly.</strong> A wrong attribution or a missed mitigation sends defenders in the wrong direction, so answers need provenance.</li>
            <li><strong>Curated ground truth exists.</strong> MITRE ATT&amp;CK v{data?.attack_version ?? "…"} is public and versioned, so every answer can be checked exactly.</li>
          </ul>
        </div>
        <div className="card">
          <h3 className="card-title">Key architectural ideas</h3>
          <ul className="plain-list">
            <li><strong>Question-focused traversal:</strong> NED + asked-for type pick the typed path to follow.</li>
            <li><strong>Graph analytics in the prompt:</strong> PageRank rank, community and mitigation coverage.</li>
            <li><strong>Provenance on every edge:</strong> answers trace to the STIX relationship that asserted them.</li>
            <li><strong>Local and reproducible:</strong> Ollama {data?.llm.model ?? ""}, temperature 0, fixed seed, pinned data.</li>
          </ul>
        </div>
      </div>

      <div className="grid-4">
        <Kpi label="Entities" value={nEntities.toLocaleString()} foot={`${entities.length} node types`} color="#60a5fa" />
        <Kpi label="Relationships" value={nEdges.toLocaleString()} foot="with provenance" color="#a78bfa" />
        <Kpi label="NED accuracy" value={pct(data?.headline.ned_accuracy, 1)}
          foot={`exact-name lookup: ${pct(data?.headline.ned_baseline_accuracy, 1)}`} color="#fbbf24" />
        <Kpi label="GDS communities" value={data?.headline.communities ?? "N/A"} foot="Louvain" color="#2fd7c3" />
      </div>

      {b && (
        <div className="card headline">
          <div className="card-head">
            <div>
              <h3 className="card-title">Headline result · {data?.headline.n_questions} multi-hop benchmark questions</h3>
              <div className="card-sub">Scored exactly against verified ATT&amp;CK answers. Details on the GraphRAG tab.</div>
            </div>
          </div>
          <div className="headline-grid">
            {[["accuracy", "Answer accuracy"], ["fully_correct", "Fully correct"], ["hallucination", "Hallucinated IDs"]].map(([k, label]) => (
              <div key={k} className="headline-cell">
                <div className="stat-label">{label}</div>
                <div className="headline-vals">
                  <span className="hv baseline">{fmtMetric(k, b.baseline[k])}<small>Text-only RAG</small></span>
                  <ArrowIcon size={18} />
                  <span className="hv threatgraph">{fmtMetric(k, b.threatgraph[k])}<small>GraphRAG</small></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="card-title" style={{ marginBottom: 12 }}>How it works</h3>
        <div className="grid-4">
          {PIPELINE.map((p, i) => (
            <a key={p.title} className="card pipe-card" href={href(TABS[p.tab].page)}
              style={{ "--m": TABS[p.tab].color } as CSSProperties}>
              <div className="pipe-step">{i + 1}</div>
              <div className="pipe-title">{p.title}</div>
              <div className="pipe-text">{p.text}</div>
              <div className="pipe-link">{TABS[p.tab].label} <ArrowIcon size={13} /></div>
            </a>
          ))}
        </div>
      </div>

      {data && (
        <div className="card">
          <h3 className="card-title" style={{ marginBottom: 12 }}>What is in the graph</h3>
          <div className="pill-row">
            {data.nodes.map((n) => (
              <span key={n.label} className="label-pill" style={{ "--m": LABEL_COLOR[n.label] ?? "#94a3b8" } as CSSProperties}>
                {n.label} <strong>{n.n.toLocaleString()}</strong>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

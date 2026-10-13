import { useCallback, useEffect, useState, type CSSProperties } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, errorText } from "../api";
import { TABS } from "../tabs";
import { PlayIcon, SparkIcon } from "../components/Icons";
import { CompareRow, PageHero, Section } from "../components/Page";
import { QuestionInput } from "../components/QuestionInput";
import { AttackChip, Notice, Spinner, useElapsed } from "../components/ui";
import { CATEGORY_LABEL, fmtMetric, LABEL_COLOR, pct, SYSTEM_LABEL, SYSTEM_ORDER } from "../format";
import type { AskResult, BenchmarkQuestion, BenchmarkResult, RunView } from "../types";

function Citations({ run }: { run: RunView }) {
  const s = run.scores;
  const cited = s?.cited ?? Array.from(new Set(run.answer.match(/\b[GTSMC]\d{4}(?:\.\d{3})?\b/g) ?? []));
  if (!cited.length) return <div className="muted">No ATT&amp;CK IDs cited.</div>;
  const traced = new Set(run.graph_facts.filter((f) => f.stix_relationship_id).flatMap((f) => [f.src_id, f.tgt_id]));
  return (
    <div className="cite-row">
      {cited.map((id) => {
        const cls = s?.unsupported.includes(id) ? "bad" : s?.correct.includes(id) ? "good" : "";
        return (
          <span key={id} className={`cite ${cls}`} title={s?.unsupported.includes(id) ? "Not in the retrieved evidence"
            : traced.has(id) ? "Traceable to a MITRE relationship" : ""}>
            <AttackChip id={id} />{traced.has(id) && <span className="trace">⛓</span>}
          </span>
        );
      })}
    </div>
  );
}

function ScoreLine({ run }: { run: RunView }) {
  const s = run.scores;
  if (!s) return null;
  return (
    <div className="score-line">
      <span>Accuracy <strong>{pct(s.accuracy)}</strong></span>
      <span>Precision <strong>{pct(s.precision)}</strong></span>
      <span>Hallucinated <strong>{pct(s.hallucination)}</strong></span>
      {s.missing.length > 0 && <span className="muted">missing {s.missing.length}</span>}
    </div>
  );
}

function GraphTrace({ run }: { run: RunView }) {
  const [open, setOpen] = useState(false);
  const seeds = run.analytics?.seeds ?? [];
  const coverage = run.analytics?.coverage ?? [];
  return (
    <div className="trace-steps">
      <div className="trace-step">
        <span className="step-n">1</span>
        <div><div className="step-t">Entities linked (NED)</div>
          <div className="row" style={{ gap: 6 }}>
            {run.linked_entities.length ? run.linked_entities.map((e) => (
              <span key={e.attack_id} className="linked" style={{ "--m": LABEL_COLOR[e.type] } as CSSProperties}>
                “{e.mention}” → {e.name} <AttackChip id={e.attack_id} />
              </span>
            )) : <span className="muted">none, using the top retrieved chunks instead</span>}
          </div>
        </div>
      </div>
      <div className="trace-step">
        <span className="step-n">2</span>
        <div><div className="step-t">Question asks for</div>
          <span className="badge" style={{ color: LABEL_COLOR[run.target_type ?? ""] }}>{run.target_type ?? "unknown → neighbourhood"}</span>
        </div>
      </div>
      <div className="trace-step">
        <span className="step-n">3</span>
        <div style={{ flex: 1 }}>
          <div className="step-t">Multi-hop subgraph · {run.graph_facts.length} facts
            <button className="link-btn" onClick={() => setOpen(!open)}>{open ? "hide" : "show"}</button></div>
          {open && (
            <div className="facts">
              {run.graph_facts.map((f, i) => (
                <div key={i} className="fact" title={f.stix_relationship_id ? `${f.source} · ${f.stix_relationship_id} · modified ${f.modified}` : ""}>
                  <span>{f.src_id} {f.src_name}</span><span className="fact-edge">{f.predicate}</span><span>{f.tgt_id} {f.tgt_name}</span>
                  {f.stix_relationship_id && <span className="prov">{f.stix_relationship_id.slice(0, 22)}…</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      {(seeds.length > 0 || coverage.length > 0) && (
        <div className="trace-step">
          <span className="step-n">4</span>
          <div><div className="step-t">GDS signals added to the prompt</div>
            {seeds.map((s) => (
              <div key={s.attack_id} className="muted">{s.name}: PageRank rank {s.rank}/{s.of_label}, community #{s.community}</div>
            ))}
            {coverage.slice(0, 3).map((c) => (
              <div key={c.attack_id} className="muted">{c.name} covers {c.covered}/{c.total} of the techniques</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function AnswerCard({ run }: { run: RunView }) {
  return (
    <div className={`card system-card ${run.system}`}>
      <div className="card-head">
        <h3 className="card-title">{SYSTEM_LABEL[run.system]}</h3>
        <span className="badge">{run.generation_cached ? "cached · " : ""}{run.total_latency_seconds.toFixed(1)} s</span>
      </div>
      {run.error ? <Notice kind="bad">{run.error}</Notice> : (
        <>
          <ScoreLine run={run} />
          <div className="answer"><Markdown remarkPlugins={[remarkGfm]}>{run.answer}</Markdown></div>
          <div className="stat-label" style={{ margin: "12px 0 6px" }}>Cited ATT&amp;CK IDs</div>
          <Citations run={run} />
          {run.system === "threatgraph" ? <GraphTrace run={run} /> : (
            <details className="details" style={{ marginTop: 12 }}>
              <summary>Retrieved text chunks ({run.retrieved_chunks.length}), the only evidence this system sees</summary>
              <div className="details-body">
                {run.retrieved_chunks.map((c) => (
                  <div key={c.chunk_id} className="chunk"><strong>{c.entity_attack_id} {c.entity_name}</strong> · {c.score.toFixed(3)}
                    <div className="muted">{c.text.slice(0, 260)}…</div></div>
                ))}
              </div>
            </details>
          )}
        </>
      )}
    </div>
  );
}

export function GraphRagPage() {
  const [questions, setQuestions] = useState<BenchmarkQuestion[]>([]);
  const [question, setQuestion] = useState("");
  const [result, setResult] = useState<AskResult | null>(null);
  const [since, setSince] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [bench, setBench] = useState<BenchmarkResult | null>(null);
  const elapsed = useElapsed(since);

  const loadBench = useCallback(() => { api.benchmark().then(setBench).catch((e) => setError(errorText(e))); }, []);
  useEffect(() => {
    api.questions().then((qs) => { setQuestions(qs); if (qs[23]) setQuestion(qs[23].question); }).catch(() => undefined);
    loadBench();
  }, [loadBench]);
  useEffect(() => {
    if (!bench?.running) return;
    const t = setInterval(loadBench, 5000);
    return () => clearInterval(t);
  }, [bench?.running, loadBench]);

  async function ask() {
    if (!question.trim()) return;
    setSince(Date.now()); setError(null);
    try { setResult(await api.ask(question)); } catch (e) { setError(errorText(e)); } finally { setSince(null); }
  }
  async function runBench() {
    setError(null);
    try { await api.runBenchmark(); loadBench(); } catch (e) { setError(errorText(e)); }
  }

  const sum = bench?.summary;
  return (
    <div className="stack" style={{ gap: 26 }}>
      <PageHero eyebrow="Pillar 4 · 25%" title="GraphRAG & Interpretability" color={TABS[4].color}
        checklist={["Multi-hop subgraph in the prompt", "GDS outputs in the prompt", "Traceable citations"]}>
        Both systems use the same LLM, the same prompt and the same top-5 text chunks. GraphRAG also links the
        question's entities, follows the multi-hop path the question asks for, and adds those facts and GDS scores to
        the prompt. Every graph fact keeps the ID of the MITRE relationship that asserts it.
      </PageHero>
      {error && <Notice kind="bad">{error}</Notice>}

      <div className="card ask-card">
        <div className="stack" style={{ gap: 12 }}>
          <label className="label" style={{ margin: 0 }}>Question <span className="muted">· pick one of {questions.length} benchmark questions or type your own</span></label>
          <QuestionInput questions={questions} value={question} onChange={setQuestion} onSubmit={ask}
            placeholder="Which mitigations address the techniques used by APT29?" />
          <div className="row spread">
            <span className="muted">{result?.benchmark_id ? `Benchmark ${result.benchmark_id}: answers are scored against the verified MITRE answer.` : "Benchmark questions are scored automatically."}</span>
            <button className="btn primary lg" disabled={!question.trim() || since !== null} onClick={ask}>
              {since !== null ? <><Spinner /> Answering… {elapsed.toFixed(0)}s</> : <><SparkIcon size={16} /> Ask both systems</>}
            </button>
          </div>
        </div>
      </div>

      {result && since === null && (
        <div className="grid-2 align-start">
          {SYSTEM_ORDER.map((s) => <AnswerCard key={s} run={result.runs[s]} />)}
        </div>
      )}

      <Section title={`Benchmark · ${bench?.n_questions ?? 30} multi-hop questions`}
        sub="Scored exactly against MITRE's verified answers (eval/answer_metrics.py), with no judge LLM involved."
        right={<button className="btn" disabled={!!bench?.running} onClick={runBench}>
          {bench?.running ? <><Spinner /> {bench.running.done}/{bench.running.total}</> : <><PlayIcon size={13} /> Run benchmark</>}
        </button>}>
        {!bench?.available && <div className="muted">No benchmark run yet.</div>}
        {sum && bench?.metrics && (
          <>
            <div className="legend-row" style={{ marginBottom: 10 }}>
              <span className="legend"><span className="sw baseline" />Text-only RAG</span>
              <span className="legend"><span className="sw threatgraph" />GraphRAG</span>
            </div>
            {bench.metrics.map((m) => {
              const a = sum.baseline[m.key]?.mean ?? null, b = sum.threatgraph[m.key]?.mean ?? null;
              const max = m.key === "total_latency_seconds" ? Math.max(a ?? 0, b ?? 0, 1) : 1;
              return <CompareRow key={m.key} label={m.label} a={a} b={b} max={max}
                higherIsBetter={m.higher_is_better} fmt={(v) => fmtMetric(m.key, v)} />;
            })}
            <div className="muted" style={{ marginTop: 10 }}>
              Accuracy = share of the expected ATT&amp;CK IDs the answer names. Hallucinated = cited IDs that are not in the
              system's retrieved evidence. Traceable = cited IDs backed by a MITRE relationship ID. LLM: {bench.config?.llm}.
            </div>

            <div className="grid-3" style={{ marginTop: 18 }}>
              {Object.entries(bench.by_category ?? {}).map(([cat, v]) => (
                <div key={cat} className="card cat-card">
                  <div className="stat-label">{CATEGORY_LABEL[cat] ?? cat}</div>
                  <div className="cat-vals">
                    <span className="hv baseline">{fmtMetric("accuracy", v.baseline.accuracy)}<small>RAG</small></span>
                    <span className="hv threatgraph">{fmtMetric("accuracy", v.threatgraph.accuracy)}<small>GraphRAG</small></span>
                  </div>
                  <div className="muted">answer accuracy · n = {v.threatgraph.accuracy.n}</div>
                </div>
              ))}
            </div>

            <details className="details" style={{ marginTop: 16 }}>
              <summary>Per-question results</summary>
              <div className="table-wrap" style={{ marginTop: 10 }}>
                <table className="data compact">
                  <thead><tr><th>ID</th><th>Question</th><th>RAG acc.</th><th>GraphRAG acc.</th><th>RAG halluc.</th><th>GraphRAG halluc.</th></tr></thead>
                  <tbody>
                    {bench.rows?.map((r) => (
                      <tr key={r.question_id} className="clickable" onClick={() => { setQuestion(r.question); window.scrollTo({ top: 0, behavior: "smooth" }); }}>
                        <td><span className="chip">{r.question_id}</span></td>
                        <td className="muted">{r.question}</td>
                        <td>{pct(r.scores.baseline?.accuracy)}</td>
                        <td><strong>{pct(r.scores.threatgraph?.accuracy)}</strong></td>
                        <td>{pct(r.scores.baseline?.hallucination)}</td>
                        <td>{pct(r.scores.threatgraph?.hallucination)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </>
        )}
      </Section>
    </div>
  );
}

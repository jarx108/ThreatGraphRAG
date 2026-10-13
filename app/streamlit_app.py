"""ThreatGraph Streamlit UI.

Lets a user ask a cybersecurity question, pick System A (traditional RAG),
System B (ThreatGraph), or both side by side, and inspect the generated
answer alongside retrieved text chunks, supporting graph relationships,
ATT&CK ID citations, and query latency.

Evaluation (all optional, so ordinary questions stay fast):
  - RAGAS metrics per answer (threatgraph.eval.ui_eval / ragas_worker).
  - Manual 1-5 human ratings per answer.
  - A benchmark runner over data/eval_queries.json with averaged results.
  - Knowledge extraction Precision/Recall/F1 against data/gold_triples.json.
Results persist to results/ui_evaluations.json.

Run with: streamlit run app/streamlit_app.py
Requires: a running Neo4j instance populated via
`python -m threatgraph.graph.populate`, and the LLM API key for
LLM_PROVIDER set for answer generation (plus the RAGAS judge's key for
evaluation).
"""
from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threatgraph.embeddings import get_embedder  # noqa: E402
from threatgraph.eval import ui_eval  # noqa: E402
from threatgraph.eval.ui_eval import HUMAN_METRICS, RAGAS_METRICS, SYSTEMS  # noqa: E402
from threatgraph.graph.neo4j_client import Neo4jClient  # noqa: E402
from threatgraph.rag.baseline_rag import BaselineRAG  # noqa: E402
from threatgraph.rag.graphrag import ThreatGraphRAG  # noqa: E402

st.set_page_config(page_title="ThreatGraph", page_icon="\U0001F578", layout="wide")

# Animated backdrop (aurora glows, a drifting graph network and a scrolling
# perspective grid) plus glass surfaces, mirroring the React frontend.
_GRAPH_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' width='520' height='520'>"
    "<g stroke-width='1' fill='none' stroke-opacity='0.35'>"
    "<path stroke='%232fd7c3' d='M40 60L170 120L120 260L40 60M170 120L310 80L420 190L300 300L170 120M300 300L120 260"
    "L210 430L380 420L300 300M420 190L490 330L380 420M310 80L470 40'/></g>"
    "<g fill='%23a78bfa'><circle cx='40' cy='60' r='3'/><circle cx='310' cy='80' r='3.5'/><circle cx='300' cy='300' r='4'/>"
    "<circle cx='210' cy='430' r='3'/><circle cx='490' cy='330' r='3'/></g>"
    "<g fill='%232fd7c3'><circle cx='170' cy='120' r='4'/><circle cx='420' cy='190' r='3'/><circle cx='120' cy='260' r='3'/>"
    "<circle cx='380' cy='420' r='3.5'/><circle cx='470' cy='40' r='2.5'/></g></svg>"
)
_BACKDROP_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;500;600;700&display=swap');
html, body, .stApp, .stApp p, .stApp li, .stApp label, .stApp input, .stApp textarea, .stApp button, .stApp h1,
.stApp h2, .stApp h3, .stApp h4, .stApp td, .stApp th, .stApp code, .stApp [data-testid="stMetricValue"],
.stApp [data-testid="stMetricLabel"], .stApp [data-baseweb="select"], .stApp [data-testid="stCaptionContainer"] {
  font-family: 'Roboto Mono', ui-monospace, monospace !important; }
.stApp h1, .stApp h2, .stApp h3, .stApp h4 { letter-spacing: -0.02em; }
.stApp { background: #07090e; }
.stApp::before {
  content: ""; position: fixed; inset: -20%; z-index: 0; pointer-events: none;
  background:
    radial-gradient(35vmax 35vmax at 20% 10%, rgba(47,215,195,0.28), transparent 70%),
    radial-gradient(35vmax 35vmax at 85% 40%, rgba(167,139,250,0.26), transparent 70%),
    radial-gradient(30vmax 30vmax at 30% 95%, rgba(244,114,182,0.18), transparent 70%);
  filter: blur(40px); animation: tg-aurora 28s ease-in-out infinite alternate;
}
.stApp::after {
  content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none; opacity: 0.55;
  background-image: url("data:image/svg+xml,GRAPH");
  background-size: 520px 520px; animation: tg-network 90s linear infinite;
  mask-image: radial-gradient(ellipse at center, #000 30%, transparent 85%);
  -webkit-mask-image: radial-gradient(ellipse at center, #000 30%, transparent 85%);
}
@keyframes tg-aurora { 0% { transform: translate(0,0) rotate(0deg) scale(1); }
  50% { transform: translate(6%, 4%) rotate(8deg) scale(1.1); } 100% { transform: translate(-5%, 6%) rotate(-6deg) scale(1.05); } }
@keyframes tg-network { to { background-position: 520px 260px; } }
[data-testid="stAppViewContainer"] > .main, [data-testid="stMain"], section.main { position: relative; z-index: 1; }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stSidebar"] { background: rgba(8,11,16,0.6); backdrop-filter: blur(14px); }
.block-container { position: relative; z-index: 1; }
.block-container::after {
  content: ""; position: fixed; left: -50%; right: -50%; bottom: -10vh; height: 50vh; z-index: -1; pointer-events: none;
  background-image: linear-gradient(rgba(47,215,195,0.12) 1px, transparent 1px),
                    linear-gradient(90deg, rgba(167,139,250,0.12) 1px, transparent 1px);
  background-size: 64px 64px; transform: perspective(500px) rotateX(62deg); transform-origin: bottom center;
  -webkit-mask-image: linear-gradient(to top, rgba(0,0,0,0.9), transparent 85%);
  mask-image: linear-gradient(to top, rgba(0,0,0,0.9), transparent 85%);
  animation: tg-grid 6s linear infinite;
}
@keyframes tg-grid { to { background-position: 0 64px, 0 0; } }
h1 { background: linear-gradient(90deg, #fff, #c4b5fd 40%, #5eead4 70%, #fff); background-size: 200% auto;
  -webkit-background-clip: text; background-clip: text; color: transparent !important; animation: tg-shine 8s linear infinite; }
@keyframes tg-shine { to { background-position: 200% center; } }
[data-testid="stExpander"] details { background: rgba(10,13,19,0.55); border-radius: 12px; }

/* ---- Tabs: one colour each (Ask teal, Benchmark violet, Extraction amber) ---- */
.stTabs { --active: #2fd7c3; }
.stTabs:has([data-testid="stTab"][data-key="1"][aria-selected="true"]) { --active: #a78bfa; }
.stTabs:has([data-testid="stTab"][data-key="2"][aria-selected="true"]) { --active: #fbbf24; }
.stTabs [role="tablist"] { gap: 10px; border-bottom: 1px solid color-mix(in srgb, var(--active) 40%, transparent); }
.stTabs [data-testid="stTab"] {
  --tab: #2fd7c3; padding: 10px 20px !important; border-radius: 12px 12px 0 0;
  color: var(--tab) !important; background: color-mix(in srgb, var(--tab) 9%, rgba(16,21,30,0.7));
  border: 1px solid color-mix(in srgb, var(--tab) 30%, transparent); border-bottom: none; backdrop-filter: blur(10px);
  transition: background .2s, box-shadow .2s;
}
.stTabs [data-testid="stTab"][data-key="1"] { --tab: #a78bfa; }
.stTabs [data-testid="stTab"][data-key="2"] { --tab: #fbbf24; }
.stTabs [data-testid="stTab"] p { font-weight: 600; font-size: 15px; color: var(--tab) !important; }
.stTabs [data-testid="stTab"]:hover { background: color-mix(in srgb, var(--tab) 18%, rgba(16,21,30,0.7)); }
.stTabs [data-testid="stTab"][aria-selected="true"] {
  background: color-mix(in srgb, var(--tab) 26%, rgba(16,21,30,0.7)); box-shadow: 0 -10px 30px -12px var(--tab); }
.stTabs .react-aria-SelectionIndicator { background: var(--active) !important; height: 3px !important; }
.stTabs [data-testid="stTabPanel"] { padding-top: 18px; }

/* ---- Coloured cards (app/streamlit_app.py: card()) ---- */
[class*="st-key-card-"] {
  --card: #2fd7c3;
  background: radial-gradient(120% 90% at 0% 0%, color-mix(in srgb, var(--card) 15%, transparent), transparent 60%),
              rgba(16,21,30,0.72) !important;
  border: 1px solid color-mix(in srgb, var(--card) 42%, transparent) !important;
  border-radius: 18px !important; padding: 20px 22px !important;
  box-shadow: 0 22px 60px -32px var(--card), inset 0 3px 0 -1px color-mix(in srgb, var(--card) 80%, transparent);
  backdrop-filter: blur(14px) saturate(140%); -webkit-backdrop-filter: blur(14px) saturate(140%);
  margin-bottom: 6px; transition: box-shadow .25s, transform .25s;
}
[class*="st-key-card-"]:hover { box-shadow: 0 26px 70px -28px var(--card), inset 0 3px 0 -1px var(--card); }
[class*="st-key-card-teal"]   { --card: #2fd7c3; }
[class*="st-key-card-indigo"] { --card: #8f9dff; }
[class*="st-key-card-violet"] { --card: #a78bfa; }
[class*="st-key-card-pink"]   { --card: #f472b6; }
[class*="st-key-card-amber"]  { --card: #fbbf24; }
[class*="st-key-card-blue"]   { --card: #60a5fa; }
[class*="st-key-card-"] h3, [class*="st-key-card-"] h4 { color: var(--card) !important; }
[class*="st-key-card-"] [data-testid="stForm"] { border: none; padding: 0; }
[class*="st-key-card-"] .stButton > button:not([kind="primary"]) {
  border-color: color-mix(in srgb, var(--card) 50%, transparent); color: var(--card); }

/* ---- Metric tiles, colour-cycled ---- */
[data-testid="stMetric"] {
  --m: #2fd7c3; padding: 14px 16px; border-radius: 14px;
  background: linear-gradient(160deg, color-mix(in srgb, var(--m) 18%, transparent), rgba(10,13,19,0.6));
  border: 1px solid color-mix(in srgb, var(--m) 35%, transparent);
}
[data-testid="stColumn"]:nth-child(5n+2) [data-testid="stMetric"] { --m: #a78bfa; }
[data-testid="stColumn"]:nth-child(5n+3) [data-testid="stMetric"] { --m: #f472b6; }
[data-testid="stColumn"]:nth-child(5n+4) [data-testid="stMetric"] { --m: #fbbf24; }
[data-testid="stColumn"]:nth-child(5n+5) [data-testid="stMetric"] { --m: #60a5fa; }
[data-testid="stMetricLabel"] p { color: var(--m) !important; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: .04em; }
.stButton > button[kind="primary"] { background: linear-gradient(90deg, #2fd7c3, #a78bfa); border: 0; color: #07090e; font-weight: 600; }
@media (prefers-reduced-motion: reduce) { .stApp::before, .stApp::after, .block-container::after, h1 { animation: none !important; } }
</style>
""".replace("GRAPH", _GRAPH_SVG.replace("<", "%3C").replace(">", "%3E"))
st.markdown(_BACKDROP_CSS, unsafe_allow_html=True)

SYSTEM_A = "Traditional RAG (System A)"
SYSTEM_B = "ThreatGraph (System B)"
BOTH = "Compare both (side-by-side)"
SYSTEM_LABELS = dict(SYSTEMS)

# Rows of the evaluation tables, in display order; "higher" says which
# direction is better for highlighting (lower latency is better).
TABLE_ROWS = (
    [(k, label, "ragas", True) for k, label in RAGAS_METRICS]
    + [(k, label, "human", True) for k, label in HUMAN_METRICS]
)
LATENCY_ROW = ("total_latency_seconds", "Total Latency", "latency", False)

RUBRIC = {
    "factuality": "Are the claims accurate per MITRE ATT&CK, with no fabricated techniques/groups/"
                  "mitigations/relationships? 1 = mostly fabricated, 5 = fully accurate.",
    "completeness": "Does the answer cover everything the question needs (e.g. all mitigations, not "
                    "just one)? 1 = missing most required facts, 5 = fully complete.",
    "coherence": "Is the answer well-organized and readable, independent of correctness? "
                 "1 = incoherent, 5 = clear and well-structured.",
}
HIGHLIGHT = "background-color: rgba(34, 197, 94, 0.28); font-weight: 600"

# Card colours (match the tab palette in _BACKDROP_CSS).
SYSTEM_CARD = {"baseline": "indigo", "threatgraph": "teal"}
_card_seq = iter(range(1_000_000))


def card(color: str):
    """A bordered container tinted with one of the theme colours (CSS keys
    off the `st-key-card-<color>-...` class Streamlit adds for `key`)."""
    return st.container(border=True, key=f"card-{color}-{next(_card_seq)}")


@st.cache_resource
def get_systems():
    client = Neo4jClient()
    embedder = get_embedder()
    if not client.verify_connectivity():
        st.error(
            "Cannot connect to Neo4j. Set NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD "
            "and ensure the database is populated (python -m threatgraph.graph.populate)."
        )
        st.stop()
    return BaselineRAG(client=client, embedder=embedder), ThreatGraphRAG(client=client, embedder=embedder)


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------

def fmt_value(kind: str, value) -> str:
    if value is None:
        return "N/A"
    if kind == "ragas":
        return f"{value:.3f}"
    if kind == "human":
        return f"{value} / 5"
    return f"{value:.2f} s"


def fmt_summary(kind: str, s: dict) -> str:
    if s["mean"] is None:
        return "N/A"
    if kind == "ragas":
        body = f"{s['mean']:.3f}" + (f" ± {s['std']:.3f}" if s["std"] is not None else "")
    elif kind == "human":
        body = f"{s['mean']:.2f}" + (f" ± {s['std']:.2f}" if s["std"] is not None else "")
    else:
        body = f"{s['mean']:.2f} s" + (f" ± {s['std']:.2f}" if s["std"] is not None else "")
    return f"{body} (n={s['n']})"


def comparison_table(values: dict[str, dict[str, float | None]], cells: dict[str, dict[str, str]]):
    """values/cells: {system_key: {metric_key: ...}}. Highlights the better
    system per row (higher is better, except latency); ties and rows with
    an N/A side are not highlighted."""
    rows = TABLE_ROWS + [LATENCY_ROW]
    sys_keys = [k for k, _ in SYSTEMS]
    df = pd.DataFrame(
        [[label] + [cells[s][key] for s in sys_keys] for key, label, _, _ in rows],
        columns=["Metric"] + [SYSTEM_LABELS[s] for s in sys_keys],
    )
    styles = pd.DataFrame("", index=df.index, columns=df.columns)
    for i, (key, _, _, higher) in enumerate(rows):
        a, b = (values[s][key] for s in sys_keys)
        if a is None or b is None or round(a, 6) == round(b, 6):
            continue
        a_wins = (a > b) if higher else (a < b)
        styles.iloc[i, 1 if a_wins else 2] = HIGHLIGHT
    return df.style.apply(lambda _: styles, axis=None).hide(axis="index")


# --------------------------------------------------------------------------
# Result + evaluation rendering
# --------------------------------------------------------------------------

def render_result(run: dict) -> None:
    if run.get("error"):
        st.error(f"Error: {run['error']}")
        return

    with card(SYSTEM_CARD.get(run["system"], "teal")):
        st.markdown("#### Answer")
        st.write(run["answer"])

        cols = st.columns(4)
        cols[0].metric("Total latency", f"{run['total_latency_seconds']:.2f}s")
        cols[1].metric("Retrieval latency", f"{run['retrieval_latency_seconds']:.2f}s")
        cols[2].metric("Generation latency", f"{run['generation_latency_seconds']:.2f}s")
        cost = run.get("estimated_cost_usd")
        cols[3].metric("Est. cost", f"${cost:.4f}" if cost else "n/a")

        chunks, facts = run["retrieved_chunks"], run["graph_facts"]
        with st.expander(f"Retrieved text chunks ({len(chunks)})"):
            for c in chunks:
                st.markdown(f"**[{c['entity_attack_id'] or '?'}] {c['entity_name'] or ''}** (score={c['score']:.3f})")
                st.caption(c["text"])

        if facts:
            with st.expander(f"Supporting graph relationships ({len(facts)})"):
                for f in facts:
                    st.markdown(
                        f"`{f['src_id']}` **{f['src_name']}** ({f['src_type']}) "
                        f"-[{f['predicate']}]-> "
                        f"`{f['tgt_id']}` **{f['tgt_name']}** ({f['tgt_type']})"
                    )

        attack_ids = sorted({c["entity_attack_id"] for c in chunks if c["entity_attack_id"]}
                            | {f["src_id"] for f in facts if f["src_id"]}
                            | {f["tgt_id"] for f in facts if f["tgt_id"]})
        if attack_ids:
            st.markdown("**Cited ATT&CK IDs:** " + ", ".join(f"`{a}`" for a in attack_ids))


def reference_note(run: dict) -> None:
    if run.get("reference"):
        st.caption(
            f"Matched benchmark question **{run['question_id']}**: Context Precision and Context "
            "Recall are scored against its verified MITRE ATT&CK reference answer."
        )
        with st.expander("Verified reference answer (used only for scoring)"):
            st.write(run["reference"])
    else:
        st.caption(
            "No verified reference answer exists for this question, so Context Precision and "
            "Context Recall are N/A. Pick a benchmark question to enable them."
        )


def ragas_meta_note(runs: list[dict]) -> None:
    meta = next((r["ragas_meta"] for r in runs if r.get("ragas_meta")), None)
    if not meta:
        return
    st.caption(
        f"RAGAS {meta.get('ragas_version')} · judge: {meta.get('judge_provider')}/{meta.get('judge_model')} · "
        f"embeddings: {meta.get('embedding_model')} · evaluation time {meta['evaluation_seconds']:.1f}s "
        "(measured separately; not included in answer latency)"
    )
    if meta.get("errors"):
        st.warning("Some judge calls failed, so the affected metrics show N/A:\n\n"
                   + "\n".join(f"- {e}" for e in meta["errors"]))


def ragas_button(runs: list[dict], key: str) -> None:
    def needs_scoring(r: dict) -> bool:
        # Not evaluated yet, or every score failed (e.g. judge auth/quota error): allow a retry.
        return not r.get("error") and (r.get("ragas") is None or all(v is None for v in r["ragas"].values()))

    if not any(needs_scoring(r) for r in runs):
        return
    retry = any(r.get("ragas") is not None for r in runs)
    if st.button("Retry RAGAS metrics" if retry else "Calculate RAGAS metrics", key=key,
                 help="Runs the RAGAS judge LLM on this answer. Takes from several seconds to minutes."):
        with st.spinner("Scoring with RAGAS (judge LLM)..."):
            try:
                ui_eval.run_ragas(runs)
                ui_eval.save_runs(*runs)
            except ui_eval.EvaluationError as exc:
                st.error(str(exc))
                return
        st.rerun()


def rating_form(run: dict, key_prefix: str = "") -> None:
    current = run.get("human") or {}
    with st.form(f"{key_prefix}rate_{run['id']}"):
        st.markdown(f"**Human evaluation: {SYSTEM_LABELS[run['system']]}**")
        picks = {}
        for k, label in HUMAN_METRICS:
            picks[k] = st.radio(
                label, [1, 2, 3, 4, 5], horizontal=True, help=RUBRIC[k],
                index=(current[k] - 1) if current.get(k) else None,
                key=f"{key_prefix}{k}_{run['id']}",
            )
        if st.form_submit_button("Save ratings"):
            ui_eval.save_human_ratings(run["id"], picks)
            st.toast("Ratings saved")
            st.rerun()


def evaluation_table(run: dict) -> None:
    rows = [(label, fmt_value(kind, ui_eval.metric_value(run, key))) for key, label, kind, _ in TABLE_ROWS]
    rows.append(("Total Latency", fmt_value("latency", ui_eval.metric_value(run, LATENCY_ROW[0]))))
    st.table(pd.DataFrame(rows, columns=["Metric", "Score"]).style.hide(axis="index"))
    if run.get("ragas") is None and not run.get("error"):
        st.caption("RAGAS metrics have not been calculated for this answer yet.")


def render_single(run: dict) -> None:
    if run.get("wall_clock_seconds") is not None:
        st.caption(f"Wall-clock time: {run['wall_clock_seconds']:.2f}s")
    render_result(run)
    with card("violet"):
        st.markdown("### Evaluation Metrics")
        evaluation_table(run)
        reference_note(run)
        ragas_meta_note([run])
        ragas_button([run], key=f"ragas_{run['id']}")
    if not run.get("error"):
        with card("pink"):
            rating_form(run)


def render_pair(runs: dict[str, dict], key_prefix: str = "") -> None:
    cols = st.columns(2)
    for col, (sys_key, label) in zip(cols, SYSTEMS):
        with col:
            st.subheader(label)
            run = runs[sys_key]
            if run.get("wall_clock_seconds") is not None:
                st.caption(f"Wall-clock time: {run['wall_clock_seconds']:.2f}s")
            render_result(run)

    sys_keys = [k for k, _ in SYSTEMS]
    rows = TABLE_ROWS + [LATENCY_ROW]
    with card("violet"):
        st.markdown("### Evaluation Metrics: side-by-side")
        values = {s: {key: ui_eval.metric_value(runs[s], key) for key, *_ in rows} for s in sys_keys}
        cells = {s: {key: fmt_value(kind, values[s][key]) for key, _, kind, _ in rows} for s in sys_keys}
        st.table(comparison_table(values, cells))
        st.caption("Highlighted = better score for that metric (lower is better for latency). "
                   "Ties and N/A rows are not highlighted.")
        first = runs[sys_keys[0]]
        reference_note(first)
        ragas_meta_note(list(runs.values()))
        ragas_button(list(runs.values()), key=f"{key_prefix}ragas_pair_{first['id']}")

    cols = st.columns(2)
    for col, sys_key, color in zip(cols, sys_keys, ("pink", "amber")):
        with col:
            if not runs[sys_key].get("error"):
                with card(color):
                    rating_form(runs[sys_key], key_prefix)


def render_runs(runs: list[dict]) -> None:
    if len(runs) == 1:
        render_single(runs[0])
    else:
        render_pair({r["system"]: r for r in runs})


# --------------------------------------------------------------------------
# Tabs
# --------------------------------------------------------------------------

def _pick_benchmark_question() -> None:
    choice = st.session_state.get("bench_pick")
    if choice and choice != "(type your own)":
        st.session_state["question"] = choice.split(" · ", 1)[1]


def ask_tab(baseline, graphrag, benchmark: list[dict]) -> None:
    with card("teal"):
        _ask_inputs(baseline, graphrag, benchmark)

    run_ids = [i for i in st.query_params.get("runs", "").split(",") if i]
    store = ui_eval.load_store()
    runs = [store["runs"][i] for i in run_ids if i in store["runs"]]
    if runs:
        render_runs(runs)

    saved_groups: dict[str, list[dict]] = {}
    for r in sorted(store["runs"].values(), key=lambda r: r["created_at"], reverse=True):
        if r.get("benchmark_id") is None:
            saved_groups.setdefault(r.get("group_id") or r["id"], []).append(r)
    if saved_groups:
        with card("blue"), st.expander(f"Saved individual evaluations ({len(saved_groups)})"):
            labels = {
                gid: f"{rs[0]['created_at'][:19].replace('T', ' ')} · "
                     f"{' + '.join(SYSTEM_LABELS[r['system']] for r in rs)} · {rs[0]['question'][:80]}"
                for gid, rs in saved_groups.items()
            }
            gid = st.selectbox("Open a saved evaluation", list(labels), format_func=labels.get)
            if st.button("Open"):
                st.query_params["runs"] = ",".join(r["id"] for r in saved_groups[gid])
                st.rerun()


def _ask_inputs(baseline, graphrag, benchmark: list[dict]) -> None:
    st.selectbox(
        "Load a benchmark question (has a verified reference answer)",
        ["(type your own)"] + [f"{q['id']} · {q['question']}" for q in benchmark],
        key="bench_pick", on_change=_pick_benchmark_question,
    )
    question = st.text_area(
        "Cybersecurity question",
        placeholder="Which threat groups use Process Injection (T1055), and which mitigations help defend against it?",
        height=80, key="question",
    )
    system_choice = st.radio("System", [SYSTEM_A, SYSTEM_B, BOTH], horizontal=True)
    auto_ragas = st.checkbox(
        "Calculate RAGAS metrics after answering",
        help="Off by default so ordinary questions stay fast. You can also calculate them afterwards.",
    )

    if st.button("Ask", type="primary") and question.strip():
        bench_item = ui_eval.match_benchmark(question, benchmark)
        systems = {SYSTEM_A: [baseline], SYSTEM_B: [graphrag], BOTH: [baseline, graphrag]}[system_choice]
        group_id = uuid.uuid4().hex[:12]
        runs = []
        with st.spinner("Retrieving evidence and generating answer..."):
            for system in systems:
                t0 = time.time()
                result = system.answer(question)
                run = ui_eval.new_run(result, bench_item)
                run["wall_clock_seconds"] = time.time() - t0
                run["group_id"] = group_id
                runs.append(run)
        ui_eval.save_runs(*runs)
        if auto_ragas:
            with st.spinner("Scoring with RAGAS (judge LLM)..."):
                try:
                    ui_eval.run_ragas(runs)
                    ui_eval.save_runs(*runs)
                except ui_eval.EvaluationError as exc:
                    st.error(str(exc))
        st.query_params["runs"] = ",".join(r["id"] for r in runs)


def benchmark_tab(baseline, graphrag, benchmark: list[dict]) -> None:
    if not benchmark:
        st.warning("No benchmark found. Run `python scripts/build_benchmarks.py` first.")
        return
    with card("violet"):
        st.markdown(
            f"Runs benchmark questions from `data/eval_queries.json` ({len(benchmark)} multi-hop questions "
            "with verified MITRE ATT&CK answers) through **both** systems. Each completed question is saved "
            "immediately, so a refresh or interruption never loses finished work, and **Resume** continues "
            "where it left off."
        )
        c1, c2 = st.columns(2)
        n = c1.number_input("Questions to run", min_value=1, max_value=len(benchmark), value=len(benchmark))
        with_ragas = c2.checkbox("Calculate RAGAS metrics", value=True)

        latest = ui_eval.latest_benchmark()
        resumable = latest if latest and not latest.get("finished_at") else None
        b1, b2 = st.columns(2)
        start = b1.button("Run Benchmark", type="primary")
        resume = b2.button(f"Resume benchmark ({len(resumable['items'])}/{len(resumable['question_ids'])} done)",
                           disabled=resumable is None) if resumable else False

        if start or resume:
            if start:
                bench = ui_eval.start_benchmark([q["id"] for q in benchmark[: int(n)]], with_ragas)
            else:
                bench = resumable
            progress = st.progress(len(bench["items"]) / len(bench["question_ids"]))
            status = st.empty()

            def on_progress(done, total, qid, last_item):
                progress.progress(done / total)
                if last_item and last_item["ragas_error"]:
                    st.warning(f"{last_item['question_id']}: RAGAS evaluation failed: {last_item['ragas_error']}")
                if qid:
                    status.info(f"Question {done + 1}/{total} ({qid}): answering with both systems"
                                + (" and scoring with RAGAS..." if bench["with_ragas"] else "..."))

            stopped = ui_eval.run_benchmark(bench["id"], baseline, graphrag, on_progress)
            status.empty()
            if stopped:
                st.error(stopped)
            st.rerun()

    benches = [b for b in ui_eval.load_store()["benchmarks"] if b["items"]]
    if not benches:
        st.info("No benchmark results yet.")
        return

    labels = {
        b["id"]: f"{b['started_at'][:19].replace('T', ' ')} · {len(b['items'])}/{len(b['question_ids'])} questions"
                 + ("" if b.get("finished_at") else " (incomplete)")
        for b in reversed(benches)
    }
    bench_id = st.selectbox("Benchmark run", list(labels), format_func=labels.get)
    bench = ui_eval.get_benchmark(bench_id)
    store = ui_eval.load_store()
    runs_by_sys = ui_eval.benchmark_runs(bench, store)

    with card("blue"):
        st.markdown("### Benchmark averages")
        st.metric("Questions evaluated", f"{len(bench['items'])} / {len(bench['question_ids'])}")
        if bench.get("stopped_reason"):
            st.warning(bench["stopped_reason"])
        rows = TABLE_ROWS + [LATENCY_ROW]
        sys_keys = [k for k, _ in SYSTEMS]
        summaries = {s: {key: ui_eval.summarize(runs_by_sys[s], key) for key, *_ in rows} for s in sys_keys}
        values = {s: {key: summaries[s][key]["mean"] for key, *_ in rows} for s in sys_keys}
        cells = {s: {key: fmt_summary(kind, summaries[s][key]) for key, _, kind, _ in rows} for s in sys_keys}
        st.table(comparison_table(values, cells))
        st.caption(
            "Mean ± sample standard deviation over the questions where the metric could be calculated "
            "(n = count; N/A values are excluded, never treated as 0). Human ratings average only answers you "
            "have rated. Latency is answer-generation latency only and excludes failed answers. "
            "Highlighted = better mean (lower is better for latency)."
        )
        metas = [r["ragas_meta"] for r in runs_by_sys["baseline"] if r.get("ragas_meta")]
        if metas:
            m = metas[0]
            st.caption(
                f"RAGAS {m.get('ragas_version')} · judge: {m.get('judge_provider')}/{m.get('judge_model')} · "
                f"total RAGAS evaluation time {sum(x['evaluation_seconds'] for x in metas):.0f}s "
                "(separate from answer latency)"
            )

    with card("amber"):
        st.markdown("### Individual question results")
        table = []
        for item in bench["items"].values():
            row = {"ID": item["question_id"], "Hops": item.get("required_hops")}
            for s in sys_keys:
                run = store["runs"].get(item[s], {})
                short = "RAG" if s == "baseline" else "GraphRAG"
                for key, label, kind, _ in rows:
                    row[f"{short} · {label}"] = fmt_value(kind, ui_eval.metric_value(run, key)) if run else "N/A"
            table.append(row)
        st.dataframe(pd.DataFrame(table), hide_index=True, width="stretch")

    with card("pink"):
        qlabels = {qid: f"{qid} · {item['question']}" for qid, item in bench["items"].items()}
        qid = st.selectbox("Inspect a question", list(qlabels), format_func=qlabels.get)
        item = bench["items"][qid]
        st.markdown(f"**Question:** {item['question']}")
        if item.get("ragas_error"):
            st.warning(f"RAGAS evaluation failed for this question: {item['ragas_error']}")
    pair = {s: store["runs"][item[s]] for s in sys_keys if item[s] in store["runs"]}
    if len(pair) == 2:
        render_pair(pair, key_prefix=f"bench_{bench_id}_")


def extraction_tab() -> None:
    with card("amber"):
        st.markdown(
            "Evaluates the **knowledge graph extraction pipeline** (LLM triple extraction + entity resolution), "
            "not the chatbot's answers. Extracted `(subject, predicate, object)` triples, after resolution to "
            "canonical ATT&CK IDs, are compared against verified MITRE ATT&CK gold triples in "
            "`data/gold_triples.json`."
        )
    ev = ui_eval.extraction_evaluation()
    if ev is None:
        st.info("No extraction evaluation has been run yet. Use the button below.")
    else:
        m = ev["metrics"]
        with card("violet"):
            st.markdown("### Knowledge Extraction Evaluation")
            st.table(pd.DataFrame(
                [("Precision", f"{m.precision:.3f}"), ("Recall", f"{m.recall:.3f}"), ("F1-score", f"{m.f1:.3f}")],
                columns=["Metric", "Score"],
            ).style.hide(axis="index"))
        cols = st.columns(5)
        cols[0].metric("True positives", m.true_positives)
        cols[1].metric("False positives", m.false_positives)
        cols[2].metric("False negatives", m.false_negatives)
        cols[3].metric("Gold triples", m.n_gold)
        cols[4].metric("Predicted triples", m.n_predicted)
        st.caption(
            f"Extraction model: {ev['model']} · source entities processed: {ev['sample_size_succeeded']}/"
            f"{ev['sample_size_requested']} · run saved {ev['computed_at'][:19].replace('T', ' ')} UTC · "
            "recomputed here from the saved predicted triples."
        )
        if not ev["consistent_with_saved_run"]:
            st.warning("These counts differ from the saved run's summary. gold_triples.json may have been "
                       "regenerated since the extraction run; re-run the evaluation.")
        fpb = ev.get("false_positive_breakdown")
        if fpb:
            with st.expander("False-positive breakdown (sample-adjusted precision)"):
                st.markdown(
                    f"- False positives that are real ATT&CK relationships outside the gold sample: "
                    f"**{fpb['n_genuine_fact_outside_sample']}**\n"
                    f"- False positives not in ATT&CK at all: **{fpb['n_hallucinated']}**\n"
                    f"- Sample-adjusted precision: **{fpb['adjusted_precision']:.3f}**"
                )
                st.caption("Precision above is the strict metric; adjusted precision is supplementary.")
        with card("pink"):
            with st.expander("Matched / missed triples"):
                st.markdown("**False positives** (predicted, not in gold)")
                st.dataframe(pd.DataFrame(m.fp_triples, columns=["Subject", "Predicate", "Object"]), hide_index=True)
                st.markdown("**False negatives** (gold, not predicted)")
                st.dataframe(pd.DataFrame(m.fn_triples, columns=["Subject", "Predicate", "Object"]), hide_index=True)

    with card("teal"):
        st.markdown("#### Re-run extraction evaluation")
        sample = st.number_input("Source entities to extract from", min_value=1, max_value=200, value=30)
        if st.button("Run extraction evaluation", help="Calls the extraction LLM once per source entity."):
            from threatgraph.eval.run_extraction_eval import run as run_extraction

            with st.spinner("Extracting triples with the LLM and scoring against gold triples..."):
                try:
                    out = run_extraction(sample_size=int(sample))
                except Exception as exc:
                    st.error(f"Extraction evaluation failed: {exc}")
                    return
            if out.get("note"):
                st.warning(out["note"])
            st.rerun()


def main() -> None:
    st.title("ThreatGraph")
    st.caption(
        "Evaluating Knowledge Graph-Augmented RAG for Multi-Hop Cyber Threat "
        "Intelligence Question Answering"
    )

    baseline, graphrag = get_systems()
    benchmark = ui_eval.load_benchmark()

    ask, bench, extraction = st.tabs(
        [":material/forum: Ask", ":material/leaderboard: Benchmark", ":material/hub: Knowledge Extraction"]
    )
    with ask:
        ask_tab(baseline, graphrag, benchmark)
    with bench:
        benchmark_tab(baseline, graphrag, benchmark)
    with extraction:
        extraction_tab()


if __name__ == "__main__":
    main()

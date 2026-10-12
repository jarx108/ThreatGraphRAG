"""Graph Data Science analytics over the ThreatGraph knowledge graph.

Executes cypher/gds_analytics.cypher statement by statement (PageRank,
Louvain, WCC and degree centrality via the Neo4j GDS plugin, written back as
node properties `pagerank`, `community`, `component`, `degree`), then
summarizes graph topology and the algorithm results into
results/graph_analytics.json for the report and the web UI.

The written properties are also used at question time: GraphRAG adds each
seed entity's PageRank/community and a mitigation-coverage ranking to the
LLM prompt (see threatgraph.graph.traversal.graph_analytics_context).

    python -m threatgraph.graph.analytics
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from threatgraph.config import REPO_ROOT, RESULTS_DIR
from threatgraph.graph.neo4j_client import Neo4jClient

CYPHER_PATH = REPO_ROOT / "cypher" / "gds_analytics.cypher"
OUT_PATH = RESULTS_DIR / "graph_analytics.json"

ALGORITHM_STEPS = ["drop_projection", "project", "pagerank", "louvain", "wcc", "degree", "drop_after"]
READ_STEPS = ["top_pagerank", "communities", "label_counts", "mitigation_coverage_example", "shortest_path_example"]


def load_statements(path=CYPHER_PATH) -> dict[str, str]:
    """Split the .cypher file on `// @name <step>` markers."""
    statements: dict[str, str] = {}
    name, buf = None, []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*//\s*@name\s+(\w+)", line)
        if m:
            if name:
                statements[name] = "\n".join(buf).strip().rstrip(";")
            name, buf = m.group(1), []
        elif name and not line.strip().startswith("//"):
            buf.append(line)
    if name:
        statements[name] = "\n".join(buf).strip().rstrip(";")
    return statements


def gds_available(client: Neo4jClient) -> str | None:
    """GDS version string, or None when the plugin is not installed."""
    try:
        return client.run("RETURN gds.version() AS v")[0]["v"]
    except Exception:
        return None


def run(client: Neo4jClient | None = None) -> dict:
    owns = client is None
    client = client or Neo4jClient()
    try:
        version = gds_available(client)
        if version is None:
            raise RuntimeError(
                "The Neo4j Graph Data Science plugin is not installed. Neo4j Desktop: select the "
                "instance > Plugins > Graph Data Science Library > Install, then restart it. "
                "Docker: `make neo4j-up` (docker-compose.yml enables the plugin)."
            )
        stmts = load_statements()
        steps = {name: client.run(stmts[name]) for name in ALGORITHM_STEPS + READ_STEPS}

        proj = steps["project"][0]
        n, rel_directed = proj["nodes"], proj["relationships"] // 2  # undirected projection stores both directions
        summary = {
            "computed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "gds_version": version,
            "projection": {"nodes": n, "relationships": rel_directed,
                           "relationship_types": ["USES", "MITIGATES", "ATTRIBUTED_TO"],
                           "source_filter": "mitre_attack_stix"},
            "topology": {
                "density": round(2 * rel_directed / (n * (n - 1)), 6) if n > 1 else 0.0,
                "mean_degree": round(steps["degree"][0]["meanDegree"], 2),
                "max_degree": int(steps["degree"][0]["maxDegree"]),
                "components": steps["wcc"][0]["componentCount"],
                "largest_component": steps["wcc"][0]["largestComponent"],
                "largest_component_share": round(steps["wcc"][0]["largestComponent"] / n, 4) if n else 0.0,
            },
            "pagerank": {"iterations": steps["pagerank"][0]["ranIterations"],
                         "converged": steps["pagerank"][0]["didConverge"],
                         "top_by_label": {r["label"]: r["top"] for r in steps["top_pagerank"]}},
            "louvain": {"communities": steps["louvain"][0]["communityCount"],
                        "modularity": round(steps["louvain"][0]["modularity"], 4),
                        "levels": steps["louvain"][0]["ranLevels"],
                        "largest": steps["communities"]},
            "label_counts": steps["label_counts"],
            "examples": {"mitigation_coverage_G0016": steps["mitigation_coverage_example"],
                         "shortest_path_G0016_G0007": steps["shortest_path_example"]},
        }
        RESULTS_DIR.mkdir(exist_ok=True)
        OUT_PATH.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
        return summary
    finally:
        if owns:
            client.close()


def load() -> dict | None:
    return json.loads(OUT_PATH.read_text(encoding="utf-8")) if OUT_PATH.exists() else None


if __name__ == "__main__":
    out = run()
    print(json.dumps({k: out[k] for k in ("gds_version", "projection", "topology")}, indent=2))
    print("louvain:", out["louvain"]["communities"], "communities, modularity", out["louvain"]["modularity"])

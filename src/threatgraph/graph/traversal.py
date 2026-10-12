"""Bounded multi-hop graph retrieval queries used by the ThreatGraph RAG system.

Every query here is parameterized Cypher with an explicit hop bound
(variable-length patterns capped at threatgraph.config.RETRIEVAL.max_hops)
so a malformed or adversarial question can never trigger an unbounded graph
scan.
"""
from __future__ import annotations

from threatgraph.config import RETRIEVAL
from threatgraph.graph.neo4j_client import Neo4jClient

# Exact (brute-force) cosine k-NN over every Chunk, not the approximate HNSW
# vector index: with k=5, db.index.vector.queryNodes returned the true top-5
# for only 16 of the 30 benchmark questions, and which neighbours it misses
# depends on how the index happened to be built. Scanning ~3k 384-dim vectors
# costs ~35 ms and gives the same, correct result on every Neo4j instance.
# (The chunk_embedding index is still created by schema_init; it is simply
# not needed for correctness at this corpus size.)
VECTOR_SEARCH_QUERY = """
MATCH (node:Chunk)
WITH node, vector.similarity.cosine(node.embedding, $query_vector) AS score
ORDER BY score DESC, node.chunk_id
LIMIT $k
RETURN node.chunk_id AS chunk_id, node.text AS text, node.entity_name AS entity_name,
       node.entity_attack_id AS entity_attack_id, node.entity_type AS entity_type,
       node.document_id AS document_id, score
ORDER BY score DESC, chunk_id
"""

ENTITIES_FOR_CHUNKS_QUERY = """
UNWIND $attack_ids AS aid
MATCH (n {attack_id: aid})
RETURN DISTINCT n.attack_id AS attack_id, n.name AS name, labels(n)[0] AS entity_type
"""

# ThreatGroup -> Technique <- Mitigation (and the Software-mediated variant).
# `software` is scoped per-technique (only software that connects THIS group
# to THIS technique), not the group's entire arsenal, so graph context stays
# relevant to the specific reasoning path instead of flooding it with
# unrelated facts.
GROUP_TECHNIQUE_MITIGATION_QUERY = """
MATCH (g:ThreatGroup {attack_id: $group_id})
CALL {
    WITH g
    MATCH (g)-[u:USES]->(t:Technique) WHERE u.source IN $sources
    RETURN t AS technique, [] AS via_software
    UNION
    WITH g
    MATCH (g)-[u1:USES]->(sw:Software)-[u2:USES]->(t:Technique)
    WHERE u1.source IN $sources AND u2.source IN $sources
    WITH t, sw ORDER BY sw.attack_id
    RETURN t AS technique, collect(DISTINCT sw) AS via_software
}
WITH g, technique, via_software
OPTIONAL MATCH (m:Mitigation)-[mr:MITIGATES]->(technique) WHERE mr.source IN $sources
WITH g, technique, via_software, m ORDER BY m.attack_id
WITH g, technique, via_software, collect(DISTINCT {attack_id: m.attack_id, name: m.name}) AS mitigations
RETURN g.attack_id AS group_id, g.name AS group_name,
       technique.attack_id AS technique_id, technique.name AS technique_name,
       mitigations,
       [s IN via_software | {attack_id: s.attack_id, name: s.name}] AS software
ORDER BY technique_id, size(software)
LIMIT $limit
"""

BOUNDED_NEIGHBORHOOD_QUERY = """
MATCH (n {attack_id: $attack_id})
CALL apoc.path.subgraphAll(n, {maxLevel: $max_hops, limit: $limit})
YIELD relationships
UNWIND relationships AS r
RETURN startNode(r).attack_id AS src_id, startNode(r).name AS src_name,
       labels(startNode(r))[0] AS src_type, type(r) AS predicate,
       endNode(r).attack_id AS tgt_id, endNode(r).name AS tgt_name,
       labels(endNode(r))[0] AS tgt_type
ORDER BY predicate, src_id, tgt_id
LIMIT $limit
"""

# APOC-free fallback: fixed-shape bounded traversal (<=3 hops) covering the
# reasoning paths this project targets, without requiring the APOC plugin.
# Restricted to the CTI ontology's own relationship types (schemas.Predicate)
# so provenance/indexing edges (MENTIONED_IN, DESCRIBES) -- real in the graph
# but not CTI facts -- never show up as "graph evidence" in a RAG answer.
CTI_PREDICATES = ["USES", "MITIGATES", "ATTRIBUTED_TO", "EXPLOITS"]

GENERIC_BOUNDED_PATHS_QUERY = """
MATCH (n {attack_id: $attack_id})
OPTIONAL MATCH (n)-[r1]-(m1) WHERE type(r1) IN $predicates AND r1.source IN $sources
WITH n, r1 ORDER BY type(r1), startNode(r1).attack_id, endNode(r1).attack_id
WITH n,
     collect(DISTINCT CASE WHEN r1 IS NULL THEN null ELSE {
         src: startNode(r1).attack_id, src_name: startNode(r1).name, src_type: labels(startNode(r1))[0],
         predicate: type(r1),
         tgt: endNode(r1).attack_id, tgt_name: endNode(r1).name, tgt_type: labels(endNode(r1))[0]
     } END) AS hop1_raw
WITH n, [x IN hop1_raw WHERE x IS NOT NULL] AS hop1
OPTIONAL MATCH (n)-[r1b]-(m1b)-[r2]-(m2)
  WHERE type(r1b) IN $predicates AND type(r2) IN $predicates AND m2 <> n
    AND r1b.source IN $sources AND r2.source IN $sources
WITH hop1, r2 ORDER BY type(r2), startNode(r2).attack_id, endNode(r2).attack_id
WITH hop1,
     collect(DISTINCT CASE WHEN r2 IS NULL THEN null ELSE {
         src: startNode(r2).attack_id, src_name: startNode(r2).name, src_type: labels(startNode(r2))[0],
         predicate: type(r2),
         tgt: endNode(r2).attack_id, tgt_name: endNode(r2).name, tgt_type: labels(endNode(r2))[0]
     } END) AS hop2_raw
WITH hop1, [x IN hop2_raw WHERE x IS NOT NULL] AS hop2
RETURN hop1[0..$pool_limit] AS hop1_facts, hop2[0..$pool_limit] AS hop2_facts
"""


def vector_search(client: Neo4jClient, query_vector: list[float], k: int = RETRIEVAL.top_k_chunks) -> list[dict]:
    return client.run(VECTOR_SEARCH_QUERY, {"k": k, "query_vector": query_vector})


# When capping a hub node's facts (e.g. a common technique with 100+ USES
# edges from Software but only 1-2 from a ThreatGroup directly), a plain
# first-N truncation can crowd out the rarer, often more directly relevant
# fact types. Facts are pooled generously then capped client-side in this
# priority order instead of Cypher's arbitrary collection order.
_TYPE_PRIORITY = {"ThreatGroup": 0, "Mitigation": 1, "Campaign": 2, "Software": 3, "Technique": 4}


def _type_priority(fact: dict) -> int:
    return min(
        _TYPE_PRIORITY.get(fact.get("src_type"), 9),
        _TYPE_PRIORITY.get(fact.get("tgt_type"), 9),
    )


def bounded_neighborhood(client: Neo4jClient, attack_id: str,
                          max_hops: int = RETRIEVAL.max_hops,
                          limit: int = RETRIEVAL.neighborhood_facts) -> list[dict]:
    """Bounded multi-hop traversal around a seed entity.

    Default: the APOC-free fixed-shape pattern match below, which behaves the
    same on every Neo4j install. APOC's subgraphAll (true bounded BFS) is
    opt-in via GRAPH_TRAVERSAL_USE_APOC=1, because silently switching paths
    depending on whether a plugin happens to be installed would make GraphRAG
    retrieve different facts in different environments."""
    if RETRIEVAL.use_apoc:
        return client.run(BOUNDED_NEIGHBORHOOD_QUERY, {
            "attack_id": attack_id, "max_hops": max_hops, "limit": limit,
        })
    pool_limit = max(limit * 10, 100)
    rows = client.run(GENERIC_BOUNDED_PATHS_QUERY, {
        "attack_id": attack_id, "pool_limit": pool_limit, "predicates": CTI_PREDICATES,
        "sources": TRUSTED_SOURCES,
    })
    hop1_buckets: dict[int, list[dict]] = {}
    hop2_buckets: dict[int, list[dict]] = {}
    for row in rows:
        for hop, hop_facts, buckets in ((1, row.get("hop1_facts"), hop1_buckets),
                                         (2, row.get("hop2_facts"), hop2_buckets)):
            for f in hop_facts or []:
                if f.get("predicate") is not None:
                    buckets.setdefault(_type_priority(f), []).append(f)

    def round_robin_fill(buckets: dict[int, list[dict]], n: int) -> list[dict]:
        keys = sorted(buckets)
        out: list[dict] = []
        while len(out) < n and any(buckets[k] for k in keys):
            for k in keys:
                if buckets[k]:
                    out.append(buckets[k].pop(0))
                    if len(out) >= n:
                        break
        return out

    # Exhaust direct (1-hop) facts first, round-robinning across entity
    # types so one high-volume type (e.g. Software USES edges on a
    # popular technique) can't crowd out rarer, often more directly
    # relevant types (e.g. the one or two ThreatGroup/Mitigation edges).
    # Only fall back to 2-hop facts if 1-hop evidence runs out.
    facts = round_robin_fill(hop1_buckets, limit)
    if len(facts) < limit:
        facts += round_robin_fill(hop2_buckets, limit - len(facts))
    return facts


def group_technique_mitigation_path(client: Neo4jClient, group_id: str,
                                     limit: int = RETRIEVAL.neighborhood_facts) -> list[dict]:
    """Direct, schema-aware path for the ThreatGroup -> Technique <- Mitigation
    (and ThreatGroup -> Software -> Technique) reasoning shapes this project
    targets. Cheaper and more precise than generic subgraph expansion when the
    question is recognized to be this shape."""
    return client.run(GROUP_TECHNIQUE_MITIGATION_QUERY, {"group_id": group_id, "limit": limit,
                                                         "sources": TRUSTED_SOURCES})


# ---------------------------------------------------------------------------
# Question-focused multi-hop retrieval (used by GraphRAG)
# ---------------------------------------------------------------------------
#
# Instead of expanding a fixed-size neighbourhood around every seed (which
# fills the fact budget with whatever is most connected), the question's
# linked entities (NED) and the entity type it asks for decide which typed
# path to follow, e.g. "mitigations for the techniques PoisonIvy implements"
# -> Software -USES-> Technique <-MITIGATES- Mitigation. Every fact carries
# its edge provenance (source, STIX relationship id, last-modified time,
# confidence) so answers can be traced back to the asserting relationship.

# Edge sources GraphRAG trusts. LLM-extracted edges (source='llm_extraction')
# are kept in the graph for analysis but not used as answer evidence.
TRUSTED_SOURCES = ["mitre_attack_stix"]

_FACT_RETURN = """
RETURN startNode(r).attack_id AS src_id, startNode(r).name AS src_name, labels(startNode(r))[0] AS src_type,
       type(r) AS predicate,
       endNode(r).attack_id AS tgt_id, endNode(r).name AS tgt_name, labels(endNode(r))[0] AS tgt_type,
       r.source AS source, r.stix_relationship_id AS stix_relationship_id,
       toString(r.modified) AS modified, r.confidence AS confidence
ORDER BY src_id, predicate, tgt_id
"""

EDGES_BETWEEN_QUERY = """
MATCH (s)-[r:USES|MITIGATES|ATTRIBUTED_TO]->(t)
WHERE s.attack_id IN $ids AND t.attack_id IN $ids AND r.source IN $sources
""" + _FACT_RETURN

_ALLOWED_LABELS = {"ThreatGroup", "Technique", "Software", "Mitigation", "Campaign"}
_ALLOWED_PREDICATES = {"USES", "MITIGATES", "ATTRIBUTED_TO"}


def _edges_query(predicate: str, label: str, outgoing: bool) -> str:
    # Labels/predicates are whitelisted above; ids and sources stay parameters.
    if predicate not in _ALLOWED_PREDICATES or label not in _ALLOWED_LABELS:
        raise ValueError(f"unsupported path step {predicate}/{label}")
    pattern = f"(s)-[r:{predicate}]->(t:{label})" if outgoing else f"(t:{label})-[r:{predicate}]->(s)"
    return f"MATCH {pattern}\nWHERE s.attack_id IN $ids AND r.source IN $sources\n" + _FACT_RETURN


def edges_from(client: Neo4jClient, ids: list[str], predicate: str, label: str,
               outgoing: bool = True, sources: list[str] = TRUSTED_SOURCES) -> list[dict]:
    """One typed hop from `ids`: outgoing (ids)-[predicate]->(:label) or
    incoming (:label)-[predicate]->(ids)."""
    if not ids:
        return []
    return client.run(_edges_query(predicate, label, outgoing), {"ids": ids, "sources": sources})


def edges_between(client: Neo4jClient, ids: list[str], sources: list[str] = TRUSTED_SOURCES) -> list[dict]:
    return client.run(EDGES_BETWEEN_QUERY, {"ids": ids, "sources": sources}) if len(ids) > 1 else []


def focused_facts(client: Neo4jClient, seeds: dict[str, list[str]], target: str | None,
                  limit: int = RETRIEVAL.max_graph_facts) -> list[dict]:
    """Multi-hop facts answering "which <target> ..." for the linked seed
    entities (`seeds`: label -> attack_ids). Returns [] when the question
    shape isn't recognized, so the caller can fall back to
    bounded_neighborhood()."""
    G, S, T = seeds.get("ThreatGroup", []), seeds.get("Software", []), seeds.get("Technique", [])
    M, C = seeds.get("Mitigation", []), seeds.get("Campaign", [])
    all_ids = sorted({i for ids in seeds.values() for i in ids})
    facts = edges_between(client, all_ids)  # how the named entities relate to each other

    if target == "Mitigation":
        if T:
            techniques = T
        else:
            hop = edges_from(client, S, "USES", "Technique") or edges_from(client, G, "USES", "Technique")
            facts += hop
            techniques = sorted({f["tgt_id"] for f in hop})
        facts += edges_from(client, techniques, "MITIGATES", "Mitigation", outgoing=False)
    elif target == "Technique":
        if S:
            facts += edges_from(client, S, "USES", "Technique")
        elif G:
            facts += edges_from(client, G, "USES", "Technique")
        elif M:
            facts += edges_from(client, M, "MITIGATES", "Technique")
    elif target == "Software":
        facts += edges_from(client, G, "USES", "Software")
        facts += edges_from(client, T, "USES", "Software", outgoing=False)
    elif target == "ThreatGroup":
        facts += edges_from(client, T + S, "USES", "ThreatGroup", outgoing=False)
        facts += edges_from(client, C, "ATTRIBUTED_TO", "ThreatGroup")
    elif target == "Campaign":
        facts += edges_from(client, G, "ATTRIBUTED_TO", "Campaign", outgoing=False)
    if target is None and not facts:
        return []

    out, seen = [], set()
    for f in facts:
        key = (f["src_id"], f["predicate"], f["tgt_id"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out[:limit]


# GDS outputs (written by threatgraph.graph.analytics) added to the prompt.
SEED_ANALYTICS_QUERY = """
UNWIND $ids AS aid
MATCH (n {attack_id: aid}) WHERE n.pagerank IS NOT NULL
CALL (n) {
  MATCH (m) WHERE labels(m)[0] = labels(n)[0] AND m.pagerank > n.pagerank
  RETURN count(m) + 1 AS rank
}
CALL (n) {
  MATCH (m) WHERE labels(m)[0] = labels(n)[0] AND m.pagerank IS NOT NULL
  RETURN count(m) AS of_label
}
CALL (n) {
  MATCH (c) WHERE c.community = n.community
  RETURN count(c) AS community_size
}
RETURN n.attack_id AS attack_id, n.name AS name, labels(n)[0] AS label, n.pagerank AS pagerank,
       rank, of_label, n.degree AS degree, n.community AS community, community_size
ORDER BY attack_id
"""

MITIGATION_COVERAGE_QUERY = """
MATCH (x)-[u:USES]->(t:Technique) WHERE x.attack_id IN $ids AND u.source IN $sources
WITH collect(DISTINCT t) AS techs
UNWIND techs AS t
MATCH (m:Mitigation)-[r:MITIGATES]->(t) WHERE r.source IN $sources
WITH m, count(DISTINCT t) AS covered, size(techs) AS total
RETURN m.attack_id AS attack_id, m.name AS name, covered, total, m.pagerank AS pagerank
ORDER BY covered DESC, pagerank DESC, attack_id LIMIT $k
"""


def graph_analytics_context(client: Neo4jClient, seed_ids: list[str], coverage_for: list[str],
                            k: int = 5) -> dict:
    """PageRank rank/community of each seed and, for group/software seeds,
    the mitigations covering the most of their techniques. Empty when the
    GDS properties have not been written yet (run threatgraph.graph.analytics)."""
    if not seed_ids:
        return {"seeds": [], "coverage": []}
    seeds = client.run(SEED_ANALYTICS_QUERY, {"ids": seed_ids})
    coverage = client.run(MITIGATION_COVERAGE_QUERY, {"ids": coverage_for, "sources": TRUSTED_SOURCES, "k": k}) \
        if coverage_for and seeds else []
    return {"seeds": seeds, "coverage": coverage}

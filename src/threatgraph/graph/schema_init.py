"""Initialize Neo4j constraints, lookup indexes, and the chunk vector index.

Runs schema.cypher (constraints + name indexes) statement by statement, then
creates the Chunk.embedding vector index with dimensions taken from the
active embedding config, so it always matches whatever model actually wrote
the embeddings.
"""
from __future__ import annotations

from threatgraph.config import EMBEDDING, REPO_ROOT
from threatgraph.graph.neo4j_client import Neo4jClient

SCHEMA_CYPHER_PATH = REPO_ROOT / "schema.cypher"


def _statements(cypher_text: str) -> list[str]:
    statements = []
    for raw in cypher_text.split(";"):
        lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("//")]
        stmt = "\n".join(lines).strip()
        if stmt:
            statements.append(stmt)
    return statements


def init_schema(client: Neo4jClient | None = None) -> None:
    owns_client = client is None
    client = client or Neo4jClient()
    try:
        cypher_text = SCHEMA_CYPHER_PATH.read_text(encoding="utf-8")
        for stmt in _statements(cypher_text):
            client.run(stmt)

        try:
            # Neo4j 5.15+ DDL syntax.
            client.run(
                "CREATE VECTOR INDEX chunk_embedding IF NOT EXISTS "
                "FOR (n:Chunk) ON n.embedding "
                "OPTIONS {indexConfig: {`vector.dimensions`: $dims, "
                "`vector.similarity_function`: 'cosine'}}",
                {"dims": EMBEDDING.dimensions},
            )
        except Exception:
            # Neo4j 5.11-5.14 procedure-based API (no IF NOT EXISTS support).
            existing = client.run("SHOW INDEXES YIELD name WHERE name = 'chunk_embedding' RETURN name")
            if not existing:
                client.run(
                    "CALL db.index.vector.createNodeIndex("
                    "'chunk_embedding', 'Chunk', 'embedding', $dims, 'cosine')",
                    {"dims": EMBEDDING.dimensions},
                )
    finally:
        if owns_client:
            client.close()


if __name__ == "__main__":
    init_schema()
    print(f"Schema initialized (vector index dimensions={EMBEDDING.dimensions}).")

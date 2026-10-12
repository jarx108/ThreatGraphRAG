"""Thin Neo4j driver wrapper. All queries elsewhere in this project are
parameterized Cypher (no string-built queries) to avoid injection."""
from __future__ import annotations

from contextlib import contextmanager

from neo4j import GraphDatabase

from threatgraph.config import NEO4J


class Neo4jClient:
    def __init__(self, uri: str = NEO4J.uri, user: str = NEO4J.user,
                 password: str = NEO4J.password, database: str = NEO4J.database):
        # Server notifications (e.g. "property key does not exist" before an
        # optional pipeline step has run) are informational; keep logs clean.
        self._driver = GraphDatabase.driver(uri, auth=(user, password), notifications_min_severity="OFF")
        self._database = database

    def close(self) -> None:
        self._driver.close()

    def run(self, query: str, parameters: dict | None = None) -> list[dict]:
        with self._driver.session(database=self._database) as session:
            result = session.run(query, parameters or {})
            return [record.data() for record in result]

    def run_write_batch(self, query: str, rows: list[dict], batch_size: int = 500,
                        params: dict | None = None) -> None:
        """Run one UNWIND-based parameterized query over `rows` in batches
        (`params` are extra query parameters shared by every batch)."""
        with self._driver.session(database=self._database) as session:
            for i in range(0, len(rows), batch_size):
                batch = rows[i:i + batch_size]
                session.run(query, {**(params or {}), "rows": batch})

    def verify_connectivity(self) -> bool:
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    @contextmanager
    def session(self):
        with self._driver.session(database=self._database) as s:
            yield s

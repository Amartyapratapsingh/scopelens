"""Durable cleanup intent journal. Production may inject its PostgreSQL implementation."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Protocol


class CleanupJournal(Protocol):
    def claim(self, recipe_id: str, resource_id: str) -> bool: ...
    def mark(self, recipe_id: str, resource_id: str, state: str) -> None: ...
    def state(self, recipe_id: str, resource_id: str) -> str | None: ...


class SQLiteCleanupJournal:
    """Fixture/offline runner journal survives restarts and serializes mutation claims.

    Never stores credentials or response bodies. One pending/failed cleanup prevents new
    mutation of that recipe/resource until explicit cleanup recovery verifies baseline.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS cleanup(recipe TEXT, resource TEXT, state TEXT NOT NULL, PRIMARY KEY(recipe,resource))"
            )

    def connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def claim(self, recipe_id: str, resource_id: str) -> bool:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                "SELECT 1 FROM cleanup WHERE resource=? AND state != 'clean'", (resource_id,)
            ).fetchone()
            if active:
                return False
            connection.execute(
                "INSERT INTO cleanup VALUES (?,?,?) ON CONFLICT(recipe,resource) DO UPDATE SET state=excluded.state",
                (recipe_id, resource_id, "pending"),
            )
        return True

    def mark(self, recipe_id: str, resource_id: str, state: str) -> None:
        if state not in {"pending", "mutation_sent", "cleanup_failed", "clean"}:
            raise ValueError("unknown cleanup state")
        with self.connect() as connection:
            result = connection.execute(
                "UPDATE cleanup SET state=? WHERE recipe=? AND resource=?",
                (state, recipe_id, resource_id),
            )
            if result.rowcount != 1:
                raise ValueError("cleanup intent missing")

    def state(self, recipe_id: str, resource_id: str) -> str | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT state FROM cleanup WHERE recipe=? AND resource=?", (recipe_id, resource_id)
            ).fetchone()
        return row[0] if row else None

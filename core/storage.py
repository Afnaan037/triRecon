"""
storage.py — Optional SQLite scan-history persistence for TriRecon.

Each scan run is stored as a JSON blob with a timestamp.
The database is created automatically at first use.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = Path.home() / ".trirecon" / "history.db"


class ScanStorage:
    """
    Lightweight SQLite wrapper to persist and retrieve TriRecon scan history.

    Usage
    -----
    ::

        store = ScanStorage()                # uses default ~/.trirecon/history.db
        run_id = store.save(target, ports, discovery, paths)
        all_runs = store.list_runs()
        run = store.get_run(run_id)
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection = sqlite3.connect(str(self.db_path))
        self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _ensure_schema(self) -> None:
        """Create tables if they don't yet exist."""
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT    NOT NULL,
                scanned_at  TEXT    NOT NULL,
                ports_json  TEXT    NOT NULL,
                discovery_json TEXT NOT NULL,
                paths_json  TEXT    NOT NULL
            )
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(
        self,
        target: str,
        ports: list[dict],
        discovery: dict,
        paths: list[dict],
    ) -> int:
        """
        Persist a scan run to the database.

        Returns
        -------
        int
            The auto-incremented row ID of the new run.
        """
        now = datetime.utcnow().isoformat() + "Z"
        cursor = self._conn.execute(
            """
            INSERT INTO scan_runs
                (target, scanned_at, ports_json, discovery_json, paths_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                target,
                now,
                json.dumps(ports),
                json.dumps(discovery),
                json.dumps(paths),
            ),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_runs(self, limit: int = 50) -> list[dict]:
        """
        Return the *limit* most recent scan runs (summary only — no full JSON blobs).
        """
        cursor = self._conn.execute(
            "SELECT id, target, scanned_at FROM scan_runs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {"id": row[0], "target": row[1], "scanned_at": row[2]}
            for row in cursor.fetchall()
        ]

    def get_run(self, run_id: int) -> Optional[dict]:
        """
        Return the full scan data for a specific run ID.

        Returns None if the ID doesn't exist.
        """
        cursor = self._conn.execute(
            "SELECT id, target, scanned_at, ports_json, discovery_json, paths_json "
            "FROM scan_runs WHERE id = ?",
            (run_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return {
            "id": row[0],
            "target": row[1],
            "scanned_at": row[2],
            "ports": json.loads(row[3]),
            "host_discovery": json.loads(row[4]),
            "found_paths": json.loads(row[5]),
        }

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()

    def __enter__(self) -> "ScanStorage":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

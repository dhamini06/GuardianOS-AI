"""GuardianOS persistence layer.

On-host SQLite storage for the two durable artifacts of the pipeline: raw
events (telemetry) and threat reports (detection + explanation + response).
Writes are batched per ingest tick / report so the file is a faithful,
queryable record of what the agent observed and decided.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from backend.core.analysis import ThreatReport
from backend.core.events import KernelEvent
from backend.core.logging import get_logger

logger = get_logger("storage.sqlite")


class SqliteStorage:
    """Append-only-friendly SQLite store for events and threat reports."""

    def __init__(self, db_path: str | Path, *, max_events: int = 100_000) -> None:
        self.db_path = Path(db_path)
        self.max_events = max_events
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # The pipeline driver writes from a worker thread while API requests
        # read; SQLite itself serialises access, so allow cross-thread use.
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                kind TEXT,
                timestamp REAL,
                pid INTEGER,
                ppid INTEGER,
                exe TEXT,
                cmdline TEXT,
                details TEXT
            );
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                timestamp REAL,
                severity TEXT,
                pid INTEGER,
                exe TEXT,
                anomaly_score REAL,
                confidence REAL,
                flagged INTEGER,
                summary TEXT,
                explanation TEXT,
                actions TEXT
            );
            """
        )
        self._conn.commit()

    # -- writes -----------------------------------------------------------
    def save_events(self, events: list[KernelEvent]) -> int:
        """Persist events; prunes the oldest once the cap is exceeded."""
        if not events:
            return 0
        rows = [
            (
                e.event_id,
                e.kind.value,
                e.timestamp,
                e.pid,
                e.ppid,
                e.exe,
                json.dumps(list(e.cmdline)),
                json.dumps(e.details, default=str),
            )
            for e in events
        ]
        self._conn.executemany(
            "INSERT INTO events (event_id, kind, timestamp, pid, ppid, exe, cmdline, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        if self.max_events:
            self._conn.execute(
                "DELETE FROM events WHERE seq NOT IN ("
                "  SELECT seq FROM events ORDER BY seq DESC LIMIT ?)",
                (self.max_events,),
            )
        self._conn.commit()
        return len(rows)

    def save_report(self, report: ThreatReport) -> None:
        data = report.to_dict()
        self._conn.execute(
            "INSERT OR REPLACE INTO reports "
            "(report_id, timestamp, severity, pid, exe, anomaly_score, confidence, flagged, summary, explanation, actions) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                data["report_id"],
                data["timestamp"],
                data["detection"]["severity"],
                data["detection"]["pid"],
                data["detection"]["exe"],
                data["detection"]["anomaly_score"],
                data["detection"]["confidence"],
                int(data["detection"]["flagged"]),
                data["explanation"]["summary"],
                json.dumps(data["explanation"]),
                json.dumps(data["actions"]),
            ),
        )
        self._conn.commit()

    # -- reads ------------------------------------------------------------
    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT event_id, kind, timestamp, pid, ppid, exe, cmdline, details "
            "FROM events ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                **dict(row),
                "cmdline": json.loads(row["cmdline"] or "[]"),
                "details": json.loads(row["details"] or "{}"),
            }
            for row in rows
        ]

    def recent_reports(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT report_id, timestamp, severity, pid, exe, anomaly_score, confidence, flagged, summary, explanation, actions "
            "FROM reports ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "report_id": row["report_id"],
                "timestamp": row["timestamp"],
                "severity": row["severity"],
                "pid": row["pid"],
                "exe": row["exe"],
                "anomaly_score": row["anomaly_score"],
                "confidence": row["confidence"],
                "flagged": bool(row["flagged"]),
                "summary": row["summary"],
                "explanation": json.loads(row["explanation"]),
                "actions": json.loads(row["actions"]),
            }
            for row in rows
        ]

    def counts(self) -> dict[str, int]:
        events = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        reports = self._conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        return {"events": events, "reports": reports}

    def close(self) -> None:
        self._conn.close()

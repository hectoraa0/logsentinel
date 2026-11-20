"""SQLite persistence. All queries are parameterized (no string-built SQL)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path

from .models import SEVERITIES, Alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    mitre       TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    count       INTEGER NOT NULL,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    description TEXT    NOT NULL,
    evidence    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
"""

# Fixed, literal queries: nothing user-controlled is ever concatenated into SQL.
_SELECT_ALL = (
    "SELECT * FROM alerts "
    "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 ELSE 3 END, count DESC, id LIMIT ?"
)
_SELECT_BY_SEVERITY = (
    "SELECT * FROM alerts WHERE severity = ? "
    "ORDER BY count DESC, id LIMIT ?"
)


def replace_alerts(db_path: str, alerts: Iterable[Alert]) -> int:
    """Replace the stored alerts with a fresh analysis run. Returns rows saved."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    rows = [
        (
            a.rule_id,
            a.title,
            a.severity,
            a.mitre,
            a.ip,
            a.count,
            a.first_seen.isoformat(),
            a.last_seen.isoformat(),
            a.description,
            json.dumps(a.evidence),
        )
        for a in alerts
    ]
    with closing(sqlite3.connect(db_path)) as conn:
        conn.executescript(_SCHEMA)
        with conn:
            conn.execute("DELETE FROM alerts")
            conn.executemany(
                "INSERT INTO alerts (rule_id, title, severity, mitre, ip, count, "
                "first_seen, last_seen, description, evidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
    return len(rows)


def _open_readonly(db_path: str) -> sqlite3.Connection | None:
    path = Path(db_path)
    if not path.is_file():
        return None
    conn = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_alerts(db_path: str, severity: str | None = None, limit: int = 500) -> list[dict]:
    if severity is not None and severity not in SEVERITIES:
        raise ValueError(f"unknown severity: {severity!r}")
    conn = _open_readonly(db_path)
    if conn is None:
        return []
    with closing(conn):
        try:
            if severity:
                rows = conn.execute(_SELECT_BY_SEVERITY, (severity, int(limit)))
            else:
                rows = conn.execute(_SELECT_ALL, (int(limit),))
            rows = rows.fetchall()
        except sqlite3.OperationalError:  # table not created yet
            return []
    result = []
    for row in rows:
        item = dict(row)
        item["evidence"] = json.loads(item["evidence"])
        result.append(item)
    return result


def fetch_stats(db_path: str) -> dict:
    stats = {"total": 0, "by_severity": {s: 0 for s in SEVERITIES}, "unique_ips": 0}
    conn = _open_readonly(db_path)
    if conn is None:
        return stats
    with closing(conn):
        try:
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
            ):
                stats["by_severity"][row["severity"]] = row["n"]
                stats["total"] += row["n"]
            stats["unique_ips"] = conn.execute(
                "SELECT COUNT(DISTINCT ip) FROM alerts"
            ).fetchone()[0]
        except sqlite3.OperationalError:
            pass
    return stats

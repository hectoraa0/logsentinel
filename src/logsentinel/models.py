"""Data structures shared by parsers, detectors, storage and the web UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Event:
    """One normalized log event, regardless of the log source."""

    ts: datetime
    source: str  # "ssh" or "nginx"
    kind: str  # ssh: failed_login | accepted_login; nginx: request
    ip: str
    user: str | None = None
    status: int | None = None
    path: str | None = None
    user_agent: str | None = None
    raw: str = ""


@dataclass
class Alert:
    """A detection produced by one rule for one source IP."""

    rule_id: str
    title: str
    severity: str
    mitre: str
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    description: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": self.mitre,
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "description": self.description,
            "evidence": list(self.evidence),
        }

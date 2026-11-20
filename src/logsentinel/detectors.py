"""Detection rules. Each rule maps to a MITRE ATT&CK technique.

Rules are deliberately simple and explainable: every alert carries the
evidence (sample log lines) that triggered it, which is what a SOC analyst
needs to triage quickly.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote_plus

from .models import SEVERITY_RANK, Alert, Event


@dataclass(frozen=True)
class Thresholds:
    ssh_bruteforce_attempts: int = 5
    ssh_bruteforce_window_s: int = 60
    ssh_spray_users: int = 5
    ssh_spray_window_s: int = 600
    ssh_success_after_failures: int = 5
    ssh_success_window_s: int = 600
    web_404_count: int = 15
    web_404_window_s: int = 60
    web_sensitive_paths: int = 3


# ---------------------------------------------------------------- patterns
SQLI_RE = re.compile(
    r"(union\s+select|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'\s*or\s*'"
    r"|sleep\s*\(\s*\d|benchmark\s*\(|information_schema|;\s*drop\s+table)",
    re.IGNORECASE,
)
TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)", re.IGNORECASE
)
SENSITIVE_RE = re.compile(
    r"(/\.env\b|/\.git(/|$)|/\.svn|wp-config|/phpmyadmin|/\.aws/credentials"
    r"|id_rsa|\.bak$|/backup\.(zip|sql|tar))",
    re.IGNORECASE,
)
BAD_USER_AGENTS = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "dirbuster",
    "wfuzz",
    "nuclei",
    "hydra",
    "zgrab",
)


def _decode(path: str) -> str:
    """URL-decode twice so double-encoded payloads (%252e%252e) are caught."""
    return unquote_plus(unquote_plus(path))


# ---------------------------------------------------------------- helpers
def _densest_window(
    times: Iterable[datetime], window_s: int, threshold: int
) -> tuple[datetime, datetime, int] | None:
    """Find the busiest sliding window. Returns (start, end, count) or None."""
    ordered = sorted(times)
    best: tuple[datetime, datetime, int] | None = None
    left = 0
    for right, t in enumerate(ordered):
        while (t - ordered[left]).total_seconds() > window_s:
            left += 1
        n = right - left + 1
        if n >= threshold and (best is None or n > best[2]):
            best = (ordered[left], t, n)
    return best


def _most_distinct_in_window(
    events: list[Event], window_s: int, threshold: int, key: Callable[[Event], str]
) -> tuple[datetime, datetime, int] | None:
    """Window with the most distinct key values (e.g. distinct usernames)."""
    ordered = sorted(events, key=lambda e: e.ts)
    counts: Counter[str] = Counter()
    best: tuple[datetime, datetime, int] | None = None
    left = 0
    for ev in ordered:
        counts[key(ev)] += 1
        while (ev.ts - ordered[left].ts).total_seconds() > window_s:
            k = key(ordered[left])
            counts[k] -= 1
            if counts[k] == 0:
                del counts[k]
            left += 1
        if len(counts) >= threshold and (best is None or len(counts) > best[2]):
            best = (ordered[left].ts, ev.ts, len(counts))
    return best


def _by_ip(events: Iterable[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        grouped[ev.ip].append(ev)
    return grouped


def _sample(events: Iterable[Event], limit: int = 5) -> list[str]:
    return [e.raw for e in list(events)[:limit]]


# ---------------------------------------------------------------- SSH rules
def detect_ssh_bruteforce(events: list[Event], t: Thresholds) -> list[Alert]:
    failed = [e for e in events if e.source == "ssh" and e.kind == "failed_login"]
    alerts = []
    for ip, evs in _by_ip(failed).items():
        hit = _densest_window(
            (e.ts for e in evs), t.ssh_bruteforce_window_s, t.ssh_bruteforce_attempts
        )
        if hit:
            start, end, n = hit
            alerts.append(
                Alert(
                    rule_id="SSH-001",
                    title="SSH brute force",
                    severity="high",
                    mitre="T1110.001 Password Guessing",
                    ip=ip,
                    count=n,
                    first_seen=start,
                    last_seen=end,
                    description=(
                        f"{n} failed SSH logins from one IP within "
                        f"{t.ssh_bruteforce_window_s}s."
                    ),
                    evidence=_sample(evs),
                )
            )
    return alerts


def detect_ssh_spray(events: list[Event], t: Thresholds) -> list[Alert]:
    failed = [e for e in events if e.source == "ssh" and e.kind == "failed_login"]
    alerts = []
    for ip, evs in _by_ip(failed).items():
        hit = _most_distinct_in_window(
            evs, t.ssh_spray_window_s, t.ssh_spray_users, lambda e: e.user or ""
        )
        if hit:
            start, end, n = hit
            alerts.append(
                Alert(
                    rule_id="SSH-002",
                    title="SSH password spraying",
                    severity="high",
                    mitre="T1110.003 Password Spraying",
                    ip=ip,
                    count=n,
                    first_seen=start,
                    last_seen=end,
                    description=(
                        f"One IP tried {n} different usernames within "
                        f"{t.ssh_spray_window_s // 60} minutes."
                    ),
                    evidence=_sample(evs),
                )
            )
    return alerts


def detect_ssh_success_after_failures(events: list[Event], t: Thresholds) -> list[Alert]:
    ssh = [e for e in events if e.source == "ssh"]
    alerts = []
    for ip, evs in _by_ip(ssh).items():
        evs.sort(key=lambda e: e.ts)
        for ev in evs:
            if ev.kind != "accepted_login":
                continue
            prior = [
                e
                for e in evs
                if e.kind == "failed_login"
                and 0 <= (ev.ts - e.ts).total_seconds() <= t.ssh_success_window_s
            ]
            if len(prior) >= t.ssh_success_after_failures:
                alerts.append(
                    Alert(
                        rule_id="SSH-003",
                        title="Successful login after repeated failures",
                        severity="critical",
                        mitre="T1078 Valid Accounts",
                        ip=ip,
                        count=len(prior) + 1,
                        first_seen=prior[0].ts,
                        last_seen=ev.ts,
                        description=(
                            f"Account '{ev.user}' logged in from {ip} right after "
                            f"{len(prior)} failed attempts. Likely compromised."
                        ),
                        evidence=_sample(prior, 3) + [ev.raw],
                    )
                )
                break  # one alert per IP is enough
    return alerts


# ---------------------------------------------------------------- web rules
def detect_web_404_flood(events: list[Event], t: Thresholds) -> list[Alert]:
    misses = [e for e in events if e.source == "nginx" and e.status == 404]
    alerts = []
    for ip, evs in _by_ip(misses).items():
        hit = _densest_window(
            (e.ts for e in evs), t.web_404_window_s, t.web_404_count
        )
        if hit:
            start, end, n = hit
            alerts.append(
                Alert(
                    rule_id="WEB-001",
                    title="Directory/endpoint enumeration",
                    severity="medium",
                    mitre="T1595.003 Wordlist Scanning",
                    ip=ip,
                    count=n,
                    first_seen=start,
                    last_seen=end,
                    description=(
                        f"{n} HTTP 404 responses to one IP within "
                        f"{t.web_404_window_s}s: typical of a wordlist scanner."
                    ),
                    evidence=_sample(evs),
                )
            )
    return alerts


def _pattern_rule(
    events: list[Event],
    matcher: Callable[[Event], bool],
    *,
    rule_id: str,
    title: str,
    severity: str,
    mitre: str,
    describe: Callable[[int], str],
    min_hits: int = 1,
) -> list[Alert]:
    web = [e for e in events if e.source == "nginx" and matcher(e)]
    alerts = []
    for ip, evs in _by_ip(web).items():
        if len(evs) < min_hits:
            continue
        evs.sort(key=lambda e: e.ts)
        alerts.append(
            Alert(
                rule_id=rule_id,
                title=title,
                severity=severity,
                mitre=mitre,
                ip=ip,
                count=len(evs),
                first_seen=evs[0].ts,
                last_seen=evs[-1].ts,
                description=describe(len(evs)),
                evidence=_sample(evs),
            )
        )
    return alerts


def detect_sqli(events: list[Event], t: Thresholds) -> list[Alert]:
    return _pattern_rule(
        events,
        lambda e: bool(SQLI_RE.search(_decode(e.path or ""))),
        rule_id="WEB-002",
        title="SQL injection attempt",
        severity="high",
        mitre="T1190 Exploit Public-Facing Application",
        describe=lambda n: f"{n} requests contained SQL injection patterns.",
    )


def detect_traversal(events: list[Event], t: Thresholds) -> list[Alert]:
    return _pattern_rule(
        events,
        lambda e: bool(TRAVERSAL_RE.search(_decode(e.path or ""))),
        rule_id="WEB-003",
        title="Path traversal attempt",
        severity="high",
        mitre="T1190 Exploit Public-Facing Application",
        describe=lambda n: f"{n} requests tried to read files outside the web root.",
    )


def detect_bad_user_agent(events: list[Event], t: Thresholds) -> list[Alert]:
    return _pattern_rule(
        events,
        lambda e: any(tool in (e.user_agent or "").lower() for tool in BAD_USER_AGENTS),
        rule_id="WEB-004",
        title="Known attack tool user-agent",
        severity="medium",
        mitre="T1595.002 Vulnerability Scanning",
        describe=lambda n: f"{n} requests came from a known scanner/attack tool.",
    )


def detect_sensitive_probe(events: list[Event], t: Thresholds) -> list[Alert]:
    """Needs several *distinct* sensitive paths from one IP to avoid noise."""
    hits = [
        e
        for e in events
        if e.source == "nginx" and SENSITIVE_RE.search(_decode(e.path or ""))
    ]
    alerts = []
    for ip, evs in _by_ip(hits).items():
        distinct = {e.path for e in evs}
        if len(distinct) < t.web_sensitive_paths:
            continue
        evs.sort(key=lambda e: e.ts)
        alerts.append(
            Alert(
                rule_id="WEB-005",
                title="Sensitive file probing",
                severity="medium",
                mitre="T1595 Active Scanning",
                ip=ip,
                count=len(distinct),
                first_seen=evs[0].ts,
                last_seen=evs[-1].ts,
                description=(
                    f"{len(distinct)} different sensitive paths requested "
                    "(.env, .git, backups, admin panels)."
                ),
                evidence=_sample(evs),
            )
        )
    return alerts


RULES: tuple[Callable[[list[Event], Thresholds], list[Alert]], ...] = (
    detect_ssh_bruteforce,
    detect_ssh_spray,
    detect_ssh_success_after_failures,
    detect_web_404_flood,
    detect_sqli,
    detect_traversal,
    detect_bad_user_agent,
    detect_sensitive_probe,
)


def analyze(events: list[Event], thresholds: Thresholds | None = None) -> list[Alert]:
    """Run all rules. Result is sorted: most severe first, then biggest count."""
    t = thresholds or Thresholds()
    alerts: list[Alert] = []
    for rule in RULES:
        alerts.extend(rule(events, t))
    alerts.sort(key=lambda a: (SEVERITY_RANK[a.severity], -a.count, a.ip))
    return alerts

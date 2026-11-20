"""Parsers that turn raw log lines into normalized Event objects.

Supported formats:
  * OpenSSH messages in syslog format (Debian/Ubuntu /var/log/auth.log)
  * nginx / Apache "combined" access log format
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from .models import Event

_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_SSH_FAILED_RE = re.compile(
    r"^Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)
_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)

_NGINX_RE = re.compile(
    r"^(?P<ip>[0-9A-Fa-f:.]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_ssh_line(line: str, year: int) -> Event | None:
    """Parse one auth.log line. Returns None if it is not a login event."""
    m = _SYSLOG_RE.match(line.rstrip("\n"))
    if not m:
        return None
    msg = m.group("msg")
    failed = _SSH_FAILED_RE.match(msg)
    accepted = None if failed else _SSH_ACCEPTED_RE.match(msg)
    hit = failed or accepted
    if not hit:
        return None
    try:
        ts = datetime.strptime(
            f"{year} {m.group('mon')} {m.group('day')} {m.group('time')}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return Event(
        ts=ts,
        source="ssh",
        kind="failed_login" if failed else "accepted_login",
        ip=hit.group("ip"),
        user=hit.group("user"),
        raw=line.rstrip("\n"),
    )


def parse_nginx_line(line: str) -> Event | None:
    """Parse one combined-format access log line."""
    m = _NGINX_RE.match(line.rstrip("\n"))
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return Event(
        ts=ts.astimezone(timezone.utc),
        source="nginx",
        kind="request",
        ip=m.group("ip"),
        status=int(m.group("status")),
        path=m.group("path"),
        user_agent=m.group("ua"),
        raw=line.rstrip("\n"),
    )


def _read_lines(path: str) -> Iterator[str]:
    with open(path, encoding="utf-8", errors="replace") as handle:
        yield from handle


def parse_ssh_lines(lines: Iterable[str], year: int) -> tuple[list[Event], int]:
    """Returns (events, number_of_lines_that_were_not_login_events)."""
    events: list[Event] = []
    skipped = 0
    for line in lines:
        ev = parse_ssh_line(line, year)
        if ev is None:
            skipped += 1
        else:
            events.append(ev)
    return events, skipped


def parse_nginx_lines(lines: Iterable[str]) -> tuple[list[Event], int]:
    events: list[Event] = []
    skipped = 0
    for line in lines:
        ev = parse_nginx_line(line)
        if ev is None:
            skipped += 1
        else:
            events.append(ev)
    return events, skipped


def parse_ssh_file(path: str, year: int) -> tuple[list[Event], int]:
    return parse_ssh_lines(_read_lines(path), year)


def parse_nginx_file(path: str) -> tuple[list[Event], int]:
    return parse_nginx_lines(_read_lines(path))

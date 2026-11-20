#!/usr/bin/env python3
"""Generate realistic, deterministic sample logs with several attack scenarios.

Only RFC 5737 documentation IP ranges are used (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), so the data can never point at a real host.

Usage: python scripts/generate_sample_logs.py [output_dir] [--seed N]
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = datetime(2026, 11, 18, 8, 0, 0, tzinfo=timezone.utc)

BENIGN_IPS = ["192.0.2.10", "192.0.2.11", "192.0.2.25", "192.0.2.40", "192.0.2.77"]
BENIGN_PATHS = ["/", "/index.html", "/api/items", "/api/items/42", "/static/app.css", "/login"]
BENIGN_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"

SPRAY_USERS = [
    "root", "admin", "test", "oracle", "postgres", "ubuntu", "git",
    "ftpuser", "deploy", "jenkins", "user", "guest", "support", "backup",
]
WORDLIST = [
    "admin", "login", "backup", "old", "test", "dev", "staging", "config", "uploads",
    "images", "tmp", "private", "api/v1", "api/v2", "dashboard", "server-status",
    "console", "manager", "cgi-bin", "static", "assets", "files", "docs", "db",
]


def ssh_line(ts: datetime, pid: int, msg: str) -> tuple[datetime, str]:
    stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
    return ts, f"{stamp} web01 sshd[{pid}]: {msg}"


def web_line(ts, ip, path, status, ua, method="GET"):
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = random.randint(120, 5000)
    return ts, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def build_auth(rng: random.Random) -> list[tuple[datetime, str]]:
    lines = []
    # Normal activity: admins logging in now and then.
    for i in range(18):
        ts = BASE + timedelta(minutes=rng.randint(0, 600))
        user = rng.choice(["alice", "bob"])
        ip = rng.choice(BENIGN_IPS)
        lines.append(ssh_line(ts, 2000 + i, f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 60000)} ssh2"))
    # Benign typo: 2 failures then success (must NOT alert).
    t0 = BASE + timedelta(hours=3)
    for i in range(2):
        lines.append(ssh_line(t0 + timedelta(seconds=5 * i), 2100 + i, f"Failed password for carol from 192.0.2.40 port {41000 + i} ssh2"))
    lines.append(ssh_line(t0 + timedelta(seconds=15), 2103, "Accepted password for carol from 192.0.2.40 port 41002 ssh2"))

    # Attack 1: classic brute force on root, 1 attempt/second.
    t0 = BASE + timedelta(hours=2)
    for i in range(45):
        lines.append(ssh_line(t0 + timedelta(seconds=i), 3000 + i, f"Failed password for root from 203.0.113.10 port {50000 + i} ssh2"))

    # Attack 2: brute force that SUCCEEDS (the dangerous one).
    t0 = BASE + timedelta(hours=4, minutes=30)
    for i in range(12):
        lines.append(ssh_line(t0 + timedelta(seconds=7 * i), 3200 + i, f"Failed password for admin from 203.0.113.77 port {52000 + i} ssh2"))
    lines.append(ssh_line(t0 + timedelta(seconds=7 * 12 + 3), 3300, "Accepted password for admin from 203.0.113.77 port 52100 ssh2"))

    # Attack 3: password spraying, slow, one attempt per username.
    t0 = BASE + timedelta(hours=5)
    for i, user in enumerate(SPRAY_USERS):
        prefix = "invalid user " if user not in ("root", "admin", "git", "ubuntu") else ""
        lines.append(ssh_line(t0 + timedelta(seconds=25 * i), 3400 + i, f"Failed password for {prefix}{user} from 198.51.100.23 port {53000 + i} ssh2"))

    # Noise that is not a login event.
    for i in range(10):
        ts = BASE + timedelta(minutes=rng.randint(0, 600))
        lines.append((ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 sshd[{1000 + i}]: Connection closed by 192.0.2.10 port {rng.randint(40000, 60000)} [preauth]"))
    return lines


def build_nginx(rng: random.Random) -> list[tuple[datetime, str]]:
    lines = []
    # Normal traffic.
    for _ in range(400):
        ts = BASE + timedelta(seconds=rng.randint(0, 36000))
        status = rng.choices([200, 304, 404], weights=[88, 10, 2])[0]
        lines.append(web_line(ts, rng.choice(BENIGN_IPS), rng.choice(BENIGN_PATHS), status, BENIGN_UA))

    # Attack 4: wordlist scanner (gobuster) + sensitive file probing.
    t0 = BASE + timedelta(hours=2, minutes=5)
    ua = "gobuster/3.6"
    for i in range(70):
        word = WORDLIST[i % len(WORDLIST)] + ("" if i < len(WORDLIST) else f"{i}")
        lines.append(web_line(t0 + timedelta(milliseconds=500 * i), "203.0.113.50", f"/{word}", 404, ua))
    for j, path in enumerate(["/.env", "/.git/config", "/wp-config.php.bak", "/phpmyadmin/"]):
        lines.append(web_line(t0 + timedelta(seconds=40 + j), "203.0.113.50", path, rng.choice([403, 404]), ua))

    # Attack 5: SQL injection + path traversal with sqlmap.
    t0 = BASE + timedelta(hours=6)
    ua = "sqlmap/1.7.11#stable (https://sqlmap.org)"
    sqli = [
        "/products?id=1%27%20OR%20%271%27%3D%271",
        "/products?id=1%20UNION%20SELECT%20null%2Cversion%28%29--",
        "/products?id=1%20AND%20SLEEP%285%29",
        "/search?q=%27%3B%20DROP%20TABLE%20users%3B--",
    ]
    for i, path in enumerate(sqli):
        lines.append(web_line(t0 + timedelta(seconds=2 * i), "198.51.100.99", path, rng.choice([200, 500]), ua))
    traversal = [
        "/download?file=../../../../etc/passwd",
        "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/download?file=..%252f..%252f..%252fetc%252fshadow",
    ]
    for i, path in enumerate(traversal):
        lines.append(web_line(t0 + timedelta(seconds=20 + 2 * i), "198.51.100.99", path, 400, ua))

    # Benign: a visitor hits a few broken links over the day (must NOT alert).
    for i in range(4):
        lines.append(web_line(BASE + timedelta(hours=i * 2), "192.0.2.77", f"/old-page-{i}", 404, BENIGN_UA))
    return lines


def write(path: Path, lines: list[tuple[datetime, str]]) -> None:
    lines.sort(key=lambda item: item[0])
    path.write_text("\n".join(text for _, text in lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", nargs="?", default="data/sample")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)  # web_line() uses the global RNG for response sizes
    rng = random.Random(args.seed)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    write(out / "auth.log", build_auth(rng))
    write(out / "nginx_access.log", build_nginx(rng))
    print(f"wrote {out / 'auth.log'} and {out / 'nginx_access.log'}")


if __name__ == "__main__":
    main()

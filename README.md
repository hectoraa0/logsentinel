# LogSentinel

A small, dependency-free **SIEM-style log analyzer**. It reads SSH (`auth.log`) and web server
(nginx/Apache combined) logs, detects common attacks, maps every detection to
**MITRE ATT&CK**, stores the results in SQLite and shows them in a read-only web dashboard.

Built to practice the full path from raw logs to a triaged alert, and to ship it the way a
real service is shipped: tests, CI, a hardened container and a security-minded web UI.

```
 auth.log ─┐                                        ┌─> CLI table / JSON
           ├─> parsers ─> detection rules ─> SQLite ─┤
nginx.log ─┘   (events)    (MITRE-mapped)            └─> web dashboard (/api/*)
```

## What it detects

| Rule     | Detection                                  | Severity | MITRE ATT&CK                  |
|----------|--------------------------------------------|----------|-------------------------------|
| SSH-001  | Brute force: ≥5 failed logins / 60 s / IP   | high     | T1110.001 Password Guessing   |
| SSH-002  | Password spraying: ≥5 usernames / 10 min    | high     | T1110.003 Password Spraying   |
| SSH-003  | Successful login right after ≥5 failures    | critical | T1078 Valid Accounts          |
| WEB-001  | Endpoint enumeration: ≥15 × HTTP 404 / 60 s | medium   | T1595.003 Wordlist Scanning   |
| WEB-002  | SQL injection patterns (URL-decoded twice)  | high     | T1190 Exploit Public-Facing App |
| WEB-003  | Path traversal (incl. double encoding)      | high     | T1190 Exploit Public-Facing App |
| WEB-004  | Known attack tool user-agent (sqlmap, nikto, gobuster, …) | medium | T1595.002 Vulnerability Scanning |
| WEB-005  | Probing ≥3 distinct sensitive paths (`.env`, `.git`, backups) | medium | T1595 Active Scanning |

Every alert includes the **evidence** (the raw log lines that triggered it), so an analyst can
triage without grepping through files. Thresholds are configurable in `detectors.Thresholds`.

Detection design choices worth knowing:

- **Sliding windows**, not totals: 10 failed logins spread over a day are a forgotten password,
  10 failed logins in 10 seconds are an attack.
- **False-positive checks are tested**: a user who mistypes a password twice, or a visitor with
  a few broken links, must *not* produce alerts (see `tests/`).
- **Success after failures (SSH-003) is the critical one**: it means the attacker probably got in.

## Quick start (no dependencies, Python 3.11+)

```bash
git clone https://github.com/hectoraa0/logsentinel.git
cd logsentinel
export PYTHONPATH=src            # Windows PowerShell: $env:PYTHONPATH="src"

# 1. analyze the bundled sample logs (they contain 5 simulated attackers)
python -m logsentinel analyze \
    --auth data/sample/auth.log --nginx data/sample/nginx_access.log \
    --db data/logsentinel.db --year 2026

# 2. open the dashboard
python -m logsentinel serve --db data/logsentinel.db
# -> http://127.0.0.1:8000
```

Expected output of step 1:

```
SEVERITY  RULE     SOURCE IP        COUNT  TITLE / MITRE
CRITICAL  SSH-003  203.0.113.77        13  Successful login after repeated failures [T1078 Valid Accounts]
HIGH      SSH-001  203.0.113.10        45  SSH brute force [T1110.001 Password Guessing]
HIGH      SSH-002  198.51.100.23       14  SSH password spraying [T1110.003 Password Spraying]
...
10 alert(s) saved to data/logsentinel.db
```

Use it on your own logs:

```bash
python -m logsentinel analyze --auth /var/log/auth.log --nginx /var/log/nginx/access.log --year 2026
python -m logsentinel analyze --auth /var/log/auth.log --json          # machine-readable
python -m logsentinel analyze --auth /var/log/auth.log --fail-on high  # exit code 2 for CI/cron
```

> The sample logs use only RFC 5737 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`,
> `203.0.113.0/24`), so they never point at real hosts. Regenerate them with
> `python scripts/generate_sample_logs.py`.

## Run with Docker

```bash
docker compose up -d --build     # analyzes the sample logs, then starts the dashboard
# -> http://127.0.0.1:8000
docker compose down -v
```

Container hardening: non-root user (UID 10001), read-only root filesystem, all Linux
capabilities dropped, `no-new-privileges`, dashboard mounts the database read-only and is
published on `127.0.0.1` only, with a `HEALTHCHECK`.

## CI

GitHub Actions (`.github/workflows/ci.yml`) on every push and pull request:

1. **Lint** with ruff, **unit tests** on Python 3.11 / 3.12 / 3.13.
2. **Detection regression test**: analyzes the sample logs and fails the build unless the
   critical SSH-003 detection still fires (exit code 2).
3. **Security scan** of the source with bandit.
4. **Docker job**: builds the image, starts the compose stack, checks `/healthz`, the alert
   count and the Content-Security-Policy header.

## Security of the tool itself

Logs are attacker-controlled input, so the tool treats them as hostile:

- The dashboard renders everything with `textContent` (never `innerHTML`) so a log line like
  `<script>…` cannot become XSS. A test enforces this.
- Strict `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `no-store`.
- Static files come from a fixed whitelist (no path traversal); the API is read-only.
- SQL is parameterized or fully literal; the dashboard opens SQLite with `mode=ro`.
- Parsers use anchored regular expressions and never `eval`/shell out.

## Project layout

```
src/logsentinel/
  parsers.py     # raw lines -> Event objects (auth.log, nginx combined)
  detectors.py   # detection rules + MITRE mapping + sliding windows
  storage.py     # SQLite persistence (read-only access for the web UI)
  web.py         # stdlib HTTP server: dashboard + /api/alerts, /api/stats, /healthz
  cli.py         # `analyze` and `serve` commands
  static/        # dashboard (HTML/CSS/JS, no frameworks)
scripts/generate_sample_logs.py   # deterministic attack simulation
tests/                            # 39 unit + integration tests
Dockerfile, docker-compose.yml, .github/workflows/ci.yml
```

Run the tests: `PYTHONPATH=src python -m unittest discover -s tests -v`

## Limitations (honest list)

- Rule-based detection: it finds known patterns, not novel attacks. Thresholds need tuning per
  environment, and attackers can stay under them (low-and-slow attacks).
- Batch analysis of files, not a live stream. Alerts are replaced on every run.
- `auth.log` timestamps have no year, so `--year` is a parameter; no timezone handling for syslog.
- Only two log formats. IPv4/IPv6 are parsed; no GeoIP or reputation lookups.
- The dashboard has no authentication: keep it on localhost or behind a reverse proxy.

## Roadmap

- [ ] Live tailing (`--follow`) and incremental alerts
- [ ] Windows Event Log (4625/4624) and Linux `auditd` parsers
- [ ] Sigma-style YAML rules instead of Python functions
- [ ] Export to Splunk/ELK/Wazuh, Telegram/Slack notifications
- [ ] Container image scanning (Trivy) in CI

## License

MIT

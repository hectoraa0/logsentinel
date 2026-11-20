"""Command line interface: `python -m logsentinel analyze|serve`."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__
from .detectors import analyze
from .models import SEVERITIES, SEVERITY_RANK, Alert
from .parsers import parse_nginx_file, parse_ssh_file
from .storage import replace_alerts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="Detect brute force, scanning and injection attacks in logs.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    an = sub.add_parser("analyze", help="parse logs, run detections, save alerts")
    an.add_argument("--auth", help="path to an sshd auth.log file")
    an.add_argument("--nginx", help="path to an nginx/Apache combined access log")
    an.add_argument("--db", default="data/logsentinel.db", help="SQLite output file")
    an.add_argument(
        "--year",
        type=int,
        default=datetime.now(timezone.utc).year,
        help="year for auth.log timestamps (syslog lines have no year)",
    )
    an.add_argument("--json", action="store_true", help="print alerts as JSON")
    an.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit with code 2 if any alert is at least this severe (useful in CI)",
    )

    sv = sub.add_parser("serve", help="start the web dashboard")
    sv.add_argument("--db", default="data/logsentinel.db")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    return parser


def _print_table(alerts: list[Alert]) -> None:
    if not alerts:
        print("No alerts.")
        return
    header = f"{'SEVERITY':<9} {'RULE':<8} {'SOURCE IP':<16} {'COUNT':>5}  TITLE / MITRE"
    print(header)
    print("-" * len(header))
    for a in alerts:
        print(
            f"{a.severity.upper():<9} {a.rule_id:<8} {a.ip:<16} {a.count:>5}  "
            f"{a.title} [{a.mitre}]"
        )


def cmd_analyze(args: argparse.Namespace) -> int:
    if not args.auth and not args.nginx:
        print("error: give at least one of --auth / --nginx", file=sys.stderr)
        return 1
    events = []
    try:
        if args.auth:
            ssh_events, skipped = parse_ssh_file(args.auth, args.year)
            events.extend(ssh_events)
            print(
                f"auth.log: {len(ssh_events)} login events "
                f"({skipped} other lines ignored)",
                file=sys.stderr,
            )
        if args.nginx:
            web_events, skipped = parse_nginx_file(args.nginx)
            events.extend(web_events)
            print(
                f"nginx:    {len(web_events)} requests ({skipped} unparsable lines)",
                file=sys.stderr,
            )
    except OSError as exc:
        print(f"error: cannot read log file: {exc}", file=sys.stderr)
        return 1

    alerts = analyze(events)
    saved = replace_alerts(args.db, alerts)
    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        _print_table(alerts)
    print(f"\n{saved} alert(s) saved to {args.db}", file=sys.stderr)

    if args.fail_on:
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[a.severity] <= limit for a in alerts):
            return 2
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .web import make_server

    server = make_server(args.db, args.host, args.port)
    print(f"Dashboard: http://{args.host}:{args.port}  (Ctrl+C to stop)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", file=sys.stderr)
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    return cmd_serve(args)

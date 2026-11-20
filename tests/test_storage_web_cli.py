import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from logsentinel.cli import main
from logsentinel.models import Alert
from logsentinel.storage import fetch_alerts, fetch_stats, replace_alerts
from logsentinel.web import make_server

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 11, 18, 10, 0, 0, tzinfo=timezone.utc)


def make_alert(severity="high", ip="1.1.1.1", evidence=None):
    return Alert(
        rule_id="SSH-001", title="t", severity=severity, mitre="T1110", ip=ip, count=5,
        first_seen=NOW, last_seen=NOW, description="d", evidence=evidence or ["line"],
    )


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "nested", "a.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip_and_replace(self):
        replace_alerts(self.db, [make_alert("high"), make_alert("critical", "2.2.2.2")])
        rows = fetch_alerts(self.db)
        self.assertEqual([r["severity"] for r in rows], ["critical", "high"])
        replace_alerts(self.db, [make_alert("low")])  # a new run replaces old results
        self.assertEqual(len(fetch_alerts(self.db)), 1)

    def test_filter_and_stats(self):
        replace_alerts(self.db, [make_alert("high"), make_alert("low", "2.2.2.2")])
        self.assertEqual(len(fetch_alerts(self.db, "low")), 1)
        stats = fetch_stats(self.db)
        self.assertEqual((stats["total"], stats["unique_ips"], stats["by_severity"]["high"]), (2, 2, 1))

    def test_invalid_severity_is_rejected(self):
        with self.assertRaises(ValueError):
            fetch_alerts(self.db, "x' OR '1'='1")

    def test_missing_database_is_empty_not_an_error(self):
        self.assertEqual(fetch_alerts(os.path.join(self.tmp.name, "none.db")), [])
        self.assertEqual(fetch_stats(os.path.join(self.tmp.name, "none.db"))["total"], 0)


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        db = os.path.join(cls.tmp.name, "a.db")
        replace_alerts(db, [make_alert("high", evidence=["<script>alert(1)</script>"]), make_alert("low", "2.2.2.2")])
        cls.server = make_server(db, "127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        try:
            return urllib.request.urlopen(self.base + path, timeout=5)
        except urllib.error.HTTPError as err:
            return err

    def test_healthz(self):
        resp = self.get("/healthz")
        self.assertEqual((resp.status, json.load(resp)), (200, {"status": "ok"}))

    def test_api_alerts_and_filter(self):
        self.assertEqual(len(json.load(self.get("/api/alerts"))), 2)
        filtered = json.load(self.get("/api/alerts?severity=low"))
        self.assertEqual([a["ip"] for a in filtered], ["2.2.2.2"])

    def test_invalid_severity_gives_400(self):
        self.assertEqual(self.get("/api/alerts?severity=bogus").status, 400)

    def test_unknown_path_and_traversal_give_404(self):
        self.assertEqual(self.get("/nope").status, 404)
        self.assertEqual(self.get("/static/../web.py").status, 404)
        self.assertEqual(self.get("/static/%2e%2e/web.py").status, 404)

    def test_security_headers_present(self):
        resp = self.get("/")
        self.assertEqual(resp.status, 200)
        self.assertIn("default-src 'none'", resp.headers["Content-Security-Policy"])
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Python", resp.headers.get("Server", ""))

    def test_attacker_controlled_evidence_is_returned_as_data(self):
        # The API returns it as JSON text; the UI renders with textContent (see app.js).
        resp = self.get("/api/alerts?severity=high")
        self.assertEqual(resp.headers["Content-Type"], "application/json")
        self.assertIn("<script>", json.load(resp)[0]["evidence"][0])

    def test_frontend_never_uses_innerhtml(self):
        js = (ROOT / "src" / "logsentinel" / "static" / "app.js").read_text()
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("insertAdjacentHTML", js)


class CliAndSampleDataTests(unittest.TestCase):
    def test_end_to_end_on_generated_sample_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "generate_sample_logs.py"), tmp],
                check=True, capture_output=True,
            )
            db = os.path.join(tmp, "out.db")
            code = main([
                "analyze", "--auth", os.path.join(tmp, "auth.log"),
                "--nginx", os.path.join(tmp, "nginx_access.log"),
                "--db", db, "--year", "2026", "--fail-on", "critical",
            ])
            self.assertEqual(code, 2)  # the sample data contains a critical attack
            found = {(a["rule_id"], a["ip"]) for a in fetch_alerts(db)}
            expected = {
                ("SSH-001", "203.0.113.10"), ("SSH-001", "203.0.113.77"), ("SSH-003", "203.0.113.77"),
                ("SSH-002", "198.51.100.23"), ("WEB-001", "203.0.113.50"), ("WEB-004", "203.0.113.50"),
                ("WEB-005", "203.0.113.50"), ("WEB-002", "198.51.100.99"), ("WEB-003", "198.51.100.99"),
                ("WEB-004", "198.51.100.99"),
            }
            self.assertEqual(found, expected)
            # No false positives on benign traffic (carol's typos, 404s from 192.0.2.77).
            self.assertFalse([ip for _, ip in found if ip.startswith("192.0.2.")])

    def test_committed_sample_data_matches_generator(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "generate_sample_logs.py"), tmp],
                check=True, capture_output=True,
            )
            for name in ("auth.log", "nginx_access.log"):
                self.assertEqual(
                    (Path(tmp) / name).read_text(), (ROOT / "data" / "sample" / name).read_text(), name
                )

    def test_missing_input_is_an_error(self):
        self.assertEqual(main(["analyze", "--db", os.devnull]), 1)
        self.assertEqual(main(["analyze", "--auth", "/does/not/exist", "--db", os.devnull]), 1)


if __name__ == "__main__":
    unittest.main()

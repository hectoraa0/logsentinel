import unittest
from datetime import datetime, timedelta, timezone

from logsentinel.detectors import Thresholds, analyze
from logsentinel.models import Event

T0 = datetime(2026, 11, 18, 10, 0, 0, tzinfo=timezone.utc)


def ssh(offset_s, kind, ip, user="root"):
    return Event(ts=T0 + timedelta(seconds=offset_s), source="ssh", kind=kind, ip=ip, user=user, raw=f"{kind} {ip} {user}")


def web(offset_s, ip, path, status=200, ua="Mozilla/5.0"):
    return Event(
        ts=T0 + timedelta(seconds=offset_s), source="nginx", kind="request", ip=ip,
        status=status, path=path, user_agent=ua, raw=f"{ip} {path} {status}",
    )


def rules(alerts):
    return {(a.rule_id, a.ip) for a in alerts}


class SshRuleTests(unittest.TestCase):
    def test_bruteforce_fires_at_threshold(self):
        events = [ssh(i, "failed_login", "1.1.1.1") for i in range(5)]
        self.assertIn(("SSH-001", "1.1.1.1"), rules(analyze(events)))

    def test_bruteforce_quiet_below_threshold(self):
        events = [ssh(i, "failed_login", "1.1.1.1") for i in range(4)]
        self.assertEqual(analyze(events), [])

    def test_slow_failures_do_not_count_as_bruteforce(self):
        # 10 failures, but one every 30 minutes: a user who forgets the password.
        events = [ssh(i * 1800, "failed_login", "1.1.1.1") for i in range(10)]
        self.assertEqual(analyze(events), [])

    def test_failures_from_different_ips_are_not_combined(self):
        events = [ssh(i, "failed_login", f"1.1.1.{i}") for i in range(10)]
        self.assertEqual(analyze(events), [])

    def test_password_spraying(self):
        users = ["a", "b", "c", "d", "e", "f"]
        events = [ssh(i * 30, "failed_login", "2.2.2.2", user=u) for i, u in enumerate(users)]
        found = rules(analyze(events))
        self.assertIn(("SSH-002", "2.2.2.2"), found)
        self.assertNotIn(("SSH-001", "2.2.2.2"), found)  # too slow for brute force

    def test_success_after_failures_is_critical(self):
        events = [ssh(i, "failed_login", "3.3.3.3", user="admin") for i in range(6)]
        events.append(ssh(10, "accepted_login", "3.3.3.3", user="admin"))
        alerts = analyze(events)
        self.assertEqual(alerts[0].rule_id, "SSH-003")  # sorted most severe first
        self.assertEqual(alerts[0].severity, "critical")

    def test_typo_then_success_is_fine(self):
        events = [ssh(0, "failed_login", "4.4.4.4"), ssh(5, "failed_login", "4.4.4.4"), ssh(9, "accepted_login", "4.4.4.4")]
        self.assertEqual(analyze(events), [])

    def test_custom_thresholds(self):
        events = [ssh(i, "failed_login", "1.1.1.1") for i in range(3)]
        strict = Thresholds(ssh_bruteforce_attempts=3)
        self.assertIn(("SSH-001", "1.1.1.1"), rules(analyze(events, strict)))


class WebRuleTests(unittest.TestCase):
    def test_404_flood(self):
        events = [web(i, "5.5.5.5", f"/p{i}", 404) for i in range(15)]
        self.assertIn(("WEB-001", "5.5.5.5"), rules(analyze(events)))

    def test_few_404s_are_fine(self):
        events = [web(i * 100, "5.5.5.5", f"/p{i}", 404) for i in range(10)]
        self.assertEqual(analyze(events), [])

    def test_sql_injection_encoded_and_plain(self):
        events = [
            web(0, "6.6.6.6", "/p?id=1%27%20OR%20%271%27%3D%271"),
            web(1, "6.6.6.6", "/p?id=1 UNION SELECT null,version()"),
            web(2, "7.7.7.7", "/p?id=1+AND+SLEEP(5)"),
        ]
        found = rules(analyze(events))
        self.assertIn(("WEB-002", "6.6.6.6"), found)
        self.assertIn(("WEB-002", "7.7.7.7"), found)

    def test_normal_query_is_not_sqli(self):
        events = [web(0, "8.8.8.8", "/search?q=how+to+select+a+union+rep")]
        self.assertEqual(analyze(events), [])

    def test_path_traversal_including_double_encoding(self):
        events = [
            web(0, "9.9.9.9", "/dl?f=../../etc/passwd"),
            web(1, "9.9.9.9", "/dl?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
            web(2, "9.9.9.9", "/dl?f=..%252f..%252fetc%252fshadow"),
        ]
        alerts = [a for a in analyze(events) if a.rule_id == "WEB-003"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 3)

    def test_attack_tool_user_agent(self):
        events = [web(0, "10.0.0.1", "/", 200, ua="sqlmap/1.7 (https://sqlmap.org)")]
        self.assertIn(("WEB-004", "10.0.0.1"), rules(analyze(events)))

    def test_sensitive_probe_needs_several_distinct_paths(self):
        one = [web(i, "10.0.0.2", "/.env", 404) for i in range(10)]
        self.assertNotIn("WEB-005", {a.rule_id for a in analyze(one)})
        many = [web(i, "10.0.0.3", p, 404) for i, p in enumerate(["/.env", "/.git/config", "/backup.zip"])]
        self.assertIn(("WEB-005", "10.0.0.3"), rules(analyze(many)))


class OutputTests(unittest.TestCase):
    def test_alerts_sorted_by_severity(self):
        events = [web(i, "5.5.5.5", f"/p{i}", 404) for i in range(15)]  # medium
        events += [ssh(i, "failed_login", "1.1.1.1") for i in range(5)]  # high
        severities = [a.severity for a in analyze(events)]
        self.assertEqual(severities, sorted(severities, key=["critical", "high", "medium", "low"].index))

    def test_alert_has_evidence_and_serializes(self):
        events = [ssh(i, "failed_login", "1.1.1.1") for i in range(5)]
        alert = analyze(events)[0]
        self.assertTrue(alert.evidence)
        data = alert.to_dict()
        self.assertEqual(data["ip"], "1.1.1.1")
        self.assertTrue(data["first_seen"].startswith("2026-11-18T10:00:00"))


if __name__ == "__main__":
    unittest.main()

import unittest

from logsentinel.parsers import parse_nginx_line, parse_ssh_line


class SshParserTests(unittest.TestCase):
    def test_failed_password(self):
        line = "Nov 18 10:00:01 web01 sshd[3000]: Failed password for root from 203.0.113.10 port 50000 ssh2"
        ev = parse_ssh_line(line, 2026)
        self.assertIsNotNone(ev)
        self.assertEqual((ev.kind, ev.user, ev.ip), ("failed_login", "root", "203.0.113.10"))
        self.assertEqual((ev.ts.year, ev.ts.month, ev.ts.day, ev.ts.hour), (2026, 11, 18, 10))

    def test_invalid_user(self):
        line = "Nov  3 10:00:01 web01 sshd[3000]: Failed password for invalid user test from 198.51.100.23 port 5 ssh2"
        ev = parse_ssh_line(line, 2026)
        self.assertEqual((ev.kind, ev.user), ("failed_login", "test"))
        self.assertEqual(ev.ts.day, 3)

    def test_accepted(self):
        line = "Nov 18 10:00:01 web01 sshd[1]: Accepted publickey for alice from 192.0.2.10 port 22222 ssh2"
        ev = parse_ssh_line(line, 2026)
        self.assertEqual((ev.kind, ev.user), ("accepted_login", "alice"))

    def test_ipv6_address(self):
        line = "Nov 18 10:00:01 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
        self.assertEqual(parse_ssh_line(line, 2026).ip, "2001:db8::1")

    def test_ignores_unrelated_lines(self):
        self.assertIsNone(parse_ssh_line("Nov 18 10:00:01 web01 sshd[1]: Connection closed by 1.2.3.4 port 1", 2026))
        self.assertIsNone(parse_ssh_line("Nov 18 10:00:01 web01 cron[1]: Failed password for root from 1.2.3.4 port 1", 2026))
        self.assertIsNone(parse_ssh_line("garbage", 2026))
        self.assertIsNone(parse_ssh_line("", 2026))


class NginxParserTests(unittest.TestCase):
    LINE = (
        '203.0.113.50 - - [18/Nov/2026:10:05:01 +0000] "GET /admin HTTP/1.1" 404 153 "-" "gobuster/3.6"'
    )

    def test_combined_format(self):
        ev = parse_nginx_line(self.LINE)
        self.assertIsNotNone(ev)
        self.assertEqual((ev.ip, ev.path, ev.status, ev.user_agent), ("203.0.113.50", "/admin", 404, "gobuster/3.6"))
        self.assertEqual(ev.ts.hour, 10)

    def test_timezone_is_normalized_to_utc(self):
        line = '1.2.3.4 - - [18/Nov/2026:10:00:00 +0600] "GET / HTTP/1.1" 200 5 "-" "x"'
        self.assertEqual(parse_nginx_line(line).ts.hour, 4)

    def test_malformed_lines_return_none(self):
        self.assertIsNone(parse_nginx_line("not a log line"))
        self.assertIsNone(parse_nginx_line('1.2.3.4 - - [bad date] "GET / HTTP/1.1" 200 5 "-" "x"'))


if __name__ == "__main__":
    unittest.main()

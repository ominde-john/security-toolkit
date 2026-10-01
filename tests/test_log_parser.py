"""test_log_parser.py - automatic tests for src/security_toolkit/log_parser.py

Run all tests from the top folder of the repo:
    python3 -m unittest discover -s tests -v

All IP addresses below are reserved "documentation" addresses (203.0.113.x,
198.51.100.x, 2001:db8::). They never belong to a real machine.
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

# Tell Python where the code lives 
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from security_toolkit.log_parser import parse_ssh_line, parse_ssh_file, parse_time

UTC = timezone.utc


def make_line(message, process="sshd-session"):
    """Helper: build a full log line around a message, so each test stays short."""
    return f"2026-09-30T01:23:45+0000 myserver {process}[1234]: {message}"


class TestParseSshLine(unittest.TestCase):
    """Tests for parse_ssh_line(): one log line in, one dictionary (or None) out."""

    def test_failed_login_for_existing_user(self):
        event = parse_ssh_line(make_line("Failed password for root from 203.0.113.5 port 52114 ssh2"))
        self.assertEqual(event["kind"], "failed_login")
        self.assertEqual(event["user"], "root")
        self.assertEqual(event["ip"], "203.0.113.5")
        self.assertEqual(event["port"], 52114)        # a number, not the text "52114"
        self.assertEqual(event["method"], "password")

    def test_failed_login_for_invalid_user(self):
        # sshd adds the words "invalid user" when the account does not exist.
        event = parse_ssh_line(make_line("Failed password for invalid user admin from 203.0.113.5 port 52114 ssh2"))
        self.assertEqual(event["kind"], "failed_login")
        self.assertEqual(event["user"], "admin")      # NOT "invalid"

    def test_failed_login_with_publickey(self):
        event = parse_ssh_line(make_line("Failed publickey for ubuntu from 203.0.113.5 port 52114 ssh2"))
        self.assertEqual(event["method"], "publickey")

    def test_username_with_dots_and_dashes(self):
        event = parse_ssh_line(make_line("Failed password for invalid user a.b-c1 from 203.0.113.5 port 1 ssh2"))
        self.assertEqual(event["user"], "a.b-c1")

    def test_accepted_login(self):
        line = make_line("Accepted publickey for ubuntu from 198.51.100.7 port 40222 ssh2: ED25519 SHA256:abc")
        event = parse_ssh_line(line)
        self.assertEqual(event["kind"], "accepted_login")
        self.assertEqual(event["user"], "ubuntu")
        self.assertEqual(event["ip"], "198.51.100.7")
        self.assertEqual(event["method"], "publickey")

    def test_invalid_user_line(self):
        event = parse_ssh_line(make_line("Invalid user test from 203.0.113.5 port 52120"))
        self.assertEqual(event["kind"], "invalid_user")
        self.assertEqual(event["user"], "test")
        self.assertEqual(event["port"], 52120)
        self.assertIsNone(event["method"])            # this kind of line has no method

    def test_invalid_user_line_without_port(self):
        event = parse_ssh_line(make_line("Invalid user oracle from 203.0.113.5"))
        self.assertEqual(event["user"], "oracle")
        self.assertIsNone(event["port"])

    def test_invalid_user_with_empty_name(self):
        # Scanners sometimes try an empty username.
        event = parse_ssh_line(make_line("Invalid user  from 203.0.113.5 port 4004"))
        self.assertEqual(event["user"], "")

    def test_ipv6_address(self):
        event = parse_ssh_line(make_line("Failed password for root from 2001:db8::1 port 4005 ssh2"))
        self.assertEqual(event["ip"], "2001:db8::1")

    def test_older_process_name_sshd(self):
        # Older systems log as "sshd[...]", newer ones as "sshd-session[...]".
        event = parse_ssh_line(make_line("Failed password for root from 203.0.113.5 port 1 ssh2", process="sshd"))
        self.assertEqual(event["kind"], "failed_login")

    def test_classic_syslog_layout(self):
        line = "Sep  5 01:02:03 myserver sshd[999]: Failed password for root from 203.0.113.5 port 1 ssh2"
        event = parse_ssh_line(line, year=2026)
        self.assertEqual(event["time"], datetime(2026, 9, 5, 1, 2, 3, tzinfo=UTC))
        self.assertEqual(event["host"], "myserver")

    def test_trailing_newline_is_ignored(self):
        event = parse_ssh_line(make_line("Invalid user x from 203.0.113.5") + "\n")
        self.assertEqual(event["ip"], "203.0.113.5")

    def test_original_line_is_kept(self):
        line = make_line("Invalid user x from 203.0.113.5")
        self.assertEqual(parse_ssh_line(line)["line"], line)

    def test_lines_we_do_not_understand_give_none(self):
        # subTest runs the same check on each line and reports each one separately.
        lines = [
            make_line("ubuntu : TTY=pts/0 ; COMMAND=/bin/ls", process="sudo"),
            make_line("Server listening on 0.0.0.0 port 22."),
            make_line("Disconnected from user ubuntu 198.51.100.7 port 4010"),
            "",
            "   ",
            "\x00\xff random text",
            "-- Journal begins at Mon 2026-09-01 --",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertIsNone(parse_ssh_line(line))


class TestParseTime(unittest.TestCase):
    """Tests for parse_time(): timestamp text in, datetime out."""

    def test_iso_time_in_utc(self):
        self.assertEqual(parse_time("2026-09-30T01:23:45+0000"), datetime(2026, 9, 30, 1, 23, 45, tzinfo=UTC))

    def test_iso_time_with_other_timezone_is_the_same_moment(self):
        # 01:23 at "+0200" is 23:23 UTC on the previous day.
        self.assertEqual(parse_time("2026-09-30T01:23:45+0200"), datetime(2026, 9, 29, 23, 23, 45, tzinfo=UTC))

    def test_iso_time_without_timezone_is_assumed_utc(self):
        self.assertEqual(parse_time("2026-09-30T01:23:45"), datetime(2026, 9, 30, 1, 23, 45, tzinfo=UTC))

    def test_classic_time_with_one_digit_day(self):
        self.assertEqual(parse_time("Sep  5 01:02:03", 2025), datetime(2025, 9, 5, 1, 2, 3, tzinfo=UTC))

    def test_classic_time_without_year_uses_current_year(self):
        this_year = datetime.now(UTC).year
        self.assertEqual(parse_time("Sep 30 01:23:45").year, this_year)


class TestParseSshFile(unittest.TestCase):
    """Tests for parse_ssh_file(): a whole file in, a list of events out."""

    def write_temp_file(self, content):
        """Helper (not a test): write bytes to a temporary file, return its path."""
        handle, path = tempfile.mkstemp()
        os.close(handle)
        with open(path, "wb") as f:
            f.write(content)
        self.addCleanup(os.remove, path)          # delete it when the test is over
        return path

    def test_keeps_ssh_events_and_skips_other_lines(self):
        text = "\n".join([
            make_line("Invalid user admin from 203.0.113.5 port 1"),
            "some unrelated line",
            make_line("Failed password for root from 203.0.113.5 port 2 ssh2"),
            make_line("ubuntu : COMMAND=/bin/ls", process="sudo"),
            "",
        ])
        events = parse_ssh_file(self.write_temp_file(text.encode("utf-8")))
        self.assertEqual([e["kind"] for e in events], ["invalid_user", "failed_login"])

    def test_junk_bytes_do_not_crash_the_parser(self):
        # \xff\xfe is not valid text. Attackers send junk like this as usernames.
        start_of_line = b"2026-09-30T01:23:45+0000 myserver sshd-session[1234]: "
        content = start_of_line + b"Invalid user \xff\xfe from 203.0.113.5 port 1\n"
        events = parse_ssh_file(self.write_temp_file(content))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["ip"], "203.0.113.5")

    def test_empty_file_gives_empty_list(self):
        self.assertEqual(parse_ssh_file(self.write_temp_file(b"")), [])

    def test_missing_file_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            parse_ssh_file("this_file_does_not_exist.log")


# Lets you also run just this file:  python3 tests/test_log_parser.py
if __name__ == "__main__":
    unittest.main()

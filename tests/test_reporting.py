"""test_reporting.py - automatic tests for src/security_toolkit/reporting.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone

# Tell Python where the code lives
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from security_toolkit.reporting import (
    redact_text,
    maybe_redact,
    format_time,
    findings_to_markdown,
    findings_to_json,
    save_report,
)
from security_toolkit.vulnerability import make_finding

# A fixed time, so the report text is the same every time the tests run.
FIXED_TIME = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def make_sample_findings():
    """Helper (not a test): three findings in a mixed-up order."""
    return [
        make_finding("A-1", "A low one", "low", "Low description", "Low fix", "from 203.0.113.5"),
        make_finding("B-1", "A critical one", "critical", "Critical description", "Critical fix"),
        make_finding("C-1", "A high one", "high", "High description", "High fix", "some evidence"),
    ]


def get_heading_lines(markdown):
    """Helper (not a test): the '### ...' lines of a Markdown report."""
    headings = []
    for line in markdown.splitlines():
        if line.startswith("### "):
            headings.append(line)
    return headings


class TestRedactText(unittest.TestCase):
    """redact_text(): hide IP addresses and email addresses."""

    def test_ipv4_is_hidden(self):
        self.assertEqual(redact_text("from 203.0.113.5 today"), "from [REDACTED-IP] today")

    def test_ipv6_is_hidden(self):
        self.assertEqual(redact_text("from 2001:db8::1 today"), "from [REDACTED-IP] today")

    def test_email_is_hidden(self):
        self.assertEqual(redact_text("mail bob@example.com now"), "mail [REDACTED-EMAIL] now")

    def test_several_addresses_are_all_hidden(self):
        text = "203.0.113.5 then 198.51.100.7 then 203.0.113.5"
        self.assertEqual(redact_text(text), "[REDACTED-IP] then [REDACTED-IP] then [REDACTED-IP]")

    def test_private_addresses_are_hidden_too(self):
        # Your internal network layout is private information as well.
        self.assertEqual(redact_text("host 10.0.0.8"), "host [REDACTED-IP]")

    def test_everywhere_and_localhost_stay_visible(self):
        text = "tcp 0.0.0.0:6379 and 127.0.0.1 and :: and ::1"
        self.assertEqual(redact_text(text), text)

    def test_version_numbers_are_left_alone(self):
        self.assertEqual(redact_text("build 1.2.3.4.5 released"), "build 1.2.3.4.5 released")

    def test_clock_times_are_left_alone(self):
        self.assertEqual(redact_text("logged at 12:34:56"), "logged at 12:34:56")

    def test_impossible_ip_is_left_alone(self):
        self.assertEqual(redact_text("value 999.1.1.1"), "value 999.1.1.1")

    def test_text_without_private_data_is_unchanged(self):
        text = "PermitRootLogin yes on port 22"
        self.assertEqual(redact_text(text), text)

    def test_empty_text(self):
        self.assertEqual(redact_text(""), "")

    def test_usernames_are_not_hidden(self):
        # Honest test of a known limit: only IPs and emails are hidden.
        self.assertEqual(redact_text("user root failed"), "user root failed")


class TestMaybeRedact(unittest.TestCase):
    """maybe_redact(): redact only when asked to."""

    def test_none_stays_none(self):
        self.assertIsNone(maybe_redact(None, True))
        self.assertIsNone(maybe_redact(None, False))

    def test_redact_false_changes_nothing(self):
        self.assertEqual(maybe_redact("from 203.0.113.5", False), "from 203.0.113.5")

    def test_redact_true_hides_the_address(self):
        self.assertEqual(maybe_redact("from 203.0.113.5", True), "from [REDACTED-IP]")


class TestFormatTime(unittest.TestCase):
    """format_time(): a datetime in, readable text out."""

    def test_fixed_time(self):
        self.assertEqual(format_time(FIXED_TIME), "2026-10-03 12:00 UTC")

    def test_none_means_now(self):
        text = format_time(None)
        self.assertTrue(text.endswith(" UTC"))
        self.assertEqual(len(text), len("2026-10-03 12:00 UTC"))


class TestFindingsToMarkdown(unittest.TestCase):
    """findings_to_markdown(): findings in, Markdown text out."""

    def test_report_starts_with_the_default_title(self):
        markdown = findings_to_markdown([], generated=FIXED_TIME)
        self.assertTrue(markdown.startswith("# Security Report"))

    def test_custom_title(self):
        markdown = findings_to_markdown([], title="My Server", generated=FIXED_TIME)
        self.assertTrue(markdown.startswith("# My Server"))

    def test_generated_time_is_shown(self):
        markdown = findings_to_markdown([], generated=FIXED_TIME)
        self.assertIn("Generated: 2026-10-03 12:00 UTC", markdown)

    def test_no_findings_message(self):
        markdown = findings_to_markdown([], generated=FIXED_TIME)
        self.assertIn("No findings.", markdown)
        self.assertIn("Total findings: 0", markdown)

    def test_summary_table_has_every_level(self):
        markdown = findings_to_markdown([], generated=FIXED_TIME)
        for level in ("Critical", "High", "Medium", "Low", "Info"):
            self.assertIn(f"| {level} |", markdown)

    def test_summary_counts_are_correct(self):
        markdown = findings_to_markdown(make_sample_findings(), generated=FIXED_TIME)
        self.assertIn("| Critical | 1 |", markdown)
        self.assertIn("| High | 1 |", markdown)
        self.assertIn("| Medium | 0 |", markdown)
        self.assertIn("| Low | 1 |", markdown)
        self.assertIn("Total findings: 3", markdown)

    def test_most_serious_finding_comes_first(self):
        markdown = findings_to_markdown(make_sample_findings(), generated=FIXED_TIME)
        headings = get_heading_lines(markdown)
        self.assertEqual(headings[0], "### 1. [CRITICAL] B-1 - A critical one")
        self.assertEqual(headings[1], "### 2. [HIGH] C-1 - A high one")
        self.assertEqual(headings[2], "### 3. [LOW] A-1 - A low one")

    def test_finding_details_are_included(self):
        markdown = findings_to_markdown(make_sample_findings(), generated=FIXED_TIME)
        self.assertIn("**Description:** Critical description", markdown)
        self.assertIn("**Recommendation:** Critical fix", markdown)

    def test_evidence_is_in_a_code_box(self):
        markdown = findings_to_markdown(make_sample_findings(), generated=FIXED_TIME)
        self.assertIn("```\nsome evidence\n```", markdown)

    def test_finding_without_evidence_has_no_evidence_section(self):
        only_critical = [make_sample_findings()[1]]       # B-1 has no evidence
        markdown = findings_to_markdown(only_critical, generated=FIXED_TIME)
        self.assertNotIn("**Evidence:**", markdown)

    def test_evidence_cannot_break_the_code_box(self):
        findings = [make_finding("X-1", "Fence", "low", "d", "r", "has ``` inside")]
        markdown = findings_to_markdown(findings, generated=FIXED_TIME)
        # The code box is opened once and closed once: exactly 2 fences.
        self.assertEqual(markdown.count("```"), 2)

    def test_redact_hides_addresses_in_evidence(self):
        markdown = findings_to_markdown(make_sample_findings(), generated=FIXED_TIME, redact=True)
        self.assertNotIn("203.0.113.5", markdown)
        self.assertIn("from [REDACTED-IP]", markdown)

    def test_without_redact_addresses_stay(self):
        markdown = findings_to_markdown(make_sample_findings(), generated=FIXED_TIME)
        self.assertIn("203.0.113.5", markdown)

    def test_redact_also_hides_addresses_in_title_and_description(self):
        findings = [make_finding("X-1", "Attack from 203.0.113.5", "low",
                                 "Mail bob@example.com about it", "r")]
        markdown = findings_to_markdown(findings, generated=FIXED_TIME, redact=True)
        self.assertNotIn("203.0.113.5", markdown)
        self.assertNotIn("bob@example.com", markdown)

    def test_original_findings_are_not_changed(self):
        findings = make_sample_findings()
        findings_to_markdown(findings, generated=FIXED_TIME, redact=True)
        self.assertEqual(findings[0]["evidence"], "from 203.0.113.5")
        self.assertEqual(findings[0]["id"], "A-1")           # order is unchanged too

    def test_result_is_text(self):
        self.assertIsInstance(findings_to_markdown([], generated=FIXED_TIME), str)


class TestFindingsToJson(unittest.TestCase):
    """findings_to_json(): findings in, JSON text out."""

    def test_result_is_valid_json(self):
        text = findings_to_json(make_sample_findings(), generated=FIXED_TIME)
        report = json.loads(text)                  # raises an error if it is not valid
        self.assertIsInstance(report, dict)

    def test_top_level_fields(self):
        report = json.loads(findings_to_json(make_sample_findings(), generated=FIXED_TIME))
        self.assertEqual(report["generated"], "2026-10-03 12:00 UTC")
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["summary"]["critical"], 1)
        self.assertEqual(report["summary"]["medium"], 0)

    def test_findings_are_sorted_most_serious_first(self):
        report = json.loads(findings_to_json(make_sample_findings(), generated=FIXED_TIME))
        ids = []
        for finding in report["findings"]:
            ids.append(finding["id"])
        self.assertEqual(ids, ["B-1", "C-1", "A-1"])

    def test_each_finding_has_all_the_fields(self):
        report = json.loads(findings_to_json(make_sample_findings(), generated=FIXED_TIME))
        first = report["findings"][0]
        for key in ("id", "title", "severity", "description", "recommendation", "evidence"):
            self.assertIn(key, first)

    def test_missing_evidence_becomes_null(self):
        report = json.loads(findings_to_json(make_sample_findings(), generated=FIXED_TIME))
        self.assertIsNone(report["findings"][0]["evidence"])      # B-1 has no evidence

    def test_redact_hides_addresses(self):
        text = findings_to_json(make_sample_findings(), generated=FIXED_TIME, redact=True)
        self.assertNotIn("203.0.113.5", text)
        self.assertIn("[REDACTED-IP]", text)

    def test_no_findings(self):
        report = json.loads(findings_to_json([], generated=FIXED_TIME))
        self.assertEqual(report["total"], 0)
        self.assertEqual(report["findings"], [])

    def test_original_findings_are_not_changed(self):
        findings = make_sample_findings()
        findings_to_json(findings, generated=FIXED_TIME, redact=True)
        self.assertEqual(findings[0]["evidence"], "from 203.0.113.5")


class TestSaveReport(unittest.TestCase):
    """save_report(): write a report to a file."""

    def setUp(self):
        # Runs before EACH test: make a temporary folder.
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder)     # delete it afterwards

    def read_back(self, path):
        """Helper: read a file's text."""
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def test_text_is_saved(self):
        path = os.path.join(self.folder, "report.md")
        save_report("hello report", path)
        self.assertEqual(self.read_back(path), "hello report\n")

    def test_a_newline_is_not_added_twice(self):
        path = os.path.join(self.folder, "report.md")
        save_report("hello report\n", path)
        self.assertEqual(self.read_back(path), "hello report\n")

    def test_existing_file_is_replaced(self):
        path = os.path.join(self.folder, "report.md")
        save_report("first version", path)
        save_report("second version", path)
        self.assertEqual(self.read_back(path), "second version\n")

    def test_a_real_report_can_be_saved(self):
        path = os.path.join(self.folder, "report.md")
        markdown = findings_to_markdown(make_sample_findings(), generated=FIXED_TIME)
        save_report(markdown, path)
        self.assertIn("# Security Report", self.read_back(path))

    def test_bad_path_raises_a_clear_error(self):
        with self.assertRaises(RuntimeError):
            save_report("text", os.path.join(self.folder, "no_such_folder", "report.md"))


# Lets you also run just this file:  python3 tests/test_reporting.py
if __name__ == "__main__":
    unittest.main()

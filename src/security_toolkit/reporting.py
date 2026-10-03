"""reporting.py - turn findings into a report you can read, share or publish.
"""

import json
from datetime import datetime, timezone

from security_toolkit.ioc import IPV4_IN_TEXT, IPV6_IN_TEXT, EMAIL_IN_TEXT, classify_ioc
from security_toolkit.vulnerability import SEVERITY_LEVELS, sort_findings, count_by_severity

REDACTED_IP = "[REDACTED-IP]"
REDACTED_EMAIL = "[REDACTED-EMAIL]"

# These addresses mean "everywhere" or "this computer". They are not private
# information, and they are useful evidence
KEEP_AS_IS = ("0.0.0.0", "127.0.0.1", "::", "::1")


# ---------------------------------------------------------------------------
# Hiding private information
# ---------------------------------------------------------------------------

def replace_ipv4(match):
    """Helper for redact_text(): replace one IPv4-looking piece of text."""
    text = match.group(0)
    if text in KEEP_AS_IS:
        return text
    if classify_ioc(text) == "ipv4":
        return REDACTED_IP
    return text                              # not a real address


def replace_ipv6(match):
    """Helper for redact_text(): replace one IPv6-looking piece of text."""
    text = match.group(0)
    if text in KEEP_AS_IS:
        return text
    if text.count(":") >= 2 and classify_ioc(text) == "ipv6":
        return REDACTED_IP
    return text


def redact_text(text):
    """Replace every IP address and email address in the text with a marker."""
    text = EMAIL_IN_TEXT.sub(REDACTED_EMAIL, text)     # emails first
    text = IPV4_IN_TEXT.sub(replace_ipv4, text)
    text = IPV6_IN_TEXT.sub(replace_ipv6, text)
    return text


def maybe_redact(text, redact):
    """Redact the text only if redact is True. Text of None stays None."""
    if text is None:
        return None
    if redact:
        return redact_text(text)
    return text


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def format_time(moment):
    """Show a time as text, like 2026-10-03 12:00 UTC. None means 'now'."""
    if moment is None:
        moment = datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def findings_to_markdown(findings, title="Security Report", generated=None, redact=False):
    """Build a Markdown report.

    findings    the list of findings (from vulnerability.py)
    title       the heading at the top
    generated   a datetime to print as the report time (default: now)
    redact      True hides IP addresses and email addresses
    """
    lines = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"Generated: {format_time(generated)}")
    lines.append("")

    # --- Summary table ---
    counts = count_by_severity(findings)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    # Show the most serious level first.
    levels = sorted(SEVERITY_LEVELS, key=SEVERITY_LEVELS.get, reverse=True)
    for level in levels:
        lines.append(f"| {level.capitalize()} | {counts[level]} |")
    lines.append("")
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")

    # --- The findings, most serious first ---
    lines.append("## Findings")
    lines.append("")

    if len(findings) == 0:
        lines.append("No findings. Every check that was run passed.")
        lines.append("")
        return "\n".join(lines)

    number = 1
    for finding in sort_findings(findings):
        severity = finding["severity"].upper()
        finding_title = maybe_redact(finding["title"], redact)
        lines.append(f"### {number}. [{severity}] {finding['id']} - {finding_title}")
        lines.append("")
        lines.append(f"**Description:** {maybe_redact(finding['description'], redact)}")
        lines.append("")
        lines.append(f"**Recommendation:** {maybe_redact(finding['recommendation'], redact)}")
        lines.append("")

        evidence = maybe_redact(finding["evidence"], redact)
        if evidence is not None:
            evidence = evidence.replace("```", "'''")   # so the evidence cannot break the box
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("```")
            lines.append(evidence)
            lines.append("```")
            lines.append("")

        number = number + 1

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def findings_to_json(findings, generated=None, redact=False):
    """Build a JSON report (text). Same information as the Markdown report."""
    cleaned = []
    for finding in sort_findings(findings):
        cleaned.append({
            "id": finding["id"],
            "title": maybe_redact(finding["title"], redact),
            "severity": finding["severity"],
            "description": maybe_redact(finding["description"], redact),
            "recommendation": maybe_redact(finding["recommendation"], redact),
            "evidence": maybe_redact(finding["evidence"], redact),
        })

    report = {
        "generated": format_time(generated),
        "total": len(findings),
        "summary": count_by_severity(findings),
        "findings": cleaned,
    }
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# Saving
# ---------------------------------------------------------------------------

def save_report(text, path):
    """Write the report text to a file. Raises RuntimeError if that fails."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
            if not text.endswith("\n"):
                f.write("\n")
    except OSError as error:
        raise RuntimeError(f"cannot write {path} ({error.strerror})")


# Runs only when you start this file directly:  python3 -m security_toolkit.reporting
# The settings, services and addresses below are made up.
if __name__ == "__main__":
    from security_toolkit.network import parse_ss_output
    from security_toolkit.vulnerability import make_finding, check_ssh_config, check_listening_services

    sample_config = "PermitRootLogin yes\nPasswordAuthentication no\n"
    sample_services = parse_ss_output("tcp LISTEN 0 4096 0.0.0.0:6379 0.0.0.0:*")

    all_findings = check_ssh_config(sample_config)
    all_findings = all_findings + check_listening_services(sample_services)
    all_findings.append(make_finding(
        "DEMO-1", "Many failed logins from one address", "medium",
        "7 failed logins in 18 seconds.",
        "Block the address in the firewall.",
        "203.0.113.5 tried: root, admin (contact: abuse@example.com)",
    ))

    print(findings_to_markdown(all_findings, title="Demo Server Report", redact=True))

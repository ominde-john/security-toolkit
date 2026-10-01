"""log_parser.py - turn SSH log lines into data a program can use.

A log line is just text. To spot attacks we first need to pull out the useful
parts: when it happened, what happened, which user, which IP address.

This file understands three kinds of SSH events:
    failed_login    "Failed password for admin from 203.0.113.5 port 52114 ssh2"
    invalid_user    "Invalid user test from 203.0.113.5 port 52120"
    accepted_login  "Accepted publickey for ubuntu from 198.51.100.7 port 40222 ssh2"

It reads two common log layouts:
    2026-09-30T01:23:45+0000 myserver sshd-session[123]: ...   (journalctl -o short-iso)
    Sep 30 01:23:45 myserver sshd[123]: ...                    (classic syslog / auth.log)

Limits: the classic layout has no year and no timezone, so we assume the current
year and UTC. Lines we do not understand are skipped (parse_ssh_line gives None).
"""

import re
from datetime import datetime, timezone

LINE_PATTERN = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T\S+"                          # 2026-09-30T01:23:45+0000
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"   # Sep 30 01:23:45  (or: Sep  5 ...)
    r")"
    r"\s+(?P<host>\S+)"                               # the server's name
    r"\s+sshd(?:-session)?\[\d+\]:"                   # sshd[123]:   or   sshd-session[123]:
    r"\s+(?P<message>.*)$"                            # everything after that
)

# The message part. 
MESSAGE_PATTERNS = [
    # Accepted publickey for ubuntu from 198.51.100.7 port 40222 ssh2
    ("accepted_login", re.compile(
        r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )),
    # Failed password for admin from 203.0.113.5 port 52114 ssh2
    # Failed password for invalid user admin from 203.0.113.5 port 52114 ssh2
    ("failed_login", re.compile(
        r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    )),
    # Invalid user test from 203.0.113.5 port 52120
    ("invalid_user", re.compile(
        r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
    )),
]


def parse_time(text, year=None):
    """Turn the timestamp text of a log line into a datetime object."""
    # Layout 1: starts with a digit, like 2026-09-30T01:23:45+0000
    if text[0].isdigit():
        moment = datetime.fromisoformat(text)
        if moment.tzinfo is None:                      # no timezone in the text
            moment = moment.replace(tzinfo=timezone.utc)
        return moment

    # Layout 2: classic syslog, like "Sep 30 01:23:45". No year, no timezone.
    if year is None:
        year = datetime.now(timezone.utc).year
    text = " ".join(text.split())                      # "Sep  5" -> "Sep 5"
    moment = datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
    return moment.replace(tzinfo=timezone.utc)


def parse_ssh_line(line, year=None):
    """Parse one log line.

    Returns a dictionary like:
        {"time": datetime, "host": "myserver", "kind": "failed_login",
         "user": "admin", "ip": "203.0.113.5", "port": 52114,
         "method": "password", "line": "<the original line>"}
    or None if the line is not an SSH event we understand.
    """
    line = line.strip()

    match = LINE_PATTERN.match(line)
    if match is None:
        return None                       # not an sshd line at all

    message = match.group("message")

    for kind, pattern in MESSAGE_PATTERNS:
        found = pattern.match(message)
        if found is None:
            continue                      # this pattern does not fit, try the next one

        details = found.groupdict()       # {"user": "admin", "ip": "...", ...}
        port = details.get("port")
        if port is not None:
            port = int(port)              # "52114" (text) -> 52114 (number)

        return {
            "time": parse_time(match.group("timestamp"), year),
            "host": match.group("host"),
            "kind": kind,
            "user": details.get("user"),
            "ip": details.get("ip"),
            "port": port,
            "method": details.get("method"),   # None for invalid_user lines
            "line": line,
        }

    return None                           # an sshd line, but not one we care about


def parse_ssh_file(path, year=None):
    """Read a whole log file and return a list of events (skipping other lines)."""
    events = []
    # errors="replace": attackers send junk bytes as usernames. Do not crash on them.
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_ssh_line(line, year)
            if event is not None:
                events.append(event)
    return events


# Runs only when you start this file directly:  python3 log_parser.py
# A quick demonstration with made-up lines (203.0.113.x and 198.51.100.x are
# reserved example addresses that never belong to a real machine).
if __name__ == "__main__":
    sample_lines = [
        "2026-09-30T01:23:45+0000 myserver sshd-session[1234]: Failed password for invalid user admin from 203.0.113.5 port 52114 ssh2",
        "2026-09-30T01:23:46+0000 myserver sshd-session[1235]: Invalid user test from 203.0.113.5 port 52120",
        "Sep  5 01:02:03 myserver sshd[999]: Accepted publickey for ubuntu from 198.51.100.7 port 40222 ssh2: ED25519 SHA256:abc",
        "Sep  5 01:02:04 myserver CRON[1000]: pam_unix(cron:session): session opened for user root",
    ]
    for sample in sample_lines:
        event = parse_ssh_line(sample, year=2026)
        if event is None:
            print("SKIPPED (not an SSH event we understand)")
        else:
            print(f"{event['kind']}: user={event['user']} ip={event['ip']} port={event['port']} time={event['time']}")

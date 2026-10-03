"""log_parser.py - turn SSH log lines into data a program can use.
"""

import re
from datetime import datetime, timezone

# The part every sshd line starts with. Python glues the quoted pieces together.
LINE_PATTERN = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T\S+"                          # 2026-09-30T01:23:45+0000
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"   # Sep 30 01:23:45  (or: Sep  5 ...)
    r")"
    r"\s+(?P<host>\S+)"                               # the server's name
    r"\s+sshd(?:-session)?\[\d+\]:"                   # sshd[123]:   or   sshd-session[123]:
    r"\s+(?P<message>.*)$"                            # everything after that
)

# The message part. We try these one after another until one fits.
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


# ---------------------------------------------------------------------------
# Detection: brute-force attempts
# ---------------------------------------------------------------------------

# Event kinds that mean "someone tried to log in and did not get in".
BAD_KINDS = ("failed_login", "invalid_user")

# Log lines from the same IP and port, this many seconds apart or less, belong to
# the SAME login attempt. (sshd often writes two lines for one attempt.)
SAME_ATTEMPT_SECONDS = 60


def seconds_between(earlier, later):
    """How many seconds passed between two datetime objects."""
    return (later - earlier).total_seconds()


def find_attempts(events):
    """Turn log events into login ATTEMPTS, counting each connection only once.

    One attempt often produces two lines, "Invalid user admin ..." and then
    "Failed password for invalid user admin ...". Both lines come from the same
    IP and the same source port, so we use that pair to recognise them as one.

    Returns a list of {"ip": ..., "time": ..., "user": ...}.
    """
    attempts = []
    last_seen = {}      # (ip, port) -> time of the latest line for that connection

    for event in events:
        if event["kind"] not in BAD_KINDS:
            continue                                  # ignore successful logins

        key = (event["ip"], event["port"])
        previous = last_seen.get(key)                 # None if we have not seen it yet
        last_seen[key] = event["time"]

        if previous is not None and seconds_between(previous, event["time"]) <= SAME_ATTEMPT_SECONDS:
            continue                                  # another line of the same attempt

        attempts.append({"ip": event["ip"], "time": event["time"], "user": event["user"]})

    return attempts


def by_busiest(finding):
    """Helper for sorting: the number we sort findings by."""
    return finding["attempts_in_window"]


def find_brute_force(events, min_attempts=5, window_seconds=300):
    """Find IP addresses with many failed attempts in a short time.

    An IP is reported when, at some moment, it made at least min_attempts failed
    attempts within window_seconds. (Defaults: 5 attempts within 5 minutes.)

    Returns a list of dictionaries, the busiest IP first:
        {"ip", "attempts_in_window", "total_attempts",
         "first_seen", "last_seen", "users"}
    """
    attempts = find_attempts(events)

    # Group the attempts by IP: {"203.0.113.5": [attempt, attempt, ...], ...}
    by_ip = {}
    for attempt in attempts:
        ip = attempt["ip"]
        if ip not in by_ip:
            by_ip[ip] = []
        by_ip[ip].append(attempt)

    findings = []
    for ip, ip_attempts in by_ip.items():
        # SLIDING WINDOW: find this IP's busiest period of window_seconds.
        # "end" walks through the attempts one by one. "start" marks the oldest
        # attempt still inside the window, and it only ever moves forward.
        busiest = 0
        start = 0
        for end in range(len(ip_attempts)):
            while seconds_between(ip_attempts[start]["time"], ip_attempts[end]["time"]) > window_seconds:
                start += 1                            # window too wide: drop the oldest
            in_window = end - start + 1
            if in_window > busiest:
                busiest = in_window

        if busiest >= min_attempts:
            users = set()                             # a set keeps each name only once
            for attempt in ip_attempts:
                users.add(attempt["user"])
            findings.append({
                "ip": ip,
                "attempts_in_window": busiest,
                "total_attempts": len(ip_attempts),
                "first_seen": ip_attempts[0]["time"],
                "last_seen": ip_attempts[-1]["time"],
                "users": sorted(users),
            })

    findings.sort(key=by_busiest, reverse=True)       # busiest IP first
    return findings


# Runs only when you start this file directly:  python3 log_parser.py.
# A quick demonstration with made-up lines (203.0.113.x, 198.51.100.x and 192.0.2.x
# are reserved example addresses that never belong to a real machine).
if __name__ == "__main__":
    print("--- Demo 1: parsing single lines ---")
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

    print()
    print("--- Demo 2: finding brute force ---")
    print("7 failed attempts from 203.0.113.5 in 18 seconds, 2 from 192.0.2.44")
    demo_events = []
    for number in range(7):
        line = (f"2026-09-30T01:00:{number * 3:02d}+0000 myserver sshd-session[1]: "
                f"Failed password for root from 203.0.113.5 port {40000 + number} ssh2")
        demo_events.append(parse_ssh_line(line))
    for number in range(2):
        line = (f"2026-09-30T01:00:{30 + number * 3:02d}+0000 myserver sshd-session[1]: "
                f"Failed password for admin from 192.0.2.44 port {50000 + number} ssh2")
        demo_events.append(parse_ssh_line(line))

    findings = find_brute_force(demo_events, min_attempts=5, window_seconds=300)
    if len(findings) == 0:
        print("No brute force found.")
    for finding in findings:
        print(f"FOUND {finding['ip']}: {finding['attempts_in_window']} attempts within 5 minutes, "
              f"users tried: {finding['users']}")

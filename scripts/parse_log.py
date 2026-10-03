"""parse_log.py - summarize SSH activity from a log.
"""

import argparse
import os
import sys
from collections import Counter

# Tell Python where our code lives (the "src" folder) so the import below works.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from security_toolkit.log_parser import parse_ssh_line


def read_events(lines, year=None):
    """Parse every line. Returns (how many lines were read, list of SSH events).
    """
    lines_read = 0
    events = []
    for line in lines:
        lines_read += 1
        event = parse_ssh_line(line, year)
        if event is not None:
            events.append(event)
    return lines_read, events


def format_time(event):
    """Show an event's time as text, like 2026-09-30 01:23:45"""
    return event["time"].strftime("%Y-%m-%d %H:%M:%S")


def print_summary(lines_read, events, top):
    print(f"Read {lines_read} lines, found {len(events)} SSH events.")
    if len(events) == 0:
        print("No SSH events found. Is this an SSH log? If it is, its layout may")
        print("differ from the two layouts that log_parser.py understands.")
        return

    # 1. Count how many events of each kind there are.
    kinds = Counter()                    
    for event in events:
        kinds[event["kind"]] += 1        

    print()
    print("Events by kind:")
    for kind in ("failed_login", "invalid_user", "accepted_login"):
        print(f"  {kind:<15} {kinds[kind]}")      

    # 2. Who is failing, and with which usernames?
    bad_ips = Counter()
    bad_users = Counter()
    for event in events:
        if event["kind"] in ("failed_login", "invalid_user"):
            bad_ips[event["ip"]] += 1
            bad_users[event["user"]] += 1

    print()
    print(f"Top {top} source IPs (failed logins + invalid users):")
    for ip, count in bad_ips.most_common(top):
        print(f"  {ip:<20} {count}")

    print()
    print(f"Top {top} usernames tried:")
    for user, count in bad_users.most_common(top):
        print(f"  {user!r:<20} {count}")           

    # 3. The most important part: who actually got IN?
    accepted = []
    for event in events:
        if event["kind"] == "accepted_login":
            accepted.append(event)

    print()
    if len(accepted) == 0:
        print("Accepted logins: none in this log.")
    else:
        print(f"Accepted logins (last 10 of {len(accepted)}):")
        for event in accepted[-10:]:                  # [-10:] = the last ten items
            print(f"  {format_time(event)}  {event['user']}  from {event['ip']}  ({event['method']})")


def print_events(events):
    print()
    print("All events:")
    for event in events:
        print(f"  {format_time(event)}  {event['kind']:<15} user={event['user']!r} ip={event['ip']}")


def main():
    parser = argparse.ArgumentParser(
        description="Summarize SSH activity from a log file or from piped input."
    )
    parser.add_argument("logfile", nargs="?",
                        help="log file to read (leave it out to read from a pipe)")
    parser.add_argument("--year", type=int,
                        help="year for classic syslog lines (default: the current year)")
    parser.add_argument("--top", type=int, default=5,
                        help="how many top IPs and usernames to show (default: 5)")
    parser.add_argument("--show-events", action="store_true",
                        help="also list every event, one per line")
    args = parser.parse_args()

    if args.logfile:
        # errors="replace": attackers send junk bytes. Do not crash on them.
        try:
            with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
                lines_read, events = read_events(f, args.year)
        except OSError as error:
            print(f"ERROR: cannot read {args.logfile} ({error.strerror})")
            return 1
    else:
        # No file name given. If we are connected to a keyboard, nothing is being
        # piped in, and waiting for typing would just look like the tool froze.
        if sys.stdin.isatty():
            print("ERROR: give a log file name, or pipe a log into this tool. Try --help")
            return 1
        sys.stdin.reconfigure(errors="replace")
        lines_read, events = read_events(sys.stdin, args.year)

    print_summary(lines_read, events, args.top)
    if args.show_events:
        print_events(events)
    return 0


# Runs only when you start this file directly, not when it is imported.
if __name__ == "__main__":
    sys.exit(main())

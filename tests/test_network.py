"""test_network.py - automatic tests for src/security_toolkit/network.py
"""

import os
import socket
import sys
import unittest

# Tell Python where the code lives
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from security_toolkit.network import (
    check_port,
    scan_ports,
    split_address,
    parse_ss_output,
    find_exposed,
    find_risky,
)

# A made-up copy of what the command `ss -tuln` prints on a server.
SAMPLE_SS = """\
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.1:5432      0.0.0.0:*
tcp   LISTEN 0      511    0.0.0.0:80          0.0.0.0:*
tcp   LISTEN 0      128    [::]:22             [::]:*
tcp   LISTEN 0      4096   0.0.0.0:6379        0.0.0.0:*
udp   UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*
tcp   ESTAB  0      0      203.0.113.9:22      198.51.100.7:50122
"""

# The same idea, but from `ss -tulnp`, which also shows the program name.
SAMPLE_SS_WITH_PROCESS = """\
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      4096   127.0.0.1:5432      0.0.0.0:*
"""


class TestSplitAddress(unittest.TestCase):
    """split_address(): "0.0.0.0:22" in, ("0.0.0.0", 22) out."""

    def test_ipv4(self):
        self.assertEqual(split_address("0.0.0.0:22"), ("0.0.0.0", 22))

    def test_ipv6_in_brackets(self):
        self.assertEqual(split_address("[::]:22"), ("::", 22))

    def test_ipv6_with_a_longer_address(self):
        self.assertEqual(split_address("[2001:db8::1]:443"), ("2001:db8::1", 443))

    def test_interface_name_is_removed(self):
        self.assertEqual(split_address("127.0.0.53%lo:53"), ("127.0.0.53", 53))

    def test_star_address(self):
        self.assertEqual(split_address("*:68"), ("*", 68))

    def test_star_port_gives_none(self):
        self.assertEqual(split_address("0.0.0.0:*"), (None, None))

    def test_no_colon_gives_none(self):
        self.assertEqual(split_address("hello"), (None, None))


class TestParseSsOutput(unittest.TestCase):
    """parse_ss_output(): the text printed by `ss` in, a list of services out."""

    def test_finds_only_listening_services(self):
        services = parse_ss_output(SAMPLE_SS)
        # 6 listening lines. The ESTAB line (an active connection) is skipped.
        self.assertEqual(len(services), 6)

    def test_service_has_the_right_details(self):
        services = parse_ss_output(SAMPLE_SS)
        first = services[0]                     # the list is sorted by port, so port 22 is first
        self.assertEqual(first["protocol"], "tcp")
        self.assertEqual(first["port"], 22)
        self.assertEqual(first["address"], "0.0.0.0")

    def test_ipv6_service_is_found(self):
        services = parse_ss_output(SAMPLE_SS)
        addresses = []
        for service in services:
            addresses.append(service["address"])
        self.assertIn("::", addresses)

    def test_udp_service_is_found(self):
        services = parse_ss_output(SAMPLE_SS)
        protocols = []
        for service in services:
            protocols.append(service["protocol"])
        self.assertIn("udp", protocols)

    def test_header_line_is_skipped(self):
        services = parse_ss_output("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port")
        self.assertEqual(services, [])

    def test_empty_text_gives_empty_list(self):
        self.assertEqual(parse_ss_output(""), [])

    def test_junk_text_gives_empty_list(self):
        self.assertEqual(parse_ss_output("garbage line here\nmore junk"), [])

    def test_process_name_is_read_when_present(self):
        services = parse_ss_output(SAMPLE_SS_WITH_PROCESS)
        self.assertEqual(services[0]["process"], "sshd")

    def test_process_is_none_when_missing(self):
        services = parse_ss_output(SAMPLE_SS)
        self.assertIsNone(services[0]["process"])

    def test_services_are_sorted_by_port(self):
        services = parse_ss_output(SAMPLE_SS)
        ports = []
        for service in services:
            ports.append(service["port"])
        self.assertEqual(ports, sorted(ports))


class TestFindExposed(unittest.TestCase):
    """find_exposed(): which services listen on the whole network unexpectedly?"""

    def test_reports_unexpected_exposed_service(self):
        services = parse_ss_output(SAMPLE_SS)
        exposed = find_exposed(services, expected_ports=(22, 80, 443))
        ports = []
        for service in exposed:
            ports.append(service["port"])
        self.assertEqual(ports, [6379])         # Redis was not expected

    def test_localhost_only_service_is_not_exposed(self):
        # Port 5432 listens on 127.0.0.1 only, so it is never reported.
        services = parse_ss_output(SAMPLE_SS)
        exposed = find_exposed(services)        # expect nothing at all
        ports = []
        for service in exposed:
            ports.append(service["port"])
        self.assertNotIn(5432, ports)

    def test_expected_ports_are_not_reported(self):
        services = parse_ss_output(SAMPLE_SS)
        exposed = find_exposed(services, expected_ports=(22, 80, 6379))
        self.assertEqual(exposed, [])

    def test_no_expected_ports_reports_every_exposed_service(self):
        services = parse_ss_output(SAMPLE_SS)
        exposed = find_exposed(services)
        # 22 (IPv4), 22 (IPv6), 80 and 6379 listen on every interface.
        self.assertEqual(len(exposed), 4)


class TestFindRisky(unittest.TestCase):
    """find_risky(): exposed services on dangerous ports."""

    def test_redis_exposed_is_risky(self):
        services = parse_ss_output(SAMPLE_SS)
        risky = find_risky(services)
        self.assertEqual(len(risky), 1)
        self.assertEqual(risky[0]["service"]["port"], 6379)

    def test_reason_is_given(self):
        services = parse_ss_output(SAMPLE_SS)
        risky = find_risky(services)
        self.assertIn("Redis", risky[0]["reason"])

    def test_risky_port_on_localhost_only_is_fine(self):
        # PostgreSQL (5432) is on the risky list, but here it only listens on 127.0.0.1.
        services = parse_ss_output(SAMPLE_SS)
        risky = find_risky(services)
        ports = []
        for item in risky:
            ports.append(item["service"]["port"])
        self.assertNotIn(5432, ports)

    def test_nothing_risky_gives_empty_list(self):
        text = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
        self.assertEqual(find_risky(parse_ss_output(text)), [])


class TestCheckPort(unittest.TestCase):
    """check_port() and scan_ports(): are ports open on a machine we own?"""

    def setUp(self):
        # Runs before EACH test. Start a tiny server on this computer.
        # Port 0 means "pick any free port for me".
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.open_port = self.server.getsockname()[1]

    def tearDown(self):
        # Runs after EACH test. Always stop the server.
        self.server.close()

    def find_closed_port(self):
        """Helper (not a test): find a port with nothing listening on it."""
        temp = socket.socket()
        temp.bind(("127.0.0.1", 0))
        port = temp.getsockname()[1]
        temp.close()                            # now nothing uses this port
        return port

    def test_open_port_is_found(self):
        self.assertTrue(check_port("127.0.0.1", self.open_port))

    def test_localhost_name_works_too(self):
        self.assertTrue(check_port("localhost", self.open_port))

    def test_closed_port_gives_false(self):
        closed = self.find_closed_port()
        self.assertFalse(check_port("127.0.0.1", closed, timeout=0.5))

    def test_public_address_is_refused(self):
        # 203.0.113.5 is not a private address, so the safety check stops us.
        with self.assertRaises(ValueError):
            check_port("203.0.113.5", 22)

    def test_port_zero_is_refused(self):
        with self.assertRaises(ValueError):
            check_port("127.0.0.1", 0)

    def test_port_too_big_is_refused(self):
        with self.assertRaises(ValueError):
            check_port("127.0.0.1", 70000)

    def test_port_as_text_is_refused(self):
        with self.assertRaises(ValueError):
            check_port("127.0.0.1", "22")

    def test_unknown_host_name_is_refused(self):
        # .invalid is reserved: it can never be a real name.
        with self.assertRaises(ValueError):
            check_port("no-such-host.invalid", 22)

    def test_scan_finds_only_the_open_port(self):
        closed = self.find_closed_port()
        found = scan_ports("127.0.0.1", [closed, self.open_port], timeout=0.5)
        self.assertEqual(found, [self.open_port])

    def test_scan_ignores_repeated_ports(self):
        found = scan_ports("127.0.0.1", [self.open_port, self.open_port], timeout=0.5)
        self.assertEqual(found, [self.open_port])

    def test_scan_refuses_too_many_ports(self):
        with self.assertRaises(ValueError):
            scan_ports("127.0.0.1", range(1, 2000))

    def test_scan_refuses_public_address(self):
        with self.assertRaises(ValueError):
            scan_ports("203.0.113.5", [22, 80])


# Lets you also run just this file:  python3 tests/test_network.py
if __name__ == "__main__":
    unittest.main()

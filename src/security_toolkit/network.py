"""network.py - defensive network checks for servers YOU own.
"""

import socket
import subprocess

from security_toolkit.ioc import is_private_ip

# A scan of more ports than this is refused. This is a checker for your own
# server, not a tool for sweeping the whole Internet.
MAX_PORTS_PER_SCAN = 1024

# Services that should almost never be reachable from outside. Listening on the
# whole network is risky because the service is old, sends passwords in clear
# text, or is a database that should only talk to the local machine.
RISKY_PORTS = {
    21: "FTP (sends passwords in clear text)",
    23: "Telnet (sends passwords in clear text)",
    69: "TFTP (no authentication)",
    110: "POP3 (clear text mail login)",
    143: "IMAP (clear text mail login)",
    445: "SMB (file sharing, common attack target)",
    1433: "Microsoft SQL Server (database)",
    3306: "MySQL / MariaDB (database)",
    3389: "RDP (remote desktop, common attack target)",
    5432: "PostgreSQL (database)",
    5900: "VNC (remote desktop)",
    6379: "Redis (database, often no password)",
    9200: "Elasticsearch (database)",
    27017: "MongoDB (database)",
}

# Addresses that mean "listening on every network interface".
ALL_INTERFACES = ("0.0.0.0", "::", "*")


# ---------------------------------------------------------------------------
# Part 1: is a port open?
# ---------------------------------------------------------------------------

def resolve_host(host):
    """Turn a host name or address into a list of IP addresses (as text).

    Raises ValueError if the name cannot be resolved.
    """
    try:
        results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise ValueError(f"cannot resolve {host!r}: {error}")
    addresses = []
    for result in results:
        address = result[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


def check_allowed(host, allow_public=False):
    """Return the IP address to test, or raise ValueError if it is not allowed.

    Every address the name resolves to must be private (or localhost), unless
    allow_public=True.
    """
    addresses = resolve_host(host)
    if not allow_public:
        for address in addresses:
            if not is_private_ip(address):
                raise ValueError(
                    f"{host} ({address}) is not a private address. Only test hosts you own. "
                    "Pass allow_public=True if you have permission."
                )
    return addresses[0]


def check_port(host, port, timeout=1.0, allow_public=False):
    """Return True if a TCP connection to host:port succeeds, False otherwise."""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"port must be a whole number from 1 to 65535, not {port!r}")

    address = check_allowed(host, allow_public)
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:                      # refused, timed out, unreachable ...
        return False


def scan_ports(host, ports, timeout=1.0, allow_public=False):
    """Check several ports on one host. Returns the open ports, lowest first."""
    ports = sorted(set(ports))
    if len(ports) > MAX_PORTS_PER_SCAN:
        raise ValueError(f"too many ports ({len(ports)}). The limit is {MAX_PORTS_PER_SCAN}.")

    check_allowed(host, allow_public)    # fail early, before testing anything

    open_ports = []
    for port in ports:
        if check_port(host, port, timeout, allow_public):
            open_ports.append(port)
    return open_ports


# ---------------------------------------------------------------------------
# Part 2: what is this server listening on?
# ---------------------------------------------------------------------------

def split_address(text):
    """Split "0.0.0.0:22", "[::]:22" or "127.0.0.53%lo:53" into (address, port).

    Returns (None, None) if the text is not an address and port.
    """
    if ":" not in text:
        return None, None

    address, port = text.rsplit(":", 1)       # the LAST colon separates the port
    if not port.isdigit():
        return None, None                     # "*" for example

    address = address.strip("[]")             # IPv6 addresses come in [brackets]
    address = address.split("%")[0]           # drop the interface name: 127.0.0.53%lo
    return address, int(port)


def parse_ss_output(text):
    """Turn the output of `ss -tuln` (or `ss -tulnp`) into a list of services.

    Only LISTENING sockets are returned (TCP "LISTEN", UDP "UNCONN").
    Each service is a dictionary:
        {"protocol": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd"}
    "process" is None unless ss was run with -p and could see the process.
    """
    services = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue                          # empty or too short
        if parts[0] not in ("tcp", "udp"):
            continue                          # the header line, or another protocol
        if parts[1] not in ("LISTEN", "UNCONN"):
            continue                          # not a listening socket

        address, port = split_address(parts[4])
        if port is None:
            continue

        process = None
        if len(parts) > 6 and parts[-1].startswith("users:"):
            # users:(("sshd",pid=812,fd=3))  ->  sshd
            start = parts[-1].find('(("')
            if start != -1:
                end = parts[-1].find('"', start + 3)
                if end != -1:
                    process = parts[-1][start + 3:end]

        services.append({
            "protocol": parts[0],
            "address": address,
            "port": port,
            "process": process,
        })

    services.sort(key=lambda service: (service["port"], service["protocol"], service["address"]))
    return services


def get_listening_services():
    """Run `ss -tuln` on this Linux server and return the parsed services.

    Raises RuntimeError if ss is not available or fails.
    """
    try:
        result = subprocess.run(
            ["ss", "-tuln"], capture_output=True, text=True, timeout=10, check=True
        )
    except FileNotFoundError:
        raise RuntimeError("the 'ss' command was not found (this check needs Linux)")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"could not run ss: {error}")
    return parse_ss_output(result.stdout)


def is_exposed(service):
    """True if the service listens on every network interface, not just localhost."""
    return service["address"] in ALL_INTERFACES


def find_exposed(services, expected_ports=()):
    """Services reachable from the whole network that you did NOT expect.

    expected_ports: ports you meant to expose, for example (22, 80, 443).
    """
    expected = set(expected_ports)
    return [s for s in services if is_exposed(s) and s["port"] not in expected]


def find_risky(services):
    """Exposed services on ports known to be risky. Returns a list of
    {"service": <service>, "reason": "<why it is risky>"}."""
    risky = []
    for service in services:
        if is_exposed(service) and service["port"] in RISKY_PORTS:
            risky.append({"service": service, "reason": RISKY_PORTS[service["port"]]})
    return risky


# Runs only when you start this file directly:  python3 -m security_toolkit.network
# The sample below is made up. It looks like the output of `ss -tuln`.
if __name__ == "__main__":
    SAMPLE = """\
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.1:5432      0.0.0.0:*
tcp   LISTEN 0      511    0.0.0.0:80          0.0.0.0:*
tcp   LISTEN 0      128    [::]:22             [::]:*
tcp   LISTEN 0      4096   0.0.0.0:6379        0.0.0.0:*
udp   UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*
"""
    found = parse_ss_output(SAMPLE)
    print(f"{len(found)} listening services")
    print()
    print("Exposed on all interfaces, not in the expected list (22, 80, 443):")
    for service in find_exposed(found, expected_ports=(22, 80, 443)):
        print(f"  {service['protocol']} {service['address']}:{service['port']}")
    print()
    print("Risky services exposed:")
    for item in find_risky(found):
        service = item["service"]
        print(f"  port {service['port']}: {item['reason']}")

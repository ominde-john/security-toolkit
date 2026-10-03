"""ioc.py - find, check and match indicators of compromise (IOCs).
"""

import ipaddress
import re

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# A hash is just hexadecimal characters of a fixed length.
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
HASH_PATTERN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")

# One part of a domain name (between the dots): letters, digits and dashes,
LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
# A domain is two or more labels. 
DOMAIN_PATTERN = re.compile(rf"^(?:{LABEL}\.)+[a-zA-Z]{{2,63}}$")
DOMAIN_IN_TEXT = re.compile(rf"(?<![\w.@-])(?:{LABEL}\.)+[a-zA-Z]{{2,63}}(?![\w-])")

URL_PATTERN = re.compile(r"^https?://[^\s/?#]+(?:[/?#]\S*)?$", re.IGNORECASE)
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

EMAIL_PATTERN = re.compile(rf"^[A-Za-z0-9._%+-]+@(?:{LABEL}\.)+[a-zA-Z]{{2,63}}$")
EMAIL_IN_TEXT = re.compile(rf"[A-Za-z0-9._%+-]+@(?:{LABEL}\.)+[a-zA-Z]{{2,63}}")

# Rough candidates for IP addresses. Python's ipaddress module does the real check.
IPV4_IN_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
IPV6_IN_TEXT = re.compile(r"(?<![0-9a-fA-F:])[0-9a-fA-F:]{2,}(?![0-9a-fA-F:])")

# File names look like domains (report.txt, run.py). When hunting inside free
# text we skip names that end like a file so they are not reported as domains.
FILE_ENDINGS = {
    "txt", "log", "py", "sh", "md", "json", "csv", "yml", "yaml", "xml", "html",
    "js", "ts", "pdf", "doc", "docx", "xls", "xlsx", "zip", "gz", "tar", "conf",
    "cfg", "ini", "sql", "png", "jpg", "jpeg", "gif", "exe", "dll", "bin",
}

# The order we report indicator types in.
IOC_TYPES = ("ipv4", "ipv6", "url", "email", "domain", "md5", "sha1", "sha256")


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------

def refang(text):
    text = text.strip()
    text = re.sub(r"hxxp", "http", text, flags=re.IGNORECASE)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = text.replace("[dot]", ".").replace("(dot)", ".")
    text = text.replace("[at]", "@").replace("(at)", "@").replace("[@]", "@")
    text = text.replace("[:]", ":").replace("[://]", "://")
    return text


# ---------------------------------------------------------------------------
# Checking ONE indicator
# ---------------------------------------------------------------------------

def classify_ioc(text):
    """Say what kind of indicator `text` is.

    Returns one of "ipv4", "ipv6", "url", "email", "domain", "md5", "sha1",
    "sha256", or None if it is none of those.
    """
    text = refang(text)
    if text == "":
        return None

    # IP addresses first. ip_address() accepts only real addresses, so
    # "999.1.1.1" is rejected here instead of being mistaken for a domain.
    try:
        address = ipaddress.ip_address(text)
        return "ipv4" if address.version == 4 else "ipv6"
    except ValueError:
        pass

    if text.lower().startswith(("http://", "https://")):
        return "url" if URL_PATTERN.match(text) else None

    if "@" in text:
        return "email" if EMAIL_PATTERN.match(text) else None

    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) in HASH_LENGTHS:
        return HASH_LENGTHS[len(text)]

    if len(text) <= 253 and DOMAIN_PATTERN.match(text):
        return "domain"

    return None


# Address ranges that only exist inside a network. We list them ourselves rather
# than using Python's built-in is_private, because that one ALSO counts the
# documentation ranges (203.0.113.x ...) that this toolkit uses as fake attackers.
PRIVATE_NETWORKS = [ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # private networks
    "127.0.0.0/8", "169.254.0.0/16",                   # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10",                # the IPv6 equivalents
)]


def is_private_ip(text):
    """True for addresses that only exist inside a network (10.x, 192.168.x, 127.x ...).

    A private address is rarely a useful threat indicator, so it is handy to know.
    Returns False for anything that is not an IP address.
    """
    try:
        address = ipaddress.ip_address(refang(text))
    except ValueError:
        return False
    for network in PRIVATE_NETWORKS:
        if address.version == network.version and address in network:
            return True
    return False


# ---------------------------------------------------------------------------
# Finding MANY indicators in text
# ---------------------------------------------------------------------------

def extract_iocs(text):
    """Find every indicator in a block of text.

    Returns a dictionary with one sorted list per type, each value only once:
        {"ipv4": [...], "ipv6": [...], "url": [...], "email": [...],
         "domain": [...], "md5": [...], "sha1": [...], "sha256": [...]}
    """
    text = refang(text)
    found = {kind: set() for kind in IOC_TYPES}

    for candidate in IPV4_IN_TEXT.findall(text):
        if classify_ioc(candidate) == "ipv4":        # drops things like 999.1.1.1
            found["ipv4"].add(candidate)

    for candidate in IPV6_IN_TEXT.findall(text):
        if candidate.count(":") >= 2 and classify_ioc(candidate) == "ipv6":
            found["ipv6"].add(candidate.lower())

    for candidate in URL_IN_TEXT.findall(text):
        candidate = candidate.rstrip(".,;:)]}")      # a sentence's punctuation is not part of the URL
        if classify_ioc(candidate) == "url":
            found["url"].add(candidate)

    for candidate in EMAIL_IN_TEXT.findall(text):
        found["email"].add(candidate.lower())

    for candidate in DOMAIN_IN_TEXT.findall(text):
        ending = candidate.rsplit(".", 1)[1].lower()
        if ending in FILE_ENDINGS:
            continue                                 # looks like a file name, skip
        found["domain"].add(candidate.lower())

    for candidate in HASH_PATTERN.findall(text):
        found[HASH_LENGTHS[len(candidate)]].add(candidate.lower())

    return {kind: sorted(values) for kind, values in found.items()}


# ---------------------------------------------------------------------------
# Matching against a known-bad list
# ---------------------------------------------------------------------------

def normalize(indicator):
    """Make an indicator comparable: refanged, trimmed and lower case."""
    return refang(indicator).strip().lower()


def match_iocs(found, known_bad):
    """Report which found indicators appear on a known-bad list.

    found      the dictionary returned by extract_iocs()
    known_bad  any collection of indicator strings (a list, a set ...)

    Returns a list of {"type": ..., "indicator": ...}, one per match.
    """
    bad = {normalize(item) for item in known_bad}
    matches = []
    for kind in IOC_TYPES:
        for indicator in found.get(kind, []):
            if normalize(indicator) in bad:
                matches.append({"type": kind, "indicator": indicator})
    return matches


# Runs only when you start this file directly:  python3 -m security_toolkit.ioc
# All values are made up. 203.0.113.x and example.com are reserved for examples.
if __name__ == "__main__":
    report = (
        "Alert: connection from 203.0.113.5 to hxxp://evil-example[.]com/payload.bin. "
        "Mail from attacker@evil-example.com. Dropped file "
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 "
        "(see notes.txt). Internal host 10.0.0.8 also seen."
    )
    iocs = extract_iocs(report)
    for kind in IOC_TYPES:
        if iocs[kind]:
            print(f"{kind:<7} {iocs[kind]}")

    print()
    print("On the known-bad list:", match_iocs(iocs, ["203.0.113.5", "EVIL-EXAMPLE.com"]))
    print("Is 10.0.0.8 private?  ", is_private_ip("10.0.0.8"))

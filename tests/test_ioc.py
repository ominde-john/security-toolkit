"""test_ioc.py - automatic tests for src/security_toolkit/ioc.py
"""

import os
import sys
import unittest

# Tell Python where the code lives
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from security_toolkit.ioc import (
    classify_ioc,
    extract_iocs,
    is_private_ip,
    match_iocs,
    refang,
)

# Real hash values of the text "hello" (md5 and sha1) and of an empty file (sha256).
MD5 = "5d41402abc4b2a76b9719d911017c592"
SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestRefang(unittest.TestCase):
    """Tests for refang(): "defanged" text in, normal text out."""

    def test_hxxp_becomes_http(self):
        self.assertEqual(refang("hxxp://example.com"), "http://example.com")

    def test_hxxps_becomes_https(self):
        self.assertEqual(refang("hxxps://example.com"), "https://example.com")

    def test_hxxp_in_capitals(self):
        self.assertEqual(refang("HXXP://example.com"), "http://example.com")

    def test_bracketed_dots(self):
        self.assertEqual(refang("evil[.]example[.]com"), "evil.example.com")

    def test_other_dot_styles(self):
        self.assertEqual(refang("a(.)example(dot)com"), "a.example.com")

    def test_bracketed_at_sign(self):
        self.assertEqual(refang("user[at]example.com"), "user@example.com")

    def test_normal_text_is_unchanged(self):
        self.assertEqual(refang("http://example.com/a.html"), "http://example.com/a.html")

    def test_spaces_around_are_removed(self):
        self.assertEqual(refang("   example.com  "), "example.com")


class TestClassifyIoc(unittest.TestCase):
    """Tests for classify_ioc(): one indicator in, its type (or None) out."""

    def test_valid_types(self):
        # subTest runs the same check on each pair and reports each one separately.
        cases = [
            ("203.0.113.5", "ipv4"),
            ("2001:db8::1", "ipv6"),
            ("::1", "ipv6"),
            ("http://example.com", "url"),
            ("https://example.com/path?x=1#top", "url"),
            ("user@example.com", "email"),
            ("first.last+tag@mail.example.com", "email"),
            ("example.com", "domain"),
            ("sub.example.co.uk", "domain"),
            ("xn--bcher-kva.example", "domain"),
            (MD5, "md5"),
            (SHA1, "sha1"),
            (SHA256, "sha256"),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(classify_ioc(text), expected)

    def test_not_indicators_give_none(self):
        cases = [
            "",
            "   ",
            "localhost",            # one label only, no dot
            "999.1.1.1",            # looks like an IP but 999 is impossible
            "1.2.3",                # too few parts
            "-bad.example.com",     # label starts with a dash
            "bad-.example.com",     # label ends with a dash
            "a..example.com",       # empty label
            "example.c",            # last part too short
            "example.123",          # last part must be letters
            "ftp://example.com",    # only http and https count as URLs
            "http://",              # no host
            "bad@@example.com",     # two @ signs
            "@example.com",         # nothing before the @
            "abc123",               # hex, but not a hash length
            "z" * 32,               # right length, but not hexadecimal
            "hello world",
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertIsNone(classify_ioc(text))

    def test_defanged_input_is_understood(self):
        self.assertEqual(classify_ioc("hxxp://evil[.]example[.]com"), "url")
        self.assertEqual(classify_ioc("203[.]0[.]113[.]5"), "ipv4")
        self.assertEqual(classify_ioc("user[at]example[.]com"), "email")

    def test_capitals_and_spaces_are_ignored(self):
        self.assertEqual(classify_ioc("  EXAMPLE.COM  "), "domain")
        self.assertEqual(classify_ioc(SHA256.upper()), "sha256")

    def test_ip_wins_over_domain(self):
        # 203.0.113.5 also fits the "dots and digits" shape, but it is an IP.
        self.assertEqual(classify_ioc("203.0.113.5"), "ipv4")

    def test_overlong_domain_is_rejected(self):
        too_long = ".".join(["a" * 60] * 5) + ".com"      # longer than 253 characters
        self.assertIsNone(classify_ioc(too_long))


class TestIsPrivateIp(unittest.TestCase):
    """Tests for is_private_ip(): is this address only used inside a network?"""

    def test_private_addresses(self):
        for ip in ("10.0.0.8", "172.16.5.5", "192.168.1.1", "127.0.0.1",
                   "169.254.1.1", "::1", "fe80::1", "fd00::1"):
            with self.subTest(ip=ip):
                self.assertTrue(is_private_ip(ip))

    def test_public_addresses(self):
        for ip in ("8.8.8.8", "172.32.0.1", "172.15.255.255", "2606:4700::1111"):
            with self.subTest(ip=ip):
                self.assertFalse(is_private_ip(ip))

    def test_documentation_addresses_count_as_public(self):
        # Our fake "attackers" must not be treated as internal machines.
        self.assertFalse(is_private_ip("203.0.113.5"))
        self.assertFalse(is_private_ip("198.51.100.7"))
        self.assertFalse(is_private_ip("2001:db8::1"))

    def test_not_an_ip_gives_false(self):
        self.assertFalse(is_private_ip("example.com"))
        self.assertFalse(is_private_ip(""))


class TestExtractIocs(unittest.TestCase):
    """Tests for extract_iocs(): a block of text in, a dictionary of lists out."""

    def test_result_has_every_type_even_when_empty(self):
        result = extract_iocs("nothing interesting here")
        self.assertEqual(
            sorted(result), ["domain", "email", "ipv4", "ipv6", "md5", "sha1", "sha256", "url"]
        )
        for values in result.values():
            self.assertEqual(values, [])

    def test_finds_each_type(self):
        text = (
            f"Seen 203.0.113.5 and 2001:db8::1, url http://example.com/a, "
            f"mail bob@example.org, host evil.example.net, "
            f"hashes {MD5} {SHA1} {SHA256}"
        )
        result = extract_iocs(text)
        self.assertEqual(result["ipv4"], ["203.0.113.5"])
        self.assertEqual(result["ipv6"], ["2001:db8::1"])
        self.assertEqual(result["url"], ["http://example.com/a"])
        self.assertEqual(result["email"], ["bob@example.org"])
        self.assertEqual(result["domain"], ["evil.example.net", "example.com"])
        self.assertEqual(result["md5"], [MD5])
        self.assertEqual(result["sha1"], [SHA1])
        self.assertEqual(result["sha256"], [SHA256])

    def test_each_value_is_listed_once(self):
        result = extract_iocs("203.0.113.5 then 203.0.113.5 again")
        self.assertEqual(result["ipv4"], ["203.0.113.5"])

    def test_lists_are_sorted(self):
        result = extract_iocs("198.51.100.7 and 10.0.0.1 and 203.0.113.5")
        self.assertEqual(result["ipv4"], ["10.0.0.1", "198.51.100.7", "203.0.113.5"])

    def test_defanged_text_is_found(self):
        result = extract_iocs("see hxxp://evil[.]example[.]com/x from 203[.]0[.]113[.]5")
        self.assertEqual(result["url"], ["http://evil.example.com/x"])
        self.assertEqual(result["ipv4"], ["203.0.113.5"])

    def test_full_stop_after_an_ip_is_not_part_of_it(self):
        self.assertEqual(extract_iocs("Attack came from 203.0.113.5.")["ipv4"], ["203.0.113.5"])

    def test_punctuation_after_a_url_is_dropped(self):
        result = extract_iocs("Visit (http://example.com/page), then stop.")
        self.assertEqual(result["url"], ["http://example.com/page"])

    def test_impossible_ip_is_not_reported(self):
        self.assertEqual(extract_iocs("value 999.1.1.1 here")["ipv4"], [])

    def test_five_part_number_is_not_an_ip(self):
        # Version numbers like 1.2.3.4.5 are not addresses.
        self.assertEqual(extract_iocs("build 1.2.3.4.5 released")["ipv4"], [])

    def test_clock_times_are_not_ipv6(self):
        self.assertEqual(extract_iocs("logged at 12:34:56 today")["ipv6"], [])

    def test_file_names_are_not_domains(self):
        result = extract_iocs("wrote report.txt and run.py and archive.zip")
        self.assertEqual(result["domain"], [])

    def test_email_domain_is_not_double_counted_as_domain(self):
        # The part after the @ belongs to the email, not a separate domain.
        result = extract_iocs("contact bob@example.org")
        self.assertEqual(result["email"], ["bob@example.org"])
        self.assertEqual(result["domain"], [])

    def test_capital_letters_are_lowered_for_domains_emails_hashes(self):
        result = extract_iocs(f"Evil.Example.COM  Bob@Example.ORG  {SHA256.upper()}")
        self.assertEqual(result["domain"], ["evil.example.com"])
        self.assertEqual(result["email"], ["bob@example.org"])
        self.assertEqual(result["sha256"], [SHA256])

    def test_a_long_hash_is_not_split_into_smaller_hashes(self):
        # A 64-character sha256 contains 32 hex characters, but it is NOT an md5.
        result = extract_iocs(SHA256)
        self.assertEqual(result["sha256"], [SHA256])
        self.assertEqual(result["md5"], [])
        self.assertEqual(result["sha1"], [])

    def test_empty_text(self):
        result = extract_iocs("")
        self.assertEqual(sum(len(values) for values in result.values()), 0)


class TestMatchIocs(unittest.TestCase):
    """Tests for match_iocs(): which found indicators are on a known-bad list?"""

    def test_reports_the_matches_only(self):
        found = extract_iocs("from 203.0.113.5 and 198.51.100.7 to evil.example.com")
        matches = match_iocs(found, ["203.0.113.5", "evil.example.com"])
        self.assertEqual(
            matches,
            [
                {"type": "ipv4", "indicator": "203.0.113.5"},
                {"type": "domain", "indicator": "evil.example.com"},
            ],
        )

    def test_no_matches_gives_empty_list(self):
        found = extract_iocs("from 203.0.113.5")
        self.assertEqual(match_iocs(found, ["198.51.100.7"]), [])

    def test_empty_bad_list_gives_empty_list(self):
        self.assertEqual(match_iocs(extract_iocs("from 203.0.113.5"), []), [])

    def test_capitals_and_spaces_in_the_bad_list_are_ignored(self):
        found = extract_iocs("host evil.example.com")
        self.assertEqual(len(match_iocs(found, ["  EVIL.Example.COM "])), 1)

    def test_defanged_entries_in_the_bad_list_still_match(self):
        found = extract_iocs("from 203.0.113.5")
        self.assertEqual(len(match_iocs(found, ["203[.]0[.]113[.]5"])), 1)

    def test_bad_list_can_be_a_set(self):
        found = extract_iocs("from 203.0.113.5")
        self.assertEqual(len(match_iocs(found, {"203.0.113.5"})), 1)

    def test_hash_match(self):
        found = extract_iocs(f"dropped {SHA256}")
        self.assertEqual(match_iocs(found, [SHA256.upper()]), [{"type": "sha256", "indicator": SHA256}])


# Lets you also run just this file:  python3 tests/test_ioc.py
if __name__ == "__main__":
    unittest.main()

import ssl
import unittest
from datetime import datetime, timezone

from modules.net_safety import UnsafeTargetError
from modules.ssl_analyzer import analyze_ssl, hostname_matches, parse_cert

CERT = {"issuer": ((("organizationName", "Test CA"),), (("commonName", "Test CA R1"),)),
        "subject": ((("commonName", "example.com"),),), "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT", "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"))}
NOW = datetime(2026, 11, 7, tzinfo=timezone.utc)


class SslTests(unittest.TestCase):
    def test_parse_valid_cert(self):
        res = parse_cert(CERT, "example.com", now=NOW)
        self.assertEqual(res["validity_status"], "valid")
        self.assertEqual(res["days_remaining"], 55)
        self.assertTrue(res["hostname_verified"])
        self.assertIn("Test CA", res["issuer"])

    def test_expired_and_mismatch(self):
        res = parse_cert(CERT, "other.org", now=datetime(2028, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(res["validity_status"], "expired")
        self.assertLess(res["days_remaining"], 0)
        self.assertFalse(res["hostname_verified"])

    def test_wildcard_rules(self):
        self.assertTrue(hostname_matches("a.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("a.b.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("example.com", ["*.example.com"]))

    def test_analyze_ok(self):
        res = analyze_ssl("example.com", resolver=lambda d: ["93.184.216.34"], fetcher=lambda d, ip, t: (CERT, "TLSv1.3", "AES"))
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res["trusted"])
        self.assertEqual(res["protocol"], "TLSv1.3")

    def test_untrusted_hostname_mismatch(self):
        def fetcher(d, ip, t):
            e = ssl.SSLCertVerificationError(1, "mismatch")
            e.verify_code, e.verify_message = 62, "Hostname mismatch"
            raise e
        res = analyze_ssl("example.com", resolver=lambda d: ["93.184.216.34"], fetcher=fetcher)
        self.assertFalse(res["trusted"])
        self.assertIs(res["hostname_verified"], False)

    def test_unreachable_and_blocked(self):
        def refuse(d, ip, t): raise ConnectionRefusedError()
        self.assertEqual(analyze_ssl("example.com", resolver=lambda d: ["93.184.216.34"], fetcher=refuse)["status"], "unavailable")
        def blocked(d): raise UnsafeTargetError("private")
        self.assertEqual(analyze_ssl("example.com", resolver=blocked)["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()

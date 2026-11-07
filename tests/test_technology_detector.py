import unittest

from modules.net_safety import UnsafeTargetError
from modules.technology_detector import analyze_response, detect_technology

HTML = '<html><head><title>Demo</title><meta name="generator" content="WordPress 6.5"></head><body><script src="/wp-content/x.js"></script></body></html>'


class FakeResp:
    def __init__(self, status=200, headers=None, body=HTML):
        self.status_code, self.headers, self.encoding, self._b = status, headers or {"Content-Type": "text/html"}, "utf-8", body.encode()
    def iter_content(self, n): yield self._b
    def close(self): pass


class TechTests(unittest.TestCase):
    def test_evidence_based_detection(self):
        res = analyze_response({"Server": "nginx/1.25.3", "X-Powered-By": "PHP/8.2", "Strict-Transport-Security": "max-age=1"}, HTML, ["PHPSESSID"])
        names = {t["name"] for t in res["technologies"]}
        self.assertTrue({"nginx", "PHP", "WordPress"} <= names)
        for t in res["technologies"]:
            self.assertTrue(t["evidence"])
        hsts = next(h for h in res["security_headers"] if h["header"] == "HSTS")
        self.assertTrue(hsts["present"])
        self.assertEqual(res["title"], "Demo")

    def test_no_evidence_no_claims(self):
        res = analyze_response({"Content-Type": "text/html"}, "<html><body>hi</body></html>")
        self.assertEqual(res["technologies"], [])
        self.assertTrue(all(not h["present"] for h in res["security_headers"]))

    def test_detect_https_ok(self):
        res = detect_technology("example.com", resolver=lambda h: ["93.184.216.34"], getter=lambda *a, **k: FakeResp())
        self.assertEqual(res["status"], "ok")
        self.assertTrue(res["https_available"])

    def test_redirect_outside_scope_not_followed(self):
        calls = []
        def getter(url, **k):
            calls.append(url)
            return FakeResp(301, {"Location": "https://evil.net/"})
        res = detect_technology("example.com", resolver=lambda h: ["93.184.216.34"], getter=getter)
        self.assertNotIn("https://evil.net/", calls)
        self.assertEqual(res["status"], "unavailable")
        self.assertTrue(any("outside the target scope" in n for n in res["notes"]))

    def test_private_resolution_blocked(self):
        def resolver(h): raise UnsafeTargetError("resolves to a private address")
        called = []
        res = detect_technology("example.com", resolver=resolver, getter=lambda *a, **k: called.append(1))
        self.assertEqual(res["status"], "unavailable")
        self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()

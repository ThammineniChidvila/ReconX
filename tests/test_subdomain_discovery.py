import unittest

import requests

from modules.subdomain_discovery import discover_subdomains, parse_crtsh

ENTRIES = [{"name_value": "example.com\nwww.example.com"}, {"name_value": "*.api.example.com\nMAIL.example.com"},
           {"name_value": "evil.com\nnotexample.com\nfoo.notexample.com"}, {"name_value": "bad host.example.com"}, {}]


class Resp:
    def __init__(self, code=200, data=None): self.status_code, self._d = code, data
    def json(self):
        if self._d is None: raise ValueError("bad json")
        return self._d


class SubdomainTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_crtsh(ENTRIES, "example.com"), ["api.example.com", "mail.example.com", "www.example.com"])

    def test_discover_ok(self):
        res = discover_subdomains("example.com", http_get=lambda *a, **k: Resp(200, ENTRIES))
        self.assertEqual((res["status"], res["count"]), ("ok", 3))

    def test_unavailable_on_errors(self):
        self.assertEqual(discover_subdomains("example.com", http_get=lambda *a, **k: Resp(502))["status"], "unavailable")
        def boom(*a, **k): raise requests.Timeout()
        self.assertEqual(discover_subdomains("example.com", http_get=boom)["status"], "unavailable")
        self.assertEqual(discover_subdomains("example.com", http_get=lambda *a, **k: Resp(200, None))["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()

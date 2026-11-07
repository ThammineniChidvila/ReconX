import unittest

from modules.rdap_analyzer import fetch_rdap, parse_rdap

DATA = {"status": ["client transfer prohibited"], "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}],
        "nameservers": [{"ldhName": "B.IANA-SERVERS.NET"}, {"ldhName": "a.iana-servers.net"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Test Registrar Inc."]]]}]}


class Resp:
    def __init__(self, code=200, data=None): self.status_code, self._d = code, data
    def json(self): return self._d


class RdapTests(unittest.TestCase):
    def test_parse_and_unavailable_fields(self):
        res = parse_rdap(DATA)
        self.assertEqual(res["registrar"], "Test Registrar Inc.")
        self.assertEqual(res["nameservers"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertEqual(res["domain_status"], ["client transfer prohibited"])
        self.assertIn("updated", res["unavailable"])
        self.assertNotIn("registrar", res["unavailable"])

    def test_fetch_keeps_domain_status_separate_from_module_status(self):
        res = fetch_rdap("example.com", http_get=lambda *a, **k: Resp(200, DATA))
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["domain_status"], ["client transfer prohibited"])

    def test_not_found_and_errors(self):
        self.assertEqual(fetch_rdap("x.com", http_get=lambda *a, **k: Resp(404))["status"], "unavailable")
        self.assertEqual(fetch_rdap("x.com", http_get=lambda *a, **k: Resp(429))["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()

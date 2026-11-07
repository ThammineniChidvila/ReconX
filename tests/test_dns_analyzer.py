import unittest

from modules.dns_analyzer import analyze_dns, query_records


class NoAnswer(Exception): pass
class NXDOMAIN(Exception): pass
class LifetimeTimeout(Exception): pass


class R:  # fake rdata
    def __init__(self, text): self.text = text
    def to_text(self): return self.text


class FakeResolver:
    def __init__(self, data): self.data = data
    def resolve(self, name, rtype):
        item = self.data.get((name, rtype), NoAnswer())
        if isinstance(item, Exception): raise item
        return [R(t) for t in item]


class DnsTests(unittest.TestCase):
    def test_full_analysis(self):
        res = analyze_dns("example.com", FakeResolver({
            ("example.com", "A"): ["93.184.216.34"], ("example.com", "AAAA"): ["2606:2800::1"],
            ("example.com", "MX"): ["10 mail.example.com."], ("example.com", "NS"): ["a.iana-servers.net."],
            ("example.com", "TXT"): ['"v=spf1 -all"', '"part1" "part2"']}))
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["ips"], ["93.184.216.34", "2606:2800::1"])
        by = {(r["type"], r["value"]): r["status"] for r in res["records"]}
        self.assertEqual(by[("NS", "a.iana-servers.net")], "found")
        self.assertIn(("TXT", "part1part2"), by)
        self.assertEqual(by[("CNAME", "-")], "no record")

    def test_nxdomain_and_failures(self):
        self.assertEqual(query_records("x.com", "A", FakeResolver({("x.com", "A"): NXDOMAIN()})), ([], "domain not found"))
        values, err = query_records("x.com", "A", FakeResolver({("x.com", "A"): LifetimeTimeout()}))
        self.assertIsNone(values)
        self.assertIn("LifetimeTimeout", err)

    def test_all_lookups_fail(self):
        class Boom:
            def resolve(self, *a): raise LifetimeTimeout()
        res = analyze_dns("example.com", Boom())
        self.assertEqual(res["status"], "error")


if __name__ == "__main__":
    unittest.main()

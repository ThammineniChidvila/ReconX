import unittest

import config
from modules import port_assessment as pa
from modules.net_safety import UnsafeTargetError, ip_block_reason, is_public_ip, resolve_public


class SafetyTests(unittest.TestCase):
    def test_blocked_ranges(self):
        for ip in ["127.0.0.1", "10.0.0.5", "172.16.3.1", "192.168.1.1", "169.254.169.254", "224.0.0.1", "0.0.0.0",
                   "240.0.0.1", "100.64.0.1", "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1"]:
            self.assertFalse(is_public_ip(ip), ip)
            self.assertIsNotNone(ip_block_reason(ip))
        for ip in ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"]:
            self.assertTrue(is_public_ip(ip), ip)

    def test_resolve_blocks_if_any_address_is_private(self):   # DNS rebinding style answer
        with self.assertRaises(UnsafeTargetError):
            resolve_public("evil.example.com", resolver=lambda h: ["93.184.216.34", "127.0.0.1"])
        with self.assertRaises(UnsafeTargetError):
            resolve_public("nx.example.com", resolver=lambda h: [])

    def test_refuses_without_verification(self):
        with self.assertRaises(pa.NotVerifiedError):
            pa.assess_ports("example.com", verified=False, resolver=lambda h: ["93.184.216.34"], probe=lambda *a: "open")

    def test_refuses_ip_input_and_private_resolution(self):
        with self.assertRaises(UnsafeTargetError):
            pa.assess_ports("127.0.0.1", verified=True, resolver=lambda h: ["127.0.0.1"], probe=lambda *a: "open")
        def private(h): raise UnsafeTargetError("private")
        with self.assertRaises(UnsafeTargetError):
            pa.assess_ports("example.com", verified=True, resolver=private, probe=lambda *a: "open")

    def test_only_safe_ports_are_probed(self):
        probed = []
        def probe(ip, port, timeout):
            probed.append(port)
            return "open" if port == 443 else "closed"
        res = pa.assess_ports("example.com", verified=True, ports={22: "SSH", 443: "HTTPS", 31337: "x", 6379: "redis"},
                              resolver=lambda h: ["93.184.216.34"], probe=probe)
        self.assertEqual(sorted(probed), [22, 443])
        self.assertEqual(res["open_count"], 1)

    def test_full_port_list_and_fields(self):
        res = pa.assess_ports("example.com", verified=True, resolver=lambda h: ["93.184.216.34"], probe=lambda *a: "filtered")
        self.assertEqual([r["port"] for r in res["ports"]], sorted(config.SAFE_PORTS))
        self.assertIn("duration_seconds", res)
        self.assertEqual(len(config.SAFE_PORTS), 14)


class VerificationTests(unittest.TestCase):
    class R:
        def __init__(self, t): self.t = t
        def to_text(self): return self.t

    def make(self, values):
        outer = self
        class Res:
            def resolve(self, name, rtype):
                assert name == "_reconx.example.com" and rtype == "TXT"
                return [outer.R(v) for v in values]
        return Res()

    def test_token_and_record(self):
        t1, t2 = pa.generate_token(), pa.generate_token()
        self.assertNotEqual(t1, t2)
        self.assertEqual(len(t1), 32)
        rec = pa.verification_record("example.com", t1)
        self.assertEqual(rec["name"], "_reconx.example.com")
        self.assertEqual(rec["value"], "reconx-verification=" + t1)

    def test_check(self):
        tok = "abc123"
        self.assertTrue(pa.check_verification("example.com", tok, self.make(['"reconx-verification=abc123"']))["verified"])
        self.assertFalse(pa.check_verification("example.com", tok, self.make(['"reconx-verification=zzz"']))["verified"])


if __name__ == "__main__":
    unittest.main()

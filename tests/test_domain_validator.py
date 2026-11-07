import unittest

from modules.domain_validator import validate_domain


class DomainValidatorTests(unittest.TestCase):
    def test_valid_and_normalised(self):
        for raw, want in [("Example.COM", "example.com"), ("https://www.Example.com/path?x=1", "www.example.com"),
                          ("example.com:8443/login", "example.com"), ("  sub.example.co.uk. ", "sub.example.co.uk"),
                          ("bücher.de", "xn--bcher-kva.de")]:
            res = validate_domain(raw)
            self.assertTrue(res["valid"], raw)
            self.assertEqual(res["domain"], want)

    def test_invalid_inputs(self):
        bad = ["", "   ", None, 123, "localhost", "example", "127.0.0.1", "192.168.1.5", "[::1]", "http://10.0.0.1/",
               "-bad.example.com", "exa mple.com", "user@example.com", "example.local", "a..b.com", "example.123", "x" * 64 + ".com"]
        for raw in bad:
            self.assertFalse(validate_domain(raw)["valid"], repr(raw))

    def test_error_message_present(self):
        res = validate_domain("127.0.0.1")
        self.assertIn("IP addresses", res["error"])
        self.assertIsNone(res["domain"])


if __name__ == "__main__":
    unittest.main()

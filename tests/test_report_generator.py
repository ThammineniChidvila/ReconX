import tempfile
import unittest
from pathlib import Path

from modules.report_generator import generate_report

SCAN = {"id": 1, "domain": "example.com", "scan_type": "intelligence", "status": "partial", "started_at": "2026-11-07T10:00:00+00:00",
        "results": {
            "dns": {"status": "ok", "ips": ["93.184.216.34"], "records": [{"type": "A", "value": "93.184.216.34", "status": "found"}, {"type": "TXT", "value": "<b>v=spf1</b> & stuff", "status": "found"}]},
            "rdap": {"status": "unavailable", "message": "RDAP service unreachable."},
            "ssl": {"status": "ok", "trusted": True, "issuer": "Test CA", "days_remaining": 12, "validity_status": "valid", "hostname_verified": True},
            "subdomains": {"status": "ok", "source": "crt.sh", "count": 2, "subdomains": ["a.example.com", "b.example.com"]},
            "technology": {"status": "ok", "https_available": True, "http_status": 200, "server": "nginx/1.2.3", "security_headers": [{"header": "HSTS", "present": False, "value": ""}], "technologies": []}}}
PORTS = {"id": 2, "domain": "example.com", "scan_type": "port_assessment", "status": "completed", "started_at": "2026-11-07T10:05:00+00:00",
         "results": {"status": "ok", "target_ip": "93.184.216.34", "duration_seconds": 2.1, "open_count": 1, "ports": [{"port": 443, "service": "HTTPS", "state": "open"}, {"port": 3389, "service": "RDP", "state": "open"}]}}


class ReportTests(unittest.TestCase):
    def test_generates_pdf_with_and_without_ports(self):
        with tempfile.TemporaryDirectory() as d:
            for ports in (None, PORTS):
                path = generate_report(SCAN, ports, out_dir=d)
                data = Path(path).read_bytes()
                self.assertTrue(data.startswith(b"%PDF"))
                self.assertGreater(len(data), 1500)

    def test_port_only_and_empty_results(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(Path(generate_report(None, PORTS, out_dir=d)).exists())
            bare = dict(SCAN, id=3, results={})
            self.assertTrue(Path(generate_report(bare, None, out_dir=d)).exists())


if __name__ == "__main__":
    unittest.main()

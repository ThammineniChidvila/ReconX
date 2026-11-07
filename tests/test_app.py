import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config

from database import db, models
from modules import port_assessment as pa
from modules.net_safety import UnsafeTargetError

H = {"X-Requested-With": "ReconX"}


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_path = db._path
        db.set_path(os.path.join(self.tmp.name, "t.db"))
        patcher = mock.patch.object(config, "REPORTS_DIR", Path(self.tmp.name) / "reports")  # keep PDFs out of the project
        patcher.start()
        self.addCleanup(patcher.stop)
        import app as app_module
        self.client = app_module.create_app().test_client()

    def tearDown(self):
        db.set_path(self._orig_path)
        self.tmp.cleanup()   # fails on Windows if any connection or file handle is still open

    def test_all_pages_render(self):
        for path in ["/", "/intelligence", "/dns", "/rdap", "/ssl", "/subdomains", "/technology", "/ports", "/history", "/reports", "/settings"]:
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertEqual(self.client.get("/nope").status_code, 404)

    def test_csrf_header_required(self):
        self.assertEqual(self.client.post("/api/validate", json={"domain": "example.com"}).status_code, 403)
        self.assertEqual(self.client.post("/api/validate", json={"domain": "example.com"}, headers=H).status_code, 200)

    def test_validate_and_reject_ip_scan(self):
        r = self.client.post("/api/scans", json={"domain": "127.0.0.1"}, headers=H)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(models.list_scans(), [])

    def test_port_scan_requires_verification(self):
        r = self.client.post("/api/ports/scan", json={"domain": "example.com"}, headers=H)
        self.assertEqual(r.status_code, 403)
        self.client.post("/api/verification", json={"domain": "example.com"}, headers=H)
        with mock.patch.object(pa, "check_verification", return_value={"verified": False, "found": [], "error": "none"}):
            self.assertEqual(self.client.post("/api/ports/scan", json={"domain": "example.com"}, headers=H).status_code, 403)
        self.assertEqual(models.list_scans(scan_type="port_assessment"), [])

    def test_verified_scan_blocked_for_private_target(self):
        self.client.post("/api/verification", json={"domain": "example.com"}, headers=H)
        with mock.patch.object(pa, "check_verification", return_value={"verified": True, "found": [], "error": None}), \
             mock.patch.object(pa, "assess_ports", side_effect=UnsafeTargetError("resolves to a private address")):
            r = self.client.post("/api/ports/scan", json={"domain": "example.com"}, headers=H)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(models.list_scans()[0]["status"], "failed")

    def test_verified_scan_success_stored_and_reported(self):
        self.client.post("/api/verification", json={"domain": "example.com"}, headers=H)
        fake = {"status": "ok", "target_ip": "93.184.216.34", "ports": [{"port": 443, "service": "HTTPS", "state": "open"}],
                "open_count": 1, "duration_seconds": 0.5, "started_at": "2026-11-07T00:00:00+00:00", "note": "n"}
        with mock.patch.object(pa, "check_verification", return_value={"verified": True, "found": [], "error": None}), \
             mock.patch.object(pa, "assess_ports", return_value=fake):
            r = self.client.post("/api/ports/scan", json={"domain": "example.com"}, headers=H)
        self.assertEqual(r.status_code, 200)
        sid = r.get_json()["scan_id"]
        self.assertEqual(models.get_scan(sid)["verification_status"], "verified")
        pdf = self.client.get(f"/api/scans/{sid}/report")
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b"%PDF"))
        pdf.close()   # release the PDF file handle held by send_file
        self.assertEqual(self.client.get("/api/stats").get_json()["verified_targets"], 1)


if __name__ == "__main__":
    unittest.main()


import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import config

from database import db, models

H = {"X-Requested-With": "ReconX"}


class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_path = db._path
        db.set_path(os.path.join(self.tmp.name, "t.db"))

        patcher = mock.patch.object(
            config, "REPORTS_DIR", Path(self.tmp.name) / "reports"
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        import app as app_module
        self.app_module = app_module
        self.client = app_module.create_app().test_client()

    def tearDown(self):
        db.set_path(self._orig_path)
        self.tmp.cleanup()

    def test_all_pages_render(self):
        pages = [
            "/", "/intelligence", "/dns", "/rdap", "/ssl",
            "/subdomains", "/technology", "/ports",
            "/history", "/reports", "/settings"
        ]

        for path in pages:
            self.assertEqual(self.client.get(path).status_code, 200, path)

        self.assertEqual(self.client.get("/nope").status_code, 404)

    def test_csrf_header_required(self):
        self.assertEqual(
            self.client.post(
                "/api/validate", json={"domain": "example.com"}
            ).status_code,
            403
        )

        self.assertEqual(
            self.client.post(
                "/api/validate",
                json={"domain": "example.com"},
                headers=H
            ).status_code,
            200
        )

    def test_validate_and_reject_ip_scan(self):
        response = self.client.post(
            "/api/scans",
            json={"domain": "127.0.0.1"},
            headers=H
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            models.list_scans(self.client_owner_id()), []
        )

    def client_owner_id(self):
     self.client.get("/")
     with self.client.session_transaction() as sess:
       return sess["owner_id"]

    def test_verification_endpoint_disabled(self):
        response = self.client.post(
            "/api/verification",
            json={"domain": "example.com"},
            headers=H
        )

        self.assertEqual(response.status_code, 403)

    def test_verification_check_disabled(self):
        response = self.client.post(
            "/api/verification/check",
            json={"domain": "example.com"},
            headers=H
        )

        self.assertEqual(response.status_code, 403)

    def test_port_scan_disabled(self):
        response = self.client.post(
            "/api/ports/scan",
            json={"domain": "example.com"},
            headers=H
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            models.list_scans(self.client_owner_id(), scan_type="port_assessment"),
            []
        )

    def test_scan_data_is_private_to_session(self):
        owner_one = self.client_owner_id()

        scan_id = models.create_scan(
            owner_one, "example.com", "intelligence"
        )
        models.finish_scan(scan_id, "completed")

        owner_two = "another-test-owner"

        self.assertIsNotNone(models.get_scan(scan_id, owner_one))
        self.assertIsNone(models.get_scan(scan_id, owner_two))


if __name__ == "__main__":
    unittest.main()

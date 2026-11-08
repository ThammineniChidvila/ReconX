
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from database import db, models


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_path = db._path
        self.db_file = os.path.join(self.tmp.name, "t.db")
        db.set_path(self.db_file)
        db.init_db()
        self.owner = "test-owner"

    def tearDown(self):
        db.set_path(self._orig_path)
        self.tmp.cleanup()

    def test_scan_lifecycle(self):
        sid = models.create_scan(self.owner, "example.com", "intelligence")
        self.assertEqual(models.get_scan(sid, self.owner)["status"], "running")

        models.set_section(sid, "subdomains", {"status": "ok", "count": 4})
        models.set_section(sid, "dns", {"status": "ok"})
        models.finish_scan(sid, "completed")

        scan = models.get_scan(sid, self.owner)
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["results"]["subdomains"]["count"], 4)
        self.assertIn("dns", scan["results"])
        self.assertIsNotNone(scan["finished_at"])
        self.assertIsNone(models.get_scan(999, self.owner))

    def test_listing_and_latest(self):
        a = models.create_scan(self.owner, "a.com", "intelligence")
        models.finish_scan(a, "completed")

        b = models.create_scan(
            self.owner, "a.com", "port_assessment",
            verification_status="verified"
        )
        models.finish_scan(b, "completed")

        self.assertEqual(
            [s["id"] for s in models.list_scans(self.owner)], [b, a]
        )
        self.assertEqual(
            len(models.list_scans(self.owner, scan_type="port_assessment")), 1
        )
        self.assertNotIn("results", models.list_scans(self.owner)[0])

        self.assertEqual(
            models.latest_scan(self.owner, "a.com", "intelligence")["id"], a
        )

    def test_verification(self):
        v = models.get_or_create_verification("a.com", lambda: "tok1")
        again = models.get_or_create_verification("a.com", lambda: "tok2")

        self.assertEqual((v["token"], again["token"]), ("tok1", "tok1"))
        self.assertEqual(v["verified"], 0)

        models.set_verified("a.com", True)
        self.assertEqual(models.get_verification("a.com")["verified"], 1)
        self.assertIsNone(models.get_verification("nope.com"))

    def test_stats_come_from_data(self):
        self.assertEqual(models.stats(self.owner)["total_scans"], 0)

        s1 = models.create_scan(self.owner, "a.com", "intelligence")
        models.set_section(s1, "subdomains", {"count": 3})
        models.finish_scan(s1, "completed")

        s2 = models.create_scan(self.owner, "a.com", "intelligence")
        models.set_section(s2, "subdomains", {"count": 5})
        models.finish_scan(s2, "partial")

        s3 = models.create_scan(self.owner, "b.com", "intelligence")
        models.set_section(s3, "subdomains", {"count": 2})
        models.finish_scan(s3, "completed")

        models.get_or_create_verification("b.com", lambda: "t")
        models.set_verified("b.com", True)

        st = models.stats(self.owner)

        self.assertEqual(
            (
                st["total_domains"],
                st["total_scans"],
                st["total_subdomains"],
                st["verified_targets"],
            ),
            (2, 3, 7, 0),
        )
        self.assertEqual(st["by_status"], {"completed": 2, "partial": 1})
        self.assertEqual(sum(d["count"] for d in st["activity"]), 3)

    def test_stale_and_clear(self):
        models.create_scan(self.owner, "a.com", "intelligence")
        models.fail_stale_scans()

        self.assertEqual(
            models.list_scans(self.owner)[0]["status"], "failed"
        )

        models.clear_scans()
        self.assertEqual(models.list_scans(self.owner), [])

    def test_connections_are_closed_on_success_and_on_error(self):
        opened, real = [], sqlite3.connect

        def spy(*a, **k):
            conn = real(*a, **k)
            opened.append(conn)
            return conn

        with mock.patch("database.db.sqlite3.connect", spy):
            sid = models.create_scan(self.owner, "a.com", "intelligence")
            models.get_scan(sid, self.owner)
            models.stats(self.owner)

            with self.assertRaises(RuntimeError):
                with db.connect():
                    raise RuntimeError("boom")

            with self.assertRaises(sqlite3.OperationalError):
                with db.connect() as c:
                    c.execute("SELECT * FROM table_that_does_not_exist")

        self.assertGreaterEqual(len(opened), 5)

        for conn in opened:
            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")

    def test_failed_transaction_is_rolled_back(self):
        with self.assertRaises(RuntimeError):
            with db.connect() as c:
                c.execute(
                    """INSERT INTO scans
                    (domain, scan_type, status, started_at)
                    VALUES ('x.com', 'intelligence', 'running', 't')"""
                )
                raise RuntimeError("abort")

        self.assertEqual(models.list_scans(self.owner), [])

    def test_database_file_can_be_deleted_after_use(self):
        models.create_scan(self.owner, "a.com", "intelligence")
        models.stats(self.owner)

        os.remove(self.db_file)
        self.assertFalse(os.path.exists(self.db_file))


if __name__ == "__main__":
    unittest.main()

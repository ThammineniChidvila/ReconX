"""Data access functions for scans and domain verifications."""
import json
from datetime import datetime, timedelta, timezone

from database.db import connect, write_lock


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _scan(row, full=True):
    if row is None:
        return None
    d = dict(row)
    d["results"] = json.loads(d["results"]) if full else None
    if not full:
        d.pop("results")
    return d


def create_scan(domain, scan_type, status="running", verification_status="not_required", results=None):
    with write_lock, connect() as c:
        cur = c.execute("INSERT INTO scans (domain, scan_type, status, verification_status, started_at, results) VALUES (?,?,?,?,?,?)",
                        (domain, scan_type, status, verification_status, now(), json.dumps(results or {})))
        return cur.lastrowid


def set_section(scan_id, key, data):
    with write_lock, connect() as c:
        row = c.execute("SELECT results FROM scans WHERE id=?", (scan_id,)).fetchone()
        if row is None:
            return
        res = json.loads(row["results"])
        res[key] = data
        c.execute("UPDATE scans SET results=? WHERE id=?", (json.dumps(res), scan_id))


def finish_scan(scan_id, status):
    with write_lock, connect() as c:
        c.execute("UPDATE scans SET status=?, finished_at=? WHERE id=?", (status, now(), scan_id))


def get_scan(scan_id):
    with connect() as c:
        return _scan(c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())


def list_scans(limit=100, scan_type=None):
    sql, args = "SELECT * FROM scans", []
    if scan_type:
        sql += " WHERE scan_type=?"
        args.append(scan_type)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    with connect() as c:
        return [_scan(r, full=False) for r in c.execute(sql, args)]


def latest_scan(domain, scan_type):
    with connect() as c:
        return _scan(c.execute("SELECT * FROM scans WHERE domain=? AND scan_type=? AND status!='running' ORDER BY id DESC LIMIT 1",
                               (domain, scan_type)).fetchone())


def count_running():
    with connect() as c:
        return c.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]


def fail_stale_scans():
    with write_lock, connect() as c:
        c.execute("UPDATE scans SET status='failed', finished_at=? WHERE status='running'", (now(),))


def clear_scans():
    with write_lock, connect() as c:
        c.execute("DELETE FROM scans")


def clear_verifications():
    with write_lock, connect() as c:
        c.execute("DELETE FROM verifications")


# ---- verification ---------------------------------------------------------
def get_verification(domain):
    with connect() as c:
        row = c.execute("SELECT * FROM verifications WHERE domain=?", (domain,)).fetchone()
        return dict(row) if row else None


def get_or_create_verification(domain, token_factory):
    with write_lock, connect() as c:
        row = c.execute("SELECT * FROM verifications WHERE domain=?", (domain,)).fetchone()
        if row is None:
            c.execute("INSERT INTO verifications (domain, token, created_at) VALUES (?,?,?)", (domain, token_factory(), now()))
            row = c.execute("SELECT * FROM verifications WHERE domain=?", (domain,)).fetchone()
        return dict(row)


def set_verified(domain, verified):
    with write_lock, connect() as c:
        c.execute("UPDATE verifications SET verified=?, verified_at=? WHERE domain=?",
                  (1 if verified else 0, now() if verified else None, domain))


# ---- dashboard statistics (all computed from stored data) ------------------
def stats():
    with connect() as c:
        one = lambda sql, *a: c.execute(sql, a).fetchone()[0]
        intel = "scan_type='intelligence'"
        latest = c.execute(f"SELECT results FROM scans WHERE {intel} AND id IN (SELECT MAX(id) FROM scans WHERE {intel} GROUP BY domain)").fetchall()
        subs = sum(((json.loads(r["results"]).get("subdomains") or {}).get("count") or 0) for r in latest)
        by_status = {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM scans GROUP BY status")}
        since = (datetime.now(timezone.utc) - timedelta(days=6)).strftime("%Y-%m-%d")
        per_day = {r["d"]: r["n"] for r in c.execute("SELECT substr(started_at,1,10) d, COUNT(*) n FROM scans WHERE substr(started_at,1,10)>=? GROUP BY d", (since,))}
        days = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        return {
            "total_domains": one("SELECT COUNT(DISTINCT domain) FROM scans"),
            "total_scans": one(f"SELECT COUNT(*) FROM scans WHERE {intel}"),
            "total_subdomains": subs,
            "verified_targets": one("SELECT COUNT(*) FROM verifications WHERE verified=1"),
            "port_assessments": one("SELECT COUNT(*) FROM scans WHERE scan_type='port_assessment'"),
            "by_status": by_status,
            "activity": [{"day": d, "count": per_day.get(d, 0)} for d in days],
        }


def set_results(scan_id, results):
    with write_lock, connect() as c:
        c.execute("UPDATE scans SET results=? WHERE id=?", (json.dumps(results), scan_id))

"""ReconX - Flask application entry point."""
import logging
import platform
import threading
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request, send_file

import config
from database import db, models
from modules import port_assessment as pa
from modules.domain_validator import validate_domain
from modules.net_safety import UnsafeTargetError
from modules.orchestrator import run_intelligence_scan
from modules.report_generator import generate_report

log = logging.getLogger("reconx")
PAGES = {  # route -> (template, nav key, title)
    "/": ("dashboard.html", "overview", "Overview"),
    "/intelligence": ("intelligence.html", "intelligence", "Domain Intelligence"),
    "/dns": ("section.html", "dns", "DNS Records"),
    "/rdap": ("section.html", "rdap", "WHOIS / RDAP"),
    "/ssl": ("section.html", "ssl", "SSL Analysis"),
    "/subdomains": ("section.html", "subdomains", "Subdomains"),
    "/technology": ("section.html", "technology", "Technology Detection"),
    "/ports": ("ports.html", "ports", "Authorised Port Assessment"),
    "/history": ("history.html", "history", "Scan History"),
    "/reports": ("reports.html", "reports", "Reports"),
    "/settings": ("settings.html", "settings", "Settings"),
}
NAV = [("overview", "/", "Overview"), ("intelligence", "/intelligence", "Domain Intelligence"), ("dns", "/dns", "DNS Records"),
       ("rdap", "/rdap", "WHOIS / RDAP"), ("ssl", "/ssl", "SSL Analysis"), ("subdomains", "/subdomains", "Subdomains"),
       ("technology", "/technology", "Technology Detection"), ("ports", "/ports", "Authorised Port Assessment"),
       ("history", "/history", "Scan History"), ("reports", "/reports", "Reports"), ("settings", "/settings", "Settings")]
_port_lock = threading.Semaphore(1)


def _err(message, code=400):
    return jsonify({"error": message}), code


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    config.REPORTS_DIR.mkdir(exist_ok=True)
    db.init_db()
    models.fail_stale_scans()

    @app.before_request
    def csrf_guard():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.headers.get("X-Requested-With") != "ReconX":
                return _err("Missing X-Requested-With header.", 403)
            origin = request.headers.get("Origin")
            if origin and urlsplit(origin).netloc != request.host:
                return _err("Cross-origin request blocked.", 403)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
        return resp

    def page(path):
        template, key, title = PAGES[path]
        def view():
            return render_template(template, active=key, title=title, nav=NAV, section=key)
        view.__name__ = f"page_{key}"
        app.add_url_rule(path, view_func=view)
    for p in PAGES:
        page(p)

    def body_domain():
        data = request.get_json(silent=True) or {}
        check = validate_domain(data.get("domain"))
        return check

    @app.post("/api/validate")
    def api_validate():
        return jsonify(body_domain())

    @app.post("/api/scans")
    def api_start_scan():
        check = body_domain()
        if not check["valid"]:
            return _err(check["error"])
        if models.count_running() >= config.MAX_ACTIVE_SCANS:
            return _err("Too many scans are running. Wait for one to finish.", 429)
        from datetime import datetime, timezone
        scan_id = models.create_scan(check["domain"], "intelligence", results={"domain_info": {
            "input": check["input"], "domain": check["domain"], "valid": True,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}})
        threading.Thread(target=_run_scan, args=(scan_id, check["domain"]), daemon=True).start()
        return jsonify({"scan_id": scan_id, "domain": check["domain"]}), 202

    def _run_scan(scan_id, domain):
        try:
            run_intelligence_scan(scan_id, domain)
        except Exception:
            log.exception("scan crashed")
            models.finish_scan(scan_id, "failed")

    @app.get("/api/scans")
    def api_list_scans():
        return jsonify(models.list_scans(request.args.get("limit", 100, type=int), request.args.get("type")))

    @app.get("/api/scans/<int:scan_id>")
    def api_get_scan(scan_id):
        scan = models.get_scan(scan_id)
        return jsonify(scan) if scan else _err("Scan not found.", 404)

    @app.get("/api/scans/<int:scan_id>/report")
    def api_report(scan_id):
        scan = models.get_scan(scan_id)
        if not scan:
            return _err("Scan not found.", 404)
        if scan["status"] == "running":
            return _err("Scan is still running.", 409)
        if scan["scan_type"] == "intelligence":
            intel, ports = scan, models.latest_scan(scan["domain"], "port_assessment")
        else:
            intel, ports = models.latest_scan(scan["domain"], "intelligence"), scan
        try:
            path = generate_report(intel, ports)
        except Exception:
            log.exception("report failed")
            return _err("Report generation failed.", 500)
        return send_file(path, mimetype="application/pdf", as_attachment=True, download_name=path.name)

    @app.get("/api/stats")
    def api_stats():
        return jsonify(models.stats())

    @app.route("/api/verification", methods=["GET", "POST"])
    def api_verification():
        data = request.get_json(silent=True) if request.method == "POST" else {"domain": request.args.get("domain")}
        check = validate_domain((data or {}).get("domain"))
        if not check["valid"]:
            return _err(check["error"])
        domain = check["domain"]
        row = models.get_or_create_verification(domain, pa.generate_token) if request.method == "POST" else models.get_verification(domain)
        if not row:
            return jsonify({"domain": domain, "token": None, "verified": False})
        return jsonify({"domain": domain, "verified": bool(row["verified"]), "record": pa.verification_record(domain, row["token"])})

    @app.post("/api/verification/check")
    def api_verification_check():
        check = body_domain()
        if not check["valid"]:
            return _err(check["error"])
        row = models.get_verification(check["domain"])
        if not row:
            return _err("Generate a verification token first.", 404)
        res = pa.check_verification(check["domain"], row["token"])
        models.set_verified(check["domain"], res["verified"])
        return jsonify({"domain": check["domain"], **res})

    @app.post("/api/ports/scan")
    def api_port_scan():
        check = body_domain()
        if not check["valid"]:
            return _err(check["error"])
        domain = check["domain"]
        row = models.get_verification(domain)
        if not row:
            return _err("Domain is not verified. Generate a token and add the DNS TXT record first.", 403)
        if not pa.check_verification(domain, row["token"])["verified"]:   # re-verify at scan time
            models.set_verified(domain, False)
            return _err("The DNS TXT verification record was not found. Port assessment refused.", 403)
        models.set_verified(domain, True)
        if not _port_lock.acquire(blocking=False):
            return _err("Another port assessment is already running.", 429)
        scan_id = models.create_scan(domain, "port_assessment", verification_status="verified")
        try:
            result = pa.assess_ports(domain, verified=True)
            models.set_results(scan_id, result)
            models.finish_scan(scan_id, "completed")
            return jsonify({"scan_id": scan_id, "result": result})
        except UnsafeTargetError as exc:
            models.set_results(scan_id, {"status": "blocked", "message": str(exc)})
            models.finish_scan(scan_id, "failed")
            return _err(str(exc), 400)
        finally:
            _port_lock.release()

    @app.get("/api/settings")
    def api_settings():
        s = models.stats()
        return jsonify({"version": config.VERSION, "python": platform.python_version(), "host": config.HOST, "port": config.PORT,
                        "timeouts": {"dns": config.DNS_TIMEOUT, "http": config.HTTP_TIMEOUT, "ssl": config.SSL_TIMEOUT,
                                     "crt.sh": config.CRTSH_TIMEOUT, "port connect": config.PORT_CONNECT_TIMEOUT},
                        "port_workers": config.PORT_MAX_WORKERS, "safe_ports": config.SAFE_PORTS,
                        "totals": {"scans": s["total_scans"], "port_assessments": s["port_assessments"], "verified": s["verified_targets"]}})

    @app.delete("/api/data")
    def api_clear():
        what = (request.get_json(silent=True) or {}).get("what")
        if what == "scans":
            models.clear_scans()
        elif what == "verifications":
            models.clear_verifications()
        else:
            return _err("Unknown data set.")
        return jsonify({"cleared": what})

    @app.errorhandler(404)
    def not_found(_):
        return (_err("Not found.", 404) if request.path.startswith("/api/") else (render_template("error.html", nav=NAV, active="", title="Not found", message="That page does not exist."), 404))

    @app.errorhandler(Exception)
    def unexpected(exc):
        log.exception("unhandled error")
        code = getattr(exc, "code", 500) if hasattr(exc, "code") else 500
        return _err("Request could not be completed." if code == 500 else getattr(exc, "description", "Error"), code if isinstance(code, int) else 500)

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"\n  ReconX {config.VERSION} running at http://{config.HOST}:{config.PORT}\n")
    create_app().run(host=config.HOST, port=config.PORT, debug=False, threaded=True)

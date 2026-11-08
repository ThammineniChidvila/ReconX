"""ReconX - Flask application entry point."""
import os
import logging
import platform
import threading
import secrets
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request, send_file, session

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

    app.secret_key = config.SECRET_KEY or (
        secrets.token_urlsafe(32) if not os.getenv("VERCEL") else None
    )

    if not app.secret_key:
        raise RuntimeError("SECRET_KEY must be configured in Vercel.")

    app.config.update(
        MAX_CONTENT_LENGTH=16 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=bool(os.getenv("VERCEL")),
        SESSION_COOKIE_SAMESITE="Lax"
    )
    if not os.getenv("VERCEL"):
        config.REPORTS_DIR.mkdir(exist_ok=True)
    @app.before_request
    def ensure_owner_id():
        if "owner_id" not in session:
            session["owner_id"] = secrets.token_urlsafe(32)
    db.init_db()
    

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
        scan_id = models.create_scan(
    session["owner_id"],
    check["domain"],
    "intelligence",
    results={"domain_info": {
        "input": check["input"],
        "domain": check["domain"],
        "valid": True,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds")
    }}
)
        _run_scan(scan_id, check["domain"])
        return jsonify({"scan_id": scan_id, "domain": check["domain"]}), 202
    def _run_scan(scan_id, domain):
        try:
            run_intelligence_scan(scan_id, domain)
        except Exception:
            log.exception("scan crashed")
            models.finish_scan(scan_id, "failed")

    @app.get("/api/scans")
    def api_list_scans():
      return jsonify(
        models.list_scans(
            session["owner_id"],
            request.args.get("limit", 100, type=int),
            request.args.get("type")
        )
    )

    @app.get("/api/scans/<int:scan_id>")
    def api_get_scan(scan_id):
      scan = models.get_scan(scan_id, session["owner_id"])
      return jsonify(scan) if scan else _err("Scan not found.", 404)
    @app.get("/api/scans/<int:scan_id>/report")
    def api_report(scan_id):
        scan = models.get_scan(scan_id, session["owner_id"])
        if not scan:
            return _err("Scan not found.", 404)
        if scan["status"] == "running":
            return _err("Scan is still running.", 409)
        if scan["scan_type"] == "intelligence":
            intel, ports = scan, models.latest_scan(
               session["owner_id"], scan["domain"], "port_assessment"
            )
        else:
            intel, ports = models.latest_scan(
              session["owner_id"], scan["domain"], "intelligence"
            ), scan
        try:
            path = generate_report(intel, ports)
        except Exception:
            log.exception("report failed")
            return _err("Report generation failed.", 500)
        return send_file(path, mimetype="application/pdf", as_attachment=True, download_name=path.name)

    @app.get("/api/stats")
    def api_stats():
       return jsonify(models.stats(session["owner_id"]))

    @app.route("/api/verification", methods=["GET", "POST"])
    def api_verification():
           return _err("Domain verification is disabled on the public demo.", 403)
    @app.post("/api/verification/check")
    def api_verification_check():
        return _err("Domain verification is disabled on the public demo.", 403)
    @app.post("/api/ports/scan")
    def api_port_scan():
        return _err("Port assessment is disabled on the public demo.", 403)
    @app.get("/api/settings")
    def api_settings():
        s = models.stats(session["owner_id"])
        return jsonify({"version": config.VERSION, "python": platform.python_version(), "host": config.HOST, "port": config.PORT,
                        "timeouts": {"dns": config.DNS_TIMEOUT, "http": config.HTTP_TIMEOUT, "ssl": config.SSL_TIMEOUT,
                                     "crt.sh": config.CRTSH_TIMEOUT, "port connect": config.PORT_CONNECT_TIMEOUT},
                        "port_workers": config.PORT_MAX_WORKERS, "safe_ports": config.SAFE_PORTS,
                        "totals": {"scans": s["total_scans"], "port_assessments": s["port_assessments"], "verified": s["verified_targets"]}})

    @app.delete("/api/data")
    def api_clear():
        return _err("Data deletion is disabled on the public demo.", 403) 

    @app.errorhandler(404)
    def not_found(_):
        return (_err("Not found.", 404) if request.path.startswith("/api/") else (render_template("error.html", nav=NAV, active="", title="Not found", message="That page does not exist."), 404))

    @app.errorhandler(Exception)
    def unexpected(exc):
        log.exception("unhandled error")
        code = getattr(exc, "code", 500) if hasattr(exc, "code") else 500
        return _err("Request could not be completed." if code == 500 else getattr(exc, "description", "Error"), code if isinstance(code, int) else 500)

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"\n  ReconX {config.VERSION} running at http://{config.HOST}:{config.PORT}\n")
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)
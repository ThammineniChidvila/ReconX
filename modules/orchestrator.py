"""Runs the passive intelligence modules in parallel and records each result as it completes."""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from database import models
from modules.dns_analyzer import analyze_dns
from modules.observations import build_observations
from modules.rdap_analyzer import fetch_rdap
from modules.ssl_analyzer import analyze_ssl
from modules.subdomain_discovery import discover_subdomains
from modules.technology_detector import detect_technology

log = logging.getLogger("reconx")
PASSIVE_MODULES = {"dns": analyze_dns, "rdap": fetch_rdap, "ssl": analyze_ssl,
                   "subdomains": discover_subdomains, "technology": detect_technology}


def _safe(fn, domain):
    try:
        return fn(domain)
    except Exception as exc:  # never let one module break the scan
        log.exception("module failed")
        return {"status": "error", "message": f"Unexpected error ({type(exc).__name__})."}


def run_intelligence_scan(scan_id, domain, modules=None):
    modules = modules or PASSIVE_MODULES
    results = {}
    with ThreadPoolExecutor(max_workers=len(modules)) as pool:
        futures = {pool.submit(_safe, fn, domain): name for name, fn in modules.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            results[name] = fut.result()
            models.set_section(scan_id, name, results[name])
    statuses = [r.get("status") for r in results.values()]
    status = "completed" if all(s == "ok" for s in statuses) else "partial" if "ok" in statuses else "failed"
    models.set_section(scan_id, "observations", build_observations(results))
    models.finish_scan(scan_id, status)
    return status

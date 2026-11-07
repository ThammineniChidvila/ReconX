"""Authorised port assessment. Refuses to run unless DNS TXT ownership has been verified."""
import secrets
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import config
from modules.dns_analyzer import make_resolver, query_records
from modules.domain_validator import validate_domain
from modules.net_safety import UnsafeTargetError, is_public_ip, resolve_public


class NotVerifiedError(Exception):
    pass


def generate_token():
    return secrets.token_hex(16)


def verification_record(domain, token):
    return {"type": "TXT", "name": f"{config.VERIFY_LABEL}.{domain}", "value": f"{config.VERIFY_PREFIX}{token}"}


def check_verification(domain, token, resolver=None):
    rec = verification_record(domain, token)
    try:
        resolver = resolver or make_resolver()
    except Exception:
        return {"verified": False, "found": [], "error": "dnspython is not installed."}
    values, err = query_records(rec["name"], "TXT", resolver)
    if values is None:
        return {"verified": False, "found": [], "error": err}
    return {"verified": rec["value"] in values, "found": values,
            "error": None if values else "TXT record not found yet (DNS changes can take several minutes)."}


def _tcp_probe(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:  # timeout, unreachable, reset: cannot tell from here
        return "filtered"


def assess_ports(domain, verified, ports=None, resolver=resolve_public, probe=_tcp_probe):
    if not verified:
        raise NotVerifiedError("Domain ownership has not been verified.")
    check = validate_domain(domain)
    if not check["valid"]:
        raise UnsafeTargetError(check["error"])
    ports = ports or config.SAFE_PORTS
    allowed = {p: ports[p] for p in ports if p in config.SAFE_PORTS}   # never scan outside the safe list
    ip = resolver(check["domain"])[0]                                  # re-resolve + validate right now
    if not is_public_ip(ip):
        raise UnsafeTargetError("Resolved address is not public.")
    started = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, min(config.PORT_MAX_WORKERS, 8))) as pool:
        states = list(pool.map(lambda p: probe(ip, p, config.PORT_CONNECT_TIMEOUT), allowed))
    rows = [{"port": p, "service": allowed[p], "state": s} for p, s in zip(allowed, states)]
    return {"status": "ok", "target_ip": ip, "ports": sorted(rows, key=lambda r: r["port"]),
            "open_count": sum(r["state"] == "open" for r in rows),
            "duration_seconds": round(time.perf_counter() - t0, 2),
            "started_at": started.isoformat(timespec="seconds"),
            "note": "Single-IP TCP connect check of a fixed safe port list. 'Filtered' means no answer or an unreachable network."}

"""TLS certificate analysis. Always verifies the chain and hostname; connects only to validated public IPs."""
import socket
import ssl
from datetime import datetime, timezone

import config
from modules.net_safety import UnsafeTargetError, resolve_public

_HOSTNAME_MISMATCH = 62  # OpenSSL X509_V_ERR_HOSTNAME_MISMATCH


def _dn(parts, preferred=("commonName", "organizationName")):
    flat = {k: v for rdn in parts or () for k, v in rdn}
    shown = [flat[k] for k in preferred if k in flat]
    return ", ".join(shown) if shown else None


def hostname_matches(hostname, sans):
    hostname = hostname.lower()
    for san in sans:
        san = san.lower()
        if san == hostname:
            return True
        if san.startswith("*.") and hostname.count(".") == san.count(".") and hostname.split(".", 1)[1] == san[2:]:
            return True
    return False


def parse_cert(cert, hostname, now=None):
    now = now or datetime.now(timezone.utc)
    start = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    end = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    days = (end - now).days
    status = "expired" if now > end else "not yet valid" if now < start else "valid"
    return {
        "issuer": _dn(cert.get("issuer")), "subject": _dn(cert.get("subject")),
        "valid_from": start.isoformat(timespec="seconds"), "valid_until": end.isoformat(timespec="seconds"),
        "days_remaining": days, "validity_status": status, "sans": sans[:50],
        "hostname_verified": hostname_matches(hostname, sans),
    }


def _fetch_cert(domain, ip, timeout):
    ctx = ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls:
            return tls.getpeercert(), tls.version(), (tls.cipher() or [None])[0]


def analyze_ssl(domain, resolver=resolve_public, fetcher=_fetch_cert):
    try:
        ip = resolver(domain)[0]
    except UnsafeTargetError as exc:
        return {"status": "unavailable", "message": str(exc)}
    try:
        cert, version, cipher = fetcher(domain, ip, config.SSL_TIMEOUT)
    except ssl.SSLCertVerificationError as exc:
        mismatch = exc.verify_code == _HOSTNAME_MISMATCH
        return {"status": "ok", "https_available": True, "trusted": False, "ip": ip,
                "validity_status": "untrusted", "hostname_verified": False if mismatch else None,
                "verification_error": exc.verify_message,
                "message": "Certificate failed verification; details are not shown for untrusted certificates."}
    except (OSError, ssl.SSLError) as exc:
        return {"status": "unavailable", "https_available": False,
                "message": f"No TLS service reachable on port 443 ({type(exc).__name__})."}
    result = parse_cert(cert, domain)
    result.update({"status": "ok", "https_available": True, "trusted": True, "ip": ip,
                   "protocol": version, "cipher": cipher})
    return result

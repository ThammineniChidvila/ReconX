"""RDAP registration data (the modern, JSON replacement for WHOIS)."""
import requests

import config

RDAP_URL = "https://rdap.org/domain/{}"
SOURCE = "RDAP (rdap.org bootstrap)"


def _registrar_name(data):
    for entity in data.get("entities", []) or []:
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray") or []
            for item in (vcard[1] if len(vcard) > 1 else []):
                if item and item[0] == "fn" and len(item) > 3 and item[3]:
                    return str(item[3])
    return None


def parse_rdap(data):
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
    nameservers = sorted({(ns.get("ldhName") or "").lower().rstrip(".") for ns in data.get("nameservers", []) or [] if ns.get("ldhName")})
    parsed = {
        "registrar": _registrar_name(data),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "domain_status": list(data.get("status") or []),
        "nameservers": nameservers,
    }
    parsed["unavailable"] = [k for k, v in parsed.items() if not v]
    return parsed


def fetch_rdap(domain, http_get=requests.get):
    try:
        resp = http_get(RDAP_URL.format(domain), timeout=config.HTTP_TIMEOUT,
                        headers={"Accept": "application/rdap+json", "User-Agent": config.USER_AGENT})
    except requests.RequestException as exc:
        return {"status": "unavailable", "source": SOURCE, "message": f"RDAP service unreachable ({type(exc).__name__})."}
    if resp.status_code == 404:
        return {"status": "unavailable", "source": SOURCE, "message": "No RDAP record was found for this domain."}
    if resp.status_code != 200:
        return {"status": "unavailable", "source": SOURCE, "message": f"RDAP service returned HTTP {resp.status_code}."}
    try:
        data = resp.json()
    except ValueError:
        return {"status": "unavailable", "source": SOURCE, "message": "RDAP response was not valid JSON."}
    result = parse_rdap(data)
    result.update({"status": "ok", "source": SOURCE})
    return result

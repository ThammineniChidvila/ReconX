"""DNS intelligence using dnspython (imported lazily so tests can inject a resolver)."""
import re

import config

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def make_resolver():
    import dns.resolver  # lazy import
    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT
    return resolver


def _clean(rtype, text):
    if rtype == "TXT":
        parts = _QUOTED.findall(text)
        return "".join(parts) if parts else text
    return text.rstrip(".") if rtype in ("NS", "CNAME") else text


def query_records(name, rtype, resolver):
    """Return (values, error). values is None on a real failure; [] when the record set is empty."""
    try:
        answer = resolver.resolve(name, rtype)
    except Exception as exc:  # dnspython raises many specific classes
        kind = type(exc).__name__
        if kind == "NoAnswer":
            return [], "no record"
        if kind == "NXDOMAIN":
            return [], "domain not found"
        return None, f"lookup failed ({kind})"
    return [_clean(rtype, r.to_text()) for r in answer], None


def analyze_dns(domain, resolver=None):
    try:
        resolver = resolver or make_resolver()
    except Exception:
        return {"status": "error", "message": "dnspython is not installed. Run: pip install -r requirements.txt",
                "records": [], "ips": []}
    records, ips, failures = [], [], 0
    for rtype in RECORD_TYPES:
        values, err = query_records(domain, rtype, resolver)
        if values is None:
            failures += 1
            records.append({"type": rtype, "value": "-", "status": err})
        elif not values:
            records.append({"type": rtype, "value": "-", "status": err or "no record"})
        else:
            for value in values:
                records.append({"type": rtype, "value": value, "status": "found"})
                if rtype in ("A", "AAAA"):
                    ips.append(value)
    if failures == len(RECORD_TYPES):
        return {"status": "error", "message": "All DNS lookups failed. Check your connection.", "records": records, "ips": []}
    return {"status": "ok", "records": records, "ips": ips, "failed_lookups": failures}

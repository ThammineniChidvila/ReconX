"""Passive subdomain discovery from Certificate Transparency logs (crt.sh). No brute forcing."""
import requests

import config
from modules.domain_validator import validate_domain

SOURCE = "crt.sh (Certificate Transparency)"


def parse_crtsh(entries, domain):
    found = set()
    for entry in entries or []:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").strip(".")
            if not name or name == domain or not name.endswith("." + domain):
                continue
            if validate_domain(name)["valid"]:
                found.add(name)
    return sorted(found)


def discover_subdomains(domain, http_get=requests.get):
    last_error = "unknown error"
    for _ in range(2):  # crt.sh is often slow; one retry
        try:
            resp = http_get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                            timeout=config.CRTSH_TIMEOUT, headers={"User-Agent": config.USER_AGENT})
            if resp.status_code != 200:
                last_error = f"HTTP {resp.status_code}"
                continue
            subs = parse_crtsh(resp.json(), domain)
            return {"status": "ok", "source": SOURCE, "subdomains": subs, "count": len(subs),
                    "message": "Discovered from public certificates." if subs else "No subdomains found in certificate logs."}
        except (requests.RequestException, ValueError) as exc:
            last_error = type(exc).__name__
    return {"status": "unavailable", "source": SOURCE, "subdomains": [], "count": 0,
            "message": f"crt.sh did not return usable data ({last_error}). Try again later."}

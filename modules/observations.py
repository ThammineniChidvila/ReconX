"""Derive security observations strictly from collected data. Nothing is inferred beyond the evidence."""
import re

RISKY_OPEN = {21: ("medium", "FTP transmits credentials in clear text."), 25: ("low", "SMTP is exposed; confirm it is intended."),
              445: ("high", "SMB should not be exposed to the internet."), 3306: ("high", "MySQL is reachable from the internet."),
              3389: ("high", "RDP is reachable from the internet."), 5432: ("high", "PostgreSQL is reachable from the internet.")}


def build_observations(results, port_scan=None):
    obs = []
    add = lambda sev, text: obs.append({"severity": sev, "text": text})
    dns, ssl_r, tech, rdap, subs = (results.get(k) or {} for k in ("dns", "ssl", "technology", "rdap", "subdomains"))
    if dns.get("status") == "ok":
        recs = dns.get("records", [])
        txt = [r["value"] for r in recs if r["type"] == "TXT" and r["status"] == "found"]
        if not dns.get("ips"):
            add("info", "No A or AAAA records were returned for the domain.")
        if not any(v.lower().startswith("v=spf1") for v in txt):
            add("medium", "No SPF record was found in the domain's TXT records.")
        if not any(r["type"] == "MX" and r["status"] == "found" for r in recs):
            add("info", "No MX records found; the domain may not receive email.")
    if ssl_r.get("status") == "ok":
        if ssl_r.get("trusted") is False:
            add("high", f"TLS certificate failed verification: {ssl_r.get('verification_error') or 'unknown reason'}.")
        elif ssl_r.get("validity_status") == "expired":
            add("high", "The TLS certificate has expired.")
        elif isinstance(ssl_r.get("days_remaining"), int) and ssl_r["days_remaining"] < 30:
            add("medium", f"The TLS certificate expires in {ssl_r['days_remaining']} days.")
        if ssl_r.get("hostname_verified") is False:
            add("high", "The certificate does not match the hostname.")
    elif ssl_r.get("https_available") is False:
        add("medium", "No TLS service was reachable on port 443.")
    if tech.get("status") == "ok":
        if not tech.get("https_available"):
            add("high", "The site did not respond over HTTPS.")
        missing = [h["header"] for h in tech.get("security_headers", []) if not h["present"]]
        if missing:
            add("low" if len(missing) < 4 else "medium", "Missing security headers: " + ", ".join(missing) + ".")
        for field, label in (("server", "Server"), ("x_powered_by", "X-Powered-By")):
            if tech.get(field) and re.search(r"\d+\.\d+", tech[field]):
                add("low", f"{label} header discloses a version number ({tech[field]}).")
    if rdap.get("status") == "ok" and rdap.get("expires"):
        add("info", f"Domain registration expires {rdap['expires'][:10]}.")
    if subs.get("status") == "ok" and subs.get("count"):
        add("info", f"{subs['count']} unique subdomains appear in Certificate Transparency logs; review for unexpected hosts.")
    if port_scan and port_scan.get("status") == "ok":
        for row in port_scan["ports"]:
            if row["state"] == "open" and row["port"] in RISKY_OPEN:
                sev, why = RISKY_OPEN[row["port"]]
                add(sev, f"Port {row['port']} ({row['service']}) is open. {why}")
        if not port_scan.get("open_count"):
            add("info", "None of the assessed ports responded as open.")
    return obs

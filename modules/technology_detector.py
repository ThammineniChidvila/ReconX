"""Technology detection from public HTTP responses. Every finding carries its supporting evidence."""
import re
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

import config
from modules.net_safety import UnsafeTargetError, resolve_public

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}
_HEADER_RULES = [  # (header, regex on value, technology, category)
    ("server", r"nginx", "nginx", "Web server"), ("server", r"apache", "Apache HTTP Server", "Web server"),
    ("server", r"microsoft-iis", "Microsoft IIS", "Web server"), ("server", r"cloudflare", "Cloudflare", "CDN / proxy"),
    ("server", r"litespeed", "LiteSpeed", "Web server"), ("x-powered-by", r"php", "PHP", "Language"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "Framework"), ("x-powered-by", r"express", "Express (Node.js)", "Framework"),
    ("cf-ray", r".", "Cloudflare", "CDN / proxy"), ("x-drupal-cache", r".", "Drupal", "CMS"),
    ("x-shopify-stage", r".", "Shopify", "Platform"), ("x-vercel-id", r".", "Vercel", "Hosting"),
    ("x-served-by", r"cache-", "Fastly", "CDN / proxy"), ("x-amz-cf-id", r".", "Amazon CloudFront", "CDN / proxy"),
]
_COOKIE_RULES = [("phpsessid", "PHP"), ("jsessionid", "Java (servlet container)"),
                 ("asp.net_sessionid", "ASP.NET"), ("laravel_session", "Laravel")]
_HTML_RULES = [(r"/wp-(content|includes)/", "WordPress", "CMS", "asset path /wp-content/ or /wp-includes/"),
               (r"/sites/default/files", "Drupal", "CMS", "asset path /sites/default/files"),
               (r"cdn\.shopify\.com", "Shopify", "Platform", "script/asset host cdn.shopify.com"),
               (r"/_next/static", "Next.js", "Framework", "asset path /_next/static"),
               (r"jquery[.-][\d.]*(min\.)?js", "jQuery", "JS library", "script file name contains jquery"),
               (r"bootstrap[.-][\d.]*(min\.)?(css|js)", "Bootstrap", "UI framework", "asset file name contains bootstrap")]


def analyze_response(headers, body, set_cookie_names=()):
    h = {k.lower(): str(v) for k, v in dict(headers).items()}
    techs, seen = [], set()

    def add(name, category, evidence):
        if (name, evidence) not in seen:
            seen.add((name, evidence))
            techs.append({"name": name, "category": category, "evidence": evidence})

    for header, pattern, name, category in _HEADER_RULES:
        if header in h and re.search(pattern, h[header], re.I):
            add(name, category, f"{header} header: {h[header][:80]}")
    for cookie in set_cookie_names:
        for key, name in _COOKIE_RULES:
            if cookie.lower() == key:
                add(name, "Language / framework", f"cookie name: {cookie}")
    title, soup = None, None
    if body:
        soup = BeautifulSoup(body, "html.parser")
        title = soup.title.get_text(strip=True)[:150] if soup.title else None
        gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        if gen and gen.get("content"):
            add(gen["content"][:60], "Generator", "meta generator tag")
        assets = " ".join([s.get("src", "") for s in soup.find_all("script")] + [l.get("href", "") for l in soup.find_all("link")] + [i.get("src", "") for i in soup.find_all("img")])
        for pattern, name, category, evidence in _HTML_RULES:
            if re.search(pattern, assets, re.I):
                add(name, category, evidence)
    return {
        "server": h.get("server"), "x_powered_by": h.get("x-powered-by"), "title": title, "technologies": techs,
        "security_headers": [{"header": label, "present": key in h, "value": h.get(key, "")[:120]} for key, label in SECURITY_HEADERS.items()],
    }


def _in_scope(host, domain):
    return host == domain or host.endswith("." + domain)


def _fetch(url, domain, resolver, getter, max_hops=4):
    """GET with manual redirects; every hop must stay inside the target's scope and resolve to a public IP."""
    chain = []
    for _ in range(max_hops + 1):
        host = urlsplit(url).hostname or ""
        if not _in_scope(host, domain):
            return None, chain, f"Redirect to {host} is outside the target scope and was not followed."
        resolver(host)  # raises UnsafeTargetError for private/loopback/etc.
        resp = getter(url, timeout=config.HTTP_TIMEOUT, allow_redirects=False, stream=True,
                      headers={"User-Agent": config.USER_AGENT})
        chain.append({"url": url, "status": resp.status_code})
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
            url = urljoin(url, resp.headers["Location"])
            resp.close()
            continue
        return resp, chain, None
    return None, chain, "Too many redirects."


def _read_body(resp, limit=262144):
    chunks, size = [], 0
    for chunk in resp.iter_content(8192):
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    resp.close()
    return b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")


def detect_technology(domain, resolver=resolve_public, getter=requests.get):
    result = {"status": "unavailable", "https_available": False, "notes": []}
    for scheme in ("https", "http"):
        try:
            resp, chain, note = _fetch(f"{scheme}://{domain}/", domain, resolver, getter)
        except UnsafeTargetError as exc:
            result["notes"].append(str(exc))
            break
        except requests.RequestException as exc:
            result["notes"].append(f"{scheme.upper()} request failed ({type(exc).__name__}).")
            continue
        if note:
            result["notes"].append(note)
        if resp is None:
            continue
        if scheme == "https":
            result["https_available"] = True
        cookies = [c.split("=", 1)[0].strip() for c in resp.headers.get("Set-Cookie", "").split(",") if "=" in c.split(";")[0]]
        ctype = resp.headers.get("Content-Type", "")
        body = _read_body(resp) if "html" in ctype.lower() else ""
        result.update(analyze_response(resp.headers, body, cookies))
        result.update({"status": "ok", "http_status": resp.status_code, "final_url": chain[-1]["url"],
                       "redirect_chain": chain, "scheme_used": scheme})
        break
    if result["status"] != "ok" and not result["notes"]:
        result["notes"].append("No HTTP response could be obtained.")
    return result

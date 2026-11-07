"""Strict domain validation and normalisation."""
import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BLOCKED_TLDS = {"local", "localhost", "internal", "lan", "home", "corp", "invalid", "test", "onion", "arpa"}


def _fail(raw, message):
    return {"valid": False, "input": raw if isinstance(raw, str) else "", "domain": None, "error": message}


def validate_domain(raw):
    """Return {valid, input, domain, error}. Accepts bare domains or URLs; rejects IPs."""
    if not isinstance(raw, str) or not raw.strip():
        return _fail(raw, "Enter a domain name, for example example.com.")
    text = raw.strip().lower()
    if len(text) > 2048:
        return _fail(raw, "Input is too long.")
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return _fail(raw, "That URL could not be parsed.")
    else:
        text = re.split(r"[/?#]", text, maxsplit=1)[0]
        if "@" in text:
            return _fail(raw, "Remove the username or credentials from the input.")
        if ":" in text:
            host, _, port = text.rpartition(":")
            if not port.isdigit():
                return _fail(raw, "Enter a domain name, not an IPv6 address.")
            text = host
    text = text.strip(".")
    try:
        ipaddress.ip_address(text.strip("[]"))
        return _fail(raw, "IP addresses are not accepted. Enter a domain name.")
    except ValueError:
        pass
    if not text:
        return _fail(raw, "Enter a domain name, for example example.com.")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return _fail(raw, "The domain contains invalid characters.")
    if len(text) > 253:
        return _fail(raw, "Domain is longer than 253 characters.")
    labels = text.split(".")
    if len(labels) < 2:
        return _fail(raw, "Enter a fully qualified domain such as example.com.")
    if not all(_LABEL.match(label) for label in labels):
        return _fail(raw, "Domain labels may only use letters, digits and hyphens (1-63 characters).")
    tld = labels[-1]
    if tld in _BLOCKED_TLDS:
        return _fail(raw, f".{tld} is not a public top-level domain.")
    if tld.isdigit() or not (tld.isalpha() or tld.startswith("xn--")):
        return _fail(raw, "The top-level domain is not valid.")
    return {"valid": True, "input": raw, "domain": text, "error": None}

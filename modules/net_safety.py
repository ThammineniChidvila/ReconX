"""Network safety helpers shared by every module that opens a connection (SSRF / rebinding defence)."""
import ipaddress
import socket


class UnsafeTargetError(Exception):
    """Raised when a hostname resolves to an address ReconX must never connect to."""


def ip_block_reason(ip):
    """Return a human-readable reason the IP is blocked, or None if it is a public address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid IP address"
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    checks = [
        (addr.is_loopback, "loopback"), (addr.is_unspecified, "unspecified"),
        (addr.is_link_local, "link-local"), (addr.is_multicast, "multicast"),
        (addr.is_private, "private or reserved"), (addr.is_reserved, "reserved"),
    ]
    for hit, label in checks:
        if hit:
            return label
    if not addr.is_global:
        return "not globally routable"
    return None


def is_public_ip(ip):
    return ip_block_reason(ip) is None


def _system_resolve(host):
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return list(dict.fromkeys(info[4][0] for info in infos))


def resolve_public(host, resolver=_system_resolve):
    """Resolve host and return its IPs (IPv4 first). Raise UnsafeTargetError if ANY address is non-public."""
    try:
        ips = resolver(host)
    except (socket.gaierror, OSError, UnicodeError) as exc:
        raise UnsafeTargetError(f"Could not resolve {host}: {type(exc).__name__}") from exc
    if not ips:
        raise UnsafeTargetError(f"{host} did not resolve to any address.")
    for ip in ips:
        reason = ip_block_reason(ip)
        if reason:
            raise UnsafeTargetError(f"{host} resolves to a {reason} address ({ip}); connection blocked.")
    return sorted(ips, key=lambda ip: ":" in ip)

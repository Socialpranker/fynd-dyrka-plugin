"""URL checks before outbound redirects and downloads."""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"example.com", "docs.example.com"})
ALLOWED_SCHEMES = frozenset({"http", "https"})


def _host_allowed(host: str) -> bool:
    """Exact match, or a subdomain with a mandatory dot before the suffix."""
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in ALLOWED_HOSTS)


def validate_redirect(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    return _host_allowed(parsed.hostname or "")


def is_internal_host(url: str) -> bool:
    """True when the host resolves to at least one non-public address."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return True
    host = parsed.hostname or ""
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped
        if not addr.is_global:
            return True
    return False

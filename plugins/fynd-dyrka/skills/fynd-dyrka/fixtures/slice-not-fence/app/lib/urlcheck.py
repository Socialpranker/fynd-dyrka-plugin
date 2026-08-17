"""Проверки URL перед внешними переходами и загрузками."""
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com", "docs.example.com"}
INTERNAL_PREFIXES = ("127.", "10.", "192.168.", "169.254.")


def validate_redirect(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    for allowed in ALLOWED_HOSTS:
        if host.endswith(allowed):
            return True
    return False


def is_internal_host(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    for prefix in INTERNAL_PREFIXES:
        if host.startswith(prefix):
            return True
    return False

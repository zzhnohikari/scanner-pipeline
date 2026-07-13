"""Shared fail-closed validation for root-relative HTTP path identities."""

import re
import unicodedata
import ipaddress
from urllib.parse import unquote, urlsplit


_PATH_CONFUSABLE_DELIMITERS = frozenset(
    "\u2044\u2215\uff0f\u29f8\uff3c\u29f5\ufe68\u2024\uff0e\ufe52"
)


def validate_root_relative_path(value, max_decode_depth=4):
    """Return the original safe path identity, or empty on locator ambiguity."""
    original = str(value or "")
    if not original or len(original) >= 250 or not original.startswith("/"):
        return ""

    def invalid_level(level):
        if (
            not level.startswith("/")
            or level.startswith("//")
            or "//" in level
            or "\\" in level
            or ";" in level
            or "\ufffd" in level
            or any(ch in _PATH_CONFUSABLE_DELIMITERS for ch in level)
            or any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in level)
        ):
            return True
        return any(part in (".", "..") for part in level.split("/"))

    current = original
    for _depth in range(max(1, int(max_decode_depth))):
        if invalid_level(current):
            return ""
        normalized = unicodedata.normalize("NFKC", current)
        if invalid_level(normalized):
            return ""
        for delimiter in ("/", "\\", ".", ";", "?", "#", "@", "%"):
            if normalized.count(delimiter) != current.count(delimiter):
                return ""
        if "%" not in current:
            return original
        if re.search(r"%(?![0-9A-Fa-f]{2})", current):
            return ""
        try:
            decoded = unquote(current, encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            return ""
        if decoded == current:
            return original
        for delimiter in ("/", "\\", ".", ";", "?", "#", "@"):
            if decoded.count(delimiter) != current.count(delimiter):
                return ""
        if any(
            (ch.isspace() or unicodedata.category(ch).startswith("C"))
            and ch not in current
            for ch in decoded
        ):
            return ""
        current = decoded
    return ""


def canonical_http_origin(value):
    """Return a canonical HTTP origin, or empty for an unsafe locator.

    DNS names are normalized with the stdlib IDNA codec, lower-cased, and
    stripped of one trailing root dot. IPv4/IPv6 literals use ``ipaddress``.
    Default ports are canonicalized away; userinfo and malformed ports fail
    closed.
    """
    raw = str(value or "")
    if not raw or "\\" in raw or any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in raw):
        return ""
    try:
        parsed = urlsplit(raw)
        scheme = str(parsed.scheme or "").lower()
        if scheme not in ("http", "https") or not parsed.netloc:
            return ""
        if (
            parsed.username is not None or parsed.password is not None or not parsed.hostname
            or "%" in parsed.netloc
        ):
            return ""
        port = parsed.port
        hostname = parsed.hostname
        if hostname.endswith(".."):
            return ""
        if hostname.endswith("."):
            hostname = hostname[:-1]
        if not hostname or ".." in hostname:
            return ""
        try:
            host = ipaddress.ip_address(hostname).compressed.lower()
            display_host = "[" + host + "]" if ":" in host else host
        except ValueError:
            host = hostname.encode("idna").decode("ascii").lower()
            if not host or len(host) > 253 or any(
                not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9-]+", label)
                or label.startswith("-") or label.endswith("-")
                for label in host.split(".")
            ):
                return ""
            display_host = host
    except (UnicodeError, TypeError, ValueError):
        return ""
    default_port = 443 if scheme == "https" else 80
    port_suffix = "" if port in (None, default_port) else ":" + str(port)
    return scheme + "://" + display_host + port_suffix


def canonical_page_api_path(literal, page_url):
    """Authorize a root/absolute queryless API literal against page origin."""
    raw = str(literal or "")
    if not raw or "\\" in raw or raw.startswith("//") or "?" in raw or "#" in raw:
        return ""
    if any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in raw):
        return ""
    try:
        parsed = urlsplit(raw)
    except (TypeError, ValueError):
        return ""
    if parsed.query or parsed.fragment:
        return ""
    if raw.startswith("/"):
        if parsed.scheme or parsed.netloc:
            return ""
        path = parsed.path
    else:
        if not parsed.scheme or not parsed.netloc:
            return ""
        if not canonical_http_origin(raw) or canonical_http_origin(raw) != canonical_http_origin(page_url):
            return ""
        path = parsed.path or "/"
    return validate_root_relative_path(path)

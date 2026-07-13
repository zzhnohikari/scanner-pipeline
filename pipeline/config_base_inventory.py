"""Extract structured API service bases from static JavaScript config.

This module inventories only URLs that are explicitly present in JavaScript.
It does not append guessed REST suffixes and does not perform network access.
"""

import ipaddress
import re
from urllib.parse import urlsplit


_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_JS_STRING = r"(?P<quote>[\"'`])(?P<value>[^\"'`\r\n]{1,2048})(?P=quote)"

_DIRECT_ASSIGNMENT_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_$])
    (?P<lhs>
        (?:window\s*\.\s*)?
        (?:
            apiconfig\s*(?:
                \.\s*%s
                |\[\s*[\"']%s[\"']\s*\]
            )
            |%s
        )
    )
    \s*=\s*%s
    """ % (_IDENT, _IDENT, _IDENT, _JS_STRING),
    re.IGNORECASE | re.VERBOSE,
)

_OBJECT_PROPERTY_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_$])
    (?P<key>%s|[\"']%s[\"'])
    \s*:\s*%s
    """ % (_IDENT, _IDENT, _JS_STRING),
    re.IGNORECASE | re.VERBOSE,
)

_APICONFIG_OBJECT_RE = re.compile(
    r"(?<![A-Za-z0-9_$])(?:window\s*\.\s*)?apiconfig\s*=\s*\{",
    re.IGNORECASE,
)

_EXACT_COMPACT_KEYS = {
    "WORKURL",
    "USERURL",
    "ACCOUNTURL",
    "BASEURL",
    "APIURL",
}

_STATIC_EXTENSIONS = {
    ".css",
    ".gif",
    ".htm",
    ".html",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".mjs",
    ".pdf",
    ".png",
    ".svg",
    ".ts",
    ".tsx",
    ".vue",
    ".woff",
    ".woff2",
    ".xml",
}


def _canonical_key(key):
    return re.sub(r"[^A-Za-z0-9]+", "_", str(key or "")).strip("_").upper()


def _compact_key(key):
    return re.sub(r"[^A-Za-z0-9]+", "", str(key or "")).upper()


def _is_config_url_key(key, api_config_context=False):
    canonical = _canonical_key(key)
    compact = _compact_key(key)
    if not canonical:
        return False
    if compact in _EXACT_COMPACT_KEYS:
        return True
    if canonical.startswith("VUE_APP_") and canonical.endswith("URL"):
        return True
    if compact.endswith(("APIURL", "BASEURL")):
        return True
    return bool(api_config_context and compact.endswith("URL"))


def _key_confidence(key, api_config_context=False):
    compact = _compact_key(key)
    canonical = _canonical_key(key)
    if compact in {"WORKURL", "USERURL", "ACCOUNTURL"}:
        return 0.94
    if compact in {"BASEURL", "APIURL"} or canonical.startswith("VUE_APP_"):
        return 0.92
    return 0.86 if api_config_context else 0.88


def _decode_js_url(value):
    value = str(value or "").strip()
    replacements = {
        r"\/": "/",
        r"\x2f": "/",
        r"\x2F": "/",
        r"\u002f": "/",
        r"\u002F": "/",
        r"\x3a": ":",
        r"\x3A": ":",
        r"\u003a": ":",
        r"\u003A": ":",
    }
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value


def _normalize_host(host):
    host = str(host or "").strip().rstrip(".")
    if not host or "%" in host or re.search(r"[\x00-\x20\x7f]", host):
        return ""
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        try:
            return host.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            return ""


def _format_origin(scheme, host, port):
    display_host = "[" + host + "]" if ":" in host else host
    return "%s://%s%s" % (
        scheme,
        display_host,
        (":" + str(port)) if port is not None else "",
    )


def _normalized_origin(raw_url):
    try:
        parsed = urlsplit(str(raw_url or "").strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            return "", ""
        if parsed.username is not None or parsed.password is not None:
            return "", ""
        host = _normalize_host(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError):
        return "", ""
    if not host:
        return "", ""
    return _format_origin(parsed.scheme.lower(), host, port), host


def _sanitize_source_url(raw_url):
    """Keep useful provenance without persisting credentials or URL secrets."""
    try:
        parsed = urlsplit(str(raw_url or "").strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            return ""
        host = _normalize_host(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    if not host:
        return ""
    path = parsed.path or "/"
    if re.search(r"[\x00-\x20\x7f]", path):
        return ""
    return _format_origin(parsed.scheme.lower(), host, port) + path


def _normalize_candidate_url(raw_url):
    value = _decode_js_url(raw_url)
    if not value or "\\" in value or re.search(r"[\x00-\x20\x7f]", value):
        return None
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.netloc:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.query or parsed.fragment:
            return None
        host = _normalize_host(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if not host or parsed.netloc.endswith(":"):
        return None

    path = parsed.path or ""
    if re.search(r"[\x00-\x20\x7f]", path):
        return None
    path = re.sub(r"/{2,}", "/", path)
    if path and not path.startswith("/"):
        return None
    segments = [part for part in path.split("/") if part]
    if any(part in {".", ".."} for part in segments):
        return None
    path_prefix = path.rstrip("/") if path != "/" else ""
    basename = path_prefix.rsplit("/", 1)[-1].lower()
    if any(basename.endswith(ext) for ext in _STATIC_EXTENSIONS):
        return None

    origin = _format_origin(scheme, host, port)
    return {
        "url": origin + path_prefix,
        "origin": origin,
        "path_prefix": path_prefix,
        "host": host,
    }


def _direct_key(lhs):
    compact_lhs = re.sub(r"\s+", "", str(lhs or ""))
    bracket = re.search(r"\[['\"](%s)['\"]\]$" % _IDENT, compact_lhs)
    if bracket:
        return bracket.group(1)
    return compact_lhs.rsplit(".", 1)[-1]


def _property_key(raw_key):
    return str(raw_key or "").strip().strip("\"'")


def _matching_brace_end(content, open_brace):
    quote = ""
    escaped = False
    depth = 0
    for index in range(open_brace, len(content or "")):
        char = content[index]
        if escaped:
            escaped = False
            continue
        if quote:
            if char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"\"", "'", "`"}:
            quote = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return len(content or "")


def _apiconfig_object_ranges(content):
    ranges = []
    for match in _APICONFIG_OBJECT_RE.finditer(content or ""):
        open_brace = content.find("{", match.start(), match.end())
        if open_brace >= 0:
            ranges.append((open_brace, _matching_brace_end(content, open_brace)))
    return ranges


def _iter_raw_candidates(content):
    api_config_ranges = _apiconfig_object_ranges(content)
    for match in _DIRECT_ASSIGNMENT_RE.finditer(content or ""):
        lhs = match.group("lhs")
        yield {
            "key": _direct_key(lhs),
            "value": match.group("value"),
            "api_config_context": "apiconfig" in lhs.lower(),
        }
    for match in _OBJECT_PROPERTY_RE.finditer(content or ""):
        api_context = any(start <= match.start() < end for start, end in api_config_ranges)
        yield {
            "key": _property_key(match.group("key")),
            "value": match.group("value"),
            "api_config_context": api_context,
        }


def extract_config_base_inventory(content, source_asset="", source_page=""):
    """Return deterministic, JSON-serializable API base candidates.

    Same-host candidates are recommended for active scope. A different or
    unknown host remains inventory-only. No DNS lookup is performed.
    """
    source_asset = _sanitize_source_url(source_asset)
    source_page = _sanitize_source_url(source_page)
    source_origin, source_host = _normalized_origin(source_page or source_asset)
    by_url = {}

    for raw in _iter_raw_candidates(content):
        key = raw["key"]
        api_context = bool(raw["api_config_context"])
        if not _is_config_url_key(key, api_config_context=api_context):
            continue
        normalized = _normalize_candidate_url(raw["value"])
        if not normalized:
            continue

        item = by_url.setdefault(normalized["url"], {
            "normalized": normalized,
            "keys": {},
            "confidence": 0.0,
        })
        canonical = _canonical_key(key)
        previous = item["keys"].get(canonical)
        if previous is None or (key.casefold(), key) < (previous.casefold(), previous):
            item["keys"][canonical] = key
        item["confidence"] = max(
            item["confidence"],
            _key_confidence(key, api_config_context=api_context),
        )

    results = []
    for normalized_url in sorted(by_url):
        item = by_url[normalized_url]
        normalized = item["normalized"]
        config_keys = sorted(item["keys"].values(), key=lambda value: (value.casefold(), value))
        same_host = (normalized["host"] == source_host) if source_host else None
        active_eligible = same_host is True
        results.append({
            "url": normalized["url"],
            "origin": normalized["origin"],
            "path_prefix": normalized["path_prefix"],
            "config_key": config_keys[0],
            "config_keys": config_keys,
            "source": "js_config_base",
            "source_asset": str(source_asset or ""),
            "source_page": str(source_page or ""),
            "source_origin": source_origin,
            "confidence": round(float(item["confidence"]), 2),
            "same_host": same_host,
            "active_eligible": active_eligible,
            "active_scope_recommendation": "same_host" if active_eligible else "inventory_only",
        })
    return results


def extract_config_api_bases(content, source_asset="", source_page=""):
    """Compatibility-friendly alias for the structured inventory extractor."""
    return extract_config_base_inventory(
        content,
        source_asset=source_asset,
        source_page=source_page,
    )


__all__ = ["extract_config_api_bases", "extract_config_base_inventory"]

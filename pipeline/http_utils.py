"""HTTP body decoding helpers used by the scanner pipeline."""

import gzip
import re
import zlib


try:
    import brotli as _brotli
except ImportError:
    try:
        import brotlicffi as _brotli
    except ImportError:
        _brotli = None


def _decompress_deflate(body):
    try:
        return zlib.decompress(body)
    except Exception:
        return zlib.decompress(body, -zlib.MAX_WBITS)


def maybe_decompress_http_body(body, headers=None, log=None):
    if not body:
        return body
    headers = headers or {}
    content_encoding = str(headers.get("Content-Encoding", "")).lower()
    tried = []
    if "gzip" in content_encoding:
        tried.append(("gzip", gzip.decompress))
    if "deflate" in content_encoding:
        tried.append(("deflate", _decompress_deflate))
    if "br" in content_encoding and _brotli:
        tried.append(("br", _brotli.decompress))
    if body[:2] == b"\x1f\x8b" and not any(name == "gzip" for name, _ in tried):
        tried.append(("gzip", gzip.decompress))
    if body[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda") and not any(name == "deflate" for name, _ in tried):
        tried.append(("deflate", _decompress_deflate))
    for name, func in tried:
        try:
            return func(body)
        except Exception as e:
            if log:
                log.debug(f"HTTP body {name} decompress failed: {e}")
    return body


def http_accept_encoding():
    return "gzip, deflate" + (", br" if _brotli else "")


def text_decode_body(raw_bytes, headers=None):
    headers = headers or {}
    content_type = str(headers.get("Content-Type", ""))
    m = re.search(r"charset=([a-zA-Z0-9._-]+)", content_type, re.I)
    encodings = []
    if m:
        encodings.append(m.group(1))
    for enc in ("utf-8", "gb18030", "latin-1"):
        if enc not in encodings:
            encodings.append(enc)
    for enc in encodings:
        try:
            return raw_bytes.decode(enc)
        except Exception:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def decode_http_body(body, headers=None, log=None):
    raw = maybe_decompress_http_body(body, headers or {}, log=log)
    return text_decode_body(raw, headers or {})


def read_limited(resp, max_size=1_000_000):
    body = b""
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        body += chunk
        if len(body) >= max_size:
            break
    return body


def read_http_response(resp, max_size=1_000_000, log=None):
    raw = read_limited(resp, max_size=max_size)
    body_bytes = maybe_decompress_http_body(raw, resp.headers, log=log)
    text = text_decode_body(body_bytes, resp.headers)
    return raw, body_bytes, text

"""HTTP body decoding helpers used by the scanner pipeline."""

import re
import zlib


try:
    import brotli as _brotli
except ImportError:
    try:
        import brotlicffi as _brotli
    except ImportError:
        _brotli = None


def _decompress_zlib_bounded(body, wbits, max_size):
    decoder = zlib.decompressobj(wbits)
    if max_size and max_size > 0:
        output = decoder.decompress(body, max_size)
        remaining = max_size - len(output)
        if remaining > 0:
            output += decoder.flush(remaining)
        return output[:max_size]
    return decoder.decompress(body) + decoder.flush()


def _decompress_deflate(body, max_size):
    try:
        return _decompress_zlib_bounded(body, zlib.MAX_WBITS, max_size)
    except Exception:
        return _decompress_zlib_bounded(body, -zlib.MAX_WBITS, max_size)


def maybe_decompress_http_body(body, headers=None, log=None, max_size=1_000_000):
    if not body:
        return body
    headers = headers or {}
    content_encoding = str(headers.get("Content-Encoding", "")).lower()
    tried = []
    if "gzip" in content_encoding:
        tried.append(("gzip", lambda value: _decompress_zlib_bounded(value, 16 + zlib.MAX_WBITS, max_size)))
    if "deflate" in content_encoding:
        tried.append(("deflate", lambda value: _decompress_deflate(value, max_size)))
    if "br" in content_encoding and _brotli and (not max_size or max_size <= 0):
        tried.append(("br", _brotli.decompress))
    if body[:2] == b"\x1f\x8b" and not any(name == "gzip" for name, _ in tried):
        tried.append(("gzip", lambda value: _decompress_zlib_bounded(value, 16 + zlib.MAX_WBITS, max_size)))
    if body[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda") and not any(name == "deflate" for name, _ in tried):
        tried.append(("deflate", lambda value: _decompress_deflate(value, max_size)))
    for name, func in tried:
        try:
            return func(body)
        except Exception as e:
            if log:
                log.debug(f"HTTP body {name} decompress failed: {e}")
    return body


def http_accept_encoding():
    # Common Python Brotli bindings expose no max-output API, so the scanner
    # does not proactively negotiate br for bounded response reads.
    return "gzip, deflate"


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


def decode_http_body(body, headers=None, log=None, max_size=1_000_000):
    raw = maybe_decompress_http_body(body, headers or {}, log=log, max_size=max_size)
    return text_decode_body(raw, headers or {})


def read_limited(resp, max_size=1_000_000):
    body = bytearray()
    while True:
        remaining = max_size - len(body) if max_size and max_size > 0 else 65536
        if max_size and max_size > 0 and remaining <= 0:
            break
        chunk = resp.read(min(65536, remaining) if max_size and max_size > 0 else 65536)
        if not chunk:
            break
        body.extend(chunk)
    return bytes(body)


def read_http_response(resp, max_size=1_000_000, log=None, include_metadata=False):
    if max_size and max_size > 0:
        raw_plus = read_limited(resp, max_size=max_size + 1)
        raw_truncated = len(raw_plus) > max_size
        decode_limit = max_size + 1
    else:
        raw_plus = read_limited(resp, max_size=max_size)
        raw_truncated = False
        decode_limit = max_size
    body_plus = maybe_decompress_http_body(raw_plus, resp.headers, log=log, max_size=decode_limit)
    body_truncated = bool(max_size and max_size > 0 and len(body_plus) > max_size)
    raw = raw_plus[:max_size] if max_size and max_size > 0 else raw_plus
    body_bytes = body_plus[:max_size] if max_size and max_size > 0 else body_plus
    text = text_decode_body(body_bytes, resp.headers)
    if include_metadata:
        return raw, body_bytes, text, {"content_truncated": bool(raw_truncated or body_truncated)}
    return raw, body_bytes, text

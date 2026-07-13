"""JS graph traversal for Phase 2 API discovery.

The graph builder deliberately delegates extraction and HTTP behavior to the
orchestrator. This keeps scanner strength identical to the existing extractor
while moving JS traversal out of the main scanner file.
"""

import copy
import hashlib
import importlib.util
import os
import re
import sys
from bisect import bisect_right
from urllib.parse import parse_qsl, urljoin, urlparse

try:
    from pipeline.contracts import APIEndpoint, JSAsset, JSGraphEdge, JSGraphResult
    from pipeline.config_base_inventory import extract_config_api_bases
    from pipeline.js_advanced_inventory import (
        analyze_javascript_ast,
        decode_source_map_data_uri,
        explicit_manifest_references,
        import_map_declarations,
        js_like_response,
        parse_asset_manifest,
        parse_import_map,
        parse_source_map,
        same_origin,
        safe_fetch_url,
        sanitize_url,
        source_map_references,
    )
except ImportError:
    _contracts_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "contracts.py")
    _spec = importlib.util.spec_from_file_location("scanner_pipeline_contracts", _contracts_path)
    _contracts_mod = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _contracts_mod
    _spec.loader.exec_module(_contracts_mod)
    APIEndpoint = _contracts_mod.APIEndpoint
    JSAsset = _contracts_mod.JSAsset
    JSGraphEdge = _contracts_mod.JSGraphEdge
    JSGraphResult = _contracts_mod.JSGraphResult
    from config_base_inventory import extract_config_api_bases
    from js_advanced_inventory import (
        analyze_javascript_ast,
        decode_source_map_data_uri,
        explicit_manifest_references,
        import_map_declarations,
        js_like_response,
        parse_asset_manifest,
        parse_import_map,
        parse_source_map,
        same_origin,
        safe_fetch_url,
        sanitize_url,
        source_map_references,
    )


def _merge_profile(dst, src, merge_param_profiles):
    if dst is None:
        return src
    if src is None:
        return dst
    return merge_param_profiles(dst, src)


def _extract_sensitive(content, valid_sensitive_value):
    sensitive = set()
    for m in re.finditer(r'''(?:secret|password|token|apiKey|accessKey|privateKey)\s*[:=]\s*["']([^"']{8,200})["']''', content, re.I):
        value = m.group(1)[:100]
        if valid_sensitive_value(value):
            sensitive.add(f"SENSITIVE:{value}")
    for m in re.finditer(r'''(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})''', content):
        sensitive.add(f"INTERNAL_IP:{m.group(0)}")
    for m in re.finditer(r'''jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+''', content, re.I):
        sensitive.add(f"JDBC:{m.group(0)}")
    return sensitive


def _merge_config_bases(store, items):
    """Merge config-base provenance deterministically across graph assets."""
    for raw in items or []:
        url = str((raw or {}).get("url") or "")
        if not url:
            continue
        item = store.setdefault(url, {
            **dict(raw),
            "config_keys": set(),
            "source_assets": set(),
            "source_pages": set(),
        })
        item["confidence"] = max(float(item.get("confidence") or 0.0), float(raw.get("confidence") or 0.0))
        item["config_keys"].update(str(value) for value in (raw.get("config_keys") or []) if str(value))
        if raw.get("config_key"):
            item["config_keys"].add(str(raw["config_key"]))
        if raw.get("source_asset"):
            item["source_assets"].add(str(raw["source_asset"]))
        if raw.get("source_page"):
            item["source_pages"].add(str(raw["source_page"]))
        item["active_eligible"] = bool(item.get("active_eligible") or raw.get("active_eligible"))
        if item["active_eligible"]:
            item["same_host"] = True
            item["active_scope_recommendation"] = "same_host"


def _finalize_config_bases(store):
    out = []
    for url in sorted(store):
        item = dict(store[url])
        keys = sorted(item.pop("config_keys", set()), key=lambda value: (value.casefold(), value))
        assets = sorted(item.pop("source_assets", set()))
        pages = sorted(item.pop("source_pages", set()))
        item["config_keys"] = keys
        item["config_key"] = keys[0] if keys else str(item.get("config_key") or "")
        item["source_assets"] = assets
        item["source_asset"] = assets[0] if assets else ""
        item["source_pages"] = pages
        item["source_page"] = pages[0] if pages else ""
        item["confidence"] = round(float(item.get("confidence") or 0.0), 2)
        out.append(item)
    return out


_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
_STRING_LITERAL_RE = re.compile(r'''^\s*(["'`])([\s\S]*)\1\s*$''')
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
_REQUEST_CALL_RE = re.compile(
    r'''(?P<callee>(?:window|globalThis)\s*\.\s*fetch|(?:uni|wx)\s*\.\s*request|'''
    r'''\$\s*\.\s*(?:ajax|getJSON)|fetch|request|axios|service|http)\s*\(''',
    re.I,
)
_DIRECT_REQUEST_NAMES = {"fetch", "axios", "request", "service", "http", "window", "globalthis", "uni", "wx", "$", "jquery"}
_EXPRESSION_PREFIX_KEYWORDS = {"await", "case", "delete", "return", "throw", "typeof", "void", "yield"}


def _scan_simple_quoted(text, start, quote):
    index = start + 1
    escaped = False
    while index < len(text):
        current = text[index]
        index += 1
        if escaped:
            escaped = False
        elif current == "\\":
            escaped = True
        elif current == quote:
            break
    return index


def _scan_template_literal(text, start, depth=0):
    if depth > 12:
        return len(text), [(start, len(text))]
    interpolations = []
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index = min(len(text), index + 2)
            continue
        if text[index] == "`":
            return index + 1, interpolations
        if text.startswith("${", index):
            expression_start = index + 2
            cursor = expression_start
            braces = 1
            while cursor < len(text) and braces:
                if text.startswith("//", cursor):
                    newline = text.find("\n", cursor + 2)
                    cursor = len(text) if newline < 0 else newline
                    continue
                if text.startswith("/*", cursor):
                    closing = text.find("*/", cursor + 2)
                    cursor = len(text) if closing < 0 else closing + 2
                    continue
                current = text[cursor]
                if current in ("'", '"'):
                    cursor = _scan_simple_quoted(text, cursor, current)
                    continue
                if current == "`":
                    cursor, nested = _scan_template_literal(text, cursor, depth + 1)
                    interpolations.extend(nested)
                    continue
                if current == "\\":
                    cursor = min(len(text), cursor + 2)
                    continue
                if current == "{":
                    braces += 1
                elif current == "}":
                    braces -= 1
                    if braces == 0:
                        interpolations.append((expression_start, cursor))
                        cursor += 1
                        break
                cursor += 1
            if braces:
                interpolations.append((expression_start, len(text)))
                return len(text), interpolations
            index = cursor
            continue
        index += 1
    return len(text), interpolations


def _js_lexical_context(content):
    """Index bounded JS strings/comments for conservative regex admission."""
    text = str(content or "")
    non_code = []
    comments = []
    template_interpolations = []
    index = 0
    size = len(text)
    while index < size:
        char = text[index]
        if char == "`":
            start = index
            index, interpolations = _scan_template_literal(text, start)
            template_interpolations.extend(interpolations)
            non_code.append((start, index))
            continue
        if char in ("'", '"'):
            start = index
            index = _scan_simple_quoted(text, start, char)
            non_code.append((start, index))
            continue
        if text.startswith("//", index):
            start = index
            newline = text.find("\n", index + 2)
            index = size if newline < 0 else newline
            comments.append((start, index))
            non_code.append((start, index))
            continue
        if text.startswith("/*", index):
            start = index
            end = text.find("*/", index + 2)
            index = size if end < 0 else end + 2
            comments.append((start, index))
            non_code.append((start, index))
            continue
        index += 1
    return {
        "text": text,
        "non_code": non_code,
        "non_code_starts": [span[0] for span in non_code],
        "comments": comments,
        "comment_starts": [span[0] for span in comments],
        "template_interpolations": template_interpolations,
        "mutated": None,
        "shadow_regions": None,
    }


def _span_at(spans, starts, position):
    item = bisect_right(starts, int(position)) - 1
    if item >= 0 and spans[item][0] <= position < spans[item][1]:
        return spans[item]
    return None


def _is_code_position(lexical, position):
    return _span_at(lexical["non_code"], lexical["non_code_starts"], position) is None


METHOD_TRUTH_METHOD = "method"
METHOD_TRUTH_ABSENT = "absent"
METHOD_TRUTH_AMBIGUOUS = "ambiguous"


def _next_significant_index(source, start, lexical, stop=None):
    limit = len(source) if stop is None else min(len(source), stop)
    index = max(0, int(start))
    while index < limit:
        if source[index].isspace():
            index += 1
            continue
        comment = _span_at(lexical["comments"], lexical["comment_starts"], index)
        if comment is not None:
            index = comment[1]
            continue
        return index
    return -1


def _matching_code_delimiter(source, opening, lexical, left="{", right="}"):
    depth = 0
    for index in range(opening, len(source)):
        if not _is_code_position(lexical, index):
            continue
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _top_level_object_segments(source, opening, closing, lexical):
    segments = []
    start = opening + 1
    braces = brackets = parens = 0
    for index in range(opening + 1, closing):
        if not _is_code_position(lexical, index):
            continue
        char = source[index]
        if char == "{": braces += 1
        elif char == "}": braces -= 1
        elif char == "[": brackets += 1
        elif char == "]": brackets -= 1
        elif char == "(": parens += 1
        elif char == ")": parens -= 1
        elif char == "," and braces == brackets == parens == 0:
            segments.append(source[start:index])
            start = index + 1
    segments.append(source[start:closing])
    return segments


def _literal_property_token(source, start, lexical):
    if start < 0 or start >= len(source) or source[start] not in ("'", '"'):
        return "", -1
    span = _span_at(lexical["non_code"], lexical["non_code_starts"], start)
    if span is None or span[0] != start:
        return "", -1
    raw = source[start + 1:max(start + 1, span[1] - 1)]
    return _decode_js_literal(raw), span[1]


def _request_options_method_truth(text, depth=0):
    """Parse one exact plain options ObjectExpression into method truth."""
    if depth > 8:
        return METHOD_TRUTH_AMBIGUOUS, ""
    source = str(text or "")
    lexical = _js_lexical_context(source)
    opening = _next_significant_index(source, 0, lexical)
    if opening < 0 or source[opening] != "{":
        return METHOD_TRUTH_AMBIGUOUS, ""
    closing = _matching_code_delimiter(source, opening, lexical)
    if closing < 0 or _next_significant_index(source, closing + 1, lexical) >= 0:
        return METHOD_TRUTH_AMBIGUOUS, ""
    effective_method = ""
    for raw_segment in _top_level_object_segments(source, opening, closing, lexical):
        segment = str(raw_segment or "")
        segment_lexical = _js_lexical_context(segment)
        start = _next_significant_index(segment, 0, segment_lexical)
        if start < 0:
            continue
        if segment.startswith("...", start):
            spread_start = _next_significant_index(segment, start + 3, segment_lexical)
            if spread_start < 0:
                return METHOD_TRUTH_AMBIGUOUS, ""
            state, method = _request_options_method_truth(segment[spread_start:], depth + 1)
            if state == METHOD_TRUTH_AMBIGUOUS:
                return state, ""
            if state == METHOD_TRUTH_METHOD:
                effective_method = method
            continue

        key = ""
        cursor = start
        if segment[cursor] in ("'", '"'):
            key, cursor = _literal_property_token(segment, cursor, segment_lexical)
        elif segment[cursor] == "[":
            close_key = _matching_code_delimiter(segment, cursor, segment_lexical, "[", "]")
            inner = _next_significant_index(segment, cursor + 1, segment_lexical, close_key)
            if close_key < 0 or inner < 0:
                return METHOD_TRUTH_AMBIGUOUS, ""
            key, after_literal = _literal_property_token(segment, inner, segment_lexical)
            if not key or _next_significant_index(segment, after_literal, segment_lexical, close_key) >= 0:
                return METHOD_TRUTH_AMBIGUOUS, ""
            cursor = close_key + 1
        else:
            match = re.match(r'''[A-Za-z_$][\w$]*''', segment[cursor:])
            if not match:
                return METHOD_TRUTH_AMBIGUOUS, ""
            key = match.group(0)
            cursor += len(key)

        colon = _next_significant_index(segment, cursor, segment_lexical)
        if colon < 0 or segment[colon] != ":":
            if key.lower() in ("method", "type"):
                return METHOD_TRUTH_AMBIGUOUS, ""
            continue
        value_start = _next_significant_index(segment, colon + 1, segment_lexical)
        if value_start < 0:
            return METHOD_TRUTH_AMBIGUOUS, ""
        if key.lower() not in ("method", "type"):
            continue
        value, after_value = _literal_property_token(segment, value_start, segment_lexical)
        if not value:
            return METHOD_TRUTH_AMBIGUOUS, ""
        if _next_significant_index(segment, after_value, segment_lexical) >= 0:
            return METHOD_TRUTH_AMBIGUOUS, ""
        value = value.lower()
        if value not in _HTTP_METHODS:
            return METHOD_TRUTH_AMBIGUOUS, ""
        effective_method = value
    if effective_method:
        return METHOD_TRUTH_METHOD, effective_method
    return METHOD_TRUTH_ABSENT, ""


def _explicit_js_object_method(text, method_constants=None, lexical=None):
    # Compatibility wrapper for callers that only need proven literal truth.
    state, method = _request_options_method_truth(text)
    return method if state == METHOD_TRUTH_METHOD else ""


def _previous_significant_index(content, start, lexical):
    text = str(content or "")
    index = int(start) - 1
    while index >= 0:
        while index >= 0 and text[index].isspace():
            index -= 1
        if index < 0:
            return -1
        comment = _span_at(lexical["comments"], lexical["comment_starts"], index)
        if comment is None:
            return index
        index = comment[0] - 1
    return -1


def _previous_identifier(content, index):
    text = str(content or "")
    end = index + 1
    while index >= 0 and (text[index].isalnum() or text[index] in "_$"):
        index -= 1
    return text[index + 1:end]


def _is_standalone_callable_context(content, start, lexical=None):
    """Reject strings/comments and any trivia-separated member/property token."""
    lexical = lexical or _js_lexical_context(content)
    if not _is_code_position(lexical, start):
        return False
    index = _previous_significant_index(content, start, lexical)
    if index < 0:
        return True
    previous = str(content)[index]
    if previous in (".", "$"):
        return False
    if previous.isalnum() or previous == "_":
        return _previous_identifier(content, index).lower() in _EXPRESSION_PREFIX_KEYWORDS
    return True


def _normalize_callee(value):
    return re.sub(r"\s+", "", str(value or ""))


def _simple_identifier_mutations(content, lexical):
    if lexical.get("mutated") is not None:
        return lexical["mutated"]
    text = str(content or "")
    mutated = set()
    pattern = re.compile(
        r'''(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*'''
        r'''(?:=(?!=|>)|\+=|-=|\*=|\/=|%=|\+\+|--)'''
    )
    for match in pattern.finditer(text):
        if _is_standalone_callable_context(text, match.start(), lexical):
            mutated.add(match.group("name").lower())
    lexical["mutated"] = mutated
    return mutated


def _matching_code_brace(text, opening, lexical):
    depth = 0
    for index in range(opening, len(text)):
        if not _is_code_position(lexical, index):
            continue
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(text)


def _shadow_regions(content, lexical):
    if lexical.get("shadow_regions") is not None:
        return lexical["shadow_regions"]
    text = str(content or "")
    regions = []
    patterns = (
        re.compile(r'''\bfunction(?:\s+[A-Za-z_$][\w$]*)?\s*\((?P<params>[^()]*)\)\s*\{'''),
        re.compile(r'''\((?P<params>[^()]*)\)\s*=>\s*\{'''),
        re.compile(r'''(?P<params>[A-Za-z_$][\w$]*)\s*=>\s*\{'''),
    )
    for pattern in patterns:
        for match in pattern.finditer(text):
            if not _is_code_position(lexical, match.start()):
                continue
            opening = text.find("{", match.start(), match.end())
            if opening < 0 or not _is_code_position(lexical, opening):
                continue
            names = {
                name.lower() for name in re.findall(r'''[A-Za-z_$][\w$]*''', match.group("params") or "")
            }
            if names & _DIRECT_REQUEST_NAMES:
                regions.append((opening + 1, _matching_code_brace(text, opening, lexical), names))
    lexical["shadow_regions"] = regions
    return regions


def _identifier_is_ambiguous(content, name, position, lexical):
    lowered = str(name or "").lower()
    if lowered in _simple_identifier_mutations(content, lexical):
        return True
    return any(start <= position < end and lowered in names for start, end, names in _shadow_regions(content, lexical))


def _source_has_identifier_escape(content, lexical):
    cached = lexical.get("identifier_escape")
    if cached is not None:
        return bool(cached)
    pattern = re.compile(r'''\\u(?:\{[0-9A-Fa-f]{1,6}\}|[0-9A-Fa-f]{4})''')
    interpolation_spans = lexical.get("template_interpolations") or []
    found = any(
        _is_code_position(lexical, match.start())
        or any(start <= match.start() < end for start, end in interpolation_spans)
        for match in pattern.finditer(str(content or ""))
    )
    lexical["identifier_escape"] = found
    return found


def _source_static_request_trust_ambiguous(content, lexical):
    cached = lexical.get("static_request_trust_ambiguous")
    if cached is not None:
        return bool(cached)
    text = str(content or "")
    ambiguous = bool(lexical.get("template_interpolations")) or any(
        char == "/" and _is_code_position(lexical, index)
        for index, char in enumerate(text)
    )
    lexical["static_request_trust_ambiguous"] = ambiguous
    return ambiguous


def _template_interpolation_mentions(content, name, lexical):
    raw = str(name or "")
    identifier = re.compile(r'''(?<![\w$])%s(?![\w$])''' % re.escape(raw))
    unicode_escape = re.compile(r'''\\u(?:\{([0-9A-Fa-f]{1,6})\}|([0-9A-Fa-f]{4}))''')
    for start, end in lexical.get("template_interpolations") or []:
        fragment = str(content or "")[start:end]
        if identifier.search(fragment):
            return True
        decoded = unicode_escape.sub(
            lambda match: chr(int(match.group(1) or match.group(2), 16)), fragment
        )
        if identifier.search(decoded):
            return True
    return False


def _harmless_trusted_property_or_key(content, match, lexical):
    text = str(content or "")
    previous = _previous_significant_index(text, match.start(), lexical)
    if previous >= 0 and text[previous] == ".":
        before_dot = _previous_significant_index(text, previous, lexical)
        return before_dot < 0 or text[before_dot] != "."
    after = _next_significant_index(text, match.end(), lexical)
    return bool(after >= 0 and text[after] == ":" and previous >= 0 and text[previous] in "{,")


def _trusted_identifier_source_ambiguous(content, name, lexical):
    """Reject a trusted global name if any code occurrence is not a direct call."""
    text = str(content or "")
    raw = str(name or "")
    if (
        raw not in {"axios", "request", "service", "http"}
        or _source_static_request_trust_ambiguous(text, lexical)
        or _source_has_identifier_escape(text, lexical)
        or _template_interpolation_mentions(text, raw, lexical)
    ):
        return True
    pattern = re.compile(r'''(?<![\w$])%s(?![\w$])''' % re.escape(raw))
    for match in pattern.finditer(text):
        if not _is_code_position(lexical, match.start()):
            continue
        if _harmless_trusted_property_or_key(text, match, lexical):
            continue
        previous = _previous_significant_index(text, match.start(), lexical)
        after = _next_significant_index(text, match.end(), lexical)
        if not _is_standalone_callable_context(text, match.start(), lexical):
            return True
        if after >= 0 and text[after] == "(":
            continue
        if after < 0 or text[after] != ".":
            return True
        member = _next_significant_index(text, after + 1, lexical)
        allowed = r'''(?:get|post|put|patch|delete)\b'''
        if raw == "axios":
            allowed = r'''(?:create|get|post|put|patch|delete)\b'''
        member_match = re.match(allowed, text[member:]) if member >= 0 else None
        if member_match is None:
            return True
        opening = _next_significant_index(text, member + len(member_match.group(0)), lexical)
        if opening < 0 or text[opening] != "(":
            return True
    return False


def _code_brace_depth(content, position, lexical):
    depth = 0
    for index in range(0, min(len(content), max(0, int(position)))):
        if not _is_code_position(lexical, index):
            continue
        if content[index] == "{":
            depth += 1
        elif content[index] == "}" and depth:
            depth -= 1
    return depth


def _trusted_exact_factory_receiver(content, name, position, lexical):
    """Admit only a top-level exact receiver bound once to axios.create()."""
    text = str(content or "")
    raw = str(name or "")
    if (
        raw not in {"http", "request", "service"}
        or _source_static_request_trust_ambiguous(text, lexical)
        or _source_has_identifier_escape(text, lexical)
        or _template_interpolation_mentions(text, raw, lexical)
        or _template_interpolation_mentions(text, "axios", lexical)
    ):
        return False
    binding_re = re.compile(
        r'''\b(?:const|let|var)\s+(?P<name>%s)\s*=\s*(?P<factory>axios)\s*\.\s*create\s*\('''
        % re.escape(raw)
    )
    bindings = [
        match for match in binding_re.finditer(text)
        if match.start() < position
        and _is_code_position(lexical, match.start())
        and _code_brace_depth(text, match.start(), lexical) == 0
    ]
    if len(bindings) != 1:
        return False
    binding = bindings[0]
    previous = _previous_significant_index(text, binding.start(), lexical)
    if previous >= 0 and text[previous] not in ";}":
        gap = text[previous + 1:binding.start()]
        if "\n" not in gap or not (text[previous].isalnum() or text[previous] in "_$'\""):
            return False

    def identifier_occurrences(identifier):
        pattern = re.compile(r'''(?<![\w$])%s(?![\w$])''' % re.escape(identifier))
        return [match for match in pattern.finditer(text) if _is_code_position(lexical, match.start())]

    for match in identifier_occurrences(raw):
        if match.start() == binding.start("name"):
            continue
        if _harmless_trusted_property_or_key(text, match, lexical):
            continue
        if not _is_standalone_callable_context(text, match.start(), lexical):
            return False
        dot = _next_significant_index(text, match.end(), lexical)
        if dot < 0 or text[dot] != ".":
            return False
        method_start = _next_significant_index(text, dot + 1, lexical)
        method_match = re.match(r'''(?:get|post|put|patch|delete)\b''', text[method_start:]) if method_start >= 0 else None
        if method_match is None:
            return False
        opening = _next_significant_index(text, method_start + len(method_match.group(0)), lexical)
        if opening < 0 or text[opening] != "(":
            return False

    for match in identifier_occurrences("axios"):
        if match.start() == binding.start("factory"):
            continue
        if _harmless_trusted_property_or_key(text, match, lexical):
            continue
        if not _is_standalone_callable_context(text, match.start(), lexical):
            return False
        after = _next_significant_index(text, match.end(), lexical)
        if after >= 0 and text[after] == "(":
            continue
        if after < 0 or text[after] != ".":
            return False
        member = _next_significant_index(text, after + 1, lexical)
        member_match = re.match(r'''(?:get|post|put|patch|delete)\b''', text[member:]) if member >= 0 else None
        if member_match is None:
            return False
        opening = _next_significant_index(text, member + len(member_match.group(0)), lexical)
        if opening < 0 or text[opening] != "(":
            return False
    return True


def _direct_request_callee_allowed(content, callee, position, lexical=None):
    lexical = lexical or _js_lexical_context(content)
    if _source_static_request_trust_ambiguous(content, lexical):
        return False
    normalized = _normalize_callee(callee)
    allowed = {
        "fetch", "axios", "request", "service", "http", "window.fetch", "globalThis.fetch",
        "uni.request", "wx.request", "$.ajax", "$.getJSON",
    }
    if normalized not in allowed or not _is_standalone_callable_context(content, position, lexical):
        return False
    root = normalized.split(".", 1)[0]
    if root in {"axios", "request", "service", "http"}:
        return not _trusted_identifier_source_ambiguous(content, root, lexical)
    return not _source_has_identifier_escape(content, lexical) and not _identifier_is_ambiguous(
        content, root, position, lexical
    )


def _iter_request_calls(content, lexical=None):
    text = str(content or "")
    lexical = lexical or _js_lexical_context(text)
    for match in _REQUEST_CALL_RE.finditer(text):
        if _direct_request_callee_allowed(text, match.group("callee"), match.start("callee"), lexical):
            yield match


def _is_request_method_receiver(value, content="", position=0, lexical=None):
    raw = _normalize_callee(value).strip(".")
    lexical = lexical or _js_lexical_context(content)
    if "." in raw or "?" in raw:
        return False
    if raw not in {"axios", "request", "service", "http", "$", "jquery"}:
        return False
    if (
        _source_static_request_trust_ambiguous(content, lexical)
        or _source_has_identifier_escape(content, lexical)
        or not _is_standalone_callable_context(content, position, lexical)
    ):
        return False
    ambiguous = (
        _trusted_identifier_source_ambiguous(content, raw, lexical)
        if raw in {"axios", "request", "service", "http"}
        else _identifier_is_ambiguous(content, raw, position, lexical)
    )
    if not ambiguous:
        return True
    return _trusted_exact_factory_receiver(content, raw, position, lexical)


def _decode_js_literal(value):
    value = value or ""
    return (
        value.replace(r"\/", "/")
        .replace(r"\'", "'")
        .replace(r'\"', '"')
        .replace(r"\`", "`")
        .replace(r"\n", "")
        .replace(r"\r", "")
        .replace(r"\t", "")
    )


def _split_top_level(expr, sep="+"):
    parts, buf = [], []
    quote = ""
    escape = False
    depth = 0
    for ch in expr:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\" and quote:
            buf.append(ch)
            escape = True
            continue
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_wrappers(expr):
    expr = (expr or "").strip().rstrip(",")
    changed = True
    while changed:
        changed = False
        if expr.startswith("(") and expr.endswith(")"):
            expr = expr[1:-1].strip()
            changed = True
        for wrapper in ("String", "encodeURI", "encodeURIComponent"):
            prefix = wrapper + "("
            if expr.startswith(prefix) and expr.endswith(")"):
                expr = expr[len(prefix):-1].strip()
                changed = True
    return expr


def _resolve_template(body, values):
    def repl(m):
        inner = m.group(1).strip()
        resolved = _resolve_expr(inner, values)
        if resolved:
            return resolved.strip("/")
        lowered = inner.lower()
        if any(k in lowered for k in ("id", "code", "type", "key", "name")):
            return "1"
        return "1"
    return re.sub(r"\$\{([^{}]{1,160})\}", repl, body)


def _resolve_expr(expr, values, depth=0):
    if depth > 8:
        return ""
    expr = _strip_wrappers(expr)
    if not expr:
        return ""
    m = _STRING_LITERAL_RE.match(expr)
    if m:
        body = _decode_js_literal(m.group(2))
        if m.group(1) == "`":
            body = _resolve_template(body, values)
        return body
    if _IDENT_RE.match(expr):
        return values.get(expr, "")
    if "+" in expr:
        resolved = []
        for part in _split_top_level(expr, "+"):
            value = _resolve_expr(part, values, depth + 1)
            if value == "":
                return ""
            resolved.append(value)
        return "".join(resolved)
    tpl = re.search(r"`([\s\S]{1,500})`", expr)
    if tpl:
        return _resolve_template(_decode_js_literal(tpl.group(1)), values)
    return ""


def _extract_braced(text, start):
    if start < 0 or start >= len(text) or text[start] != "{":
        return "", start
    quote = ""
    escape = False
    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\" and quote:
            escape = True
            continue
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:idx + 1], idx + 1
    return "", start


def _extract_call_args(text, open_paren):
    if open_paren < 0 or open_paren >= len(text) or text[open_paren] != "(":
        return "", open_paren
    quote = ""
    escape = False
    depth = 0
    for idx in range(open_paren, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\" and quote:
            escape = True
            continue
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:idx], idx + 1
    return "", open_paren


def _split_args(args):
    return _split_top_level(args, ",")


def _find_object_after_keyword(text, keyword):
    m = re.search(r"\b%s\s*:" % re.escape(keyword), text, re.I)
    if not m:
        return ""
    rest = text[m.end():]
    rest = rest.lstrip()
    if rest.startswith("JSON.stringify"):
        p = rest.find("(")
        args, _ = _extract_call_args(rest, p)
        return args.strip()
    if rest.startswith("new URLSearchParams"):
        p = rest.find("(")
        args, _ = _extract_call_args(rest, p)
        return args.strip()
    if rest.startswith("{"):
        obj, _ = _extract_braced(rest, 0)
        return obj
    ident = re.match(r"([A-Za-z_$][\w$]*)", rest)
    return ident.group(1) if ident else ""


def _body_object_from_expr(expr, object_values):
    expr = _strip_wrappers(expr)
    if not expr:
        return ""
    if expr.startswith("JSON.stringify"):
        p = expr.find("(")
        args, _ = _extract_call_args(expr, p)
        return _body_object_from_expr(args, object_values)
    if expr.startswith("new URLSearchParams"):
        p = expr.find("(")
        args, _ = _extract_call_args(expr, p)
        return _body_object_from_expr(args, object_values)
    if expr.startswith("{"):
        obj, _ = _extract_braced(expr, 0)
        return obj
    if _IDENT_RE.match(expr):
        return object_values.get(expr, "")
    return ""


def _collect_assignments(content):
    values = {}
    objects = {}
    assignments = []
    for m in re.finditer(r'''(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,800})[;\n]''', content):
        assignments.append((m.group(1), m.group(2).strip()))
    for m in re.finditer(r'''(^|[;\n])\s*([A-Za-z_$][\w$]*)\s*=\s*([^=;\n][^;\n]{0,800})[;\n]''', content):
        assignments.append((m.group(2), m.group(3).strip()))

    # Line-oriented assignment regexes intentionally stay bounded, but object
    # payloads are commonly formatted across many lines. Recover those with
    # the same balanced-brace parser used for request arguments.
    object_patterns = (
        re.compile(r'''(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(\{)'''),
        re.compile(r'''(?:^|[;\n])\s*([A-Za-z_$][\w$]*)\s*=\s*(\{)'''),
    )
    for pattern in object_patterns:
        for m in pattern.finditer(content):
            obj, _ = _extract_braced(content, m.start(2))
            if obj:
                objects[m.group(1)] = obj

    for name, expr in assignments:
        if expr.startswith("{"):
            obj, _ = _extract_braced(expr, 0)
            if obj:
                objects[name] = obj
    for _ in range(8):
        changed = False
        for name, expr in assignments:
            value = _resolve_expr(expr, values)
            if value and values.get(name) != value:
                values[name] = value
                changed = True
        if not changed:
            break
    for m in re.finditer(r'''baseURL\s*:\s*([^,\n}]{1,300})''', content, re.I):
        value = _resolve_expr(m.group(1), values)
        if value:
            values.setdefault("__baseURL__", value)
    return values, objects


def _join_paths(base, suffix):
    base = (base or "").strip()
    suffix = (suffix or "").strip()
    if not base:
        return suffix
    if not suffix:
        return base
    if suffix.startswith(("http://", "https://", "//")):
        return suffix
    return base.rstrip("/") + "/" + suffix.lstrip("/")


def _add_api_from_value(apis, value, extract_apis):
    if not value:
        return
    for api in extract_apis('"%s"' % value.replace('"', '\\"')):
        apis.add(api)


def _expand_object_shorthand(expr):
    """Expand ``{userId}`` to ``{userId:userId}`` for profile extraction.

    This is deliberately a small lexical transform rather than a JS parser. It
    only rewrites identifiers immediately following an object delimiter and
    ignores quoted strings, explicit properties, spreads, and method syntax.
    """
    out = []
    i = 0
    quote = ""
    escape = False
    while i < len(expr or ""):
        ch = expr[i]
        if escape:
            out.append(ch)
            escape = False
            i += 1
            continue
        if quote:
            out.append(ch)
            if ch == "\\":
                escape = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch in "{,":
            out.append(ch)
            i += 1
            ws_start = i
            while i < len(expr) and expr[i].isspace():
                i += 1
            whitespace = expr[ws_start:i]
            ident = re.match(r"[A-Za-z_][A-Za-z0-9_]*", expr[i:])
            if ident:
                name = ident.group(0)
                end = i + len(name)
                lookahead = end
                while lookahead < len(expr) and expr[lookahead].isspace():
                    lookahead += 1
                if lookahead < len(expr) and expr[lookahead] in ",}":
                    out.append(whitespace + name + ":" + name)
                    i = end
                    continue
            out.append(whitespace)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _synthesize_param_profile(path, body_obj, source, extract_param_profile, merge_param_profiles, profile):
    if not path or not body_obj:
        return profile
    prop = "params" if source == "query" else "data" if source == "json" else "body"
    body_obj = _expand_object_shorthand(body_obj)
    synthetic = 'request({url:"%s", %s:%s});' % (path.replace('"', '\\"'), prop, body_obj)
    return _merge_profile(profile, extract_param_profile(synthetic), merge_param_profiles)


def _method_filter_key(path, extract_apis):
    candidates = extract_apis('"%s"' % (path or "").replace('"', '\\"'))
    if candidates:
        return sorted(candidates, key=len)[0].split("?", 1)[0].rstrip("/")
    value = (path or "").strip().strip('"\'`')
    if not value or value.startswith(("http:", "https:", "//", "data:", "javascript:", "#")):
        return ""
    if not value.startswith("/"):
        value = "/" + value
    return value.split("?", 1)[0].rstrip("/")


def _mark_explicit_method(method_map, path, method, extract_apis):
    key = _method_filter_key(path, extract_apis)
    if key:
        method_map.setdefault(key, set()).add((method or "").lower())


def _should_skip_delete_path(path, method_map, extract_apis, include_delete_method=False):
    if include_delete_method:
        return False
    key = _method_filter_key(path, extract_apis)
    if not key:
        return False
    methods = set(method_map.get(key, set()))
    return "delete" in methods and not (methods - {"delete"})


def _collect_explicit_method_map(content, values, extract_apis, lexical=None):
    method_map = {}
    lexical = lexical or _js_lexical_context(content)

    def explicit_method_hint(text):
        return _explicit_js_object_method(text)

    for m in re.finditer(
        r'''(?P<receiver>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*'''
        r'''(?P<method>get|post|put|patch|delete)\s*\(''',
        content or "",
    ):
        if not _is_request_method_receiver(m.group("receiver"), content, m.start("receiver"), lexical):
            continue
        open_paren = content.find("(", m.start())
        args_text, _ = _extract_call_args(content, open_paren)
        args = _split_args(args_text)
        if not args:
            continue
        path = _resolve_expr(args[0], values)
        if path:
            _mark_explicit_method(method_map, path, m.group("method"), extract_apis)

    # Destructive syntax is only method metadata when the receiver itself is
    # trusted. Property/alias receivers remain ordinary inventory.
    for m in re.finditer(
        r'''(?P<receiver>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*delete\s*\(''',
        content or "",
    ):
        if not _is_request_method_receiver(m.group("receiver"), content, m.start("receiver"), lexical):
            continue
        open_paren = content.find("(", m.start())
        args_text, _ = _extract_call_args(content, open_paren)
        args = _split_args(args_text)
        path = _resolve_expr(args[0], values) if args else ""
        if path:
            _mark_explicit_method(method_map, path, "delete", extract_apis)

    for m in re.finditer(r'''(?P<callee>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(''', content or "", re.I):
        if not _direct_request_callee_allowed(
            content, m.group("callee"), m.start("callee"), lexical
        ):
            continue
        args_text, _ = _extract_call_args(content, content.find("(", m.start()))
        args = _split_args(args_text)
        if not args or not args[0].strip().startswith("{"):
            continue
        obj = args[0].strip()
        state, method = _request_options_method_truth(obj)
        if state != METHOD_TRUTH_METHOD or method != "delete":
            continue
        url_m = re.search(r'''(?:url|path)\s*:\s*([^,\n}]{1,400})''', obj, re.I)
        path = _resolve_expr(url_m.group(1), values) if url_m else ""
        if path:
            _mark_explicit_method(method_map, path, "delete", extract_apis)

    for m in re.finditer(
        r'''(?P<name>[A-Za-z_$][\w$]*)\s*\.\s*open\s*\(\s*'''
        r'''(?P<method>["']?[A-Za-z_$][\w$]*["']?)\s*,\s*(?P<path>[^,\)\n;]{1,400})''',
        content or "",
        re.I,
    ):
        if not _is_standalone_callable_context(content, m.start("name"), lexical):
            continue
        raw_method = m.group("method").strip()
        method = raw_method.strip('"\'').lower() if raw_method[:1] in ("'", '"') else ""
        path = _resolve_expr(m.group("path"), values)
        if method == "delete" and path:
            _mark_explicit_method(method_map, path, "delete", extract_apis)
    for m in _iter_request_calls(content, lexical):
        open_paren = content.find("(", m.start())
        args_text, _ = _extract_call_args(content, open_paren)
        args = _split_args(args_text)
        if not args:
            continue
        first = args[0].strip()
        callee = _normalize_callee(m.group("callee")).lower()
        default_method = "get" if callee in ("fetch", "window.fetch", "globalthis.fetch") else ""
        if first.startswith("{"):
            url_expr = ""
            url_m = re.search(r'''url\s*:\s*([^,\n}]{1,400})''', first, re.I)
            if url_m:
                url_expr = url_m.group(1)
            path = _resolve_expr(url_expr, values)
            state, method = _request_options_method_truth(first)
            method = method if state == METHOD_TRUTH_METHOD else ""
            if path and method:
                _mark_explicit_method(method_map, path, method, extract_apis)
            continue
        if len(args) > 1:
            state, proven = _request_options_method_truth(args[1])
            method = proven if state == METHOD_TRUTH_METHOD else default_method if state == METHOD_TRUTH_ABSENT else ""
        else:
            method = default_method
        path = _resolve_expr(first, values)
        if path and method:
            _mark_explicit_method(method_map, path, method, extract_apis)
    return method_map


def _request_dataflow(content, extract_apis, extract_param_profile, merge_param_profiles, profile, include_delete_method=False):
    values, objects = _collect_assignments(content)
    lexical = _js_lexical_context(content)
    apis = set()
    request_apis = set()
    blocked_apis = set()
    param_profile = profile
    explicit_methods = _collect_explicit_method_map(content, values, extract_apis, lexical)
    base_values = {v for k, v in values.items() if k == "__baseURL__" or k.lower().endswith(("base", "baseurl", "baseapi"))}

    if include_delete_method:
        for path, methods in explicit_methods.items():
            if "delete" not in methods:
                continue
            inventory_paths = set()
            _add_api_from_value(inventory_paths, path, extract_apis)
            # The orchestrator extractor may itself filter DELETE by default;
            # retain the already-normalized safety hint for explicit inventory.
            if not inventory_paths and path.startswith("/"):
                inventory_paths.add(path.split("?", 1)[0].rstrip("/"))
            apis.update(inventory_paths)
            for inventory_path in inventory_paths:
                key = _method_filter_key(inventory_path, extract_apis) or inventory_path
                param_profile.setdefault("api_methods", {}).setdefault(key, set()).add("delete")

    def explicit_method_hint(text):
        return _explicit_js_object_method(text)

    def add_request(path, body_obj="", source="json", method="", proven_request=True):
        nonlocal param_profile
        if not path:
            return
        if _should_skip_delete_path(path, explicit_methods, extract_apis, include_delete_method):
            return
        sink_apis = set()
        _add_api_from_value(sink_apis, path, extract_apis)
        apis.update(sink_apis)
        if proven_request:
            request_apis.update(sink_apis)
        normalized_method = str(method or "").lower()
        if normalized_method in _HTTP_METHODS:
            for sink_path in sink_apis:
                key = _method_filter_key(sink_path, extract_apis)
                if key:
                    param_profile.setdefault("api_methods", {}).setdefault(key, set()).add(normalized_method)
        for base in base_values:
            if path and not path.startswith("/") and not path.startswith(("http://", "https://", "//")):
                joined_apis = set()
                _add_api_from_value(joined_apis, _join_paths(base, path), extract_apis)
                apis.update(joined_apis)
                if proven_request:
                    request_apis.update(joined_apis)
                if normalized_method in _HTTP_METHODS:
                    for joined_path in joined_apis:
                        key = _method_filter_key(joined_path, extract_apis)
                        if key:
                            param_profile.setdefault("api_methods", {}).setdefault(key, set()).add(normalized_method)
        if body_obj:
            param_profile = _synthesize_param_profile(path, body_obj, source, extract_param_profile, merge_param_profiles, param_profile)

    def block_request(path):
        blocked = set()
        _add_api_from_value(blocked, path, extract_apis)
        if not blocked and str(path or "").startswith("/"):
            blocked.add(str(path).split("?", 1)[0].rstrip("/"))
        blocked_apis.update(blocked)

    for m in _iter_request_calls(content, lexical):
        open_paren = content.find("(", m.start())
        args_text, _ = _extract_call_args(content, open_paren)
        if not args_text:
            continue
        args = _split_args(args_text)
        if not args:
            continue
        first = args[0].strip()
        callee = _normalize_callee(m.group("callee")).lower()
        default_method = "get" if callee in {
            "fetch", "window.fetch", "globalthis.fetch", "uni.request", "wx.request", "$.ajax", "$.getjson"
        } else ""
        if first.startswith("{"):
            state, proven = _request_options_method_truth(first)
            request_method = proven if state == METHOD_TRUTH_METHOD else default_method if state == METHOD_TRUTH_ABSENT else ""
            if not include_delete_method and request_method == "delete":
                continue
            url_expr = ""
            url_m = re.search(r'''url\s*:\s*([^,\n}]{1,400})''', first, re.I)
            if url_m:
                url_expr = url_m.group(1)
            path = _resolve_expr(url_expr, values)
            if state == METHOD_TRUTH_AMBIGUOUS:
                block_request(path)
                continue
            if path:
                for prop, source in (("params", "query"), ("data", "json"), ("body", "json")):
                    body_expr = _find_object_after_keyword(first, prop)
                    body_obj = _body_object_from_expr(body_expr, objects)
                    add_request(path, body_obj, source, request_method)
                if not any(k in first for k in ("params", "data", "body")):
                    add_request(path, method=request_method)
            continue
        path = _resolve_expr(first, values)
        if path:
            body_obj = ""
            source = "json"
            if len(args) > 1:
                second = args[1].strip()
                state, proven = _request_options_method_truth(second)
                if state == METHOD_TRUTH_AMBIGUOUS:
                    block_request(path)
                    continue
                request_method = proven if state == METHOD_TRUTH_METHOD else default_method
                if not include_delete_method and request_method == "delete":
                    continue
                if "URLSearchParams" in second:
                    source = "form"
                if "params" in second:
                    body_obj = _body_object_from_expr(_find_object_after_keyword(second, "params"), objects)
                    source = "query"
                elif "data" in second:
                    body_obj = _body_object_from_expr(_find_object_after_keyword(second, "data"), objects)
                    source = "json"
                elif "body" in second:
                    body_expr = _find_object_after_keyword(second, "body")
                    body_obj = _body_object_from_expr(body_expr, objects)
                    source = "form" if "URLSearchParams" in body_expr else "json"
                else:
                    body_obj = _body_object_from_expr(second, objects)
            else:
                request_method = default_method
            add_request(path, body_obj, source, request_method)

    method_group = "get|post|put|patch|delete" if include_delete_method else "get|post|put|patch"
    for m in re.finditer(
        r'''(?P<receiver>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*'''
        r'''(?P<method>%s)\s*\(''' % method_group,
        content,
    ):
        if not _is_code_position(lexical, m.start("receiver")):
            continue
        open_paren = content.find("(", m.start())
        args_text, _ = _extract_call_args(content, open_paren)
        args = _split_args(args_text)
        if not args:
            continue
        path = _resolve_expr(args[0], values)
        if not path:
            continue
        method = m.group("method").lower()
        proven_request = _is_request_method_receiver(m.group("receiver"), content, m.start("receiver"), lexical)
        body_obj = ""
        source = "query" if method == "get" else "json"
        if len(args) > 1:
            second = args[1].strip()
            if method == "get" and "params" in second:
                body_obj = _body_object_from_expr(_find_object_after_keyword(second, "params"), objects)
                source = "query"
            else:
                body_obj = _body_object_from_expr(second, objects)
        add_request(
            path,
            body_obj if proven_request else "",
            source,
            method if proven_request else "",
            proven_request=proven_request,
        )

    for value in values.values():
        if _should_skip_delete_path(value, explicit_methods, extract_apis, include_delete_method):
            continue
        if "/" in value:
            _add_api_from_value(apis, value, extract_apis)
    return apis, param_profile, request_apis, blocked_apis



def _parse_string_array(text):
    values = []
    for m in re.finditer(r'''["']([^"']+?\.js(?:\?[^"']*)?)["']''', text or "", re.I):
        values.append(_decode_js_literal(m.group(1)))
    return values


def _parse_runtime_string_map(text):
    values = {}
    for m in re.finditer(
        r'''
        (?:(?P<quote>["'])(?P<quoted>[^"']{1,180})(?P=quote)|(?P<bare>[A-Za-z0-9_$-]+))
        \s*:\s*["'](?P<value>[A-Za-z0-9_$-]{1,180})["']
        ''',
        text or "",
        re.X,
    ):
        key = m.group("quoted") or m.group("bare") or ""
        if key:
            values[key] = m.group("value")
    return values


def _webpack_public_path(content, public_var=""):
    patterns = []
    if public_var:
        patterns.append(re.compile(
            r'''\b%s\.p\s*=\s*(["'])([^"']*)\1''' % re.escape(public_var)
        ))
    patterns.append(re.compile(r'''__webpack_public_path__\s*=\s*(["'])([^"']*)\1'''))
    if not public_var:
        patterns.append(re.compile(r'''\b[A-Za-z_$][\w$]*\.p\s*=\s*(["'])([^"']*)\1'''))
    for pattern in patterns:
        matches = list(pattern.finditer(content or ""))
        if matches:
            value = _decode_js_literal(matches[-1].group(2))
            if value and value.lower() != "auto":
                return value
    return ""


def _resolve_runtime_chunk_url(content, base_url, prefix, filename, public_var=""):
    prefix = _decode_js_literal(prefix or "")
    if not prefix or not filename:
        return ""

    public_path = _webpack_public_path(content, public_var)
    if public_path:
        public_base = urljoin(base_url, public_path.rstrip("/") + "/")
        return urljoin(public_base, prefix.lstrip("/") + filename)

    if prefix.startswith(("http://", "https://", "//", "/")):
        return urljoin(base_url, prefix + filename)

    # Runtime manifests usually repeat their asset directory (static/js,
    # assets, ...). When the runtime itself lives in that directory, resolving
    # against the JS file directly would produce static/js/static/js. Strip the
    # repeated suffix while retaining an inferred deployment prefix.
    clean_prefix = re.sub(r"^(?:\./)+", "", prefix)
    if not clean_prefix.startswith("../"):
        asset_dir = urljoin(urlparse(base_url).path or "/", ".")
        marker = "/" + clean_prefix
        marker_pos = asset_dir.rfind(marker)
        if marker_pos >= 0:
            deployment_path = asset_dir[:marker_pos + 1]
            return urljoin(base_url, deployment_path + clean_prefix + filename)
    return urljoin(base_url, prefix + filename)


def _extract_webpack_runtime_chunk_urls(content, base_url):
    """Recover Webpack JSONP chunk filenames from runtime filename builders.

    Vue CLI/Webpack 4 commonly emits a runtime similar to:
    return a.p+"static/js/"+({}[c]||c)+"."+{"chunk-x":"hash"}[c]+".js"
    A plain string search sees only hash + ".js", which becomes /hash.js and
    often returns the SPA HTML fallback instead of the real JS chunk.
    """
    urls = set()
    for m in re.finditer(
        r'''
        (?:(?P<public_var>[A-Za-z_$][\w$]*)\.p\s*\+\s*)?
        (?P<prefix_quote>["'])(?P<prefix>[^"']*(?:static/js|assets|js)/)(?P=prefix_quote)
        \s*\+\s*
        (?:\(\s*\{(?P<name_map>[^{}]{0,2000})\}\s*\[\s*(?P<lookup_var>[A-Za-z_$][\w$]*)\s*\]\s*\|\|\s*)?
        (?P<chunk_var>[A-Za-z_$][\w$]*)
        \s*\)?\s*\+\s*["']\.["']\s*\+\s*
        \{(?P<hash_map>[^{}]{1,20000})\}\s*\[\s*(?P=chunk_var)\s*\]
        \s*\+\s*["']\.js["']
        ''',
        content or "",
        re.I | re.S | re.X,
    ):
        if m.group("lookup_var") and m.group("lookup_var") != m.group("chunk_var"):
            continue
        prefix = m.group("prefix")
        name_map = _parse_runtime_string_map(m.group("name_map") or "")
        hash_map = _parse_runtime_string_map(m.group("hash_map"))
        for chunk_key, chunk_hash in hash_map.items():
            chunk_name = name_map.get(chunk_key, chunk_key)
            if chunk_name.endswith(".js") or "/" in chunk_name:
                continue
            resolved = _resolve_runtime_chunk_url(
                content,
                base_url,
                prefix,
                f"{chunk_name}.{chunk_hash}.js",
                public_var=m.group("public_var") or "",
            )
            if resolved:
                urls.add(resolved)
    return urls


def extract_lazy_chunk_urls(content, base_url):
    """Extract common lazy JS chunk URLs from Webpack/Vite runtime snippets."""
    urls = set()
    if not content:
        return urls

    def add(spec):
        spec = (spec or "").strip()
        if not spec or spec.startswith(("data:", "javascript:", "#")):
            return
        path = spec.split("?", 1)[0].split("#", 1)[0]
        if not (path.endswith(".js") or ".js" in path):
            return
        # Only runtime chunks are JS graph assets. API-like /prefix/download/foo.js
        # URLs should remain API/file candidates, not JS modules.
        if path.startswith("/") and not re.search(r"(?:^|/)(?:static/js|assets|js|chunk)[^/]*/", path, re.I):
            if re.search(r"/(?:api|[a-z0-9]{1,24}-api|gateway|download|file|export|preview|upload|attach|attachment)/", path, re.I):
                return
        urls.add(urljoin(base_url, spec))

    for pat in [
        re.compile(r'''import\s*\(\s*["']([^"']+?\.js(?:\?[^"']*)?)["']\s*\)''', re.I),
        re.compile(r'''["']([^"']*?(?:static/js|assets|js)/[^"']+?\.js(?:\?[^"']*)?)["']''', re.I),
    ]:
        for m in pat.finditer(content):
            add(m.group(1))

    for runtime_url in _extract_webpack_runtime_chunk_urls(content, base_url):
        add(runtime_url)

    for m in re.finditer(r'''\{([^{}]{1,8000})\}\s*\[[^\]]{1,80}\]\s*\+\s*["']([^"']*?\.js)["']''', content, re.S):
        suffix = _decode_js_literal(m.group(2))
        for _key, val in re.findall(r'''["']?([A-Za-z0-9_$-]+)["']?\s*:\s*["']([^"']{1,240})["']''', m.group(1)):
            if suffix == ".js" and re.fullmatch(r"[a-f0-9]{6,16}", val, re.I):
                continue
            add(val + suffix)

    for m in re.finditer(r'''__webpack_require__\.u\s*=\s*(?:function\s*\([^)]*\)|\(?[^=()]+\)?\s*=>)\s*\{?\s*return\s+([\s\S]{1,9000}?);''', content):
        expr = m.group(1)
        for chunk in extract_lazy_chunk_urls(expr, base_url):
            add(chunk)

    arrays = []
    for m in re.finditer(r'''(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*\[([^\]]{1,12000})\]''', content, re.S):
        arr = _parse_string_array(m.group(1))
        if arr:
            arrays.append(arr)
    for m in re.finditer(r'''__vite__mapDeps\s*\(\s*\[([^\]]{1,1000})\]\s*\)''', content):
        indexes = []
        for n in re.findall(r'''\d+''', m.group(1)):
            try:
                indexes.append(int(n))
            except Exception:
                pass
        for arr in arrays:
            for idx in indexes:
                if 0 <= idx < len(arr):
                    add(arr[idx])
    for arr in arrays:
        for spec in arr:
            add(spec)
    return urls


def deterministic_subpage_links(links, limit):
    ordered = sorted(set(links or []))
    return ordered[:max(0, int(limit or 0))]


def _unpack_fetch_response(response):
    """Accept legacy 4-tuples plus optional safe fetch metadata."""
    if not isinstance(response, (tuple, list)) or len(response) < 4:
        return None, None, "", "", {}
    metadata = response[4] if len(response) > 4 else {}
    if isinstance(metadata, bool):
        metadata = {"content_truncated": metadata}
    elif not isinstance(metadata, dict):
        metadata = {}
    return response[0], response[1], response[2], response[3], metadata


def _profile_without_bound_values(profile, empty_param_profile):
    """Keep source-map structure while dropping every materialized value."""
    clean = empty_param_profile()
    clean["names"].update(profile.get("names") or set())
    clean["api_params"] = copy.deepcopy(profile.get("api_params") or {})
    clean["api_param_sources"] = copy.deepcopy(profile.get("api_param_sources") or {})
    clean["api_param_shapes"] = copy.deepcopy(profile.get("api_param_shapes") or {})
    clean["api_methods"] = copy.deepcopy(profile.get("api_methods") or {})
    clean["api_content_types"] = copy.deepcopy(profile.get("api_content_types") or {})
    clean["api_path_templates"] = copy.deepcopy(profile.get("api_path_templates") or {})
    clean["_apis_from_params"] = {
        str(path).split("?", 1)[0].split("#", 1)[0]
        for path in (profile.get("_apis_from_params") or set()) if str(path).startswith("/")
    }
    for path, sources in (profile.get("api_param_specs") or {}).items():
        for source, specs in (sources or {}).items():
            for name, spec in (specs or {}).items():
                safe_spec = {
                    key: copy.deepcopy(value)
                    for key, value in (spec or {}).items()
                    if key not in {"seed", "seed_candidates", "enum", "default", "example", "examples"}
                }
                clean.setdefault("api_param_specs", {}).setdefault(path, {}).setdefault(source, {})[name] = safe_spec
    return clean


def remove_profile_values(profile, values):
    values = {str(value) for value in (values or set()) if str(value)}
    if not values:
        return profile
    profile.setdefault("seeds", set()).difference_update(values)
    profile.setdefault("file_seeds", set()).difference_update(values)
    for sources in (profile.get("api_param_specs") or {}).values():
        for specs in (sources or {}).values():
            for spec in (specs or {}).values():
                if not isinstance(spec, dict):
                    continue
                if str(spec.get("seed")) in values:
                    spec.pop("seed", None)
                for key in ("seed_candidates", "enum"):
                    if isinstance(spec.get(key), list):
                        spec[key] = [value for value in spec[key] if str(value) not in values]
                        if not spec[key]:
                            spec.pop(key, None)
    return profile

def build_js_graph(
    *,
    page_url,
    html,
    fetch_text,
    fetch_advanced_text=None,
    js_limit=0,
    extract_js_from_html,
    extract_links_from_html,
    extract_apis,
    extract_module_urls_from_content,
    extract_prefixes_from_content,
    extract_param_profile,
    empty_param_profile,
    merge_param_profiles,
    common_libs,
    valid_sensitive_value,
    vue_instance_re=None,
    vue_router_re=None,
    react_route_re=None,
    subpage_limit=5,
    max_size=500_000,
    js_max_bytes=2 * 1024 * 1024,
    include_delete_method=False,
    ast_mode="auto",
    ast_limits=None,
    import_maps=True,
    manifest_inventory=True,
    advanced_limits=None,
    source_map_mode="off",
    source_map_limits=None,
):
    result = JSGraphResult(param_profile=empty_param_profile())
    fetch_advanced_text = fetch_advanced_text or fetch_text
    ast_limits = dict(ast_limits or {})
    advanced_limits = dict(advanced_limits or {})
    source_map_limits = dict(source_map_limits or {})
    js_max_bytes = int(js_max_bytes or 0)
    if js_max_bytes <= 0:
        js_max_bytes = 2 * 1024 * 1024
    config_bases = {}
    all_apis = set()
    blocked_request_apis = set()
    api_provenance = {}
    advanced_only_identities = set()
    regular_asset_identities = set()
    regular_fetch_urls = set()
    manifest_declarations_seen = set()
    source_map_declarations_seen = set()
    import_map_declarations_seen = set()
    manifest_active_count = 0
    source_map_active_count = 0
    import_map_active_count = 0
    ast_methods_seen = {}
    ast_blocked_param_paths = set()
    pending_advanced_assets = []
    pending_advanced_identities = set()
    def js_queue_key(value):
        identity = sanitize_url(value)
        return (
            identity in advanced_only_identities and identity not in regular_asset_identities,
            value not in regular_fetch_urls,
            identity,
            value,
        )

    advanced_stats = {
        "ast_mode": str(ast_mode or "auto"),
        "ast_parser": "",
        "ast_parser_version": "",
        "ast_off": 0,
        "ast_parsed": 0,
        "ast_parse_errors": 0,
        "ast_unavailable": 0,
        "ast_oversize": 0,
        "ast_truncated": 0,
        "ast_nodes": 0,
        "ast_expressions": 0,
        "ast_assets": 0,
        "ast_apis": 0,
        "ast_param_bindings": 0,
        "advanced_assets_type_rejected": 0,
        "advanced_origin_rejected": 0,
        "import_maps_declared": 0,
        "import_maps_parsed": 0,
        "import_map_entries": 0,
        "asset_manifest_declared": 0,
        "asset_manifest_parsed": 0,
        "asset_manifest_entries": 0,
        "source_map_declared": 0,
        "source_map_parsed": 0,
        "source_map_sources_processed": 0,
        "content_truncated": 0,
    }
    html_apis, result.param_profile, html_request_apis, html_blocked_apis = _request_dataflow(
        html,
        extract_apis,
        extract_param_profile,
        merge_param_profiles,
        result.param_profile,
        include_delete_method=include_delete_method,
    )
    all_apis.update(html_apis)
    blocked_request_apis.update(html_blocked_apis)

    js_urls = set(extract_js_from_html(html, page_url))
    regular_fetch_urls.update(js_urls)
    regular_asset_identities.update(sanitize_url(url) for url in js_urls if sanitize_url(url))
    lazy_chunk_urls = set()
    result.discovered_urls.update(js_urls)
    links = extract_links_from_html(html, page_url)

    def remember_api(path, source, confidence):
        if not path:
            return
        current = api_provenance.get(path)
        if current is None or float(confidence) > float(current[1]):
            api_provenance[path] = (source, float(confidence))

    for path in html_request_apis:
        remember_api(path, "js_request", 0.96)

    def mark_regular_asset(url):
        identity = sanitize_url(url)
        fetch_url = safe_fetch_url(url)
        freed = bool(identity and identity in advanced_only_identities)
        if identity:
            regular_asset_identities.add(identity)
            advanced_only_identities.discard(identity)
        if fetch_url:
            regular_fetch_urls.add(fetch_url)
        if freed:
            max_assets = max(0, int(advanced_limits.get("max_new_assets", 64) or 0))
            while pending_advanced_assets and (max_assets == 0 or len(advanced_only_identities) < max_assets):
                pending = pending_advanced_assets.pop(0)
                pending_advanced_identities.discard(pending[0])
                add_advanced_asset(*pending[1:])

    def append_bounded_inventory(target, record, eligible):
        cap = max(0, int(advanced_limits.get("inventory_max_declarations", 64) or 0))
        if cap == 0 or len(target) < cap:
            target.append(record)
            return record
        if eligible:
            for index in range(len(target) - 1, -1, -1):
                if not target[index].get("active_eligible"):
                    target[index] = record
                    return record
        return None

    def remember_fetch_query_values(fetch_url):
        if fetch_url:
            raw_query = urlparse(fetch_url).query
            result.redacted_values.update(
                value for _name, value in parse_qsl(raw_query, keep_blank_values=True) if value
            )
            result.redacted_values.update(
                part.partition("=")[2] for part in raw_query.split("&") if "=" in part and part.partition("=")[2]
            )

    def add_advanced_asset(item, edge_src, edge_type, source_page, queue=None, queued=None):
        clean = sanitize_url(item.get("url") or item.get("_fetch_url"))
        fetch_url = safe_fetch_url(item.get("_fetch_url") or item.get("url"))
        if not clean:
            return
        remember_fetch_query_values(fetch_url)
        max_assets = max(0, int(advanced_limits.get("max_new_assets", 64) or 0))
        eligible = bool(item.get("active_eligible") and fetch_url and same_origin(page_url, fetch_url))
        inventory = {
            "url": clean,
            "source": str(item.get("source") or edge_type),
            "sink": str(item.get("sink") or item.get("field") or "")[:80],
            "source_asset": sanitize_url(item.get("source_asset") or edge_src),
            "source_page": sanitize_url(source_page),
            "same_origin": bool(fetch_url and same_origin(page_url, fetch_url)),
            "active_eligible": eligible,
            "confidence": round(float(item.get("confidence") or 0.0), 2),
        }
        key = (inventory["url"], inventory["source"], inventory["sink"], inventory["source_asset"])
        existing = {
            (entry.get("url"), entry.get("source"), entry.get("sink"), entry.get("source_asset"))
            for entry in result.js_resource_inventory
        }
        if key not in existing:
            result.js_resource_inventory.append(inventory)
        if not inventory["active_eligible"]:
            return
        if not fetch_url:
            return
        if clean in regular_asset_identities:
            return
        if clean in advanced_only_identities:
            return
        if max_assets > 0 and len(advanced_only_identities) >= max_assets:
            if clean not in pending_advanced_identities:
                pending_advanced_identities.add(clean)
                pending_advanced_assets.append((clean, item, edge_src, edge_type, source_page, queue, queued))
            return
        advanced_only_identities.add(clean)
        js_urls.add(fetch_url)
        result.discovered_urls.add(fetch_url)
        result.edges.append(JSGraphEdge(src=edge_src, dst=fetch_url, type=edge_type))
        js_source_pages.setdefault(fetch_url, source_page)
        if queue is not None and queued is not None and fetch_url not in queued and fetch_url not in downloaded_js:
            queue.append(fetch_url)
            queue.sort(key=js_queue_key)
            queued.add(fetch_url)

    def process_ast(content, source_url, source_page, queue=None, queued=None):
        analysis = analyze_javascript_ast(
            content, source_url, page_url, mode=ast_mode, limits=ast_limits,
        )
        status = analysis.get("status") or ""
        if analysis.get("parser"):
            advanced_stats["ast_parser"] = analysis.get("parser")
            advanced_stats["ast_parser_version"] = analysis.get("parser_version") or ""
        if status == "parsed":
            advanced_stats["ast_parsed"] += 1
        elif status == "off":
            advanced_stats["ast_off"] += 1
        elif status == "parse_error":
            advanced_stats["ast_parse_errors"] += 1
        elif status == "unavailable":
            advanced_stats["ast_unavailable"] += 1
        elif status == "oversize":
            advanced_stats["ast_oversize"] += 1
        if analysis.get("truncated"):
            advanced_stats["ast_truncated"] += 1
        advanced_stats["ast_nodes"] += int(analysis.get("nodes") or 0)
        advanced_stats["ast_expressions"] += int(analysis.get("expressions") or 0)
        grouped = {}
        ast_blocked_param_paths.update(
            str(path) for path in (analysis.get("blocked_param_paths") or [])
            if str(path).startswith("/")
        )
        for endpoint in analysis.get("apis") or []:
            path = endpoint.get("path") or ""
            if path:
                grouped.setdefault(path, {"methods": set(), "confidence": 0.0, "source": "js_request"})
                method = str(endpoint.get("method") or "").lower()
                if method:
                    grouped[path]["methods"].add(method)
                grouped[path]["confidence"] = max(grouped[path]["confidence"], float(endpoint.get("confidence") or 0.86))
                if endpoint.get("source"):
                    grouped[path]["source"] = str(endpoint.get("source"))
        for path in sorted(grouped):
            methods = grouped[path]["methods"]
            ast_methods_seen.setdefault(path, set()).update(methods)
            effective_methods = set(methods)
            if not include_delete_method:
                effective_methods.discard("delete")
                if methods and not effective_methods:
                    continue
            remember_api(path, grouped[path]["source"], grouped[path]["confidence"])
            all_apis.add(path)
            for method in sorted(effective_methods):
                result.param_profile.setdefault("api_methods", {}).setdefault(path, set()).add(method)
            advanced_stats["ast_apis"] += 1
        for binding in analysis.get("param_bindings") or []:
            path = str(binding.get("path") or "").split("?", 1)[0].split("#", 1)[0]
            source = str(binding.get("source") or "")
            method = str(binding.get("method") or "").lower()
            names = {
                str(name) for name in (binding.get("names") or [])
                if isinstance(name, str) and name and len(name) <= 160
            }
            if not path.startswith("/") or source not in ("query", "json", "form") or not names:
                continue
            if method != "get" or source != "query":
                continue
            result.param_profile.setdefault("api_params", {}).setdefault(path, set()).update(names)
            result.param_profile.setdefault("api_param_sources", {}).setdefault(path, {}).setdefault(source, set()).update(names)
            result.param_profile.setdefault("api_methods", {}).setdefault(path, set()).add(method)
            remember_api(path, "js_request", 0.96)
            all_apis.add(path)
            advanced_stats["ast_param_bindings"] += 1
        for asset in analysis.get("assets") or []:
            add_advanced_asset(asset, source_url, "ast-resource", source_page, queue, queued)
            advanced_stats["ast_assets"] += 1

    def process_manifest(reference, declared_from, source_page, queue=None, queued=None):
        nonlocal manifest_active_count
        clean = sanitize_url(reference)
        fetch_url = safe_fetch_url(reference)
        remember_fetch_query_values(fetch_url)
        if not clean or clean in manifest_declarations_seen:
            return
        manifest_declarations_seen.add(clean)
        advanced_stats["asset_manifest_declared"] += 1
        eligible = bool(fetch_url and same_origin(page_url, fetch_url))
        record = {
            "url": clean,
            "source": "explicit_manifest",
            "declared_from": sanitize_url(declared_from),
            "same_origin": eligible,
            "active_eligible": eligible,
            "status": "inventory_only",
            "entry_count": 0,
        }
        stored_record = append_bounded_inventory(result.asset_manifest_inventory, record, eligible)
        if not manifest_inventory or not eligible:
            return
        max_count = max(0, int(advanced_limits.get("manifest_max_count", 8) or 0))
        if max_count > 0 and manifest_active_count >= max_count:
            if stored_record is not None:
                stored_record["status"] = "active_limit"
            return
        manifest_active_count += 1
        max_bytes = max(1, int(advanced_limits.get("manifest_max_bytes", 262144) or 262144))
        status, final_url, content, _content_type, _metadata = _unpack_fetch_response(
            fetch_advanced_text(fetch_url, max_size=max_bytes + 1)
        )
        if status != 200 or not content:
            record["status"] = "fetch_failed"
            return
        if not same_origin(page_url, final_url or fetch_url):
            record["status"] = "origin_rejected"
            return
        entries, nested, parsed_status = parse_asset_manifest(
            content, final_url or fetch_url, page_url,
            max_bytes=max_bytes,
            max_nodes=max(1, int(advanced_limits.get("manifest_max_nodes", 2048) or 2048)),
            max_entries=max(0, int(advanced_limits.get("manifest_max_entries", 256) or 0)),
        )
        record["status"] = parsed_status
        record["entry_count"] = len(entries)
        if parsed_status == "parsed":
            advanced_stats["asset_manifest_parsed"] += 1
            advanced_stats["asset_manifest_entries"] += len(entries)
        for entry in entries:
            entry = dict(entry)
            entry["source_asset"] = clean
            add_advanced_asset(entry, clean, "manifest-resource", source_page, queue, queued)
        for nested_ref in nested:
            process_manifest(nested_ref, clean, source_page, queue, queued)

    def process_import_maps(document, document_url, queue=None, queued=None):
        nonlocal import_map_active_count
        if not import_maps:
            return
        declarations = import_map_declarations(document, document_url, max_maps=0)
        for declaration in declarations:
            if declaration.get("kind") == "inline":
                parsed_document = urlparse(document_url)
                declaration_key = "inline:%s://%s:%s" % (
                    parsed_document.scheme.lower(), parsed_document.netloc.lower(),
                    hashlib.sha256(str(declaration.get("content") or "").encode("utf-8", "replace")).hexdigest(),
                )
            else:
                declaration_key = declaration.get("url") or ""
            if not declaration_key or declaration_key in import_map_declarations_seen:
                continue
            import_map_declarations_seen.add(declaration_key)
            advanced_stats["import_maps_declared"] += 1
            fetch_url = safe_fetch_url(declaration.get("_fetch_url"))
            remember_fetch_query_values(fetch_url)
            eligible = (
                same_origin(page_url, document_url)
                if declaration.get("kind") == "inline"
                else bool(fetch_url and same_origin(page_url, fetch_url))
            )
            record = {
                "url": declaration.get("url") or sanitize_url(document_url),
                "kind": declaration.get("kind"),
                "source_page": sanitize_url(document_url),
                "same_origin": eligible,
                "active_eligible": eligible,
                "status": "inventory_only",
                "entry_count": 0,
                "entries": [],
            }
            stored_record = append_bounded_inventory(result.import_map_inventory, record, eligible)
            content = declaration.get("content")
            base_url = document_url
            if not eligible:
                continue
            max_maps = max(0, int(advanced_limits.get("import_map_max_count", 8) or 0))
            if max_maps > 0 and import_map_active_count >= max_maps:
                if stored_record is not None:
                    stored_record["status"] = "active_limit"
                continue
            import_map_active_count += 1
            if declaration.get("kind") == "external":
                max_bytes = max(1, int(advanced_limits.get("import_map_max_bytes", 131072) or 131072))
                status, final_url, content, _ct, _metadata = _unpack_fetch_response(
                    fetch_advanced_text(fetch_url, max_size=max_bytes + 1)
                )
                if status != 200 or not content:
                    record["status"] = "fetch_failed"
                    continue
                if not same_origin(page_url, final_url or fetch_url):
                    record["status"] = "origin_rejected"
                    continue
                base_url = final_url or fetch_url
            entries, parsed_status = parse_import_map(
                content, base_url, page_url,
                max_bytes=max(1, int(advanced_limits.get("import_map_max_bytes", 131072) or 131072)),
                max_entries=max(0, int(advanced_limits.get("import_map_max_entries", 128) or 0)),
            )
            record["status"] = parsed_status
            record["entry_count"] = len(entries)
            record["entries"] = [
                {key: value for key, value in entry.items() if not str(key).startswith("_")}
                for entry in entries
            ]
            if parsed_status == "parsed":
                advanced_stats["import_maps_parsed"] += 1
                advanced_stats["import_map_entries"] += len(entries)
            for entry in entries:
                resource = dict(entry)
                resource["source_asset"] = record["url"]
                add_advanced_asset(resource, record["url"], "import-map-resource", document_url, queue, queued)

    def process_source_maps(content, js_url, source_page, queue=None, queued=None):
        nonlocal source_map_active_count
        if source_map_mode == "off":
            return
        max_count = max(0, int(source_map_limits.get("max_count", 4) or 0))
        for reference in source_map_references(content, js_url, max_refs=0):
            if reference.get("kind") == "data":
                declaration_key = "data:%s" % hashlib.sha256(str(reference.get("data") or "").encode("utf-8", "replace")).hexdigest()
            else:
                declaration_key = reference.get("reference") or ""
            if not declaration_key or declaration_key in source_map_declarations_seen:
                continue
            source_map_declarations_seen.add(declaration_key)
            advanced_stats["source_map_declared"] += 1
            fetch_url = safe_fetch_url(reference.get("_fetch_url"))
            remember_fetch_query_values(fetch_url)
            eligible = reference.get("kind") == "data" or bool(fetch_url and same_origin(page_url, fetch_url))
            record = {
                "reference": reference.get("reference") or "inline-data-uri",
                "kind": reference.get("kind"),
                "source_asset": sanitize_url(js_url),
                "same_origin": eligible,
                "active_eligible": eligible,
                "status": "inventory_only",
                "source_count": 0,
            }
            stored_record = append_bounded_inventory(result.source_map_inventory, record, eligible)
            if not eligible:
                continue
            if max_count > 0 and source_map_active_count >= max_count:
                if stored_record is not None:
                    stored_record["status"] = "active_limit"
                continue
            source_map_active_count += 1
            max_bytes = max(1, int(source_map_limits.get("max_bytes", 524288) or 524288))
            map_content = None
            if reference.get("kind") == "data":
                map_content, record["status"] = decode_source_map_data_uri(reference.get("data"), max_bytes)
            elif eligible:
                status, final_url, map_content, _ct, _metadata = _unpack_fetch_response(
                    fetch_advanced_text(fetch_url, max_size=max_bytes + 1)
                )
                if status != 200 or not map_content:
                    record["status"] = "fetch_failed"
                    map_content = None
                elif not same_origin(page_url, final_url or fetch_url):
                    record["status"] = "origin_rejected"
                    map_content = None
            if map_content is None:
                continue
            sources, parsed_status = parse_source_map(
                map_content,
                max_bytes=max_bytes,
                max_sources=max(0, int(source_map_limits.get("max_sources", 32) or 0)),
                max_ratio=float(source_map_limits.get("max_ratio", 8.0) or 0.0),
            )
            record["status"] = parsed_status
            record["source_count"] = len(sources)
            if parsed_status != "parsed":
                continue
            advanced_stats["source_map_parsed"] += 1
            for source in sources:
                advanced_stats["source_map_sources_processed"] += 1
                source_content = source.get("content") or ""
                source_virtual_url = urljoin(js_url, source.get("source") or "source.js")
                all_apis.update(
                    str(path).split("?", 1)[0].split("#", 1)[0]
                    for path in extract_apis(source_content) if str(path)
                )
                source_profile = empty_param_profile()
                source_apis, source_profile, source_request_apis, source_blocked_apis = _request_dataflow(
                    source_content, extract_apis, extract_param_profile,
                    merge_param_profiles, source_profile,
                    include_delete_method=include_delete_method,
                )
                _merge_profile(source_profile, extract_param_profile(source_content), merge_param_profiles)
                _merge_profile(
                    result.param_profile,
                    _profile_without_bound_values(source_profile, empty_param_profile),
                    merge_param_profiles,
                )
                all_apis.update(
                    str(path).split("?", 1)[0].split("#", 1)[0]
                    for path in source_apis if str(path)
                )
                blocked_request_apis.update(source_blocked_apis)
                for path in source_request_apis:
                    remember_api(str(path).split("?", 1)[0].split("#", 1)[0], "js_request", 0.96)
                _merge_config_bases(config_bases, extract_config_api_bases(
                    source_content, source_asset=js_url, source_page=source_page,
                ))
                process_ast(source_content, source_virtual_url, source_page, queue, queued)
                modules = set(extract_module_urls_from_content(source_content, source_virtual_url))
                modules.update(extract_lazy_chunk_urls(source_content, source_virtual_url))
                for module_url in sorted(modules):
                    item = {
                        "url": sanitize_url(module_url), "_fetch_url": safe_fetch_url(module_url), "source": "source_map",
                        "source_asset": sanitize_url(js_url), "same_origin": same_origin(page_url, module_url),
                        "active_eligible": same_origin(page_url, module_url), "confidence": 0.78,
                    }
                    add_advanced_asset(item, js_url, "source-map-resource", source_page, queue, queued)

    def process_declared_manifests(content, base_url, source_page, html_document=False, queue=None, queued=None):
        if not manifest_inventory:
            return
        for reference in explicit_manifest_references(content, base_url, html=html_document, max_refs=0):
            process_manifest(reference, base_url, source_page, queue, queued)

    downloaded_js = set()
    downloaded_regular_identities = set()
    downloaded_advanced_identities = set()
    successful_js = set()
    js_source_pages = {url: page_url for url in js_urls}
    import_map_inline_contents = {
        declaration.get("content")
        for declaration in import_map_declarations(
            html, page_url,
            max_maps=0,
        )
        if declaration.get("kind") == "inline"
    }
    process_import_maps(html, page_url)
    process_declared_manifests(html, page_url, page_url, html_document=True)

    inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
    for script in inline_scripts:
        if not script.strip() or script in import_map_inline_contents:
            continue
        _merge_config_bases(config_bases, extract_config_api_bases(
            script, source_asset="", source_page=page_url,
        ))
        all_apis.update(extract_apis(script))
        script_apis, result.param_profile, script_request_apis, script_blocked_apis = _request_dataflow(
            script,
            extract_apis,
            extract_param_profile,
            merge_param_profiles,
            result.param_profile,
            include_delete_method=include_delete_method,
        )
        all_apis.update(script_apis)
        blocked_request_apis.update(script_blocked_apis)
        for path in script_request_apis:
            remember_api(path, "js_request", 0.96)
        modules = extract_module_urls_from_content(script, page_url)
        for module_url in modules:
            mark_regular_asset(module_url)
            result.edges.append(JSGraphEdge(src=page_url, dst=module_url, type="inline-import"))
        js_urls.update(modules)
        result.discovered_urls.update(modules)
        lazy_modules = extract_lazy_chunk_urls(script, page_url)
        for module_url in sorted(lazy_modules):
            mark_regular_asset(module_url)
            lazy_chunk_urls.add(module_url)
            js_urls.add(module_url)
            result.discovered_urls.add(module_url)
            result.edges.append(JSGraphEdge(src=page_url, dst=module_url, type="lazy-chunk"))
        process_ast(script, page_url, page_url)
        process_declared_manifests(script, page_url, page_url)
        result.prefixes.update(extract_prefixes_from_content(script))
        _merge_profile(result.param_profile, extract_param_profile(script), merge_param_profiles)

    if vue_instance_re and vue_router_re and vue_instance_re.search(html):
        for m in vue_router_re.finditer(html):
            all_apis.add(m.group(1))
    if react_route_re:
        for m in react_route_re.finditer(html):
            all_apis.add(m.group(1))

    def harvest_js(js_candidates, max_items):
        count = 0
        queue = sorted(js_candidates, key=js_queue_key)
        queued = set(queue)
        while queue:
            js_url = queue.pop(0)
            identity = sanitize_url(js_url)
            advanced_only = bool(identity and identity in advanced_only_identities and identity not in regular_asset_identities)
            if js_url in downloaded_js:
                continue
            if advanced_only and identity in (downloaded_regular_identities | downloaded_advanced_identities):
                continue
            if not advanced_only and identity in downloaded_advanced_identities:
                continue
            if common_libs.search(js_url):
                result.skipped_common_urls.add(js_url)
                continue
            if max_items > 0 and count >= max_items:
                break
            downloaded_js.add(js_url)
            if identity:
                (downloaded_advanced_identities if advanced_only else downloaded_regular_identities).add(identity)
            result.attempted_urls.add(js_url)
            count += 1
            fetcher = fetch_advanced_text if advanced_only else fetch_text
            status, final_url, content, content_type, fetch_metadata = _unpack_fetch_response(
                fetcher(js_url, max_size=js_max_bytes)
            )
            content_truncated = bool(fetch_metadata.get("content_truncated"))
            result.assets.append(JSAsset(
                url=js_url,
                final_url=final_url or js_url,
                status=status or 0,
                content_type=content_type or "",
                source="module" if js_url != page_url else "html",
                size=len(content or ""),
                content_truncated=content_truncated,
            ))
            if status != 200 or not content:
                continue
            if advanced_only and not same_origin(page_url, final_url or js_url):
                advanced_stats["advanced_origin_rejected"] += 1
                continue
            if advanced_only and not js_like_response(final_url or js_url, content_type):
                advanced_stats["advanced_assets_type_rejected"] += 1
                continue
            if content_type and "html" in content_type.lower():
                continue
            if content_truncated:
                advanced_stats["content_truncated"] += 1
            source_page = js_source_pages.get(js_url) or page_url
            _merge_config_bases(config_bases, extract_config_api_bases(
                content,
                source_asset=final_url or js_url,
                source_page=source_page,
            ))
            successful_js.add(js_url)
            result.successful_urls.add(js_url)
            all_apis.update(extract_apis(content))
            dataflow_apis, result.param_profile, request_apis, blocked_apis = _request_dataflow(
                content,
                extract_apis,
                extract_param_profile,
                merge_param_profiles,
                result.param_profile,
                include_delete_method=include_delete_method,
            )
            all_apis.update(dataflow_apis)
            blocked_request_apis.update(blocked_apis)
            for path in request_apis:
                remember_api(path, "js_request", 0.96)
            modules = extract_module_urls_from_content(content, final_url or js_url)
            lazy_modules = extract_lazy_chunk_urls(content, final_url or js_url)
            for module_url in set(modules) | set(lazy_modules):
                mark_regular_asset(module_url)
            if not content_truncated:
                process_ast(content, final_url or js_url, source_page, queue, queued)
            process_declared_manifests(content, final_url or js_url, source_page, queue=queue, queued=queued)
            process_source_maps(content, final_url or js_url, source_page, queue, queued)
            for module_url in sorted(modules):
                js_urls.add(module_url)
                result.discovered_urls.add(module_url)
                result.edges.append(JSGraphEdge(src=js_url, dst=module_url, type="module-import"))
                if module_url not in queued and module_url not in downloaded_js:
                    queue.append(module_url)
                    queue.sort(key=js_queue_key)
                    queued.add(module_url)
                js_source_pages.setdefault(module_url, source_page)
            for module_url in sorted(lazy_modules):
                lazy_chunk_urls.add(module_url)
                js_urls.add(module_url)
                result.discovered_urls.add(module_url)
                result.edges.append(JSGraphEdge(src=js_url, dst=module_url, type="lazy-chunk"))
                if module_url not in queued and module_url not in downloaded_js:
                    queue.append(module_url)
                    queue.sort(key=js_queue_key)
                    queued.add(module_url)
                js_source_pages.setdefault(module_url, source_page)
            result.prefixes.update(extract_prefixes_from_content(content))
            _merge_profile(result.param_profile, extract_param_profile(content), merge_param_profiles)
            result.sensitive.update(_extract_sensitive(content, valid_sensitive_value))
        return count

    harvest_js(js_urls, js_limit)

    crawled = set()
    for link in deterministic_subpage_links(links, subpage_limit):
        if link in crawled:
            continue
        crawled.add(link)
        status, final_url, page, _content_type, _metadata = _unpack_fetch_response(
            fetch_text(link, max_size=max_size)
        )
        if status != 200 or not page or len(page) < 100:
            continue
        process_import_maps(page, final_url or link)
        process_declared_manifests(page, final_url or link, final_url or link, html_document=True)
        sub_js = extract_js_from_html(page, final_url or link)
        for js_url in sub_js:
            mark_regular_asset(js_url)
            result.edges.append(JSGraphEdge(src=link, dst=js_url, type="subpage-script"))
            js_urls.add(js_url)
            result.discovered_urls.add(js_url)
            js_source_pages.setdefault(js_url, final_url or link)
        for script in re.findall(r'<script[^>]*>([\s\S]*?)</script>', page, re.I):
            sub_import_map_contents = {
                declaration.get("content")
                for declaration in import_map_declarations(
                    page, final_url or link,
                    max_maps=0,
                )
                if declaration.get("kind") == "inline"
            }
            if not script.strip() or script in sub_import_map_contents:
                continue
            _merge_config_bases(config_bases, extract_config_api_bases(
                script, source_asset="", source_page=final_url or link,
            ))
            all_apis.update(extract_apis(script))
            script_apis, result.param_profile, script_request_apis, script_blocked_apis = _request_dataflow(
                script,
                extract_apis,
                extract_param_profile,
                merge_param_profiles,
                result.param_profile,
                include_delete_method=include_delete_method,
            )
            all_apis.update(script_apis)
            blocked_request_apis.update(script_blocked_apis)
            for path in script_request_apis:
                remember_api(path, "js_request", 0.96)
            modules = extract_module_urls_from_content(script, final_url or link)
            for module_url in modules:
                mark_regular_asset(module_url)
                result.edges.append(JSGraphEdge(src=link, dst=module_url, type="subpage-inline-import"))
            js_urls.update(modules)
            result.discovered_urls.update(modules)
            for module_url in modules:
                js_source_pages.setdefault(module_url, final_url or link)
            process_ast(script, final_url or link, final_url or link)
            process_declared_manifests(script, final_url or link, final_url or link)
            result.prefixes.update(extract_prefixes_from_content(script))
            _merge_profile(result.param_profile, extract_param_profile(script), merge_param_profiles)

    if js_limit > 0:
        remaining = max(0, js_limit - len(downloaded_js))
        if remaining > 0:
            harvest_js(js_urls, remaining)
    else:
        harvest_js(js_urls, 0)

    if not include_delete_method:
        for path, methods in ast_methods_seen.items():
            recorded = set(result.param_profile.get("api_methods", {}).get(path) or set())
            if methods == {"delete"} and not (recorded - {"delete"}):
                all_apis.discard(path)
                api_provenance.pop(path, None)

    for path in blocked_request_apis:
        if api_provenance.get(path, ("", 0.0))[0] != "js_request":
            all_apis.discard(path)

    trusted_param_paths = {
        path for path, names in (result.param_profile.get("api_params") or {}).items() if names
    }
    result.param_profile.setdefault("api_param_blocked", set()).update(
        path for path in ast_blocked_param_paths if path not in trusted_param_paths
    )

    remove_profile_values(result.param_profile, result.redacted_values)

    for api in sorted(all_apis):
        source, confidence = api_provenance.get(api, ("js-graph", 0.8))
        result.apis.append(APIEndpoint(path=api, source=source, confidence=confidence))
    result.config_service_bases = _finalize_config_bases(config_bases)
    result.js_resource_inventory.sort(key=lambda item: (
        item.get("url", ""), item.get("source", ""), item.get("sink", ""), item.get("source_asset", ""),
    ))
    result.import_map_inventory.sort(key=lambda item: (item.get("url", ""), item.get("kind", "")))
    result.asset_manifest_inventory.sort(key=lambda item: item.get("url", ""))
    result.source_map_inventory.sort(key=lambda item: (item.get("source_asset", ""), item.get("reference", "")))
    result.discovered_urls.update(js_urls)
    result.stats = {
        "js_max_bytes": js_max_bytes,
        "js_discovered": len(result.discovered_urls),
        "js_app_candidates": sum(1 for url in result.discovered_urls if not common_libs.search(url)),
        "js_attempted": len(result.attempted_urls),
        "js_count": len(result.successful_urls),
        "assets": len(result.assets),
        "edges": len(result.edges),
        "apis": len(result.apis),
        "skipped_common": len(result.skipped_common_urls),
        "lazy_chunks_discovered": len(lazy_chunk_urls),
        "lazy_chunks_attempted": len(lazy_chunk_urls & result.attempted_urls),
        "lazy_chunks_downloaded": len(lazy_chunk_urls & result.successful_urls),
    }
    result.stats.update(advanced_stats)
    return result

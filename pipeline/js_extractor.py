"""JS graph traversal for Phase 2 API discovery.

The graph builder deliberately delegates extraction and HTTP behavior to the
orchestrator. This keeps scanner strength identical to the existing extractor
while moving JS traversal out of the main scanner file.
"""

import importlib.util
import os
import re
import sys

try:
    from pipeline.types import APIEndpoint, JSAsset, JSGraphEdge, JSGraphResult
except ImportError:
    _types_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "types.py")
    _spec = importlib.util.spec_from_file_location("scanner_pipeline_types", _types_path)
    _types_mod = importlib.util.module_from_spec(_spec)
    sys.modules[_spec.name] = _types_mod
    _spec.loader.exec_module(_types_mod)
    APIEndpoint = _types_mod.APIEndpoint
    JSAsset = _types_mod.JSAsset
    JSGraphEdge = _types_mod.JSGraphEdge
    JSGraphResult = _types_mod.JSGraphResult


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


_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")
_STRING_LITERAL_RE = re.compile(r'''^\s*(["'`])([\s\S]*)\1\s*$''')


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


def _synthesize_param_profile(path, body_obj, source, extract_param_profile, merge_param_profiles, profile):
    if not path or not body_obj:
        return profile
    prop = "params" if source == "query" else "data" if source == "json" else "body"
    synthetic = 'request({url:"%s", %s:%s});' % (path.replace('"', '\\"'), prop, body_obj)
    return _merge_profile(profile, extract_param_profile(synthetic), merge_param_profiles)


def _request_dataflow(content, extract_apis, extract_param_profile, merge_param_profiles, profile):
    values, objects = _collect_assignments(content)
    apis = set()
    param_profile = profile
    base_values = {v for k, v in values.items() if k == "__baseURL__" or k.lower().endswith(("base", "baseurl", "baseapi"))}

    def add_request(path, body_obj="", source="json"):
        nonlocal param_profile
        if not path:
            return
        _add_api_from_value(apis, path, extract_apis)
        for base in base_values:
            if path and not path.startswith("/") and not path.startswith(("http://", "https://", "//")):
                _add_api_from_value(apis, _join_paths(base, path), extract_apis)
        if body_obj:
            param_profile = _synthesize_param_profile(path, body_obj, source, extract_param_profile, merge_param_profiles, param_profile)

    for m in re.finditer(r'''(?:fetch|request|axios|service|http)\s*\(''', content, re.I):
        open_paren = content.find("(", m.start())
        args_text, _ = _extract_call_args(content, open_paren)
        if not args_text:
            continue
        args = _split_args(args_text)
        if not args:
            continue
        first = args[0].strip()
        if first.startswith("{"):
            url_expr = ""
            url_m = re.search(r'''url\s*:\s*([^,\n}]{1,400})''', first, re.I)
            if url_m:
                url_expr = url_m.group(1)
            path = _resolve_expr(url_expr, values)
            if path:
                for prop, source in (("params", "query"), ("data", "json"), ("body", "json")):
                    body_expr = _find_object_after_keyword(first, prop)
                    body_obj = _body_object_from_expr(body_expr, objects)
                    add_request(path, body_obj, source)
                if not any(k in first for k in ("params", "data", "body")):
                    add_request(path)
            continue
        path = _resolve_expr(first, values)
        if path:
            body_obj = ""
            source = "json"
            if len(args) > 1:
                second = args[1].strip()
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
            add_request(path, body_obj, source)

    for m in re.finditer(r'''([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.(get|post|put|patch|delete)\s*\(''', content, re.I):
        open_paren = content.find("(", m.start())
        args_text, _ = _extract_call_args(content, open_paren)
        args = _split_args(args_text)
        if not args:
            continue
        path = _resolve_expr(args[0], values)
        if not path:
            continue
        method = m.group(2).lower()
        body_obj = ""
        source = "query" if method == "get" else "json"
        if len(args) > 1:
            second = args[1].strip()
            if method == "get" and "params" in second:
                body_obj = _body_object_from_expr(_find_object_after_keyword(second, "params"), objects)
                source = "query"
            else:
                body_obj = _body_object_from_expr(second, objects)
        add_request(path, body_obj, source)

    for value in values.values():
        if "/" in value:
            _add_api_from_value(apis, value, extract_apis)
    return apis, param_profile


def build_js_graph(
    *,
    page_url,
    html,
    fetch_text,
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
):
    result = JSGraphResult(param_profile=empty_param_profile())
    all_apis = set()
    html_apis, result.param_profile = _request_dataflow(
        html,
        extract_apis,
        extract_param_profile,
        merge_param_profiles,
        result.param_profile,
    )
    all_apis.update(html_apis)

    js_urls = set(extract_js_from_html(html, page_url))
    result.discovered_urls.update(js_urls)
    links = extract_links_from_html(html, page_url)

    inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
    for script in inline_scripts:
        if not script.strip():
            continue
        all_apis.update(extract_apis(script))
        script_apis, result.param_profile = _request_dataflow(
            script,
            extract_apis,
            extract_param_profile,
            merge_param_profiles,
            result.param_profile,
        )
        all_apis.update(script_apis)
        modules = extract_module_urls_from_content(script, page_url)
        for module_url in modules:
            result.edges.append(JSGraphEdge(src=page_url, dst=module_url, type="inline-import"))
        js_urls.update(modules)
        result.discovered_urls.update(modules)
        result.prefixes.update(extract_prefixes_from_content(script))
        _merge_profile(result.param_profile, extract_param_profile(script), merge_param_profiles)

    if vue_instance_re and vue_router_re and vue_instance_re.search(html):
        for m in vue_router_re.finditer(html):
            all_apis.add(m.group(1))
    if react_route_re:
        for m in react_route_re.finditer(html):
            all_apis.add(m.group(1))

    downloaded_js = set()
    successful_js = set()

    def harvest_js(js_candidates, max_items):
        count = 0
        queue = sorted(js_candidates)
        queued = set(queue)
        while queue:
            js_url = queue.pop(0)
            if js_url in downloaded_js:
                continue
            if common_libs.search(js_url):
                result.skipped_common_urls.add(js_url)
                continue
            if max_items > 0 and count >= max_items:
                break
            downloaded_js.add(js_url)
            result.attempted_urls.add(js_url)
            count += 1
            status, final_url, content, content_type = fetch_text(js_url, max_size=max_size)
            result.assets.append(JSAsset(
                url=js_url,
                final_url=final_url or js_url,
                status=status or 0,
                content_type=content_type or "",
                source="module" if js_url != page_url else "html",
                size=len(content or ""),
            ))
            if status != 200 or not content:
                continue
            successful_js.add(js_url)
            result.successful_urls.add(js_url)
            all_apis.update(extract_apis(content))
            dataflow_apis, result.param_profile = _request_dataflow(
                content,
                extract_apis,
                extract_param_profile,
                merge_param_profiles,
                result.param_profile,
            )
            all_apis.update(dataflow_apis)
            modules = extract_module_urls_from_content(content, final_url or js_url)
            for module_url in sorted(modules):
                js_urls.add(module_url)
                result.discovered_urls.add(module_url)
                result.edges.append(JSGraphEdge(src=js_url, dst=module_url, type="module-import"))
                if module_url not in queued and module_url not in downloaded_js:
                    queue.append(module_url)
                    queued.add(module_url)
            result.prefixes.update(extract_prefixes_from_content(content))
            _merge_profile(result.param_profile, extract_param_profile(content), merge_param_profiles)
            result.sensitive.update(_extract_sensitive(content, valid_sensitive_value))
        return count

    harvest_js(js_urls, js_limit)

    crawled = set()
    for link in list(links)[:subpage_limit]:
        if link in crawled:
            continue
        crawled.add(link)
        status, final_url, page, _content_type = fetch_text(link, max_size=max_size)
        if status != 200 or not page or len(page) < 100:
            continue
        sub_js = extract_js_from_html(page, final_url or link)
        for js_url in sub_js:
            result.edges.append(JSGraphEdge(src=link, dst=js_url, type="subpage-script"))
            js_urls.add(js_url)
            result.discovered_urls.add(js_url)
        for script in re.findall(r'<script[^>]*>([\s\S]*?)</script>', page, re.I):
            if not script.strip():
                continue
            all_apis.update(extract_apis(script))
            script_apis, result.param_profile = _request_dataflow(
                script,
                extract_apis,
                extract_param_profile,
                merge_param_profiles,
                result.param_profile,
            )
            all_apis.update(script_apis)
            modules = extract_module_urls_from_content(script, final_url or link)
            for module_url in modules:
                result.edges.append(JSGraphEdge(src=link, dst=module_url, type="subpage-inline-import"))
            js_urls.update(modules)
            result.discovered_urls.update(modules)
            result.prefixes.update(extract_prefixes_from_content(script))
            _merge_profile(result.param_profile, extract_param_profile(script), merge_param_profiles)

    if js_limit > 0:
        remaining = max(0, js_limit - len(downloaded_js))
        if remaining > 0:
            harvest_js(js_urls, remaining)
    else:
        harvest_js(js_urls, 0)

    for api in sorted(all_apis):
        result.apis.append(APIEndpoint(path=api, source="js-graph", confidence=0.8))
    result.discovered_urls.update(js_urls)
    result.stats = {
        "js_discovered": len(result.discovered_urls),
        "js_app_candidates": sum(1 for url in result.discovered_urls if not common_libs.search(url)),
        "js_attempted": len(result.attempted_urls),
        "js_count": len(result.successful_urls),
        "assets": len(result.assets),
        "edges": len(result.edges),
        "apis": len(result.apis),
        "skipped_common": len(result.skipped_common_urls),
    }
    return result

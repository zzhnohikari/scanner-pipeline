"""Bounded, non-executing JavaScript and declared asset inventory helpers."""

from __future__ import annotations

import base64
import json
import posixpath
import re
from html.parser import HTMLParser
from urllib.parse import unquote_to_bytes, urljoin, urlsplit, urlunsplit

try:
    from pipeline.path_safety import canonical_page_api_path, validate_root_relative_path
except ImportError:  # pragma: no cover - direct module execution fallback
    from path_safety import canonical_page_api_path, validate_root_relative_path


try:
    import esprima  # type: ignore
except ImportError:  # pragma: no cover - exercised through mode/status tests
    esprima = None


JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue")
MANIFEST_NAME_RE = re.compile(
    r"(?:^|/)(?:(?:asset|build|vite|webpack)[._-]?manifest|manifest)"
    r"(?:[._-][A-Za-z0-9_-]+)?\.(?:json|webmanifest)$",
    re.I,
)
SOURCE_MAP_RE = re.compile(
    r"(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)", re.I
)
DIRECT_REQUEST_NAMES = {"fetch", "axios", "request", "service", "http", "window", "globalthis", "uni", "wx", "$", "jquery"}


def _trusted_request_receiver(value, shadowed=None, mutated=None):
    raw = str(value or "").strip(".")
    lowered = raw.lower()
    if "." in raw or "?" in raw:
        return False
    return raw in {"axios", "request", "service", "http", "$", "jquery"} and lowered not in set(shadowed or ()) and lowered not in set(mutated or ())


def _binding_identifier_names(node):
    if not isinstance(node, dict):
        return set()
    kind = node.get("type")
    if kind == "Identifier":
        return {str(node.get("name") or "")}
    if kind in ("RestElement", "SpreadElement"):
        return _binding_identifier_names(node.get("argument"))
    if kind == "AssignmentPattern":
        return _binding_identifier_names(node.get("left"))
    if kind == "ArrayPattern":
        names = set()
        for item in node.get("elements") or []:
            names.update(_binding_identifier_names(item))
        return names
    if kind == "ObjectPattern":
        names = set()
        for prop in node.get("properties") or []:
            if not isinstance(prop, dict):
                continue
            if prop.get("type") in ("RestElement", "SpreadElement"):
                names.update(_binding_identifier_names(prop.get("argument")))
            else:
                names.update(_binding_identifier_names(prop.get("value")))
        return names
    return set()


def _collect_mutated_direct_names(node):
    mutated = set()

    def visit(value):
        if not isinstance(value, dict):
            return
        kind = value.get("type")
        if kind == "VariableDeclarator":
            mutated.update(
                name.lower() for name in _binding_identifier_names(value.get("id"))
                if name.lower() in DIRECT_REQUEST_NAMES
            )
            init = value.get("init") or {}
            if init.get("type") == "Identifier":
                captured = str(init.get("name") or "").lower()
                if captured in DIRECT_REQUEST_NAMES:
                    mutated.add(captured)
        elif kind in ("AssignmentExpression", "UpdateExpression"):
            target = value.get("left") if kind == "AssignmentExpression" else value.get("argument")
            mutated.update(
                name.lower() for name in _binding_identifier_names(target)
                if name.lower() in DIRECT_REQUEST_NAMES
            )
            right = value.get("right") or {}
            if kind == "AssignmentExpression" and right.get("type") == "Identifier":
                captured = str(right.get("name") or "").lower()
                if captured in DIRECT_REQUEST_NAMES:
                    mutated.add(captured)
        elif kind in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            for param in value.get("params") or []:
                mutated.update(
                    name.lower() for name in _binding_identifier_names(param)
                    if name.lower() in DIRECT_REQUEST_NAMES
                )
        elif kind == "CatchClause":
            mutated.update(
                name.lower() for name in _binding_identifier_names(value.get("param"))
                if name.lower() in DIRECT_REQUEST_NAMES
            )
        elif kind in ("ForInStatement", "ForOfStatement"):
            left = value.get("left") or {}
            if left.get("type") != "VariableDeclaration":
                mutated.update(
                    name.lower() for name in _binding_identifier_names(left)
                    if name.lower() in DIRECT_REQUEST_NAMES
                )
        elif kind in ("BinaryExpression", "LogicalExpression"):
            for operand in (value.get("left"), value.get("right")):
                if isinstance(operand, dict) and operand.get("type") == "Identifier":
                    name = str(operand.get("name") or "").lower()
                    if name in DIRECT_REQUEST_NAMES:
                        mutated.add(name)
        elif kind == "Property":
            prop_value = value.get("value") or {}
            if prop_value.get("type") == "Identifier":
                name = str(prop_value.get("name") or "").lower()
                if name in DIRECT_REQUEST_NAMES:
                    mutated.add(name)
        for key, child in value.items():
            if key in ("loc", "range", "tokens", "comments"):
                continue
            if isinstance(child, dict):
                visit(child)
            elif isinstance(child, list):
                for item in child:
                    visit(item)

    visit(node)
    return mutated


def _literal_member_name(node):
    if not isinstance(node, dict) or node.get("type") != "MemberExpression":
        return ""
    prop = node.get("property") or {}
    if not node.get("computed") and prop.get("type") == "Identifier":
        return str(prop.get("name") or "")
    if node.get("computed") and prop.get("type") == "Literal" and isinstance(prop.get("value"), str):
        return str(prop.get("value") or "")
    return ""


def _member_root_identifier(node):
    if not isinstance(node, dict) or node.get("type") != "MemberExpression":
        return ""
    obj = node.get("object") or {}
    return str(obj.get("name") or "") if obj.get("type") == "Identifier" else ""


def _collect_mutated_request_members(node):
    """Return receivers whose ``get`` member cannot be proven immutable."""
    mutated = set()

    def mark_member(member):
        if not isinstance(member, dict) or member.get("type") != "MemberExpression":
            return
        root = _member_root_identifier(member)
        if not root:
            return
        prop = member.get("property") or {}
        literal = _literal_member_name(member)
        if literal == "get" or (member.get("computed") and prop.get("type") != "Literal"):
            mutated.add(root)

    def direct_callee_name(callee):
        if not isinstance(callee, dict) or callee.get("type") != "MemberExpression" or callee.get("computed"):
            return ""
        obj = callee.get("object") or {}
        prop = callee.get("property") or {}
        if obj.get("type") == "Identifier" and prop.get("type") == "Identifier":
            return "%s.%s" % (obj.get("name") or "", prop.get("name") or "")
        return ""

    def object_may_write_get(node):
        if not isinstance(node, dict) or node.get("type") != "ObjectExpression":
            return True
        for prop in node.get("properties") or []:
            if not isinstance(prop, dict) or prop.get("type") != "Property":
                return True
            key = prop.get("key") or {}
            if prop.get("computed") and not (
                key.get("type") == "Literal" and isinstance(key.get("value"), str)
            ):
                return True
            name = str(key.get("name") or "") if not prop.get("computed") else ""
            if key.get("type") == "Literal" and isinstance(key.get("value"), str):
                name = str(key.get("value") or "")
            if name == "get":
                return True
        return False

    def visit(value):
        if not isinstance(value, dict):
            return
        kind = value.get("type")
        if kind == "AssignmentExpression":
            mark_member(value.get("left"))
        elif kind == "UpdateExpression":
            mark_member(value.get("argument"))
        elif kind == "UnaryExpression" and value.get("operator") == "delete":
            mark_member(value.get("argument"))
        elif kind == "CallExpression":
            callee_name = direct_callee_name(value.get("callee"))
            args = value.get("arguments") or []
            if callee_name in {
                "Object.defineProperty", "Reflect.defineProperty", "Reflect.set",
                "Reflect.deleteProperty",
            } and len(args) >= 2:
                receiver = str((args[0] or {}).get("name") or "") if (args[0] or {}).get("type") == "Identifier" else ""
                prop = args[1] or {}
                if receiver and (
                    prop.get("type") != "Literal"
                    or not isinstance(prop.get("value"), str)
                    or prop.get("value") == "get"
                ):
                    mutated.add(receiver)
            elif callee_name in {"Object.defineProperties", "Object.assign"} and len(args) >= 2:
                receiver = str((args[0] or {}).get("name") or "") if (args[0] or {}).get("type") == "Identifier" else ""
                if receiver and any(
                    object_may_write_get(arg)
                    for arg in args[1:]
                ):
                    mutated.add(receiver)
        for key, child in value.items():
            if key in ("loc", "range", "tokens", "comments"):
                continue
            if isinstance(child, dict):
                visit(child)
            elif isinstance(child, list):
                for item in child:
                    visit(item)

    visit(node)
    return mutated


def ast_parser_status():
    return {
        "available": esprima is not None,
        "name": "esprima" if esprima is not None else "",
        "version": str(getattr(esprima, "version", "") or getattr(esprima, "__version__", "")) if esprima else "",
    }


def _origin(url):
    try:
        parsed = urlsplit(str(url or ""))
        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return ""
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    host = parsed.hostname.lower().rstrip(".")
    display = "[" + host + "]" if ":" in host else host
    default = 443 if parsed.scheme.lower() == "https" else 80
    return "%s://%s%s" % (
        parsed.scheme.lower(), display, (":" + str(port)) if port and port != default else "",
    )


def sanitize_url(url):
    """Drop credentials, query, and fragment from persisted provenance URLs."""
    try:
        parsed = urlsplit(str(url or ""))
        origin = _origin(url)
    except (TypeError, ValueError):
        return ""
    if not origin or parsed.username is not None or parsed.password is not None:
        return ""
    path = parsed.path or "/"
    if re.search(r"[\x00-\x20\x7f]", path):
        return ""
    return origin + path


def safe_fetch_url(url):
    """Retain query semantics for an internal GET without retaining secrets."""
    try:
        parsed = urlsplit(str(url or ""))
    except (TypeError, ValueError):
        return ""
    if not _origin(url) or parsed.username is not None or parsed.password is not None:
        return ""
    if re.search(r"[\x00-\x20\x7f]", parsed.path or "/"):
        return ""
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def same_origin(left, right):
    return bool(_origin(left) and _origin(left) == _origin(right))


def js_like_url(url, allow_extensionless=False):
    try:
        path = urlsplit(str(url or "")).path.lower()
    except (TypeError, ValueError):
        return False
    suffix = posixpath.splitext(path)[1]
    return suffix in JS_EXTENSIONS or (allow_extensionless and not suffix)


def js_like_response(url, content_type):
    lowered = str(content_type or "").lower()
    return js_like_url(url, allow_extensionless=False) or any(
        marker in lowered for marker in ("javascript", "ecmascript", "typescript")
    )


class HTMLDiscoveryParser(HTMLParser):
    """Small stdlib fallback for script/link/a plus inline import maps."""

    def __init__(self, source=""):
        super().__init__(convert_charrefs=True)
        self.scripts = []
        self.links = []
        self.anchors = []
        self._script = None
        self._script_chunks = []
        self._line_offsets = [0]
        for match in re.finditer(r"\n", str(source or "")):
            self._line_offsets.append(match.end())

    @staticmethod
    def _attrs(attrs):
        return {str(key or "").lower(): str(value or "") for key, value in attrs}

    def handle_starttag(self, tag, attrs):
        data = self._attrs(attrs)
        tag = str(tag or "").lower()
        if tag == "script":
            self._script = data
            self._script_chunks = []
            self.scripts.append({"attrs": data, "content": ""})
        elif tag == "link":
            line, column = self.getpos()
            if 1 <= line <= len(self._line_offsets):
                data["_source_offset"] = self._line_offsets[line - 1] + column
            self.links.append(data)
        elif tag == "a":
            self.anchors.append(data)

    def handle_data(self, data):
        if self._script is not None:
            self._script_chunks.append(data)

    def handle_endtag(self, tag):
        if str(tag or "").lower() == "script" and self._script is not None:
            self.scripts[-1]["content"] = "".join(self._script_chunks)
            self._script = None
            self._script_chunks = []


def parse_html_discovery(html):
    text = str(html or "")
    parser = HTMLDiscoveryParser(text)
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        # HTMLParser is intentionally best-effort; regex extraction remains active.
        pass
    return parser


def import_map_declarations(html, page_url, max_maps=8):
    out = []
    parser = parse_html_discovery(html)
    for script in parser.scripts:
        attrs = script.get("attrs") or {}
        if str(attrs.get("type") or "").strip().lower() != "importmap":
            continue
        src = str(attrs.get("src") or "").strip()
        if src:
            resolved = urljoin(page_url, src)
            fetch_url = safe_fetch_url(resolved)
            if not fetch_url:
                continue
            out.append({
                "kind": "external", "url": sanitize_url(resolved), "_fetch_url": fetch_url,
                "source_page": sanitize_url(page_url),
            })
        else:
            out.append({
                "kind": "inline", "url": sanitize_url(page_url),
                "content": str(script.get("content") or ""),
                "source_page": sanitize_url(page_url),
            })
        if max_maps > 0 and len(out) >= max_maps:
            break
    return out


def parse_import_map(content, base_url, page_url, max_bytes=131072, max_entries=128):
    encoded_size = len(str(content or "").encode("utf-8", "replace"))
    if max_bytes > 0 and encoded_size > max_bytes:
        return [], "oversize"
    try:
        document = json.loads(content)
    except (TypeError, ValueError):
        return [], "malformed"
    if not isinstance(document, dict):
        return [], "malformed"
    entries = []

    def add(specifier, value, scope=""):
        if not isinstance(value, str) or not value.strip():
            return
        resolved = urljoin(base_url, value.strip())
        clean = sanitize_url(resolved)
        if not clean:
            return
        safe_specifier = str(specifier)[:240].split("?", 1)[0].split("#", 1)[0]
        safe_scope = sanitize_url(urljoin(base_url, scope)) if scope else ""
        entries.append({
            "specifier": safe_specifier,
            "scope": safe_scope,
            "url": clean,
            "same_origin": same_origin(page_url, resolved),
            "active_eligible": same_origin(page_url, resolved) and js_like_url(resolved, allow_extensionless=True),
            "source": "import_map",
            "confidence": 0.94,
            "_fetch_url": safe_fetch_url(resolved),
        })

    imports = document.get("imports")
    if isinstance(imports, dict):
        for key in sorted(imports, key=str):
            add(key, imports[key])
            if max_entries > 0 and len(entries) >= max_entries:
                break
    scopes = document.get("scopes")
    if isinstance(scopes, dict) and not (max_entries > 0 and len(entries) >= max_entries):
        for scope in sorted(scopes, key=str):
            mapping = scopes[scope]
            if not isinstance(mapping, dict):
                continue
            for key in sorted(mapping, key=str):
                add(key, mapping[key], scope=scope)
                if max_entries > 0 and len(entries) >= max_entries:
                    break
            if max_entries > 0 and len(entries) >= max_entries:
                break
    dedup = {(item["specifier"], item["scope"], item["url"]): item for item in entries}
    return [dedup[key] for key in sorted(dedup)], "parsed"


def explicit_manifest_references(content, base_url, html=False, max_refs=16):
    text = str(content or "")
    candidates = []
    refs = []
    seen = set()

    def add_candidate(offset, raw_reference, kind):
        resolved = urljoin(base_url, raw_reference)
        fetch_url = safe_fetch_url(resolved)
        if fetch_url:
            candidates.append((int(offset), fetch_url, str(kind)))

    if html:
        parser = parse_html_discovery(text)
        for link in parser.links:
            rels = {part.lower() for part in re.split(r"\s+", link.get("rel", "").strip()) if part}
            href = link.get("href", "").strip()
            offset = link.get("_source_offset")
            if "manifest" in rels and href and isinstance(offset, int):
                add_candidate(offset, href, "link")
    for match in re.finditer(r'''["']([^"']{1,500}\.(?:json|webmanifest)(?:\?[^"']*)?)["']''', text, re.I):
        resolved = urljoin(base_url, match.group(1))
        if MANIFEST_NAME_RE.search(urlsplit(resolved).path):
            add_candidate(match.start(), match.group(1), "quoted")

    # HTMLParser supplies honest start-tag offsets. Merge those with regex
    # match offsets before exact fetch-URL dedup so the first lexical query
    # variant wins; the full URL is only an in-memory deterministic tie key.
    for _offset, fetch_url, _kind in sorted(candidates, key=lambda item: (item[0], item[1], item[2])):
        if fetch_url in seen:
            continue
        seen.add(fetch_url)
        refs.append(fetch_url)
    return refs[:max_refs] if max_refs > 0 else refs


def parse_asset_manifest(content, manifest_url, page_url, max_bytes=262144, max_nodes=2048, max_entries=256):
    encoded_size = len(str(content or "").encode("utf-8", "replace"))
    if max_bytes > 0 and encoded_size > max_bytes:
        return [], [], "oversize"
    try:
        document = json.loads(content)
    except (TypeError, ValueError):
        return [], [], "malformed"
    if not isinstance(document, (dict, list)):
        return [], [], "malformed"
    asset_keys = {"file", "entry", "module", "browser", "imports", "dynamicimports", "entrypoints", "files", "js"}
    manifest_keys = {"manifest", "manifests"}
    non_build_contexts = {
        "icons", "screenshots", "shortcuts", "protocol_handlers", "file_handlers",
        "share_target", "related_applications", "prefer_related_applications",
    }
    entries = []
    nested = []
    stack = [(document, "", 0, False)]
    nodes = 0
    while stack and nodes < max_nodes:
        value, key, depth, blocked = stack.pop()
        nodes += 1
        lowered = str(key or "").lower()
        if isinstance(value, dict):
            for child_key in sorted(value, key=str, reverse=True):
                child_blocked = blocked or lowered in non_build_contexts or str(child_key).lower() in non_build_contexts
                stack.append((value[child_key], key if lowered in asset_keys else child_key, depth + 1, child_blocked))
            continue
        if isinstance(value, list):
            for child in reversed(value):
                stack.append((child, key, depth + 1, blocked or lowered in non_build_contexts))
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        resolved = urljoin(manifest_url, value.strip())
        clean = sanitize_url(resolved)
        if not clean:
            continue
        if not blocked and lowered in manifest_keys and MANIFEST_NAME_RE.search(urlsplit(resolved).path):
            nested.append(resolved)
        if not blocked and lowered in asset_keys and js_like_url(resolved, allow_extensionless=False):
            entries.append({
                "url": clean,
                "field": str(key)[:80],
                "same_origin": same_origin(page_url, resolved),
                "active_eligible": same_origin(page_url, resolved),
                "source": "asset_manifest",
                "confidence": 0.92,
                "_fetch_url": safe_fetch_url(resolved),
            })
        if max_entries > 0 and len(entries) >= max_entries:
            break
    dedup = {(item["url"], item["field"]): item for item in entries}
    return [dedup[key] for key in sorted(dedup)], sorted(set(nested)), "parsed"


def source_map_references(content, js_url, max_refs=4):
    out = []
    for match in SOURCE_MAP_RE.finditer(str(content or "")):
        value = match.group(1).strip().rstrip("*/")
        if value.startswith("data:"):
            out.append({"kind": "data", "reference": "inline-data-uri", "data": value})
        else:
            resolved = urljoin(js_url, value)
            clean = sanitize_url(resolved)
            if not clean:
                continue
            out.append({
                "kind": "external", "reference": clean, "_fetch_url": safe_fetch_url(resolved),
                "same_origin": same_origin(js_url, resolved),
            })
        if max_refs > 0 and len(out) >= max_refs:
            break
    return out


def decode_source_map_data_uri(value, max_bytes):
    if not str(value or "").startswith("data:"):
        return None, "malformed"
    header, separator, payload = value.partition(",")
    if not separator or "json" not in header.lower():
        return None, "malformed"
    try:
        raw = base64.b64decode(payload, validate=True) if ";base64" in header.lower() else unquote_to_bytes(payload)
    except (ValueError, TypeError):
        return None, "malformed"
    if max_bytes > 0 and len(raw) > max_bytes:
        return None, "oversize"
    try:
        return raw.decode("utf-8"), "decoded"
    except UnicodeDecodeError:
        return None, "malformed"


def parse_source_map(content, max_bytes=524288, max_sources=32, max_ratio=8.0):
    encoded_size = len(str(content or "").encode("utf-8", "replace"))
    if max_bytes > 0 and encoded_size > max_bytes:
        return [], "oversize"
    try:
        document = json.loads(content)
    except (TypeError, ValueError):
        return [], "malformed"
    if not isinstance(document, dict) or document.get("version") != 3:
        return [], "invalid_schema"
    sources = document.get("sources")
    contents = document.get("sourcesContent")
    if not isinstance(sources, list) or not isinstance(contents, list):
        return [], "no_sources_content"
    out = []
    total = 0
    for source, source_content in list(zip(sources, contents))[:max_sources if max_sources > 0 else None]:
        if not isinstance(source, str) or not isinstance(source_content, str):
            continue
        normalized = source.replace("\\", "/")
        if normalized.startswith(("/", "file:", "http:", "https:")) or ".." in normalized.split("/"):
            continue
        raw_size = len(source_content.encode("utf-8", "replace"))
        total += raw_size
        if max_ratio > 0 and total > max(1, encoded_size) * max_ratio:
            return [], "ratio_exceeded"
        out.append({"source": normalized[:300], "content": source_content})
    return out, "parsed"


class _ASTAnalyzer:
    def __init__(self, tree, source_url, page_url, limits):
        self.tree = tree
        self.source_url = source_url
        self.page_url = page_url
        self.max_nodes = int(limits.get("max_nodes", 20000))
        self.max_depth = int(limits.get("max_depth", 64))
        self.max_expressions = int(limits.get("max_expressions", 4000))
        self.max_assets = int(limits.get("max_assets", 64))
        self.nodes = 0
        self.expressions = 0
        self.truncated = False
        self.env = {}
        self.functions = {}
        self.script_vars = set()
        self.mutated_direct_names = _collect_mutated_direct_names(tree)
        self.mutated_get_receivers = {
            name.lower() for name in _collect_mutated_request_members(tree)
        }
        self.assets = []
        self.apis = []

    @staticmethod
    def _type(node):
        return node.get("type", "") if isinstance(node, dict) else ""

    def _eval(self, node, env, depth=0):
        self.expressions += 1
        if self.expressions > self.max_expressions or depth > self.max_depth or not isinstance(node, dict):
            self.truncated = True
            return None
        kind = self._type(node)
        if kind == "Literal":
            return node.get("value")
        if kind == "Identifier":
            return env.get(node.get("name"))
        if kind == "TemplateLiteral":
            values = [""]
            quasis = node.get("quasis") or []
            expressions = node.get("expressions") or []
            for index, quasi in enumerate(quasis):
                text = ((quasi.get("value") or {}).get("cooked") if isinstance(quasi, dict) else "") or ""
                values = [prefix + str(text) for prefix in values]
                if index < len(expressions):
                    resolved = self._strings(self._eval(expressions[index], env, depth + 1))
                    if not resolved:
                        resolved = ["1"]
                    values = [prefix + suffix for prefix in values for suffix in resolved[:8]][:32]
            return set(values)
        if kind == "BinaryExpression" and node.get("operator") == "+":
            left = self._strings(self._eval(node.get("left"), env, depth + 1))
            right = self._strings(self._eval(node.get("right"), env, depth + 1))
            if left and right:
                return set(a + b for a in left[:16] for b in right[:16])
            return None
        if kind == "ConditionalExpression":
            yes = self._strings(self._eval(node.get("consequent"), env, depth + 1))
            no = self._strings(self._eval(node.get("alternate"), env, depth + 1))
            return set((yes + no)[:32])
        if kind == "LogicalExpression":
            left = self._strings(self._eval(node.get("left"), env, depth + 1))
            right = self._strings(self._eval(node.get("right"), env, depth + 1))
            return set((left + right)[:32])
        if kind == "ObjectExpression":
            result = {}
            for prop in node.get("properties") or []:
                key = self._property_name(prop.get("key"), env)
                if key:
                    result[key] = self._eval(prop.get("value"), env, depth + 1)
            return result
        if kind == "ArrayExpression":
            return [self._eval(item, env, depth + 1) for item in node.get("elements") or []]
        if kind == "MemberExpression":
            obj = self._eval(node.get("object"), env, depth + 1)
            key = self._property_name(node.get("property"), env, computed=bool(node.get("computed")))
            if isinstance(obj, dict):
                return obj.get(key)
            if isinstance(obj, list):
                try:
                    return obj[int(key)]
                except (TypeError, ValueError, IndexError):
                    return None
        return None

    @staticmethod
    def _strings(value):
        if isinstance(value, str):
            return [value]
        if isinstance(value, set):
            return sorted(item for item in value if isinstance(item, str))
        return []

    def _property_name(self, node, env, computed=False):
        if not isinstance(node, dict):
            return ""
        if not computed and node.get("type") == "Identifier":
            return str(node.get("name") or "")
        value = self._eval(node, env)
        if isinstance(value, (str, int)):
            return str(value)
        return ""

    def _callee_name(self, node, env):
        if not isinstance(node, dict):
            return ""
        if node.get("type") == "Identifier":
            return str(node.get("name") or "")
        if node.get("type") == "ThisExpression":
            return "this"
        if node.get("type") == "Import":
            return "import"
        if node.get("type") == "MemberExpression":
            left = self._callee_name(node.get("object"), env)
            right = self._property_name(node.get("property"), env, computed=bool(node.get("computed")))
            return ".".join(part for part in (left, right) if part)
        return ""

    def _record_asset(self, value, sink):
        for raw in self._strings(value):
            if self.max_assets > 0 and len(self.assets) >= self.max_assets:
                self.truncated = True
                return
            if not raw.strip() or raw.startswith(("data:", "javascript:", "#")):
                continue
            resolved = urljoin(self.source_url, raw.strip())
            clean = sanitize_url(resolved)
            if not clean or not js_like_url(resolved, allow_extensionless=True):
                continue
            self.assets.append({
                "url": clean,
                "_fetch_url": safe_fetch_url(resolved),
                "sink": sink,
                "source": "js_ast",
                "source_asset": sanitize_url(self.source_url),
                "same_origin": same_origin(self.page_url, resolved),
                "active_eligible": same_origin(self.page_url, resolved),
                "confidence": 0.88,
            })

    def _record_api(self, value, method=""):
        for raw in self._strings(value):
            raw = raw.strip()
            if not raw or raw.startswith(("data:", "javascript:", "#")):
                continue
            path = canonical_page_api_path(raw, self.page_url)
            if not path or js_like_url(path):
                continue
            self.apis.append({
                "path": path,
                "method": str(method or "").upper(),
                "source": "js_request",
                "source_asset": sanitize_url(self.source_url),
                "confidence": 0.96,
            })

    def _bind_function(self, function, args, env):
        local = dict(env)
        for index, param in enumerate(function.get("params") or []):
            if isinstance(param, dict) and param.get("type") == "Identifier":
                local[param.get("name")] = self._eval(args[index], env) if index < len(args) else None
        return local

    def _request_method_truth(self, node, env, depth=0):
        if depth > 8 or self._type(node) != "ObjectExpression":
            return "ambiguous", ""
        effective = ""
        for prop in node.get("properties") or []:
            if self._type(prop) == "SpreadElement":
                state, method = self._request_method_truth(prop.get("argument"), env, depth + 1)
                if state == "ambiguous":
                    return state, ""
                if state == "method":
                    effective = method
                continue
            if self._type(prop) != "Property" or prop.get("kind") not in (None, "init"):
                return "ambiguous", ""
            key_node = prop.get("key") or {}
            if prop.get("computed") and self._type(key_node) != "Literal":
                return "ambiguous", ""
            key = self._property_name(key_node, env, computed=bool(prop.get("computed"))).lower()
            value_node = prop.get("value") or {}
            if key not in ("method", "type"):
                continue
            if self._type(value_node) != "Literal" or not isinstance(value_node.get("value"), str):
                return "ambiguous", ""
            method = str(value_node.get("value") or "").lower()
            if method not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                return "ambiguous", ""
            effective = method
        return ("method", effective) if effective else ("absent", "")

    def _visit(self, node, env, depth=0, wrapper_depth=0, shadowed=None):
        if not isinstance(node, dict):
            return
        self.nodes += 1
        if self.nodes > self.max_nodes or depth > self.max_depth:
            self.truncated = True
            return
        kind = self._type(node)
        node_shadowed = set(shadowed or ())
        if kind in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            node_shadowed.update(
                str(param.get("name") or "").lower()
                for param in node.get("params") or []
                if isinstance(param, dict) and param.get("type") == "Identifier"
            )
        if kind == "VariableDeclarator":
            ident = node.get("id") or {}
            name = ident.get("name") if ident.get("type") == "Identifier" else ""
            init = node.get("init")
            if name:
                if self._type(init) in ("FunctionExpression", "ArrowFunctionExpression"):
                    self.functions[name] = init
                else:
                    env[name] = self._eval(init, env)
                if self._type(init) == "CallExpression" and self._callee_name(init.get("callee"), env).endswith("createElement"):
                    args = init.get("arguments") or []
                    if args and "script" in self._strings(self._eval(args[0], env)):
                        self.script_vars.add(name)
        elif kind == "FunctionDeclaration":
            ident = node.get("id") or {}
            if ident.get("name"):
                self.functions[ident["name"]] = node
        elif kind == "AssignmentExpression":
            left = node.get("left") or {}
            right = node.get("right")
            if left.get("type") == "Identifier":
                env[left.get("name")] = self._eval(right, env)
            elif left.get("type") == "MemberExpression":
                obj = left.get("object") or {}
                prop = self._property_name(left.get("property"), env, computed=bool(left.get("computed")))
                if obj.get("type") == "Identifier" and obj.get("name") in self.script_vars and prop == "src":
                    self._record_asset(self._eval(right, env), "script.src")
        elif kind == "ImportExpression":
            self._record_asset(self._eval(node.get("source"), env), "import")
        elif kind == "CallExpression":
            callee = self._callee_name(node.get("callee"), env)
            args = node.get("arguments") or []
            lowered = callee.lower()
            callee_tail = lowered.rsplit(".", 1)[-1]
            if callee in ("import", "require", "System.import") or lowered.endswith(".system.import") or callee_tail in {
                "loadscript", "loadmodule", "loadjs", "injectscript", "appendscript"
            }:
                if args:
                    self._record_asset(self._eval(args[0], env), callee or "loader")
            request_method = ""
            root = callee.split(".", 1)[0]
            is_request = callee in {
                "fetch", "request", "axios", "service", "http", "window.fetch", "globalThis.fetch",
                "uni.request", "wx.request", "$.ajax", "$.getJSON",
            } and root.lower() not in node_shadowed and root.lower() not in self.mutated_direct_names
            if not is_request and "." in callee and callee_tail in {"fetch", "request"}:
                raw_receiver = callee.rsplit(".", 1)[0]
                is_request = _trusted_request_receiver(raw_receiver, node_shadowed, self.mutated_direct_names)
            method_callee = node.get("callee") or {}
            method_name = ""
            raw_receiver = ""
            if self._type(method_callee) == "MemberExpression" and not method_callee.get("computed"):
                method_name = self._property_name(method_callee.get("property"), env)
                raw_receiver = self._callee_name(method_callee.get("object"), env)
            if method_name in {"get", "post", "put", "patch", "delete", "head"}:
                mutated_receivers = set(self.mutated_direct_names) | self.mutated_get_receivers
                if _trusted_request_receiver(raw_receiver, node_shadowed, mutated_receivers):
                    request_method = method_name.upper()
                    is_request = True
            if is_request and args:
                first = self._eval(args[0], env)
                truth_state = "absent"
                truth_method = ""
                if request_method:
                    # Receiver.method(path, body/config) proves the method; its
                    # second argument is payload/config, not fetch options.
                    truth_state, truth_method = "method", request_method.lower()
                elif isinstance(first, dict):
                    truth_state, truth_method = self._request_method_truth(args[0], env)
                elif len(args) > 1:
                    truth_state, truth_method = self._request_method_truth(args[1], env)
                if truth_state == "ambiguous":
                    first = None
                if isinstance(first, dict):
                    self._record_api(first.get("url"), str(truth_method or request_method))
                elif first is not None:
                    fetch_default = lowered in {"fetch", "window.fetch", "globalthis.fetch", "axios"}
                    self._record_api(first, request_method or truth_method or ("GET" if truth_state == "absent" and fetch_default else ""))
            if callee in self.functions and wrapper_depth < 1:
                function = self.functions[callee]
                local = self._bind_function(function, args, env)
                body = function.get("body")
                function_shadowed = node_shadowed | {
                    str(param.get("name") or "").lower()
                    for param in function.get("params") or []
                    if isinstance(param, dict) and param.get("type") == "Identifier"
                }
                self._visit(body, local, depth + 1, wrapper_depth + 1, function_shadowed)
        for key, value in node.items():
            if key in ("loc", "range", "tokens", "comments"):
                continue
            if isinstance(value, dict):
                self._visit(value, env, depth + 1, wrapper_depth, node_shadowed)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, dict):
                        self._visit(child, env, depth + 1, wrapper_depth, node_shadowed)

    def run(self):
        self._visit(self.tree, self.env)
        assets = {(item["url"], item["sink"], item["source_asset"]): item for item in self.assets}
        apis = {(item["path"], item["method"], item["source_asset"]): item for item in self.apis}
        return {
            "assets": [assets[key] for key in sorted(assets)],
            "apis": [apis[key] for key in sorted(apis)],
            "nodes": self.nodes,
            "expressions": self.expressions,
            "truncated": self.truncated,
        }


class _ScopedWrapperParamAnalyzer:
    """Recover object keys forwarded through one direct request wrapper.

    This pass intentionally models only lexical bindings, direct literal GET
    wrappers, object literals, and structurally bounded object-merge helpers.
    It does not evaluate JavaScript or infer values.
    """

    _GLOBAL_REQUEST_RECEIVERS = {"axios", "request", "service", "http"}
    _IMPORTED_REQUEST_NAMES = _GLOBAL_REQUEST_RECEIVERS

    class Scope:
        def __init__(self, parent=None):
            self.parent = parent
            self.bindings = {}

        def resolve(self, name):
            scope = self
            while scope is not None:
                if name in scope.bindings:
                    return scope.bindings[name]
                scope = scope.parent
            return None

    def __init__(self, tree, source_url, page_url, limits):
        self.tree = tree
        self.source_url = str(source_url or "")
        self.page_url = str(page_url or "")
        self.max_nodes = max(1, int(limits.get("max_nodes", 20000)))
        self.max_depth = max(1, int(limits.get("max_depth", 64)))
        self.max_expressions = max(1, int(limits.get("max_expressions", 4000)))
        self.max_bindings = max(1, min(256, int(limits.get("max_param_bindings", 128))))
        self.max_params = max(1, min(128, int(limits.get("max_params_per_binding", 64))))
        self.nodes = 0
        self.expressions = 0
        self.truncated = False
        self.bindings = []
        self.apis = []
        self.blocked_param_paths = set()
        self.mutated_names = self._collect_mutated_names(tree)
        self.mutated_get_receivers = _collect_mutated_request_members(tree)
        self.wrapper_cache = {}
        self.merge_cache = {}

    @staticmethod
    def _type(node):
        return node.get("type", "") if isinstance(node, dict) else ""

    @staticmethod
    def _identifier(node):
        return str(node.get("name") or "") if isinstance(node, dict) and node.get("type") == "Identifier" else ""

    @classmethod
    def _collect_mutated_names(cls, tree):
        names = set()

        def visit(node):
            if not isinstance(node, dict):
                return
            kind = cls._type(node)
            if kind == "AssignmentExpression":
                names.update(_binding_identifier_names(node.get("left")))
            elif kind == "UpdateExpression":
                names.update(_binding_identifier_names(node.get("argument")))
            for key, value in node.items():
                if key in ("loc", "range", "tokens", "comments"):
                    continue
                if isinstance(value, dict):
                    visit(value)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)

        visit(tree)
        return names

    def _tick(self, depth):
        self.nodes += 1
        if self.nodes > self.max_nodes or depth > self.max_depth:
            self.truncated = True
            return False
        return True

    def _predeclare(self, statements, scope):
        for statement in statements or []:
            kind = self._type(statement)
            if kind == "ImportDeclaration":
                for specifier in statement.get("specifiers") or []:
                    name = self._identifier(specifier.get("local"))
                    if name:
                        scope.bindings[name] = {"kind": "unknown"}
            elif kind == "VariableDeclaration":
                for declaration in statement.get("declarations") or []:
                    for name in _binding_identifier_names(declaration.get("id")):
                        scope.bindings[name] = {"kind": "unknown"}
            elif kind == "FunctionDeclaration":
                name = self._identifier(statement.get("id"))
                if name:
                    scope.bindings[name] = {"kind": "function", "node": statement, "scope": scope}
            elif kind == "ClassDeclaration":
                name = self._identifier(statement.get("id"))
                if name:
                    scope.bindings[name] = {"kind": "unknown"}

    def _new_function_scope(self, function, parent):
        scope = self.Scope(parent)
        for param in function.get("params") or []:
            for name in _binding_identifier_names(param):
                scope.bindings[name] = {"kind": "unknown"}
        body = function.get("body") or {}
        if self._type(body) == "BlockStatement":
            self._predeclare(body.get("body") or [], scope)
        return scope

    def _import_binding(self, specifier):
        local = self._identifier(specifier.get("local"))
        imported = self._identifier(specifier.get("imported"))
        trusted = imported in self._IMPORTED_REQUEST_NAMES
        if self._type(specifier) in ("ImportDefaultSpecifier", "ImportNamespaceSpecifier"):
            trusted = local in self._GLOBAL_REQUEST_RECEIVERS
        if trusted and local not in self.mutated_names:
            return {"kind": "trusted_receiver"}
        return {"kind": "unknown"}

    def _receiver_trusted(self, node, scope):
        name = self._identifier(node)
        if not name or name in self.mutated_names or name in self.mutated_get_receivers:
            return False
        binding = scope.resolve(name)
        if binding is not None:
            return binding.get("kind") == "trusted_receiver"
        return name in self._GLOBAL_REQUEST_RECEIVERS

    def _factory_receiver(self, node, scope):
        if self._type(node) != "CallExpression":
            return False
        callee = node.get("callee") or {}
        if self._type(callee) != "MemberExpression" or callee.get("computed"):
            return False
        return (
            self._identifier(callee.get("property")) == "create"
            and self._receiver_trusted(callee.get("object"), scope)
        )

    def _object_builtin_kind(self, node):
        if self._type(node) != "MemberExpression" or node.get("computed"):
            return ""
        if self._identifier(node.get("object")) != "Object":
            return ""
        method = self._identifier(node.get("property"))
        if method in ("assign", "defineProperties"):
            return "object_merge"
        if method == "defineProperty":
            return "object_property_setter"
        if method == "getOwnPropertyDescriptors":
            return "object_shape_identity"
        return ""

    def _property_name(self, prop):
        if not isinstance(prop, dict) or prop.get("computed"):
            return ""
        key = prop.get("key") or {}
        if self._type(key) == "Identifier":
            return self._identifier(key)
        if self._type(key) == "Literal" and isinstance(key.get("value"), str):
            return str(key.get("value") or "")
        return ""

    def _wrapper_spec(self, binding):
        function = binding.get("node") or {}
        cache_key = id(function)
        if cache_key in self.wrapper_cache:
            return self.wrapper_cache[cache_key]
        self.wrapper_cache[cache_key] = None
        params = function.get("params") or []
        if len(params) != 1 or self._type(params[0]) != "Identifier":
            return None
        formal = self._identifier(params[0])
        function_scope = self._new_function_scope(function, binding.get("scope"))
        potential_paths = self._potential_forwarded_paths(function.get("body") or {}, formal, function_scope)
        if self._formal_mutated(function.get("body") or {}, formal) or self._binding_declared_anywhere(
            function.get("body") or {}, formal
        ):
            self.blocked_param_paths.update(potential_paths)
            return None
        candidates = []

        def inspect(node, nested=False, root=False):
            if not isinstance(node, dict):
                return
            kind = self._type(node)
            if nested and kind in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
                return
            if not root and kind == "BlockStatement" and self._scope_declares(node.get("body") or [], formal):
                return
            if kind == "CatchClause" and formal in _binding_identifier_names(node.get("param")):
                return
            if kind in ("ForStatement", "ForInStatement", "ForOfStatement"):
                binding_node = node.get("init") if kind == "ForStatement" else node.get("left")
                if self._declaration_binds(binding_node, formal):
                    return
            if kind == "CallExpression":
                candidate = self._direct_forwarding_request(node, formal, function_scope)
                if candidate:
                    candidates.append(candidate)
            for key, value in node.items():
                if key in ("loc", "range", "tokens", "comments"):
                    continue
                if isinstance(value, dict):
                    inspect(value, True, False)
                elif isinstance(value, list):
                    for child in value:
                        inspect(child, True, False)

        inspect(function.get("body") or {}, root=True)
        if len(candidates) == 1 and not self._binding_declared_anywhere(
            function.get("body") or {}, candidates[0].get("receiver") or ""
        ):
            candidates[0].pop("receiver", None)
            self.wrapper_cache[cache_key] = candidates[0]
        elif potential_paths:
            self.blocked_param_paths.update(potential_paths)
        return self.wrapper_cache[cache_key]

    def _potential_forwarded_paths(self, node, formal, scope):
        paths = set()

        def visit(value):
            if not isinstance(value, dict):
                return
            if self._type(value) == "CallExpression":
                candidate = self._direct_forwarding_request(value, formal, scope)
                if candidate:
                    paths.add(candidate["path"])
            for key, child in value.items():
                if key in ("loc", "range", "tokens", "comments"):
                    continue
                if isinstance(child, dict):
                    visit(child)
                elif isinstance(child, list):
                    for item in child:
                        visit(item)

        visit(node)
        return paths

    def _declaration_binds(self, node, name):
        if not isinstance(node, dict):
            return False
        if self._type(node) == "VariableDeclaration":
            return any(name in _binding_identifier_names(item.get("id")) for item in node.get("declarations") or [])
        return name in _binding_identifier_names(node)

    def _scope_declares(self, statements, name):
        for statement in statements or []:
            kind = self._type(statement)
            if kind == "VariableDeclaration" and self._declaration_binds(statement, name):
                return True
            if kind in ("FunctionDeclaration", "ClassDeclaration") and self._identifier(statement.get("id")) == name:
                return True
        return False

    def _binding_declared_anywhere(self, node, name):
        """Reject name-only reasoning when an inner/hoisted binding exists."""
        if not name or not isinstance(node, dict):
            return False
        kind = self._type(node)
        if kind == "VariableDeclarator" and name in _binding_identifier_names(node.get("id")):
            return True
        if kind in ("FunctionDeclaration", "ClassDeclaration") and self._identifier(node.get("id")) == name:
            return True
        if kind in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            if any(name in _binding_identifier_names(param) for param in node.get("params") or []):
                return True
        if kind == "CatchClause" and name in _binding_identifier_names(node.get("param")):
            return True
        if kind in ("ForInStatement", "ForOfStatement"):
            left = node.get("left") or {}
            if self._type(left) == "VariableDeclaration":
                if any(name in _binding_identifier_names(item.get("id")) for item in left.get("declarations") or []):
                    return True
            elif name in _binding_identifier_names(left):
                return True
        for key, value in node.items():
            if key in ("loc", "range", "tokens", "comments"):
                continue
            if isinstance(value, dict) and self._binding_declared_anywhere(value, name):
                return True
            if isinstance(value, list) and any(
                self._binding_declared_anywhere(child, name) for child in value if isinstance(child, dict)
            ):
                return True
        return False

    def _formal_mutated(self, node, formal, nested=False):
        if not isinstance(node, dict):
            return False
        kind = self._type(node)
        if nested and kind in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            return False
        if kind == "AssignmentExpression" and formal in _binding_identifier_names(node.get("left")):
            return True
        if kind == "UpdateExpression" and formal in _binding_identifier_names(node.get("argument")):
            return True
        if kind in ("AssignmentExpression", "UpdateExpression", "UnaryExpression"):
            target = node.get("left") if kind == "AssignmentExpression" else node.get("argument")
            if (
                self._type(target) == "MemberExpression"
                and self._identifier(target.get("object")) == formal
                and (kind != "UnaryExpression" or node.get("operator") == "delete")
            ):
                return True
        if kind == "CallExpression":
            callee = node.get("callee") or {}
            if self._type(callee) == "MemberExpression" and not callee.get("computed"):
                owner = self._identifier(callee.get("object"))
                method = self._identifier(callee.get("property"))
                args = node.get("arguments") or []
                if owner in ("Object", "Reflect") and method in (
                    "assign", "defineProperty", "defineProperties"
                ) and args and self._identifier(args[0]) == formal:
                    return True
        for key, value in node.items():
            if key in ("loc", "range", "tokens", "comments"):
                continue
            if isinstance(value, dict) and self._formal_mutated(value, formal, True):
                return True
            if isinstance(value, list) and any(
                self._formal_mutated(child, formal, True) for child in value if isinstance(child, dict)
            ):
                return True
        return False

    def _direct_forwarding_request(self, call, formal, scope):
        callee = call.get("callee") or {}
        if self._type(callee) != "MemberExpression" or callee.get("computed"):
            return None
        if self._identifier(callee.get("property")) != "get":
            return None
        if not self._receiver_trusted(callee.get("object"), scope):
            return None
        args = call.get("arguments") or []
        if len(args) < 2 or self._type(args[0]) != "Literal" or not isinstance(args[0].get("value"), str):
            return None
        path = canonical_page_api_path(args[0].get("value"), self.page_url)
        if not path:
            return None
        options = args[1]
        if self._type(options) != "ObjectExpression":
            return None
        forwarded = False
        for prop in options.get("properties") or []:
            if self._type(prop) != "Property" or prop.get("computed"):
                return None
            if self._property_name(prop) != "params":
                continue
            if self._identifier(prop.get("value")) != formal:
                return None
            forwarded = True
        receiver = self._identifier(callee.get("object"))
        return {
            "path": path, "method": "GET", "source": "query", "receiver": receiver,
        } if forwarded else None

    def _merge_helper(self, binding, seen=None):
        if not binding or binding.get("kind") != "function":
            return False
        function = binding.get("node") or {}
        cache_key = id(function)
        if cache_key in self.merge_cache:
            return self.merge_cache[cache_key]
        seen = set(seen or ())
        if cache_key in seen:
            return False
        seen.add(cache_key)
        params = [self._identifier(param) for param in function.get("params") or []]
        if len(params) < 2 or not all(params):
            self.merge_cache[cache_key] = False
            return False
        body = function.get("body") or {}
        if self._type(body) == "BlockStatement":
            result = self._strong_copy_helper(body, params[0], params[1], binding.get("scope"))
        else:
            result = self._merge_expression(body, set(params), binding.get("scope"), seen)
        self.merge_cache[cache_key] = bool(result)
        return bool(result)

    def _strong_copy_helper(self, body, target, source, scope):
        statements = body.get("body") or []
        # Accept only one unconditional canonical copy loop followed by one
        # exact target return. Any branch, early/alternate return or extra side
        # effect makes the helper semantically opaque.
        if len(statements) != 2:
            return False
        loop, returned = statements
        if self._type(returned) != "ReturnStatement" or self._identifier(returned.get("argument")) != target:
            return False
        if self._type(loop) != "ForInStatement" or self._identifier(loop.get("right")) != source:
            return False
        left = loop.get("left") or {}
        key_name = ""
        if self._type(left) == "VariableDeclaration":
            declarations = left.get("declarations") or []
            if len(declarations) != 1 or declarations[0].get("init") is not None:
                return False
            key_name = self._identifier(declarations[0].get("id"))
        if not key_name:
            return False
        statement = loop.get("body") or {}
        if self._type(statement) == "BlockStatement":
            body_items = statement.get("body") or []
            if len(body_items) != 1:
                return False
            statement = body_items[0]
        if self._type(statement) != "ExpressionStatement":
            return False
        expression = statement.get("expression") or {}
        if self._type(expression) != "AssignmentExpression" or expression.get("operator") != "=":
            return False
        left_member = expression.get("left") or {}
        right_member = expression.get("right") or {}
        return bool(
            self._type(left_member) == "MemberExpression" and left_member.get("computed")
            and self._identifier(left_member.get("object")) == target
            and self._identifier(left_member.get("property")) == key_name
            and self._type(right_member) == "MemberExpression" and right_member.get("computed")
            and self._identifier(right_member.get("object")) == source
            and self._identifier(right_member.get("property")) == key_name
        )

    def _expression_references_identifier(self, node, name):
        if not isinstance(node, dict):
            return False
        if self._type(node) == "Identifier" and self._identifier(node) == name:
            return True
        return any(
            self._expression_references_identifier(value, name)
            for key, value in node.items()
            if key not in ("loc", "range", "tokens", "comments") and isinstance(value, dict)
        ) or any(
            self._expression_references_identifier(child, name)
            for key, value in node.items()
            if key not in ("loc", "range", "tokens", "comments") and isinstance(value, list)
            for child in value if isinstance(child, dict)
        )

    def _contains_member_copy(self, node, target, source, key_name, scope):
        if not isinstance(node, dict):
            return False
        if self._type(node) in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            return False
        if self._type(node) == "AssignmentExpression" and node.get("operator") == "=":
            left = node.get("left") or {}
            right = node.get("right") or {}
            if (
                self._type(left) == "MemberExpression" and left.get("computed")
                and self._identifier(left.get("object")) == target
                and self._identifier(left.get("property")) == key_name
                and self._type(right) == "MemberExpression" and right.get("computed")
                and self._identifier(right.get("object")) == source
                and self._identifier(right.get("property")) == key_name
            ):
                return True
        if self._type(node) == "CallExpression" and self._type(node.get("callee")) == "Identifier":
            args = node.get("arguments") or []
            if len(args) == 3:
                callee_name = self._identifier(node.get("callee"))
                binding = scope.resolve(callee_name) if scope else None
                right = args[2] or {}
                if (
                    self._property_setter_helper(binding)
                    and self._identifier(args[0]) == target
                    and self._identifier(args[1]) == key_name
                    and self._type(right) == "MemberExpression" and right.get("computed")
                    and self._identifier(right.get("object")) == source
                    and self._identifier(right.get("property")) == key_name
                ):
                    return True
        for key, value in node.items():
            if key in ("loc", "range", "tokens", "comments"):
                continue
            if isinstance(value, dict) and self._contains_member_copy(value, target, source, key_name, scope):
                return True
            if isinstance(value, list) and any(
                self._contains_member_copy(child, target, source, key_name, scope)
                for child in value if isinstance(child, dict)
            ):
                return True
        return False

    def _property_setter_helper(self, binding):
        if not binding or binding.get("kind") != "function":
            return False
        function = binding.get("node") or {}
        params = [self._identifier(param) for param in function.get("params") or []]
        if len(params) != 3 or not all(params):
            return False
        return self._setter_expression(function.get("body"), params[0], params[1], params[2], binding.get("scope"))

    def _setter_expression(self, node, target, key_name, value_name, scope):
        kind = self._type(node)
        if kind == "ConditionalExpression":
            return (
                self._setter_expression(node.get("consequent"), target, key_name, value_name, scope)
                and self._setter_expression(node.get("alternate"), target, key_name, value_name, scope)
            )
        if kind == "AssignmentExpression" and node.get("operator") == "=":
            left = node.get("left") or {}
            return (
                self._type(left) == "MemberExpression" and left.get("computed")
                and self._identifier(left.get("object")) == target
                and self._identifier(left.get("property")) == key_name
                and self._identifier(node.get("right")) == value_name
            )
        if kind != "CallExpression" or self._type(node.get("callee")) != "Identifier":
            return False
        callee_binding = scope.resolve(self._identifier(node.get("callee"))) if scope else None
        if (callee_binding or {}).get("kind") != "object_property_setter":
            return False
        args = node.get("arguments") or []
        if len(args) < 3 or self._identifier(args[0]) != target or self._identifier(args[1]) != key_name:
            return False
        descriptor = args[2] or {}
        if self._type(descriptor) != "ObjectExpression":
            return False
        return any(
            self._property_name(prop) == "value" and self._identifier(prop.get("value")) == value_name
            for prop in descriptor.get("properties") or [] if self._type(prop) == "Property"
        )

    def _identity_helper(self, binding):
        if not binding or binding.get("kind") != "function":
            return False
        function = binding.get("node") or {}
        params = function.get("params") or []
        if len(params) != 1 or self._type(params[0]) != "Identifier":
            return False
        formal = self._identifier(params[0])
        body = function.get("body") or {}
        if self._type(body) == "Identifier":
            return self._identifier(body) == formal
        if self._type(body) != "BlockStatement":
            return False
        statements = body.get("body") or []
        return (
            len(statements) == 1
            and self._type(statements[0]) == "ReturnStatement"
            and self._identifier(statements[0].get("argument")) == formal
        )

    def _merge_expression(self, node, params, scope, seen):
        kind = self._type(node)
        if kind == "Identifier":
            return self._identifier(node) in params
        if kind == "ObjectExpression":
            return not (node.get("properties") or [])
        if kind != "CallExpression":
            return False
        callee = node.get("callee") or {}
        binding = scope.resolve(self._identifier(callee)) if self._type(callee) == "Identifier" else None
        callee_kind = (binding or {}).get("kind") or self._object_builtin_kind(callee)
        if callee_kind == "object_shape_identity":
            args = node.get("arguments") or []
            return len(args) == 1 and self._merge_expression(args[0], params, scope, seen)
        if callee_kind == "object_merge":
            return all(self._merge_expression(arg, params, scope, seen) for arg in node.get("arguments") or [])
        if not self._merge_helper(binding, seen):
            return False
        return all(self._merge_expression(arg, params, scope, seen) for arg in node.get("arguments") or [])

    def _shape_keys(self, node, scope, depth=0):
        self.expressions += 1
        if self.expressions > self.max_expressions or depth > min(12, self.max_depth) or not isinstance(node, dict):
            self.truncated = True
            return None
        kind = self._type(node)
        if kind == "Identifier":
            binding = scope.resolve(self._identifier(node))
            if binding and binding.get("kind") == "shape":
                return set(binding.get("keys") or ())
            return None
        if kind == "ObjectExpression":
            keys = set()
            for prop in node.get("properties") or []:
                if self._type(prop) == "SpreadElement":
                    spread = self._shape_keys(prop.get("argument"), scope, depth + 1)
                    if spread is None:
                        return None
                    keys.update(spread)
                    continue
                if self._type(prop) != "Property":
                    return None
                name = self._property_name(prop)
                if not name or len(name) > 160 or any(ord(ch) < 32 for ch in name):
                    return None
                keys.add(name)
                if len(keys) > self.max_params:
                    self.truncated = True
                    return None
            return keys
        if kind != "CallExpression" or self._type(node.get("callee")) != "Identifier":
            return None
        args = node.get("arguments") or []
        binding = scope.resolve(self._identifier(node.get("callee")))
        if len(args) == 1:
            allowed = (
                (binding or {}).get("kind") == "object_shape_identity"
                or self._identity_helper(binding)
            )
            return self._shape_keys(args[0], scope, depth + 1) if allowed else None
        if not self._merge_helper(binding):
            return None
        keys = set()
        for arg in args:
            resolved = self._shape_keys(arg, scope, depth + 1)
            if resolved is None:
                return None
            keys.update(resolved)
            if len(keys) > self.max_params:
                self.truncated = True
                return None
        return keys

    def _record_wrapper_call(self, call, scope):
        if len(self.bindings) >= self.max_bindings or self._type(call.get("callee")) != "Identifier":
            return
        binding = scope.resolve(self._identifier(call.get("callee")))
        if not binding or binding.get("kind") != "function":
            return
        wrapper = self._wrapper_spec(binding)
        args = call.get("arguments") or []
        if not wrapper or len(args) != 1:
            return
        keys = self._shape_keys(args[0], scope)
        if not keys:
            self.blocked_param_paths.add(wrapper["path"])
            return
        record = dict(wrapper)
        record["names"] = sorted(keys)
        self.bindings.append(record)
        self.apis.append({
            "path": record["path"], "method": record["method"],
            "source": "js_request", "confidence": 0.96,
        })

    def _visit_expression(self, node, scope, depth, allow_wrapper_call=True):
        if not isinstance(node, dict) or not self._tick(depth):
            return
        kind = self._type(node)
        if kind in ("FunctionExpression", "ArrowFunctionExpression"):
            child = self._new_function_scope(node, scope)
            body = node.get("body") or {}
            if self._type(body) == "BlockStatement":
                self._visit_body(body.get("body") or [], child, depth + 1)
            else:
                self._visit_expression(body, child, depth + 1, True)
            return
        if kind == "CallExpression" and allow_wrapper_call:
            self._record_wrapper_call(node, scope)
        child_allows_wrapper = bool(
            allow_wrapper_call and kind not in ("ArrayExpression", "ObjectExpression", "CallExpression")
        )
        for key, value in node.items():
            if key in ("loc", "range", "tokens", "comments"):
                continue
            if isinstance(value, dict):
                self._visit_expression(value, scope, depth + 1, child_allows_wrapper)
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, dict):
                        self._visit_expression(child, scope, depth + 1, child_allows_wrapper)

    def _visit_body(self, statements, scope, depth):
        self._predeclare(statements, scope)
        for statement in statements or []:
            if not self._tick(depth):
                return
            kind = self._type(statement)
            if kind == "ImportDeclaration":
                for specifier in statement.get("specifiers") or []:
                    name = self._identifier(specifier.get("local"))
                    if name:
                        scope.bindings[name] = self._import_binding(specifier)
            elif kind == "VariableDeclaration":
                for declaration in statement.get("declarations") or []:
                    init = declaration.get("init")
                    if init is not None:
                        self._visit_expression(init, scope, depth + 1)
                    names = list(_binding_identifier_names(declaration.get("id")))
                    if len(names) != 1 or self._type(declaration.get("id")) != "Identifier":
                        continue
                    name = names[0]
                    binding = {"kind": "unknown"}
                    if name not in self.mutated_names and self._type(init) in ("FunctionExpression", "ArrowFunctionExpression"):
                        binding = {"kind": "function", "node": init, "scope": scope}
                    elif name not in self.mutated_names and self._factory_receiver(init, scope):
                        binding = {"kind": "trusted_receiver"}
                    elif name not in self.mutated_names and self._object_builtin_kind(init):
                        binding = {"kind": self._object_builtin_kind(init)}
                    elif name not in self.mutated_names:
                        keys = self._shape_keys(init, scope) if init is not None else None
                        if keys is not None:
                            binding = {"kind": "shape", "keys": sorted(keys)}
                    scope.bindings[name] = binding
            elif kind == "FunctionDeclaration":
                child = self._new_function_scope(statement, scope)
                body = statement.get("body") or {}
                self._visit_body(body.get("body") or [], child, depth + 1)
            elif kind == "BlockStatement":
                child = self.Scope(scope)
                self._visit_body(statement.get("body") or [], child, depth + 1)
            elif kind == "CatchClause":
                child = self.Scope(scope)
                for name in _binding_identifier_names(statement.get("param")):
                    child.bindings[name] = {"kind": "unknown"}
                body = statement.get("body") or {}
                self._visit_body(body.get("body") or [], child, depth + 1)
            else:
                for key, value in statement.items():
                    if key in ("loc", "range", "tokens", "comments"):
                        continue
                    if isinstance(value, dict):
                        if self._type(value) == "BlockStatement":
                            child = self.Scope(scope)
                            self._visit_body(value.get("body") or [], child, depth + 1)
                        elif self._type(value) == "CatchClause":
                            self._visit_body([value], scope, depth + 1)
                        elif self._type(value) == "VariableDeclaration":
                            self._visit_body([value], scope, depth + 1)
                        else:
                            self._visit_expression(value, scope, depth + 1)
                    elif isinstance(value, list):
                        for child_node in value:
                            if not isinstance(child_node, dict):
                                continue
                            if self._type(child_node) in ("VariableDeclaration", "CatchClause"):
                                self._visit_body([child_node], scope, depth + 1)
                            else:
                                self._visit_expression(child_node, scope, depth + 1)

    def run(self):
        root = self.Scope()
        self._visit_body(self.tree.get("body") or [], root, 0)
        binding_map = {}
        for item in self.bindings:
            key = (item["path"], item["method"], item["source"])
            binding_map.setdefault(key, set()).update(item.get("names") or [])
        api_map = {(item["path"], item["method"]): item for item in self.apis}
        return {
            "param_bindings": [
                {"path": key[0], "method": key[1], "source": key[2], "names": sorted(names)}
                for key, names in sorted(binding_map.items())
            ],
            "apis": [api_map[key] for key in sorted(api_map)],
            "blocked_param_paths": sorted(self.blocked_param_paths),
            "binding_nodes": self.nodes,
            "binding_expressions": self.expressions,
            "binding_truncated": self.truncated,
        }


def analyze_javascript_ast(content, source_url, page_url, mode="auto", limits=None):
    mode = str(mode or "auto").lower()
    limits = dict(limits or {})
    max_bytes = int(limits.get("max_bytes", 750000))
    size = len(str(content or "").encode("utf-8", "replace"))
    status = ast_parser_status()
    base = {
        "status": "off" if mode == "off" else "unavailable",
        "parser": status.get("name", ""),
        "parser_version": status.get("version", ""),
        "assets": [], "apis": [], "param_bindings": [], "blocked_param_paths": [],
        "nodes": 0, "expressions": 0, "truncated": False,
    }
    if mode == "off":
        return base
    if esprima is None:
        if mode == "required":
            raise RuntimeError("JavaScript AST mode 'required' needs esprima; install requirements-ast.txt")
        return base
    if max_bytes > 0 and size > max_bytes:
        base["status"] = "oversize"
        base["truncated"] = True
        return base
    try:
        tree = esprima.parseModule(str(content or ""), {"tolerant": True, "jsx": True}).toDict()
    except Exception:
        base["status"] = "parse_error"
        return base
    analyzed = _ASTAnalyzer(tree, source_url, page_url, limits).run()
    scoped = _ScopedWrapperParamAnalyzer(tree, source_url, page_url, limits).run()
    analyzed["apis"].extend(scoped.get("apis") or [])
    analyzed["param_bindings"] = scoped.get("param_bindings") or []
    analyzed["blocked_param_paths"] = scoped.get("blocked_param_paths") or []
    analyzed["binding_nodes"] = scoped.get("binding_nodes") or 0
    analyzed["binding_expressions"] = scoped.get("binding_expressions") or 0
    analyzed["truncated"] = bool(analyzed.get("truncated") or scoped.get("binding_truncated"))
    base.update(analyzed)
    base["status"] = "parsed"
    return base

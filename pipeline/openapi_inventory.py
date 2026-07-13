"""Offline, bounded OpenAPI/Swagger inventory extraction.

The parser deliberately has no network access. Absolute servers and external
references are inventory metadata only; callers must not turn them into active
targets without a separate, explicit scope decision.
"""

from __future__ import annotations

import copy
import json
import re
from urllib.parse import quote, urlparse, urlunparse


HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
JSON_CONTENT_RE = re.compile(r"^(?:application|text)/(?:[^;]+\+)?json(?:;|$)", re.I)
SENSITIVE_PARAM_RE = re.compile(
    r"(?:^|[_-])(?:auth(?:orization)?|cookie|token|jwt|session|password|passwd|pwd|"
    r"secret|api[_-]?key|access[_-]?key|signature|sign)(?:$|[_-])",
    re.I,
)
ACTION_WORD_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:delete|remove|update|save|create|add|insert|edit|modify|"
    r"submit|upload|import|logout|reset|grant|bind|unbind|disable|enable|approve|"
    r"pay|cancel|start|stop|clear|sync)(?:$|[^a-z0-9])",
    re.I,
)
PATH_TEMPLATE_RE = re.compile(r"\{([^{}\/]{1,100})\}")


def _is_json_content_type(value):
    return bool(JSON_CONTENT_RE.match(str(value or "").strip()))


def _is_form_content_type(value):
    return str(value or "").split(";", 1)[0].strip().lower() in {
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    }


def _safe_scalar(value, max_length=160):
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    if not text or len(text) > max_length or any(ord(ch) < 32 for ch in text):
        return None
    return text


def _is_sensitive_param_name(value):
    text = str(value or "")
    compact = re.sub(r"[^a-z0-9]", "", text.lower())
    if SENSITIVE_PARAM_RE.search(text):
        return True
    return any(marker in compact for marker in (
        "authorization", "cookie", "token", "jwt", "session", "password",
        "passwd", "secret", "apikey", "accesskey", "signature",
    )) or compact in {"pwd", "sign"}


def _first_example(value):
    if not isinstance(value, dict):
        return None
    for key in sorted(value):
        item = value.get(key)
        if isinstance(item, dict) and "value" in item:
            return item.get("value")
    return None


def _seed_candidates(parameter, schema):
    candidates = [
        parameter.get("example"),
        _first_example(parameter.get("examples")),
        parameter.get("default"),
        schema.get("example") if isinstance(schema, dict) else None,
        schema.get("default") if isinstance(schema, dict) else None,
    ]
    for owner in (parameter, schema if isinstance(schema, dict) else {}):
        enum = owner.get("enum")
        if isinstance(enum, list) and enum:
            candidates.append(enum[0])
    return candidates


def _path_seed(parameter):
    if not parameter or parameter.get("auto_materialize") is False:
        return None
    candidates = []
    if parameter.get("seed") is not None:
        candidates.append(parameter.get("seed"))
    candidates.extend(parameter.get("seed_candidates") or [])
    candidates.append("1")
    for candidate in candidates:
        text = _safe_scalar(candidate, max_length=80)
        if text is None or text in {".", ".."}:
            continue
        if any(ch in text for ch in ("/", "\\", "?", "#")):
            continue
        encoded = quote(text, safe="-._~")
        if encoded and encoded not in {".", ".."}:
            return encoded
    return None


def _clean_local_prefix(value):
    text = str(value or "").strip()
    if not text or text in {".", "/"}:
        return ""
    parsed = urlparse(text)
    if parsed.scheme or parsed.netloc or text.startswith("//"):
        return None
    if parsed.query or parsed.fragment or "\\" in parsed.path:
        return None
    parts = []
    for part in parsed.path.split("/"):
        if not part or part == ".":
            continue
        if part == ".." or any(ord(ch) < 32 for ch in part):
            return None
        parts.append(part)
    return "/" + "/".join(parts) if parts else ""


def _join_local_path(prefix, path):
    prefix = str(prefix or "").rstrip("/")
    path = str(path or "")
    if not path.startswith("/") or "\\" in path:
        return ""
    raw_parts = [part for part in path.split("/") if part]
    if any(part in {".", ".."} or any(ord(ch) < 32 for ch in part) for part in raw_parts):
        return ""
    return "/" + "/".join([part for part in prefix.strip("/").split("/") if part] + raw_parts)


def _sanitize_external_url(value):
    text = str(value or "").strip()
    parsed = urlparse(text)
    if not (parsed.scheme or parsed.netloc or text.startswith("//")):
        return ""
    hostname = parsed.hostname or ""
    if not hostname:
        return ""
    netloc = hostname
    try:
        if parsed.port:
            netloc += ":" + str(parsed.port)
    except ValueError:
        return ""
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "", "", "", ""))


class _Resolver:
    def __init__(self, document, max_depth, max_refs):
        self.document = document
        self.max_depth = max(0, int(max_depth))
        self.max_refs = max(0, int(max_refs))
        self.ref_count = 0
        self.unresolved = []
        self._unresolved_keys = set()

    def note(self, ref, reason):
        ref_text = str(ref or "")
        if ref_text.startswith(("http://", "https://", "//")):
            ref_text = _sanitize_external_url(ref_text) or "<external-ref>"
        item = {"ref": ref_text, "reason": str(reason or "unresolved")}
        key = (item["ref"], item["reason"])
        if key not in self._unresolved_keys:
            self._unresolved_keys.add(key)
            self.unresolved.append(item)

    def pointer(self, ref):
        if ref == "#":
            return self.document
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return None
        current = self.document
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def resolve(self, value, depth=0, trail=()):
        if not isinstance(value, dict) or "$ref" not in value:
            return copy.deepcopy(value), tuple(trail)
        ref = value.get("$ref")
        siblings = {key: copy.deepcopy(item) for key, item in value.items() if key != "$ref"}
        if not isinstance(ref, str) or not ref.startswith("#"):
            self.note(ref, "external_ref")
            return siblings, tuple(trail)
        if depth >= self.max_depth:
            self.note(ref, "depth_limit")
            return siblings, tuple(trail)
        if ref in trail:
            self.note(ref, "cycle")
            return siblings, tuple(trail)
        if self.ref_count >= self.max_refs:
            self.note(ref, "ref_limit")
            return siblings, tuple(trail)
        target = self.pointer(ref)
        if target is None:
            self.note(ref, "missing")
            return siblings, tuple(trail)
        self.ref_count += 1
        next_trail = tuple(trail) + (ref,)
        resolved, resolved_trail = self.resolve(target, depth + 1, next_trail)
        if not isinstance(resolved, dict):
            self.note(ref, "non_object")
            resolved = {}
        resolved.update(siblings)
        return resolved, resolved_trail


def _normalize_parameter(raw, resolver, depth=0, trail=()):
    parameter, next_trail = resolver.resolve(raw, depth, trail)
    if not isinstance(parameter, dict):
        return None, next_trail
    name = str(parameter.get("name") or "").strip()
    location = str(parameter.get("in") or "").strip()
    if not name or location not in {"query", "path", "header", "body", "formData", "cookie"}:
        return None, next_trail
    schema_raw = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {}
    schema, schema_trail = resolver.resolve(schema_raw, depth + 1, next_trail)
    if not isinstance(schema, dict):
        schema = {}
    value_type = str(schema.get("type") or parameter.get("type") or "string")
    sensitive = _is_sensitive_param_name(name)
    candidates = [_safe_scalar(item) for item in _seed_candidates(parameter, schema)]
    candidates = [item for item in candidates if item is not None]
    descriptor = {
        "name": name,
        "in": location,
        "required": bool(parameter.get("required")) or location == "path",
        "type": value_type,
        "auto_materialize": location not in {"header", "cookie"} and not sensitive,
        "safe": location not in {"header", "cookie"} and not sensitive,
        "sensitive": sensitive,
    }
    if candidates and descriptor["auto_materialize"]:
        descriptor["seed"] = candidates[0]
        descriptor["seed_candidates"] = candidates[:8]
    enum = schema.get("enum") if isinstance(schema.get("enum"), list) else parameter.get("enum")
    if isinstance(enum, list):
        descriptor["enum"] = copy.deepcopy(enum[:20])
    for key in ("style", "explode", "collectionFormat", "format"):
        value = parameter.get(key, schema.get(key))
        if value is not None and not isinstance(value, (dict, list)):
            descriptor[key] = value
    descriptor["schema"] = schema
    return descriptor, schema_trail


def _public_parameter(parameter):
    item = copy.deepcopy(parameter)
    item.pop("schema", None)
    return item


def _merge_descriptor(existing, incoming):
    if not existing:
        return copy.deepcopy(incoming)
    merged = copy.deepcopy(existing)
    merged["required"] = bool(existing.get("required") or incoming.get("required"))
    merged["auto_materialize"] = bool(existing.get("auto_materialize", True) and incoming.get("auto_materialize", True))
    merged["safe"] = bool(existing.get("safe", True) and incoming.get("safe", True))
    for key in ("type", "seed", "enum", "parent", "leaf", "array"):
        if key not in merged and key in incoming:
            merged[key] = copy.deepcopy(incoming[key])
    candidates = []
    for item in list(existing.get("seed_candidates") or []) + list(incoming.get("seed_candidates") or []):
        if item not in candidates:
            candidates.append(item)
    if candidates:
        merged["seed_candidates"] = candidates[:8]
    return merged


def _flatten_schema(raw, resolver, source, prefix="", depth=0, trail=(), inherited_required=()):
    if depth > resolver.max_depth or not isinstance(raw, dict):
        return []
    schema, next_trail = resolver.resolve(raw, depth, trail)
    if not isinstance(schema, dict):
        return []
    required = set(inherited_required) | set(schema.get("required") or [])
    records = {}

    for combinator in ("allOf", "oneOf", "anyOf"):
        branches = schema.get(combinator)
        if isinstance(branches, list):
            for branch in branches:
                for item in _flatten_schema(branch, resolver, source, prefix, depth + 1, next_trail, required):
                    records[item["name"]] = _merge_descriptor(records.get(item["name"]), item)

    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name in sorted(properties):
            child_raw = properties.get(name)
            child, child_trail = resolver.resolve(child_raw, depth + 1, next_trail)
            if not isinstance(child, dict):
                child = {}
            full_name = (prefix + "." + str(name)).strip(".")
            child_type = str(child.get("type") or ("object" if child.get("properties") else "string"))
            sensitive = _is_sensitive_param_name(name)
            candidates = []
            for item in _seed_candidates(child, child):
                scalar = _safe_scalar(item)
                if scalar is not None and scalar not in candidates:
                    candidates.append(scalar)
            is_array = child_type == "array"
            is_object = child_type == "object" or isinstance(child.get("properties"), dict) or any(child.get(k) for k in ("allOf", "oneOf", "anyOf"))
            descriptor = {
                "name": full_name,
                "in": source,
                "required": str(name) in required,
                "type": child_type,
                "parent": prefix,
                "leaf": not is_object and not (is_array and isinstance(child.get("items"), dict) and (child.get("items") or {}).get("type") == "object"),
                "array": is_array,
                "auto_materialize": not sensitive,
                "safe": not sensitive,
                "sensitive": sensitive,
            }
            if candidates and descriptor["auto_materialize"]:
                descriptor["seed"] = candidates[0]
                descriptor["seed_candidates"] = candidates[:8]
            enum = child.get("enum")
            if isinstance(enum, list):
                descriptor["enum"] = copy.deepcopy(enum[:20])
            records[full_name] = _merge_descriptor(records.get(full_name), descriptor)
            if is_object:
                for item in _flatten_schema(child, resolver, source, full_name, depth + 1, child_trail, required):
                    records[item["name"]] = _merge_descriptor(records.get(item["name"]), item)
            if is_array and isinstance(child.get("items"), dict):
                item_schema = child.get("items") or {}
                item_type = str(item_schema.get("type") or "string")
                if item_type != "object" and not item_schema.get("properties"):
                    array_name = full_name + "[]"
                    array_descriptor = copy.deepcopy(descriptor)
                    array_descriptor.update({"name": array_name, "type": item_type, "parent": full_name, "leaf": True, "array": True})
                    records[array_name] = _merge_descriptor(records.get(array_name), array_descriptor)
                else:
                    for item in _flatten_schema(item_schema, resolver, source, full_name + "[]", depth + 1, child_trail, required):
                        records[item["name"]] = _merge_descriptor(records.get(item["name"]), item)

    if not records and prefix and str(schema.get("type") or "") not in {"object", "array"}:
        descriptor = {
            "name": prefix,
            "in": source,
            "required": True,
            "type": str(schema.get("type") or "string"),
            "parent": prefix.rsplit(".", 1)[0] if "." in prefix else "",
            "leaf": True,
            "array": False,
            "auto_materialize": not _is_sensitive_param_name(prefix.rsplit(".", 1)[-1]),
            "safe": not _is_sensitive_param_name(prefix.rsplit(".", 1)[-1]),
        }
        candidates = []
        for item in _seed_candidates(schema, schema):
            scalar = _safe_scalar(item)
            if scalar is not None and scalar not in candidates:
                candidates.append(scalar)
        if candidates and descriptor["auto_materialize"]:
            descriptor["seed"] = candidates[0]
            descriptor["seed_candidates"] = candidates[:8]
        records[prefix] = descriptor
    return [records[name] for name in sorted(records)]


def _expand_server_entries(raw_servers, resolver, scope, path_template="", method=""):
    entries = []
    if not isinstance(raw_servers, list):
        return entries
    for raw in raw_servers:
        server, _trail = resolver.resolve(raw)
        if not isinstance(server, dict) or not server.get("url"):
            continue
        raw_url = str(server.get("url") or "").strip()
        expanded = raw_url
        unresolved_variable = False
        variables = server.get("variables") if isinstance(server.get("variables"), dict) else {}
        for name in sorted(set(re.findall(r"\{([^{}]+)\}", raw_url))):
            if _is_sensitive_param_name(name):
                resolver.note("server:" + re.sub(r"\{[^{}]+\}", "{variable}", raw_url), "sensitive_server_variable:" + name)
                unresolved_variable = True
                break
            variable = variables.get(name) if isinstance(variables.get(name), dict) else {}
            value = variable.get("default")
            if value is None and isinstance(variable.get("enum"), list) and variable.get("enum"):
                value = variable.get("enum")[0]
            scalar = _safe_scalar(value, max_length=120)
            if scalar is None:
                resolver.note("server:" + raw_url, "missing_server_variable:" + name)
                unresolved_variable = True
                break
            expanded = expanded.replace("{" + name + "}", scalar)
        if unresolved_variable or "{" in expanded or "}" in expanded:
            continue
        external_url = _sanitize_external_url(expanded)
        local_prefix = None if external_url else _clean_local_prefix(expanded)
        if not external_url and local_prefix is None:
            resolver.note("server:" + raw_url, "unsafe_server_url")
            continue
        entries.append({
            "scope": scope,
            "raw_url": external_url or raw_url,
            "url": external_url or local_prefix,
            "external": bool(external_url),
            "local_prefix": None if external_url else local_prefix,
            "path_template": path_template,
            "method": method.upper() if method else "",
        })
    entries.sort(key=lambda item: (item["external"], item["url"], item["scope"], item["method"]))
    return entries


def _swagger_server_entries(document, resolver):
    base_path = _clean_local_prefix(document.get("basePath") or "")
    if base_path is None:
        resolver.note("server:" + str(document.get("basePath") or ""), "unsafe_base_path")
        base_path = ""
    host = str(document.get("host") or "").strip()
    if not host:
        return [{
            "scope": "root",
            "raw_url": str(document.get("basePath") or ""),
            "url": base_path,
            "external": False,
            "local_prefix": base_path,
            "path_template": "",
            "method": "",
        }]
    schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else []
    schemes = [str(item).lower() for item in schemes if str(item).lower() in {"http", "https"}]
    raw_urls = [(scheme + "://" + host + base_path) for scheme in schemes] or [("//" + host + base_path)]
    entries = []
    for raw_url in raw_urls:
        external_url = _sanitize_external_url(raw_url)
        if external_url:
            entries.append({
                "scope": "root",
                "raw_url": raw_url,
                "url": external_url,
                "external": True,
                "local_prefix": None,
                "path_template": "",
                "method": "",
            })
    return entries


def _merge_parameters(path_parameters, operation_parameters, resolver, trail=()):
    merged = {}
    for raw in list(path_parameters or []) + list(operation_parameters or []):
        descriptor, _trail = _normalize_parameter(raw, resolver, trail=trail)
        if not descriptor:
            continue
        key = (descriptor.get("name"), descriptor.get("in"))
        merged[key] = descriptor
    return [merged[key] for key in sorted(merged, key=lambda item: (str(item[1]), str(item[0])))]


def _seed_path(template, path_parameters):
    by_name = {str(item.get("name")): item for item in path_parameters}
    seeded = template
    active = True
    for name in PATH_TEMPLATE_RE.findall(template):
        seed = _path_seed(by_name.get(name))
        if not seed:
            active = False
            continue
        seeded = seeded.replace("{" + name + "}", seed)
    if PATH_TEMPLATE_RE.search(seeded):
        active = False
    return seeded if active else "", active


def _operation_body(op, parameters, resolver, document, trail=()):
    content_types = []
    by_content_type = {}
    json_params = {}
    form_params = {}

    request_body_raw = op.get("requestBody")
    request_body, body_trail = resolver.resolve(request_body_raw, trail=trail) if isinstance(request_body_raw, dict) else ({}, trail)
    if isinstance(request_body, dict):
        content = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
        for content_type in sorted(content):
            media = content.get(content_type) if isinstance(content.get(content_type), dict) else {}
            media_schema = media.get("schema") if isinstance(media.get("schema"), dict) else {}
            source = "form" if _is_form_content_type(content_type) else "json"
            params = _flatten_schema(media_schema, resolver, source, depth=1, trail=body_trail)
            by_content_type[content_type] = params
            content_types.append(content_type)
            target = form_params if _is_form_content_type(content_type) else json_params if _is_json_content_type(content_type) else None
            if target is not None:
                for item in params:
                    target[item["name"]] = _merge_descriptor(target.get(item["name"]), item)

    consumes = op.get("consumes") if isinstance(op.get("consumes"), list) else document.get("consumes")
    consumes = [str(item) for item in (consumes or []) if str(item).strip()]
    content_types.extend(consumes)
    for parameter in parameters:
        location = parameter.get("in")
        if location == "body":
            schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {}
            schema_type = str(schema.get("type") or ("object" if schema.get("properties") else ""))
            prefix = "" if schema_type == "object" or schema.get("properties") or schema.get("allOf") else str(parameter.get("name") or "body")
            params = _flatten_schema(schema, resolver, "json", prefix=prefix, depth=1, trail=trail)
            if not params:
                params = [dict(parameter, **{"in": "json", "leaf": True, "parent": ""})]
            for content_type in consumes:
                if _is_json_content_type(content_type):
                    by_content_type.setdefault(content_type, []).extend(copy.deepcopy(params))
            if any(_is_json_content_type(content_type) for content_type in consumes):
                for item in params:
                    json_params[item["name"]] = _merge_descriptor(json_params.get(item["name"]), item)
        elif location == "formData":
            item = copy.deepcopy(parameter)
            item.update({"in": "form", "leaf": True, "parent": ""})
            for content_type in consumes:
                if _is_form_content_type(content_type):
                    by_content_type.setdefault(content_type, []).append(copy.deepcopy(item))
            if any(_is_form_content_type(content_type) for content_type in consumes):
                form_params[item["name"]] = _merge_descriptor(form_params.get(item["name"]), item)

    return {
        "content_types": sorted(set(content_types)),
        "body_params_by_content_type": {
            content_type: sorted(items, key=lambda item: item.get("name", ""))
            for content_type, items in sorted(by_content_type.items())
        },
        "json_params": [json_params[name] for name in sorted(json_params)],
        "form_params": [form_params[name] for name in sorted(form_params)],
    }


def parse_openapi_inventory(source, max_depth=12, max_refs=256):
    """Return a deterministic, JSON-serializable API operation inventory."""
    document = json.loads(source) if isinstance(source, str) else copy.deepcopy(source)
    if not isinstance(document, dict):
        raise ValueError("OpenAPI document must be an object")
    resolver = _Resolver(document, max_depth=max_depth, max_refs=max_refs)
    is_swagger2 = str(document.get("swagger") or "").startswith("2")
    root_servers = _swagger_server_entries(document, resolver) if is_swagger2 else _expand_server_entries(document.get("servers"), resolver, "root")
    if not root_servers and not is_swagger2:
        root_servers = [{
            "scope": "implicit",
            "raw_url": "",
            "url": "",
            "external": False,
            "local_prefix": "",
            "path_template": "",
            "method": "",
        }]

    operations = []
    methods = {}
    path_templates = set()
    external_servers = [copy.deepcopy(item) for item in root_servers if item.get("external")]
    paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
    for raw_path in sorted(paths):
        if not isinstance(raw_path, str) or not raw_path.startswith("/") or len(raw_path) > 500:
            continue
        path_item, path_trail = resolver.resolve(paths.get(raw_path))
        if not isinstance(path_item, dict):
            continue
        path_server_defined = isinstance(path_item.get("servers"), list) and bool(path_item.get("servers"))
        path_servers = _expand_server_entries(path_item.get("servers"), resolver, "path", raw_path) if path_server_defined else []
        external_servers.extend(copy.deepcopy(item) for item in path_servers if item.get("external"))
        path_parameters = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method in HTTP_METHODS:
            if method not in path_item:
                continue
            operation, operation_trail = resolver.resolve(path_item.get(method), trail=path_trail)
            if not isinstance(operation, dict):
                continue
            operation_server_defined = isinstance(operation.get("servers"), list) and bool(operation.get("servers"))
            operation_servers = _expand_server_entries(operation.get("servers"), resolver, "operation", raw_path, method) if operation_server_defined else []
            external_servers.extend(copy.deepcopy(item) for item in operation_servers if item.get("external"))
            effective_servers = operation_servers if operation_server_defined else path_servers if path_server_defined else root_servers
            parameters = _merge_parameters(
                path_parameters,
                operation.get("parameters") if isinstance(operation.get("parameters"), list) else [],
                resolver,
                operation_trail,
            )
            path_parameters_normalized = [item for item in parameters if item.get("in") == "path"]
            query_parameters = [_public_parameter(item) for item in parameters if item.get("in") == "query"]
            path_parameters_public = [_public_parameter(item) for item in path_parameters_normalized]
            header_parameters = []
            for item in parameters:
                if item.get("in") in {"header", "cookie"}:
                    header = copy.deepcopy(item)
                    header.update({"auto_materialize": False, "safe": False})
                    header_parameters.append(_public_parameter(header))
            body = _operation_body(operation, parameters, resolver, document, operation_trail)
            destructive = method == "delete" or bool(ACTION_WORD_RE.search(raw_path.replace("/", " ")))
            local_servers = [item for item in effective_servers if not item.get("external")]
            external_effective = [item for item in effective_servers if item.get("external")]

            if not local_servers:
                operations.append({
                    "path": "",
                    "path_template": raw_path,
                    "raw_path_template": raw_path,
                    "path_templates": [raw_path],
                    "method": method.upper(),
                    "local": False,
                    "active": False,
                    "destructive": destructive,
                    "query_params": query_parameters,
                    "path_params": path_parameters_public,
                    "header_params": header_parameters,
                    "json_params": body["json_params"],
                    "form_params": body["form_params"],
                    "body_params_by_content_type": body["body_params_by_content_type"],
                    "content_types": body["content_types"],
                    "servers": {
                        "root": copy.deepcopy(root_servers),
                        "path": copy.deepcopy(path_servers),
                        "operation": copy.deepcopy(operation_servers),
                        "effective": copy.deepcopy(effective_servers),
                    },
                    "external_servers": copy.deepcopy(external_effective),
                })
                continue

            for server in local_servers:
                template = _join_local_path(server.get("local_prefix"), raw_path)
                if not template:
                    continue
                seeded_path, active = _seed_path(template, path_parameters_normalized)
                path_templates.add(template)
                methods.setdefault(template, set()).add(method.upper())
                operations.append({
                    "path": seeded_path,
                    "path_template": template,
                    "raw_path_template": raw_path,
                    "path_templates": [template],
                    "method": method.upper(),
                    "local": True,
                    "active": bool(active),
                    "destructive": destructive,
                    "query_params": query_parameters,
                    "path_params": path_parameters_public,
                    "header_params": header_parameters,
                    "json_params": body["json_params"],
                    "form_params": body["form_params"],
                    "body_params_by_content_type": body["body_params_by_content_type"],
                    "content_types": body["content_types"],
                    "servers": {
                        "root": copy.deepcopy(root_servers),
                        "path": copy.deepcopy(path_servers),
                        "operation": copy.deepcopy(operation_servers),
                        "effective": [copy.deepcopy(server)],
                    },
                    "external_servers": copy.deepcopy(external_effective),
                })

    deduped = {}
    for operation in operations:
        key = (
            bool(operation.get("local")),
            str(operation.get("path_template") or ""),
            str(operation.get("path") or ""),
            str(operation.get("method") or ""),
            json.dumps(operation.get("servers", {}).get("effective", []), ensure_ascii=False, sort_keys=True, default=str),
        )
        deduped[key] = operation
    operations = [deduped[key] for key in sorted(deduped, key=lambda item: (item[1], item[3], item[2], item[0]))]
    external_deduped = {}
    for item in external_servers:
        key = (item.get("url"), item.get("scope"), item.get("path_template"), item.get("method"))
        external_deduped[key] = item
    return {
        "apis": operations,
        "methods": {path: sorted(values) for path, values in sorted(methods.items())},
        "path_templates": sorted(path_templates),
        "external_servers": [external_deduped[key] for key in sorted(external_deduped, key=lambda item: tuple(str(part or "") for part in item))],
        "unresolved_refs": sorted(resolver.unresolved, key=lambda item: (item.get("ref", ""), item.get("reason", ""))),
    }

#!/usr/bin/env python3
"""Structured OpenAPI inventory and scanner integration regression."""

import importlib.util
import copy
import itertools
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "pipeline" / "deep_scanner.py"
sys.path.insert(0, str(ROOT))

from pipeline.input_tools import load_targets
from pipeline.openapi_inventory import parse_openapi_inventory


def local_records(inventory):
    return [item for item in inventory["apis"] if item.get("local")]


def record_for(inventory, template, method):
    return next(
        item
        for item in inventory["apis"]
        if item.get("path_template") == template and item.get("method") == method
    )


def spec_by_name(items):
    return {item["name"]: item for item in items}


def test_oas3_get_override_headers_and_safe_path_seed():
    document = {
        "openapi": "3.0.0",
        "servers": [
            {"url": "/v{version}", "variables": {"version": {"default": "1"}}},
            {"url": "https://user:pass@external.test:8443/api?token=secret"},
        ],
        "paths": {
            "/users/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "schema": {"type": "string", "default": "alice"}},
                    {"name": "q", "in": "query", "schema": {"type": "string", "default": "old"}},
                    {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}},
                    {"name": "Authorization", "in": "header", "example": "Bearer real-secret"},
                ],
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string", "example": "new"}},
                    ]
                },
            },
            "/unsafe/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "example": "../admin?danger=1"},
                    ]
                }
            },
            "/missing/{id}": {"get": {}},
            "/secret/{token}": {
                "get": {"parameters": [{"name": "token", "in": "path", "example": "real-token"}]}
            },
        },
    }
    inventory = parse_openapi_inventory(document)
    users = record_for(inventory, "/v1/users/{id}", "GET")
    assert users["path"] == "/v1/users/alice" and users["active"] is True, users
    query = spec_by_name(users["query_params"])
    assert query["q"]["seed"] == "new", query
    headers = spec_by_name(users["header_params"])
    assert headers["X-Tenant"]["auto_materialize"] is False, headers
    assert headers["Authorization"]["safe"] is False and headers["Authorization"]["sensitive"] is True, headers

    unsafe = record_for(inventory, "/v1/unsafe/{id}", "GET")
    assert unsafe["path"] == "/v1/unsafe/1" and ".." not in unsafe["path"] and "?" not in unsafe["path"], unsafe
    missing = record_for(inventory, "/v1/missing/{id}", "GET")
    assert missing["active"] is False and missing["path"] == "", missing
    secret = record_for(inventory, "/v1/secret/{token}", "GET")
    assert secret["active"] is False and secret["path"] == "", secret

    external = inventory["external_servers"]
    assert external and external[0]["url"] == "https://external.test:8443/api", external
    serialized = json.dumps(inventory, ensure_ascii=False, sort_keys=True)
    assert "pass@" not in serialized and "token=secret" not in serialized, serialized


def test_oas3_request_body_ref_composition_and_content_isolation():
    document = {
        "openapi": "3.0.0",
        "components": {
            "schemas": {
                "Search": {
                    "allOf": [
                        {
                            "type": "object",
                            "required": ["id"],
                            "properties": {
                                "id": {"type": "integer", "default": 2},
                                "filters": {
                                    "type": "object",
                                    "properties": {
                                        "status": {"type": "string", "enum": ["open"]},
                                    },
                                },
                            },
                        },
                        {
                            "oneOf": [
                                {"type": "object", "properties": {"tag": {"type": "string"}}},
                                {"type": "object", "properties": {"owner": {"type": "string"}}},
                            ]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "tags": {"type": "array", "items": {"type": "string"}},
                                "accessToken": {"type": "string", "example": "do-not-send"},
                            },
                        },
                    ]
                }
            },
            "requestBodies": {
                "SearchBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Search"}},
                        "application/merge-patch+json": {
                            "schema": {"type": "object", "properties": {"patchOnly": {"type": "string"}}}
                        },
                        "application/x-www-form-urlencoded": {
                            "schema": {"type": "object", "properties": {"formOnly": {"type": "string"}}}
                        },
                        "multipart/form-data": {
                            "schema": {"type": "object", "properties": {"file": {"type": "string", "format": "binary"}}}
                        },
                    },
                }
            },
        },
        "paths": {
            "/search": {"post": {"requestBody": {"$ref": "#/components/requestBodies/SearchBody"}}}
        },
    }
    inventory = parse_openapi_inventory(document)
    operation = record_for(inventory, "/search", "POST")
    json_specs = spec_by_name(operation["json_params"])
    form_specs = spec_by_name(operation["form_params"])
    by_type = operation["body_params_by_content_type"]
    assert json_specs["id"]["required"] is True, json_specs["id"]
    assert "filters.status" in json_specs and "tags[]" in json_specs, json_specs
    assert "tag" in json_specs and "owner" in json_specs and "patchOnly" in json_specs, json_specs
    assert json_specs["accessToken"]["auto_materialize"] is False, json_specs["accessToken"]
    assert "formOnly" not in json_specs and "formOnly" in form_specs, (json_specs, form_specs)
    assert {item["name"] for item in by_type["application/json"]}.isdisjoint({"formOnly", "patchOnly"}), by_type
    assert {item["name"] for item in by_type["application/merge-patch+json"]} == {"patchOnly"}, by_type
    assert {item["name"] for item in by_type["application/x-www-form-urlencoded"]} == {"formOnly"}, by_type
    assert "application/merge-patch+json" in operation["content_types"], operation


def test_swagger2_body_form_methods_and_path_item_ref():
    document = {
        "swagger": "2.0",
        "basePath": "/legacy",
        "consumes": ["application/json"],
        "definitions": {
            "Body": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "integer"}, "name": {"type": "string"}},
            }
        },
        "x-delete-path": {"delete": {"parameters": [{"name": "id", "in": "query", "type": "integer"}]}},
        "paths": {
            "/body/search": {
                "post": {
                    "parameters": [{"name": "payload", "in": "body", "schema": {"$ref": "#/definitions/Body"}}]
                }
            },
            "/form/query": {
                "post": {
                    "consumes": ["application/x-www-form-urlencoded"],
                    "parameters": [{"name": "term", "in": "formData", "type": "string", "required": True}],
                }
            },
            "/delete-direct": {"delete": {}},
            "/delete-ref": {"$ref": "#/x-delete-path"},
            "/mixed": {"get": {}, "delete": {}},
        },
    }
    inventory = parse_openapi_inventory(document)
    body = record_for(inventory, "/legacy/body/search", "POST")
    form = record_for(inventory, "/legacy/form/query", "POST")
    assert {item["name"] for item in body["json_params"]} == {"id", "name"}, body
    assert body["content_types"] == ["application/json"], body
    assert {item["name"] for item in form["form_params"]} == {"term"}, form
    assert form["content_types"] == ["application/x-www-form-urlencoded"], form
    assert inventory["methods"]["/legacy/delete-direct"] == ["DELETE"], inventory["methods"]
    assert inventory["methods"]["/legacy/delete-ref"] == ["DELETE"], inventory["methods"]
    assert inventory["methods"]["/legacy/mixed"] == ["DELETE", "GET"], inventory["methods"]

    external_document = {
        "swagger": "2.0",
        "host": "api.external.test:9443",
        "schemes": ["https"],
        "basePath": "/v2",
        "paths": {"/users": {"get": {}}},
    }
    external = parse_openapi_inventory(external_document)
    assert not local_records(external), external
    assert external["external_servers"][0]["url"] == "https://api.external.test:9443/v2", external


def test_server_override_external_quarantine_and_no_recursive_prefixes():
    override = {
        "openapi": "3.0.0",
        "servers": [{"url": "/root"}],
        "paths": {
            "/x": {
                "servers": [{"url": "/path"}],
                "get": {"servers": [{"url": "/operation"}]},
            },
            "/external": {
                "get": {"servers": [{"url": "https://external.test/api"}]},
            },
        },
    }
    inventory = parse_openapi_inventory(override)
    templates = {item["path_template"] for item in local_records(inventory)}
    assert "/operation/x" in templates, templates
    assert "/root/x" not in templates and "/path/x" not in templates, templates
    external_record = record_for(inventory, "/external", "GET")
    assert external_record["local"] is False and external_record["active"] is False, external_record
    assert any(item["scope"] == "operation" and item["url"] == "https://external.test/api" for item in inventory["external_servers"]), inventory

    variants = parse_openapi_inventory({
        "openapi": "3.0.0",
        "servers": [{"url": "/v1"}, {"url": "/v2"}],
        "paths": {"/items": {"get": {}}},
    })
    variant_templates = [item["path_template"] for item in local_records(variants)]
    assert variant_templates == ["/v1/items", "/v2/items"], variant_templates
    assert not any("/v1/v2/" in value or "/v2/v1/" in value for value in variant_templates), variant_templates


def test_refs_limits_pointer_escaping_invalid_items_and_determinism():
    document = {
        "openapi": "3.0.0",
        "components": {
            "schemas": {
                "a/b~c": {"type": "object", "properties": {"value": {"type": "string"}}},
                "Cycle": {
                    "type": "object",
                    "properties": {"self": {"$ref": "#/components/schemas/Cycle"}},
                },
            }
        },
        "paths": {
            "/escaped": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/a~1b~0c"}}
                        }
                    }
                }
            },
            "/cycle": {
                "post": {
                    "requestBody": {
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Cycle"}}}
                    }
                }
            },
            "/missing": {"get": {"parameters": [{"$ref": "#/components/parameters/Missing"}]}},
            "/external-ref": {"get": {"parameters": [{"$ref": "https://external.test/params.json#/x"}]}},
            "/invalid": None,
        },
    }
    first = parse_openapi_inventory(document, max_depth=4, max_refs=20)
    second = parse_openapi_inventory(document, max_depth=4, max_refs=20)
    escaped = record_for(first, "/escaped", "POST")
    assert {item["name"] for item in escaped["json_params"]} == {"value"}, escaped
    reasons = {(item["ref"], item["reason"]) for item in first["unresolved_refs"]}
    assert any(reason in {"cycle", "depth_limit"} for _ref, reason in reasons), reasons
    assert ("#/components/parameters/Missing", "missing") in reasons, reasons
    assert ("https://external.test/params.json", "external_ref") in reasons, reasons
    assert first == second and json.loads(json.dumps(first, ensure_ascii=False)) == first

    limited = parse_openapi_inventory(document, max_depth=1, max_refs=1)
    assert any(item["reason"] in {"depth_limit", "ref_limit"} for item in limited["unresolved_refs"]), limited


def test_httpx_original_preference_and_fallback():
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as handle:
        handle.write('{"url":"http://host/original","final_url":"http://host/final"}\n')
        handle.write('{"input":"http://host/input","final_url":"http://host/final-2"}\n')
        handle.write('{"final_url":"http://host/fallback"}\n')
        path = handle.name
    try:
        targets = load_targets(path, "httpx-json")
        assert [item[0] for item in targets] == [
            "http://host/original",
            "http://host/input",
            "http://host/fallback",
        ], targets
    finally:
        os.unlink(path)


def load_scanner_module():
    old_argv = sys.argv[:]
    try:
        sys.argv = [str(SCANNER)]
        spec = importlib.util.spec_from_file_location("deep_scanner_v32", SCANNER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        sys.argv = old_argv


def integration_document():
    return {
        "openapi": "3.0.0",
        "paths": {
            "/api/users/{id}": {
                "get": {
                    "parameters": [
                        {"name": "id", "in": "path", "schema": {"type": "integer", "default": 7}},
                        {"name": "X-Tenant", "in": "header", "schema": {"type": "string"}},
                    ]
                }
            },
            "/api/search": {
                "get": {"parameters": [{"name": "q", "in": "query", "schema": {"default": "needle"}}]}
            },
            "/api/report/search": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/merge-patch+json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "keyword": {"type": "string", "default": "needle"},
                                        "accessToken": {"type": "string", "example": "do-not-send"},
                                    },
                                }
                            }
                        }
                    }
                }
            },
            "/api/form/query": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {"type": "object", "properties": {"term": {"type": "string", "default": "needle"}}}
                            }
                        }
                    }
                }
            },
            "/api/user/update": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"id": {"type": "integer", "default": 1}}}
                            }
                        }
                    }
                }
            },
            "/api/delete/{id}": {
                "delete": {"parameters": [{"name": "id", "in": "path", "schema": {"default": 1}}]}
            },
            "/api/external": {
                "get": {"servers": [{"url": "https://external.test/v1"}]}
            },
        },
    }


def test_scanner_profile_mapping_scheduling_serialization_and_replay():
    scanner = load_scanner_module()
    inventory = parse_openapi_inventory(integration_document())
    profile = scanner.empty_param_profile()
    scanner.args.include_delete_method = False
    scanner.args.allow_active_post = False
    apis = scanner.merge_openapi_inventory(profile, inventory)
    assert "/api/users/7" in apis and "/api/search" in apis, apis
    assert "/api/delete/1" not in apis and "/api/external" not in apis, apis
    assert "q" in profile["api_param_sources"]["/api/search"]["query"], profile
    assert "X-Tenant" in profile["api_param_specs"]["/api/users/7"]["header"], profile
    assert "X-Tenant" not in profile["api_param_sources"].get("/api/users/7", {}).get("query", set()), profile
    assert "accessToken" not in profile["api_param_sources"]["/api/report/search"]["json"], profile
    assert profile["api_content_types"]["/api/report/search"] == {"application/merge-patch+json"}, profile

    report_tests = scanner.scheduled_bypass_tests("/api/report/search", scanner.FULL_BYPASS, profile)
    assert report_tests and {item[2] for item in report_tests} == {"application/merge-patch+json"}, report_tests
    assert {item[1] for item in report_tests} == {"POST"}, report_tests
    report_variants = scanner.request_variants(
        "/api/report/search", "POST", "application/merge-patch+json", lambda value: json.dumps(value).encode(), profile, True
    )
    assert report_variants and all("keyword" in payload and "page" not in payload for _query, payload in report_variants), report_variants
    assert all("accessToken" not in json.dumps(payload) for _query, payload in report_variants), report_variants

    form_tests = scanner.scheduled_bypass_tests("/api/form/query", scanner.FULL_BYPASS, profile)
    assert form_tests and {item[2] for item in form_tests} == {"application/x-www-form-urlencoded"}, form_tests
    assert scanner.scheduled_bypass_tests("/api/user/update", scanner.FULL_BYPASS, profile) == []
    scanner.args.allow_active_post = True
    update_tests = scanner.scheduled_bypass_tests("/api/user/update", scanner.FULL_BYPASS, profile)
    assert update_tests and {item[2] for item in update_tests} == {"application/json"}, update_tests
    scanner.args.allow_active_post = False
    scanner.args.include_delete_method = True
    delete_apis = scanner.merge_openapi_inventory(profile, inventory)
    assert "/api/delete/1" in delete_apis, delete_apis
    assert scanner.scheduled_bypass_tests("/api/delete/1", scanner.FULL_BYPASS, profile) == []

    serialized = scanner.serialize_param_profile(profile)
    restored = scanner.deserialize_param_profile(json.loads(json.dumps(serialized)))
    assert restored["api_content_types"] == profile["api_content_types"], restored
    assert restored["api_path_templates"] == profile["api_path_templates"], restored
    assert restored["api_param_specs"]["/api/search"]["query"]["q"]["seed"] == "needle", restored

    source = {"param_profile": profile}
    destination = {"param_profile": scanner.empty_param_profile()}
    assert scanner.carry_replay_param_profile(destination, source, "/api/report/search") is True
    copied = destination["param_profile"]
    assert copied["api_content_types"]["/api/report/search"] == {"application/merge-patch+json"}, copied
    assert "keyword" in copied["api_param_specs"]["/api/report/search"]["json"], copied

    replay_path = "/api/report/search"
    replay_profile = scanner.deserialize_param_profile(
        json.loads(json.dumps(scanner.serialize_param_profile(profile)))
    )
    replay_profile["names"].update({"keyword", "status"})
    replay_profile["seeds"].update({"open", "1"})
    replay_profile["file_seeds"].add("report.csv")
    replay_profile["api_params"].setdefault(replay_path, set()).update({"keyword", "status"})
    replay_profile["api_param_sources"].setdefault(replay_path, {}).setdefault("json", set()).update({"keyword", "status"})
    replay_profile["api_param_shapes"].setdefault(replay_path, {}).setdefault("json", {}).setdefault("filters", set()).add("status")
    replay_profile["api_methods"].setdefault(replay_path, set()).add("post")
    replay_profile["api_content_types"].setdefault(replay_path, set()).add("application/merge-patch+json")
    replay_profile["api_path_templates"].setdefault(replay_path, set()).add("/api/report/search")

    source_live = {
        "base": "http://replay.test:8080",
        "apis": [replay_path],
        "api_meta": {replay_path: {"confidence": 0.95, "sources": ["openapi"]}},
        "param_profile": replay_profile,
    }
    destination_live = {
        "base": "http://replay.test:9090",
        "apis": ["/local/status"],
        "api_meta": {},
        "param_profile": scanner.empty_param_profile(),
    }

    def record_round_trip(record):
        wire = json.loads(json.dumps(scanner.serialize_scan_record(record), sort_keys=True))
        return scanner.deserialize_scan_record(wire)

    source_round = record_round_trip(source_live)
    destination_round = record_round_trip(destination_live)
    assert isinstance(source_round["param_profile"]["names"], set), source_round["param_profile"]
    assert isinstance(destination_round["param_profile"]["names"], set), destination_round["param_profile"]
    added, touched = scanner.apply_cross_base_replay([source_round, destination_round], "host", 0)
    assert added == 1 and touched == 1, (added, touched)
    assert not source_round.get("replay_apis"), source_round
    assert replay_path in destination_round.get("replay_apis", []), destination_round
    replayed = destination_round["param_profile"]
    assert {"keyword", "status"} <= replayed["api_params"][replay_path], replayed
    assert {"keyword", "status"} <= replayed["api_param_sources"][replay_path]["json"], replayed
    assert replayed["api_param_shapes"][replay_path]["json"]["filters"] == {"status"}, replayed
    assert replayed["api_methods"][replay_path] == {"post"}, replayed
    assert "keyword" in replayed["api_param_specs"][replay_path]["json"], replayed
    assert replayed["api_content_types"][replay_path] == {"application/merge-patch+json"}, replayed
    assert replayed["api_path_templates"][replay_path] == {"/api/report/search"}, replayed
    assert replayed["names"] == set() and replayed["seeds"] == set(), replayed
    assert replayed["file_seeds"] == set(), replayed
    assert "/local/status" not in replayed["api_params"], replayed
    assert not scanner.has_bound_params(replayed, "/local/status"), replayed
    assert scanner.body_probe_bypass_tests(replayed, "/local/status") == [], replayed
    serialized_once = scanner.serialize_scan_record(destination_round)
    serialized_twice = scanner.serialize_scan_record(
        scanner.deserialize_scan_record(json.loads(json.dumps(serialized_once, sort_keys=True)))
    )
    assert serialized_once == serialized_twice, (serialized_once, serialized_twice)

    list_source = json.loads(json.dumps(scanner.serialize_scan_record(source_live), sort_keys=True))
    list_destination = json.loads(json.dumps(scanner.serialize_scan_record(destination_live), sort_keys=True))
    list_profile = list_destination["param_profile"]
    list_profile["names"] = "malformed"
    list_profile["seeds"] = {"malformed": True}
    list_profile["file_seeds"] = 7
    list_profile["api_params"] = {replay_path: {"malformed": True}}
    list_profile["api_param_sources"] = {replay_path: {"json": "malformed"}}
    list_profile["api_param_shapes"] = {replay_path: {"json": {"filters": "malformed"}}}
    list_profile["api_methods"] = {replay_path: "post"}
    list_profile["api_content_types"] = {replay_path: "application/json"}
    list_profile["api_path_templates"] = {replay_path: {"malformed": True}}
    assert scanner.carry_replay_param_profile(list_destination, list_source, replay_path) is True
    normalized = list_destination["param_profile"]
    for field in ("api_params", "api_methods", "api_content_types", "api_path_templates"):
        assert isinstance(normalized[field][replay_path], set), (field, normalized[field])
    assert isinstance(normalized["api_param_sources"][replay_path]["json"], set), normalized
    assert isinstance(normalized["api_param_shapes"][replay_path]["json"]["filters"], set), normalized
    normalized_wire = scanner.serialize_scan_record(list_destination)
    assert normalized_wire["param_profile"]["names"] == [], normalized_wire
    assert normalized_wire["param_profile"]["seeds"] == [], normalized_wire
    assert normalized_wire["param_profile"]["file_seeds"] == [], normalized_wire
    json.dumps(normalized_wire, sort_keys=True, allow_nan=False)


def test_replay_metadata_order_identity_and_stream_recovery():
    scanner = load_scanner_module()
    clean_api = "/api/shared/replay"
    templates = [
        {
            "base": "http://replay.test:8101",
            "apis": [clean_api],
            "api_meta": {
                clean_api: {
                    "confidence": 0.8,
                    "sources": {"js-graph"},
                    "unsupported": {"hash-order-a", "hash-order-b"},
                }
            },
            "param_profile": scanner.empty_param_profile(),
        },
        {
            "base": "http://replay.test:8102",
            "apis": [clean_api],
            "api_meta": {
                clean_api: {"confidence": 0.95, "sources": ["openapi"]},
                clean_api + "?mode=read": {"confidence": float("nan"), "sources": ["business_pattern"]},
            },
            "param_profile": scanner.empty_param_profile(),
        },
        {
            "base": "http://replay.test:8201",
            "apis": ["/local/a"],
            "api_meta": {clean_api: {"confidence": 0.4, "sources": ["baseline"]}},
            "param_profile": scanner.empty_param_profile(),
        },
        {
            "base": "http://replay.test:8202",
            "apis": ["/local/b"],
            "api_meta": {},
            "param_profile": scanner.empty_param_profile(),
        },
    ]
    snapshots = []
    first_records = None
    for order in itertools.permutations(range(len(templates))):
        records = [copy.deepcopy(templates[index]) for index in order]
        scanner.apply_cross_base_replay(records, "host", 0)
        by_base = {record["base"]: record for record in records}
        selected = {}
        for base in ("http://replay.test:8201", "http://replay.test:8202"):
            meta = by_base[base]["api_meta"]
            selected[base] = {
                "clean": copy.deepcopy(meta[clean_api]),
            }
            assert meta[clean_api] == {
                "confidence": 0.95,
                "sources": ["baseline", "business_pattern", "js-graph", "openapi"],
            }, meta
            assert set(meta[clean_api]) == {"confidence", "sources"}, meta
        snapshots.append(json.dumps(selected, sort_keys=True, allow_nan=False))
        if first_records is None:
            first_records = by_base
    assert len(set(snapshots)) == 1, snapshots

    left = first_records["http://replay.test:8201"]["api_meta"]
    right = first_records["http://replay.test:8202"]["api_meta"]
    assert left[clean_api] is not right[clean_api], (left, right)
    left[clean_api]["sources"].append("mutation")
    assert "mutation" not in right[clean_api]["sources"], right

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        stream_path = tmp / "records.jsonl"
        good_a = scanner.serialize_scan_record({
            "base": "http://good-a.test", "apis": ["/api/a"],
            "api_meta": {"/api/a": {"confidence": 0.8, "sources": {"js-graph"}, "drop": {"x"}}},
            "param_profile": scanner.empty_param_profile(),
        })
        bad = {
            "base": "http://bad.test", "apis": ["/api/bad"],
            "param_profile": {"names": "not-a-list", "api_params": []},
        }
        good_b = scanner.serialize_scan_record({
            "base": "http://good-b.test", "apis": ["/api/b"],
            "api_meta": {"/api/b": {"confidence": 0.9, "sources": ["openapi"]}},
            "param_profile": scanner.empty_param_profile(),
        })
        stream_path.write_text(
            "\n".join(json.dumps(item, sort_keys=True, allow_nan=False) for item in (good_a, bad, good_b)) + "\n",
            encoding="utf-8",
        )
        loaded = scanner.StreamedResultSet(str(stream_path), 3).materialize()
        assert [item["base"] for item in loaded] == ["http://good-a.test", "http://good-b.test"], loaded

        writer_path = tmp / "writer.jsonl"
        writer = scanner._JsonlWriter(str(writer_path))
        writer.write({
            "base": "http://writer.test", "apis": ["/api/writer"],
            "api_meta": {"/api/writer": {"confidence": 0.8, "sources": {"openapi", "js-graph"}, "drop": {"unordered"}}},
            "param_profile": scanner.empty_param_profile(),
        })
        persisted = json.loads(writer_path.read_text(encoding="utf-8"))
        assert persisted["api_meta"]["/api/writer"] == {
            "confidence": 0.8, "sources": ["js-graph", "openapi"],
        }, persisted


def test_replay_numeric_spec_and_hash_determinism():
    scanner = load_scanner_module()

    huge = scanner._canonical_api_meta_item({
        "confidence": 10 ** 400,
        "sources": ["openapi"],
    })
    assert huge == {"confidence": 0.0, "sources": ["openapi"]}, huge
    non_finite = scanner._canonical_api_meta_item({
        "confidence": float("inf"),
        "sources": ["js-graph"],
    })
    assert non_finite == {"confidence": 0.0, "sources": ["js-graph"]}, non_finite

    path = "/api/spec-order"
    source_specs = [
        {
            "base": "http://spec.test:8101",
            "apis": [path],
            "api_meta": {path: {"confidence": 0.8, "sources": ["openapi"]}},
            "param_profile": {
                "api_param_specs": {path: {"query": {"q": {
                    "name": "q", "in": "query", "seed": "zeta",
                    "seed_candidates": {"middle", "alpha"},
                    "enum": [float("nan"), float("inf"), "z", "a"],
                }}}},
            },
        },
        {
            "base": "http://spec.test:8102",
            "apis": [path],
            "api_meta": {path: {"confidence": 0.9, "sources": ["js-graph"]}},
            "param_profile": {
                "api_param_specs": {path: {"query": {"q": {
                    "name": "q", "in": "query", "seed": "beta",
                    "seed_candidates": {"xray", "charlie"},
                    "enum": [3, 1, float("-inf")],
                }}}},
            },
        },
    ]
    snapshots = []
    active_seeds = []
    for order in itertools.permutations(source_specs):
        records = [copy.deepcopy(item) for item in order]
        destination = {
            "base": "http://spec.test:8200",
            "apis": ["/local"],
            "api_meta": {},
            "param_profile": scanner.empty_param_profile(),
        }
        records.append(destination)
        scanner.apply_cross_base_replay(records, "host", 0)
        serialized = scanner.serialize_scan_record(destination)
        snapshots.append(json.dumps(serialized, sort_keys=True, allow_nan=False))
        spec = destination["param_profile"]["api_param_specs"][path]["query"]["q"]
        active_seeds.append(scanner.param_spec_seed_value(spec, "q", []))
        assert spec["enum"] == ["a", "z", 1, 3], spec
    assert len(set(snapshots)) == 1, snapshots
    assert active_seeds == ["beta", "beta"], active_seeds

    with tempfile.TemporaryDirectory() as tmpdir:
        stream_path = Path(tmpdir) / "huge-records.jsonl"
        good_a = scanner.serialize_scan_record({"base": "http://good-a.test", "apis": ["/a"]})
        huge_meta = {
            "base": "http://huge.test", "apis": ["/huge"],
            "api_meta": {"/huge": {"confidence": 10 ** 400, "sources": ["openapi"]}},
        }
        bad_shape = {"base": "http://bad.test", "apis": ["/bad"], "param_profile": {"names": "bad"}}
        good_b = scanner.serialize_scan_record({"base": "http://good-b.test", "apis": ["/b"]})
        stream_path.write_text(
            "\n".join(json.dumps(item, sort_keys=True) for item in (good_a, huge_meta, bad_shape, good_b)) + "\n",
            encoding="utf-8",
        )
        loaded = scanner.StreamedResultSet(str(stream_path), 4).materialize()
        assert [item["base"] for item in loaded] == [
            "http://good-a.test", "http://huge.test", "http://good-b.test",
        ], loaded
        assert loaded[1]["api_meta"]["/huge"]["confidence"] == 0.0, loaded[1]

        overflow_path = Path(tmpdir) / "overflow-records.jsonl"
        overflow_record = {"base": "http://overflow.test", "apis": ["/overflow"]}
        overflow_path.write_text(
            "\n".join(json.dumps(item, sort_keys=True) for item in (good_a, overflow_record, good_b)) + "\n",
            encoding="utf-8",
        )
        original_deserialize = scanner.deserialize_scan_record

        def overflow_once(record):
            if record.get("base") == "http://overflow.test":
                raise OverflowError("synthetic numeric conversion overflow")
            return original_deserialize(record)
        scanner.deserialize_scan_record = overflow_once
        try:
            recovered = scanner.StreamedResultSet(str(overflow_path), 3).materialize()
        finally:
            scanner.deserialize_scan_record = original_deserialize
        assert [item["base"] for item in recovered] == [
            "http://good-a.test", "http://good-b.test",
        ], recovered

        writer_path = Path(tmpdir) / "finite.jsonl"
        writer = scanner._JsonlWriter(str(writer_path))
        writer_record = copy.deepcopy(source_specs[0])
        writer_record["api_meta"][path]["confidence"] = 10 ** 400
        writer.write(writer_record)
        persisted_text = writer_path.read_text(encoding="utf-8")
        assert "NaN" not in persisted_text and "Infinity" not in persisted_text, persisted_text
        persisted = json.loads(persisted_text)
        assert persisted["api_meta"][path]["confidence"] == 0.0, persisted

    code = """
from tests.v32_openapi_inventory_test import load_scanner_module
s = load_scanner_module()
profile = {
    "names": {"name%05d" % i for i in range(5000)},
    "api_param_specs": {"/api/oversize": {"query": {"q": {
        "name": "q", "seed_candidates": {"seed%05d" % i for i in range(5000)}
    }}}},
}
wire = s.serialize_param_profile(profile)
print("|".join(wire["names"][:5]))
print("|".join(wire["api_param_specs"]["/api/oversize"]["query"]["q"]["seed_candidates"]))
"""
    outputs = []
    for seed in ("1", "77", "999"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        outputs.append(subprocess.check_output(
            [sys.executable, "-c", code], cwd=str(ROOT), env=env, text=True,
        ))
    assert len(set(outputs)) == 1, outputs
    lines = outputs[0].splitlines()
    assert lines[0] == "name00000|name00001|name00002|name00003|name00004", lines
    assert lines[1] == "seed00000|seed00001|seed00002|seed00003|seed00004|seed00005|seed00006|seed00007", lines


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.hits = []

    @property
    def url(self):
        return "http://127.0.0.1:" + str(self.server_address[1])


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def send_payload(self, body, content_type="application/json", status=200):
        raw = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def record(self, body=""):
        self.server.hits.append({
            "method": self.command,
            "path": urlparse(self.path).path,
            "query": parse_qs(urlparse(self.path).query),
            "content_type": self.headers.get("Content-Type", "").split(";", 1)[0],
            "body": body,
        })

    def do_GET(self):
        path = urlparse(self.path).path
        self.record()
        if path == "/":
            return self.send_payload("<html><title>v32</title></html>", "text/html")
        if path == "/v3/api-docs":
            return self.send_payload(json.dumps(integration_document()))
        if path == "/api/users/7":
            return self.send_payload(json.dumps({"code": 0, "data": [{"id": 7, "phone": "13800138000"}]}))
        if path == "/api/search":
            return self.send_payload(json.dumps({"code": 0, "data": [{"q": parse_qs(urlparse(self.path).query).get("q", [""])[0]}]}))
        return self.send_payload(json.dumps({"code": 404, "message": "not found", "path": path}), status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length).decode("utf-8", "ignore")
        path = urlparse(self.path).path
        self.record(body)
        if path in {"/api/report/search", "/api/form/query", "/api/user/update"}:
            return self.send_payload(json.dumps({"code": 0, "data": [{"path": path, "body": body}]}))
        return self.send_payload(json.dumps({"code": 404, "message": "not found", "path": path}), status=404)

    def do_DELETE(self):
        self.record()
        return self.send_payload(json.dumps({"code": 0, "data": [{"deleted": True}]}))


def test_end_to_end_documented_methods_params_and_content_types():
    server = LabServer(("127.0.0.1", 0), LabHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            targets = root / "targets.json"
            outdir = root / "out"
            targets.write_text(json.dumps([{"url": server.url, "title": "v32", "score": 100}]), encoding="utf-8")
            command = [
                sys.executable,
                str(SCANNER),
                "--input", str(targets),
                "--outdir", str(outdir),
                "--workers", "3",
                "--timeout", "3",
                "--phase2-timeout", "40",
                "--phase3a-timeout", "60",
                "--phase3b-layer-timeout", "60",
                "--full-bypass",
                "--param-probe-mode", "broad",
                "--phase3a-param-rescue",
                "--phase3a-param-rescue-max-apis", "0",
                "--phase3a-body-max-apis", "0",
                "--disable-api-fuzz",
                "--disable-rescue-baseline",
                "--replay-scope", "none",
                "--no-capture-finding-evidence",
                "--no-proxy",
                "--fresh",
            ]
            process = subprocess.run(command, text=True, capture_output=True, timeout=150)
            if process.returncode != 0:
                print(process.stdout)
                print(process.stderr)
                raise SystemExit(process.returncode)
            inventory_lines = [
                json.loads(line)
                for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert len(inventory_lines) == 1, inventory_lines
            item = inventory_lines[0]
            apis = set(item["apis"])
            assert "/api/users/7" in apis and "/api/report/search" in apis and "/api/form/query" in apis, apis
            assert "/api/delete/1" not in apis and "/api/external" not in apis, apis
            profile = item["param_profile"]
            assert profile["api_content_types"]["/api/report/search"] == ["application/merge-patch+json"], profile
            assert profile["api_content_types"]["/api/form/query"] == ["application/x-www-form-urlencoded"], profile

            actual = [hit for hit in server.hits if not hit["path"].startswith("/__scanner") and "__scanner_not_found_" not in hit["path"]]
            assert any(hit["method"] == "GET" and hit["path"] == "/api/users/7" for hit in actual), actual
            assert any(hit["method"] == "GET" and hit["path"] == "/api/search" and hit["query"].get("q") == ["needle"] for hit in actual), actual
            report_posts = [hit for hit in actual if hit["method"] == "POST" and hit["path"] == "/api/report/search"]
            assert report_posts and {hit["content_type"] for hit in report_posts} == {"application/merge-patch+json"}, report_posts
            assert all("keyword" in hit["body"] and "accessToken" not in hit["body"] for hit in report_posts), report_posts
            form_posts = [hit for hit in actual if hit["method"] == "POST" and hit["path"] == "/api/form/query"]
            assert form_posts and {hit["content_type"] for hit in form_posts} == {"application/x-www-form-urlencoded"}, form_posts
            assert all("term=needle" in hit["body"] for hit in form_posts), form_posts
            assert not any(hit["method"] == "POST" and hit["path"] == "/api/user/update" for hit in actual), actual
            assert not any(hit["method"] == "DELETE" or hit["path"] == "/api/delete/1" for hit in actual), actual
    finally:
        server.shutdown()
        server.server_close()


class RedirectPageHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        body = b'<html><script>fetch("/api/from-redirect")</script></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RedirectOriginHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):
        if urlparse(self.path).path == "/":
            self.send_response(302)
            self.send_header("Location", self.server.redirect_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"code":0,"data":[{"id":1}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_same_host_cross_port_redirect_preserves_original_scan_base():
    page_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectPageHandler)
    origin_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectOriginHandler)
    origin_server.redirect_url = "http://127.0.0.1:" + str(page_server.server_address[1]) + "/"
    threads = [
        threading.Thread(target=page_server.serve_forever, daemon=True),
        threading.Thread(target=origin_server.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target_url = "http://127.0.0.1:" + str(origin_server.server_address[1]) + "/"
            targets = root / "targets.json"
            outdir = root / "out"
            targets.write_text(json.dumps([{"url": target_url, "title": "redirect", "score": 100}]), encoding="utf-8")
            process = subprocess.run([
                sys.executable,
                str(SCANNER),
                "--input", str(targets),
                "--outdir", str(outdir),
                "--workers", "2",
                "--timeout", "3",
                "--phase2-timeout", "30",
                "--dry-run",
                "--disable-api-fuzz",
                "--replay-scope", "none",
                "--no-proxy",
                "--fresh",
            ], text=True, capture_output=True, timeout=90)
            if process.returncode != 0:
                print(process.stdout)
                print(process.stderr)
                raise SystemExit(process.returncode)
            records = [
                json.loads(line)
                for line in (outdir / "phase2_inventory.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            assert len(records) == 1, records
            expected_base = target_url.rstrip("/")
            assert records[0]["base"] == expected_base, records[0]
            assert "/api/from-redirect" in records[0]["apis"], records[0]["apis"]
            assert str(page_server.server_address[1]) not in records[0]["base"], records[0]
    finally:
        origin_server.shutdown()
        page_server.shutdown()
        origin_server.server_close()
        page_server.server_close()


def main():
    tests = [
        test_oas3_get_override_headers_and_safe_path_seed,
        test_oas3_request_body_ref_composition_and_content_isolation,
        test_swagger2_body_form_methods_and_path_item_ref,
        test_server_override_external_quarantine_and_no_recursive_prefixes,
        test_refs_limits_pointer_escaping_invalid_items_and_determinism,
        test_httpx_original_preference_and_fallback,
        test_scanner_profile_mapping_scheduling_serialization_and_replay,
        test_replay_metadata_order_identity_and_stream_recovery,
        test_replay_numeric_spec_and_hash_determinism,
        test_end_to_end_documented_methods_params_and_content_types,
        test_same_host_cross_port_redirect_preserves_original_scan_base,
    ]
    for test in tests:
        test()
        print(test.__name__ + ": PASS")
    print("V32 OPENAPI INVENTORY PASS")


if __name__ == "__main__":
    main()

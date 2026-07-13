#!/usr/bin/env python3
"""Offline loopback regression for opt-in exact GET+POST coverage."""

import copy
import json
import os
import subprocess
import sys
import threading
import time
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from pipeline import deep_scanner as scanner


FILE_JSON_PATH = "/api/dual/upload-json"
FILE_FORM_PATH = "/api/dual/import-form"


class MethodHandler(BaseHTTPRequestHandler):
    records = []
    lock = threading.Lock()

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        body_keys = set()
        try:
            if content_type == "application/json" and body:
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict):
                    body_keys = set(parsed)
            elif content_type == "application/x-www-form-urlencoded" and body:
                body_keys = set(parse_qs(body.decode("utf-8"), keep_blank_values=True))
        except Exception:
            body_keys = {"__parse_error__"}
        split = urlsplit(self.path)
        record = {
            "method": self.command,
            "path": split.path,
            "query_keys": tuple(sorted({key for key, _value in parse_qsl(split.query, keep_blank_values=True)})),
            "content_type": content_type,
            "body_length": len(body),
            "body_keys": tuple(sorted(body_keys)),
            "has_authorization": bool(self.headers.get("Authorization")),
        }
        with self.lock:
            type(self).records.append(record)
        response_body = b'{"code":0,"data":[{"id":1}]}' if (
            split.path == "/api/dual/get-finding" and self.command == "GET"
        ) else b"{}"
        status = 200 if len(response_body) > 2 else 404
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, *_args):
        pass


def build_target(base):
    exact = [
        "/api/dual/unknown",
        "/api/dual/json",
        "/api/dual/form",
        "/api/dual/query",
        "/api/dual/action-delete",
        "/api/dual/explicit-post",
        "/api/dual/items/1",
        "/api/dual/upload",
        FILE_JSON_PATH,
        FILE_FORM_PATH,
        "/api/dual/schema-only-json",
        "/api/dual/blocked",
        "/api/dual/get-finding",
    ]
    heuristic = "/guess/dual-heuristic"
    prefix = "/prefix/dual-only"
    profile = scanner.empty_param_profile()
    profile["names"].add("globalOnly")
    profile["seeds"].add("globalSeed")
    profile["api_methods"]["/api/dual/action-delete"] = {"delete"}
    profile["api_methods"]["/api/dual/explicit-post"] = {"post"}
    profile["api_param_sources"]["/api/dual/json"] = {
        "json": {"jsonAlpha", "jsonBeta"},
    }
    profile["api_content_types"]["/api/dual/json"] = {"application/json"}
    profile["api_param_sources"]["/api/dual/form"] = {
        "form": {"formAlpha", "formBeta"},
    }
    profile["api_content_types"]["/api/dual/form"] = {
        "application/x-www-form-urlencoded",
    }
    profile["api_param_sources"]["/api/dual/query"] = {
        "query": {"queryAlpha", "queryBeta"},
    }
    profile["api_param_sources"]["/api/dual/explicit-post"] = {
        "json": {"explicitAlpha"},
    }
    profile["api_content_types"]["/api/dual/explicit-post"] = {"application/json"}
    profile["api_params"]["/api/dual/items/1"] = {"itemId"}
    profile["api_param_sources"]["/api/dual/items/1"] = {"path": {"itemId"}}
    profile["api_content_types"]["/api/dual/upload"] = {"multipart/form-data"}
    profile["api_param_sources"][FILE_JSON_PATH] = {
        "json": {"fileName", "metadata"},
    }
    profile["api_content_types"][FILE_JSON_PATH] = {"application/json"}
    profile["api_param_sources"][FILE_FORM_PATH] = {
        "form": {"fileName", "metadata"},
    }
    profile["api_content_types"][FILE_FORM_PATH] = {
        "application/x-www-form-urlencoded",
    }
    profile["api_content_types"]["/api/dual/schema-only-json"] = {"application/json"}
    profile["api_params"]["/api/dual/blocked"] = {"blockedQuery", "blockedBody"}
    profile["api_param_sources"]["/api/dual/blocked"] = {
        "query": {"blockedQuery"}, "json": {"blockedBody"},
    }
    profile["api_content_types"]["/api/dual/blocked"] = {"application/json"}
    profile["api_param_blocked"].add("/api/dual/blocked")
    profile["file_seeds"].add("local-file-evidence.bin")
    meta = {
        api: {"confidence": 0.95, "sources": ["openapi"]}
        for api in exact
    }
    meta[heuristic] = {"confidence": 0.35, "sources": ["baseline"]}
    meta[prefix] = {"confidence": 0.25, "sources": ["prefix_inventory"]}
    return {
        "base": base,
        "apis": exact + [heuristic, prefix],
        "api_meta": meta,
        "param_profile": profile,
    }, exact, heuristic, prefix


def records_for(path):
    return [record for record in MethodHandler.records if record["path"] == path]


def run_dual_exact(target, tracker, ledger):
    tasks = scanner.exact_api_sweep_plan([target], tracker=tracker)
    for item, api in tasks:
        tracker.mark_scheduled(item["base"], api, "exact")
        tracker.mark_post_scheduled(
            item["base"], api,
            scanner.exact_post_body_kind(item.get("param_profile"), api),
        )

    def worker(task):
        item, api = task
        profile = item["param_profile"]
        tests = scanner.exact_dual_method_bypass_tests(profile, api, scanner.FAST_BYPASS)
        findings = scanner.test_api(
            item["base"], api, tests,
            short_circuit=False, param_profile=profile,
            allow_param_probe=True, single_variant=False,
            coverage_tracker=tracker, coverage_kind="exact",
            opportunity_ledger=ledger, exact_dual_method=True,
        )
        return item["base"], api, findings

    def done(result):
        tracker.mark_completed(result[0], result[1])

    stats = scanner.run_task_pool(
        tasks, 4, 0, "v39/dual-exact", worker, done, progress_every=0,
    )
    return tasks, stats


def assert_dual_method_loopback():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MethodHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    target, exact, heuristic, prefix = build_target(base)
    old = {
        "post_every_api": scanner.args.post_every_api,
        "max_requests_per_host": scanner.args.max_requests_per_host,
        "min_delay_ms": scanner.args.min_delay_ms,
        "max_rps_per_host": scanner.args.max_rps_per_host,
        "disable_file_hunter": scanner.args.disable_file_hunter,
        "capture_finding_evidence": scanner.args.capture_finding_evidence,
    }
    scanner.args.post_every_api = True
    scanner.args.max_requests_per_host = 0
    scanner.args.min_delay_ms = 0
    scanner.args.max_rps_per_host = 0
    scanner.args.disable_file_hunter = True
    scanner.args.capture_finding_evidence = False
    scanner.PHASE3_RATE_STATE.clear()
    scanner.CATCH_ALL_BASELINES.clear()
    MethodHandler.records = []
    request_data = []
    original_request = scanner.Request

    def capture_request_data(*request_args, **request_kwargs):
        request = original_request(*request_args, **request_kwargs)
        if request.get_method() == "POST":
            with MethodHandler.lock:
                request_data.append((urlsplit(request.full_url).path, request.data))
        return request

    scanner.Request = capture_request_data
    tracker = scanner.ApiCoverageTracker()
    ledger = scanner.Phase3OpportunityLedger()
    try:
        tasks, stats = run_dual_exact(target, tracker, ledger)
        assert len(tasks) == len(exact)
        assert set(api for _item, api in tasks) == set(exact)
        assert [api for _item, api in tasks] == [
            api for _item, api in scanner.exact_api_sweep_plan([target])
        ]
        assert stats == scanner.TaskPoolStats(len(exact), len(exact), 0, 0), stats
        for path in exact:
            methods = [record["method"] for record in records_for(path)]
            assert methods.count("GET") == 1 and methods.count("POST") == 1, (path, methods)
            assert not [method for method in methods if method not in ("GET", "POST")]
            assert not any(record["has_authorization"] for record in records_for(path))

        unknown_post = next(record for record in records_for("/api/dual/unknown") if record["method"] == "POST")
        assert unknown_post["body_length"] == 0
        assert unknown_post["content_type"] == ""
        assert unknown_post["body_keys"] == ()

        json_post = next(record for record in records_for("/api/dual/json") if record["method"] == "POST")
        assert json_post["content_type"] == "application/json"
        assert json_post["body_keys"] == ("jsonAlpha", "jsonBeta")
        form_post = next(record for record in records_for("/api/dual/form") if record["method"] == "POST")
        assert form_post["content_type"] == "application/x-www-form-urlencoded"
        assert form_post["body_keys"] == ("formAlpha", "formBeta")
        query_post = next(record for record in records_for("/api/dual/query") if record["method"] == "POST")
        assert query_post["query_keys"] == ("queryAlpha", "queryBeta")
        assert query_post["body_length"] == 0
        for record in records_for("/api/dual/items/1"):
            assert record["path"] == "/api/dual/items/1"
            assert record["query_keys"] == ()
        upload_post = next(record for record in records_for("/api/dual/upload") if record["method"] == "POST")
        assert upload_post["body_length"] == 0
        assert upload_post["content_type"] == ""
        for path in (FILE_JSON_PATH, FILE_FORM_PATH):
            assert scanner.is_file_endpoint(path)
            opportunity = scanner.exact_post_body_opportunity(target["param_profile"], path)
            assert opportunity["body_kind"] == "empty"
            assert opportunity["content_type"] is None
            file_post = next(record for record in records_for(path) if record["method"] == "POST")
            assert file_post["body_length"] == 0
            assert file_post["body_keys"] == ()
            assert file_post["content_type"] == ""
            assert file_post["query_keys"] == ()
            captured = [data for request_path, data in request_data if request_path == path]
            assert captured and all(data is None for data in captured), (path, captured)
        schema_post = next(record for record in records_for("/api/dual/schema-only-json") if record["method"] == "POST")
        assert schema_post["body_length"] == 0
        assert schema_post["body_keys"] == ()
        assert schema_post["content_type"] == ""
        for record in records_for("/api/dual/blocked"):
            assert record["query_keys"] == ()
        blocked_post = next(record for record in records_for("/api/dual/blocked") if record["method"] == "POST")
        assert blocked_post["body_length"] == 0
        assert blocked_post["body_keys"] == ()
        assert blocked_post["content_type"] == ""
        assert all("globalOnly" not in record["query_keys"] for record in MethodHandler.records)
        assert all("globalOnly" not in record["body_keys"] for record in MethodHandler.records)

        # Heuristic and prefix paths remain under ordinary GET-only authority.
        for path in (heuristic, prefix):
            tracker.mark_scheduled(base, path, "heuristic")
            scanner.test_api(
                base, path, scanner.FAST_BYPASS,
                param_profile=target["param_profile"], allow_param_probe=False,
                single_variant=True, opportunity_ledger=ledger,
                coverage_tracker=tracker, coverage_kind="heuristic",
            )
            assert [record["method"] for record in records_for(path)] == ["GET"]

        # Re-entering the same exact dual provider cannot retransmit either mode.
        before = len(MethodHandler.records)
        for path in exact:
            duplicate_tests = scanner.exact_dual_method_bypass_tests(
                target["param_profile"], path, scanner.FAST_BYPASS,
            )
            scanner.test_api(
                base, path, duplicate_tests,
                short_circuit=False, param_profile=target["param_profile"],
                coverage_tracker=tracker, coverage_kind="exact",
                opportunity_ledger=ledger, exact_dual_method=True,
            )
        assert len(MethodHandler.records) == before

        coverage = tracker.snapshot(base)
        assert coverage["exact_post_eligible"] == len(exact)
        assert coverage["exact_post_scheduled"] == len(exact)
        assert coverage["exact_post_attempted"] == len(exact)
        assert coverage["exact_post_completed"] == len(exact)
        assert coverage["exact_get_eligible"] == len(exact)
        assert coverage["exact_get_scheduled"] == len(exact)
        assert coverage["exact_get_attempted"] == len(exact)
        assert coverage["exact_get_completed"] == len(exact)
        for stage in ("eligible", "scheduled", "attempted", "completed"):
            assert coverage[f"exact_post_empty_body_{stage}"] == len(exact) - 3
            assert coverage[f"exact_post_bound_body_{stage}"] == 3
        assert coverage["exact_post_skipped_by_request_budget"] == 0
        assert coverage["exact_post_skipped_by_timeout"] == 0
        assert coverage["coverage_complete"] is True, coverage

        wire = scanner.serialize_scan_record({**copy.deepcopy(target), "api_coverage": coverage})
        restored = scanner.deserialize_scan_record(json.loads(json.dumps(wire, allow_nan=False)))
        assert restored["api_coverage"] == coverage
        malformed = copy.deepcopy(wire)
        malformed["api_coverage"]["exact_post_attempted"] = "6"
        try:
            scanner.deserialize_scan_record(malformed)
        except ValueError:
            pass
        else:
            raise AssertionError("malformed exact POST coverage accepted")
        for mutate in (
            lambda value: value.__setitem__("exact_get_scheduled", value["exact_get_scheduled"] - 1),
            lambda value: value.__setitem__("exact_post_skipped_by_request_budget", 1),
            lambda value: value.__setitem__("exact_post_empty_body_completed", 0),
        ):
            inconsistent = copy.deepcopy(coverage)
            mutate(inconsistent)
            try:
                scanner.canonical_api_coverage(inconsistent)
            except ValueError:
                pass
            else:
                raise AssertionError("inconsistent dual-method coverage accepted")
    finally:
        scanner.Request = original_request
        server.shutdown()
        server.server_close()
        for key, value in old.items():
            setattr(scanner.args, key, value)


def assert_file_post_helper_fail_closed():
    profile = scanner.empty_param_profile()
    for path, source, content_type in (
        (FILE_JSON_PATH, "json", "application/json"),
        (FILE_FORM_PATH, "form", "application/x-www-form-urlencoded"),
    ):
        profile["api_param_sources"][path] = {
            source: {"fileName", "metadata"},
        }
        profile["api_param_shapes"][path] = {
            source: {"metadata": {"fileName"}},
        }
        profile["api_param_specs"][path] = {
            source: {
                "fileName": {
                    "name": "fileName", "source": source,
                    "leaf": True, "auto_materialize": True,
                },
            },
        }
        profile["api_content_types"][path] = {content_type}
        opportunity = scanner.exact_post_body_opportunity(profile, path)
        assert opportunity["body_kind"] == "empty"
        assert opportunity["content_type"] is None

    helper_names = (
        "api_content_types_for", "bound_param_specs_by_source",
        "bound_param_names_by_source", "bound_param_shapes_by_source",
    )
    originals = {name: getattr(scanner, name) for name in helper_names}

    def unexpected_profile_lookup(*_args, **_kwargs):
        raise AssertionError("file endpoint consulted body profile evidence")

    try:
        for name in helper_names:
            setattr(scanner, name, unexpected_profile_lookup)
        for path in (FILE_JSON_PATH, FILE_FORM_PATH):
            opportunity = scanner.exact_post_body_opportunity(profile, path)
            assert opportunity["body_kind"] == "empty"
            assert opportunity["content_type"] is None
    finally:
        for name, helper in originals.items():
            setattr(scanner, name, helper)


def exact_target(base, count):
    paths = [f"/api/coverage/item-{index}" for index in range(count)]
    return {
        "base": base,
        "apis": paths,
        "api_meta": {path: {"confidence": 0.95, "sources": ["swagger"]} for path in paths},
        "param_profile": scanner.empty_param_profile(),
    }, paths


def assert_post_budget_cap_timeout_accounting():
    old = scanner.args.post_every_api
    scanner.args.post_every_api = True
    try:
        budget_target, budget_paths = exact_target("http://127.0.0.1:39101", 1)
        budget_tracker = scanner.ApiCoverageTracker()
        budget_tasks = scanner.exact_api_sweep_plan([budget_target], tracker=budget_tracker)
        item, api = budget_tasks[0]
        budget_tracker.mark_scheduled(item["base"], api, "exact")
        budget_tracker.mark_post_scheduled(item["base"], api, "empty")
        budget_tracker.mark_attempted(item["base"], api, "exact", method="GET")
        budget_tracker.mark_completed(item["base"], api)
        budget_tracker.mark_budget(item["base"], api, method="POST")
        budget = budget_tracker.snapshot(item["base"])
        assert budget["exact_post_skipped_by_request_budget"] == 1
        assert "exact_post_request_budget" in budget["incomplete_reasons"]

        cap_target, _cap_paths = exact_target("http://127.0.0.1:39102", 3)
        cap_tracker = scanner.ApiCoverageTracker()
        cap_tasks = scanner.exact_api_sweep_plan([cap_target], max_per_target=1, tracker=cap_tracker)
        assert len(cap_tasks) == 1
        cap = cap_tracker.snapshot(cap_target["base"])
        assert cap["exact_post_eligible"] == 3
        assert cap["exact_post_skipped_by_exact_cap"] == 2
        assert "exact_post_max" in cap["incomplete_reasons"]

        timeout_target, timeout_paths = exact_target("http://127.0.0.1:39103", 2)
        timeout_tracker = scanner.ApiCoverageTracker()
        timeout_tasks = scanner.exact_api_sweep_plan([timeout_target], tracker=timeout_tracker)
        for target, path in timeout_tasks:
            timeout_tracker.mark_scheduled(target["base"], path, "exact")
            timeout_tracker.mark_post_scheduled(target["base"], path, "empty")

        def worker(task):
            time.sleep(0.05)
            return task

        def done(task):
            timeout_tracker.mark_completed(task[0]["base"], task[1])

        def timed_out(task):
            timeout_tracker.mark_timeout(task[0]["base"], task[1])

        stats = scanner.run_task_pool(
            timeout_tasks, 1, 0.01, "v39/post-timeout", worker, done,
            progress_every=0, on_timeout=timed_out,
        )
        frozen = timeout_tracker.snapshot(timeout_target["base"])
        assert stats == scanner.TaskPoolStats(2, 1, 1, 2), stats
        assert frozen["exact_post_skipped_by_timeout"] == 1
        assert "exact_post_timeout" in frozen["incomplete_reasons"]
        time.sleep(0.05)
        assert timeout_tracker.snapshot(timeout_target["base"]) == frozen
        assert timeout_paths[1] not in timeout_tracker._states[timeout_target["base"]]["_attempted_post"]
    finally:
        scanner.args.post_every_api = old


def assert_blocked_round_trip_and_replay():
    path = "/api/replay/blocked-dual"
    profile = scanner.empty_param_profile()
    profile["api_params"][path] = {"opaqueQuery", "opaqueBody"}
    profile["api_param_sources"][path] = {
        "query": {"opaqueQuery"}, "json": {"opaqueBody"},
    }
    profile["api_content_types"][path] = {"application/json"}
    profile["api_param_blocked"].add(path)
    source = {
        "base": "http://127.0.0.1:39201",
        "apis": [path],
        "api_meta": {path: {"confidence": 0.95, "sources": ["openapi"]}},
        "param_profile": profile,
    }
    source = scanner.deserialize_scan_record(json.loads(json.dumps(scanner.serialize_scan_record(source))))
    destination = {
        "base": "http://127.0.0.1:39202",
        "apis": ["/baseline/local"],
        "api_meta": {"/baseline/local": {"confidence": 0.35, "sources": ["baseline"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    scanner.apply_cross_base_replay([source, destination], "global", 0)
    restored = destination["param_profile"]
    assert path in restored["api_param_blocked"]
    assert scanner.exact_path_local_query_suffix(path, restored) == ""
    opportunity = scanner.exact_post_body_opportunity(restored, path)
    assert opportunity["body_kind"] == "empty"
    assert opportunity["content_type"] is None
    assert opportunity["payload"] == {}

    merged_blocked = copy.deepcopy(restored)
    scanner.merge_param_profiles(merged_blocked, scanner.empty_param_profile())
    assert path in merged_blocked["api_param_blocked"]
    trusted_profile = scanner.empty_param_profile()
    trusted_profile["api_params"][path] = {"trustedQuery"}
    scanner.merge_param_profiles(merged_blocked, trusted_profile)
    assert path not in merged_blocked["api_param_blocked"]

    trusted_destination = {
        "base": "http://127.0.0.1:39203",
        "apis": [path],
        "api_meta": {path: {"confidence": 0.95, "sources": ["js_request"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    trusted_destination["param_profile"]["api_params"][path] = {"trustedQuery"}
    scanner.carry_replay_param_profile(trusted_destination, source, path)
    assert path not in trusted_destination["param_profile"]["api_param_blocked"]


def assert_slot_cancellation_and_get_obligation():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MethodHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    target, paths = exact_target(base, 1)
    path = paths[0]
    old_flag = scanner.args.post_every_api
    old_baseline = scanner.get_catch_all_baseline
    old_acquire = scanner.acquire_phase3_request_slot
    scanner.args.post_every_api = True
    tracker = scanner.ApiCoverageTracker()
    scanner.exact_api_sweep_plan([target], tracker=tracker)
    tracker.mark_scheduled(base, path, "exact")
    ledger = scanner.Phase3OpportunityLedger()
    calls = {"count": 0}

    def acquire(_url, consume_probe_hold=False):
        calls["count"] += 1
        return (True, "") if calls["count"] == 1 else (False, "task_pool_timeout")

    scanner.get_catch_all_baseline = lambda *_args, **_kwargs: (None, "")
    scanner.acquire_phase3_request_slot = acquire
    MethodHandler.records = []
    try:
        tests = scanner.exact_dual_method_bypass_tests(target["param_profile"], path, scanner.FAST_BYPASS)
        scanner.test_api(
            base, path, tests, short_circuit=False,
            param_profile=target["param_profile"], coverage_tracker=tracker,
            coverage_kind="exact", opportunity_ledger=ledger,
            exact_dual_method=True,
        )
        tracker.mark_completed(base, path)
        coverage = tracker.snapshot(base)
        assert coverage["exact_get_attempted"] == 1
        assert coverage["exact_get_completed"] == 1
        assert coverage["exact_post_attempted"] == 0
        assert coverage["exact_post_completed"] == 0
        assert coverage["exact_post_skipped_by_timeout"] == 1
        assert coverage["completed_unique_exact"] == 0
        assert coverage["coverage_complete"] is False
        wire = scanner.serialize_scan_record({
            **copy.deepcopy(target), "api_coverage": coverage,
        })
        forged = json.loads(json.dumps(wire, allow_nan=False))
        forged_coverage = forged["api_coverage"]
        forged_coverage["completed_unique_exact"] = 1
        forged_coverage["incomplete_reasons"].remove("eligible_exact_incomplete")
        try:
            scanner.deserialize_scan_record(forged)
        except ValueError:
            pass
        else:
            raise AssertionError("GET-only coverage forged path completion")
        methods = [record["method"] for record in records_for(path)]
        assert methods and set(methods) == {"GET"}, methods
    finally:
        scanner.get_catch_all_baseline = old_baseline
        scanner.acquire_phase3_request_slot = old_acquire
        scanner.args.post_every_api = old_flag
        server.shutdown()
        server.server_close()

    old_flag = scanner.args.post_every_api
    scanner.args.post_every_api = True
    try:
        post_only_target, post_only_paths = exact_target("http://127.0.0.1:39204", 1)
        post_only_tracker = scanner.ApiCoverageTracker()
        scanner.exact_api_sweep_plan([post_only_target], tracker=post_only_tracker)
        post_path = post_only_paths[0]
        post_only_tracker.mark_scheduled(post_only_target["base"], post_path, "exact")
        post_only_tracker.mark_attempted(
            post_only_target["base"], post_path, "exact",
            method="POST", body_kind="empty",
        )
        post_only_tracker.mark_completed(post_only_target["base"], post_path)
        post_only = post_only_tracker.snapshot(post_only_target["base"])
        assert post_only["exact_post_completed"] == 1
        assert post_only["exact_get_completed"] == 0
        assert post_only["completed_unique_exact"] == 0
        assert post_only["coverage_complete"] is False
        wire = scanner.serialize_scan_record({
            **copy.deepcopy(post_only_target), "api_coverage": post_only,
        })
        forged = json.loads(json.dumps(wire, allow_nan=False))
        forged_coverage = forged["api_coverage"]
        forged_coverage["completed_unique_exact"] = 1
        forged_coverage["incomplete_reasons"].remove("eligible_exact_incomplete")
        try:
            scanner.deserialize_scan_record(forged)
        except ValueError:
            pass
        else:
            raise AssertionError("POST-only coverage forged path completion")
    finally:
        scanner.args.post_every_api = old_flag


def assert_leaf_authorization_guard():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MethodHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    path = "/api/leaf-guard"
    old = scanner.args.post_every_api
    scanner.args.post_every_api = False
    MethodHandler.records = []
    scanner.CATCH_ALL_BASELINES.clear()
    try:
        tests = scanner.exact_dual_method_bypass_tests(scanner.empty_param_profile(), path, scanner.FAST_BYPASS)
        scanner.test_api(
            base, path, tests, short_circuit=False,
            param_profile=scanner.empty_param_profile(), coverage_kind="exact",
            exact_dual_method=True,
        )
        methods = [record["method"] for record in records_for(path)]
        assert methods and set(methods) == {"GET"}, methods
    finally:
        scanner.args.post_every_api = old
        server.shutdown()
        server.server_close()


def assert_cli_report_and_checkpoint():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MethodHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    exact_path = "/api/cli-dual"
    MethodHandler.records = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            target_file = tmp / "targets.json"
            wordlist = tmp / "exact.txt"
            outdir = tmp / "out"
            target_file.write_text(
                json.dumps([{"url": base, "title": "dual-method-loopback", "score": 1}]),
                encoding="utf-8",
            )
            wordlist.write_text(exact_path + "\n", encoding="utf-8")
            cmd = [
                sys.executable, os.path.join(ROOT, "pipeline", "deep_scanner.py"),
                "--input", str(target_file), "--outdir", str(outdir),
                "--extra-api-wordlist", str(wordlist), "--post-every-api",
                "--workers", "4", "--timeout", "2",
                "--phase2-timeout", "10", "--phase3a-timeout", "10",
                "--exact-sweep-timeout", "10", "--phase3b-layer-timeout", "10",
                "--skip-port-probe", "--no-proxy", "--disable-api-fuzz",
                "--disable-file-hunter", "--disable-rescue-baseline",
                "--config-service-base-mode", "off", "--replay-scope", "none",
                "--no-capture-finding-evidence", "--redact-raw-findings",
            ]
            proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=45)
            assert proc.returncode == 0, proc.stderr[-1000:]
            methods = [record["method"] for record in records_for(exact_path)]
            assert methods.count("GET") == 1 and methods.count("POST") == 1, methods

            checkpoint = json.loads((outdir / "api_coverage.json").read_text(encoding="utf-8"))
            report = json.loads((outdir / "report.json").read_text(encoding="utf-8"))
            checkpoint_coverage = checkpoint["api_coverage"]
            report_coverage = report["api_coverage"]
            assert checkpoint_coverage == report_coverage
            assert report["stats"]["api_coverage"] == report_coverage
            assert report_coverage["exact_post_eligible"] == 1
            assert report_coverage["exact_post_scheduled"] == 1
            assert report_coverage["exact_post_attempted"] == 1
            assert report_coverage["exact_post_completed"] == 1
            assert report_coverage["exact_post_empty_body_completed"] == 1
            assert report_coverage["exact_get_completed"] == 1
            assert report_coverage["coverage_complete"] is True
            markdown = (outdir / "report.md").read_text(encoding="utf-8")
            assert "exact_post_eligible/scheduled/attempted/completed: 1/1/1/1" in markdown
            assert exact_path not in markdown
            assert exact_path not in json.dumps(checkpoint["api_coverage"], sort_keys=True)
    finally:
        server.shutdown()
        server.server_close()


def assert_default_mode_unchanged():
    assert scanner.build_parser().parse_args([]).post_every_api is False
    profile = scanner.empty_param_profile()
    scheduled = scanner.scheduled_bypass_tests("/api/default-read", scanner.FAST_BYPASS, profile)
    assert [item[1] for item in scheduled] == ["GET"]
    target, paths = exact_target("http://127.0.0.1:39104", 1)
    tracker = scanner.ApiCoverageTracker()
    tasks = scanner.exact_api_sweep_plan([target], tracker=tracker)
    assert len(tasks) == 1
    tracker.mark_scheduled(target["base"], paths[0], "exact")
    tracker.mark_attempted(target["base"], paths[0], "exact", method="GET")
    tracker.mark_completed(target["base"], paths[0])
    coverage = tracker.snapshot(target["base"])
    assert coverage["exact_post_eligible"] == 0
    assert coverage["exact_post_scheduled"] == 0
    assert coverage["exact_get_completed"] == 0
    assert coverage["completed_unique_exact"] == 1
    assert coverage["coverage_complete"] is True
    wire = scanner.serialize_scan_record({
        **copy.deepcopy(target), "api_coverage": coverage,
    })
    restored = scanner.deserialize_scan_record(json.loads(json.dumps(wire)))
    assert restored["api_coverage"] == coverage


def main():
    assert_file_post_helper_fail_closed()
    assert_dual_method_loopback()
    assert_post_budget_cap_timeout_accounting()
    assert_blocked_round_trip_and_replay()
    assert_slot_cancellation_and_get_obligation()
    assert_leaf_authorization_guard()
    assert_cli_report_and_checkpoint()
    assert_default_mode_unchanged()
    print("V39 DUAL METHOD COVERAGE LAB PASS")


if __name__ == "__main__":
    main()

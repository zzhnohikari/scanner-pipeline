#!/usr/bin/env python3
"""Offline regression for the independently-exact Phase 3 sweep."""

import copy
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from pipeline import deep_scanner as scanner


class QuietHandler(BaseHTTPRequestHandler):
    attempts = 0
    paths = []
    lock = threading.Lock()

    def _reply(self):
        with self.lock:
            type(self).attempts += 1
            type(self).paths.append(self.path.split("?", 1)[0])
        body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _reply
    do_POST = _reply

    def log_message(self, *_args):
        pass


class SlowHandler(QuietHandler):
    delay = 0.15

    def _reply(self):
        with self.lock:
            type(self).attempts += 1
            type(self).paths.append(self.path.split("?", 1)[0])
        time.sleep(self.delay)
        body = b"{}"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = _reply
    do_POST = _reply


def exact_target(base, exact_count=502, heuristic_count=502):
    exact = [f"/api/exact-{index:04d}" for index in range(exact_count)]
    safe_post = "/api/search-late"
    delete_only = "/api/delete-late"
    action_post = "/api/create-late"
    heuristic = [f"/guess/item-{index:04d}" for index in range(heuristic_count)]
    apis = exact + [safe_post, delete_only, action_post] + heuristic
    meta = {
        api: {"confidence": 0.95, "sources": ["swagger"]}
        for api in exact + [safe_post, delete_only, action_post]
    }
    meta.update({api: {"confidence": 0.4, "sources": ["baseline"]} for api in heuristic})
    profile = scanner.empty_param_profile()
    profile["api_methods"][safe_post] = {"post"}
    profile["api_methods"][delete_only] = {"delete"}
    profile["api_methods"][action_post] = {"post"}
    profile["api_param_sources"][safe_post] = {"json": {"term"}}
    profile["api_param_sources"][action_post] = {"json": {"item"}}
    return {"base": base, "apis": apis, "api_meta": meta, "param_profile": profile}


def assert_all_exact_loopback():
    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    old = {
        "max_requests_per_host": scanner.args.max_requests_per_host,
        "min_delay_ms": scanner.args.min_delay_ms,
        "max_rps_per_host": scanner.args.max_rps_per_host,
        "allow_active_post": scanner.args.allow_active_post,
        "disable_file_hunter": scanner.args.disable_file_hunter,
    }
    scanner.args.max_requests_per_host = 0
    scanner.args.min_delay_ms = 0
    scanner.args.max_rps_per_host = 0
    scanner.args.allow_active_post = False
    scanner.args.disable_file_hunter = True
    scanner.PHASE3_RATE_STATE.clear()
    scanner.CATCH_ALL_BASELINES.clear()
    QuietHandler.attempts = 0
    try:
        target = exact_target(base)
        tracker = scanner.ApiCoverageTracker()
        tasks = scanner.exact_api_sweep_plan([target], tracker=tracker)
        assert len(tasks) == 503
        reversed_target = copy.deepcopy(target)
        reversed_target["apis"] = list(reversed(reversed_target["apis"]))
        reversed_tasks = scanner.exact_api_sweep_plan([reversed_target])
        assert [api for _item, api in reversed_tasks] == [api for _item, api in tasks]
        for item, api in tasks:
            tracker.mark_scheduled(item["base"], api, "exact")

        def worker(task):
            item, api = task
            profile, single = item.get("param_profile"), False
            tests = list(scanner.FAST_BYPASS) + scanner.body_probe_bypass_tests(profile, api)
            findings = scanner.test_api(
                item["base"], api, tests, short_circuit=True,
                param_profile=profile, allow_param_probe=True,
                single_variant=single, coverage_tracker=tracker,
                coverage_kind="exact",
            )
            return item["base"], api, findings

        def done(result):
            tracker.mark_completed(result[0], result[1])

        stats = scanner.run_task_pool(tasks, 16, 0, "v38/exact", worker, done, progress_every=0)
        assert stats.submitted == stats.completed == 503
        assert stats.timed_out is False and stats.skipped_timeout == 0
        coverage = tracker.snapshot(base)
        assert coverage["independently_exact_discovered"] == 505
        assert coverage["safe_eligible_exact"] == 503
        assert coverage["scheduled_unique_exact"] == 503
        assert coverage["attempted_unique_exact"] == 503
        assert coverage["completed_unique_exact"] == 503
        assert coverage["skipped_by_safety"] == {
            "action_post_not_enabled": 1,
            "delete_only": 1,
        }
        assert coverage["coverage_complete"] is True
        assert QuietHandler.attempts >= 503
        heuristic = scanner.phase3_heuristic_seed_tasks([target])
        assert all(not scanner.is_independently_exact_api(item, api) for item, api in heuristic)

        capped = scanner.ApiCoverageTracker()
        capped_tasks = scanner.exact_api_sweep_plan([target], max_per_target=7, tracker=capped)
        assert len(capped_tasks) == 7
        capped_snapshot = capped.snapshot(base)
        assert capped_snapshot["skipped_by_exact_cap"] == 496
        assert capped_snapshot["coverage_complete"] is False
        assert "exact_api_max" in capped_snapshot["incomplete_reasons"]

        wire = json.dumps(tracker.global_snapshot(), allow_nan=False, sort_keys=True)
        assert "/api/" not in wire and "exact-" not in wire and "guess/" not in wire
    finally:
        server.shutdown()
        server.server_close()
        for key, value in old.items():
            setattr(scanner.args, key, value)


def assert_replay_unlimited_and_capped():
    paths = [f"/openapi/replay-{index:04d}" for index in range(405)]
    source = {
        "base": "http://127.0.0.1:31001",
        "apis": paths,
        "api_meta": {api: {"confidence": 0.9, "sources": ["openapi"]} for api in paths},
        "param_profile": scanner.empty_param_profile(),
    }
    destination = {
        "base": "http://127.0.0.1:31002",
        "apis": ["/baseline/only"],
        "api_meta": {"/baseline/only": {"confidence": 0.3, "sources": ["baseline"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    unlimited = [copy.deepcopy(source), copy.deepcopy(destination)]
    scanner.apply_cross_base_replay(unlimited, "global", 0)
    assert len(unlimited[1]["replay_apis"]) == 405
    assert unlimited[1]["replay_skipped_by_cap"] == 0
    unlimited_tracker = scanner.ApiCoverageTracker()
    unlimited_tasks = scanner.exact_api_sweep_plan([unlimited[1]], tracker=unlimited_tracker)
    for item, api in unlimited_tasks:
        unlimited_tracker.mark_scheduled(item["base"], api, "exact")
        unlimited_tracker.mark_attempted(item["base"], api, "exact")
        unlimited_tracker.mark_completed(item["base"], api)
    unlimited_coverage = unlimited_tracker.snapshot(unlimited[1]["base"])
    assert unlimited_coverage["coverage_complete"] is True, unlimited_coverage

    capped = [copy.deepcopy(source), copy.deepcopy(destination)]
    scanner.apply_cross_base_replay(capped, "global", 400)
    assert len(capped[1]["replay_apis"]) == 400
    assert capped[1]["replay_exact_discovered"] == 405
    assert capped[1]["replay_skipped_by_cap"] == 5
    capped_tracker = scanner.ApiCoverageTracker()
    capped_tasks = scanner.exact_api_sweep_plan([capped[1]], tracker=capped_tracker)
    for item, api in capped_tasks:
        capped_tracker.mark_scheduled(item["base"], api, "exact")
        capped_tracker.mark_attempted(item["base"], api, "exact")
        capped_tracker.mark_completed(item["base"], api)
    capped_coverage = capped_tracker.snapshot(capped[1]["base"])
    assert capped_coverage["coverage_complete"] is False, capped_coverage
    assert capped_coverage["incomplete_reasons"] == ["replay_max_apis"], capped_coverage

    reversed_records = [copy.deepcopy(destination), copy.deepcopy(source)]
    scanner.apply_cross_base_replay(reversed_records, "global", 400)
    assert reversed_records[0]["replay_apis"] == capped[1]["replay_apis"]


def assert_same_path_replay_promotion_coverage():
    path = "/api/promoted-read"
    source = {
        "base": "http://127.0.0.1:31101",
        "apis": [path],
        "api_meta": {path: {"confidence": 0.95, "sources": ["openapi"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    destination = {
        "base": "http://127.0.0.1:31102",
        "apis": [path],
        "api_meta": {path: {"confidence": 0.35, "sources": ["baseline"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    scanner.apply_cross_base_replay([source, destination], "global", 0)
    assert destination.get("replay_apis") == []
    assert destination.get("replay_promoted_apis") == [path]
    tracker = scanner.ApiCoverageTracker()
    tasks = scanner.exact_api_sweep_plan([destination], tracker=tracker)
    assert [api for _target, api in tasks] == [path]
    tracker.mark_scheduled(destination["base"], path, "exact")
    tracker.mark_attempted(destination["base"], path, "exact")
    tracker.mark_completed(destination["base"], path)
    coverage = tracker.snapshot(destination["base"])
    assert (
        coverage["replay_exact_discovered"], coverage["replay_exact_scheduled"],
        coverage["replay_exact_attempted"], coverage["replay_exact_completed"],
    ) == (1, 1, 1, 1), coverage
    assert path not in [api for _target, api in scanner.phase3_seed_tasks([destination])]


def assert_config_rest_exact_dedup():
    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    path = "/api/exact-config"
    target = {
        "base": base,
        "apis": [path],
        "api_meta": {path: {"confidence": 0.95, "sources": ["openapi", "js_request"]}},
        "param_profile": scanner.empty_param_profile(),
        "config_rest_candidates": [{"path": path, "source": "rest_convention"}],
    }
    tracker = scanner.ApiCoverageTracker()
    scanner.exact_api_sweep_plan([target], tracker=tracker)
    tracker.mark_scheduled(base, path, "exact")
    ledger = scanner.Phase3OpportunityLedger()
    scanner.PHASE3_RATE_STATE.clear()
    scanner.CATCH_ALL_BASELINES.clear()
    QuietHandler.attempts = 0
    QuietHandler.paths = []
    try:
        scanner.test_api(
            base, path, scanner.FAST_BYPASS,
            param_profile=target["param_profile"], allow_param_probe=False,
            single_variant=True,
            coverage_tracker=tracker, coverage_kind="exact",
            opportunity_ledger=ledger,
        )
        tracker.mark_completed(base, path)
        assert scanner.config_rest_phase3_tasks([target]) == []
        scanner.test_api(
            base, path, [("CONFIG_REST_GET_no_auth", "GET", None, None, {})],
            param_profile=scanner.empty_param_profile(), allow_param_probe=False,
            single_variant=True, coverage_tracker=tracker,
            coverage_kind="heuristic", opportunity_ledger=ledger,
        )
        coverage = tracker.snapshot(base)
        assert QuietHandler.paths.count(path) == 1, QuietHandler.paths
        assert coverage["attempted_unique_exact"] == coverage["completed_unique_exact"] == 1
        assert coverage["heuristic_scheduled"] == coverage["heuristic_attempted"] == 0
    finally:
        server.shutdown()
        server.server_close()


def assert_timeout_drains_and_freezes():
    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    old = (scanner.args.min_delay_ms, scanner.args.max_rps_per_host, scanner.args.max_requests_per_host)
    scanner.args.min_delay_ms = 0
    scanner.args.max_rps_per_host = 0
    scanner.args.max_requests_per_host = 0
    scanner.PHASE3_RATE_STATE.clear()
    scanner.CATCH_ALL_BASELINES.clear()
    SlowHandler.attempts = 0
    try:
        target = exact_target(base, exact_count=3, heuristic_count=0)
        keep = [api for api in target["apis"] if api.startswith("/api/exact-")]
        target["apis"] = keep
        target["api_meta"] = {api: target["api_meta"][api] for api in keep}
        scanner._invalidate_api_meta_index(target)
        tracker = scanner.ApiCoverageTracker()
        tasks = scanner.exact_api_sweep_plan([target], tracker=tracker)
        for item, api in tasks:
            tracker.mark_scheduled(item["base"], api, "exact")

        def worker(task):
            item, api = task
            url = item["base"] + api
            allowed, reason = scanner.acquire_phase3_request_slot(url)
            assert allowed, reason
            tracker.mark_attempted(item["base"], api, "exact")
            response = scanner.scoped_urlopen(scanner.Request(url, method="GET"), timeout=2)
            response.read()
            return item["base"], api

        def done(result):
            tracker.mark_completed(result[0], result[1])

        def timed_out(task):
            tracker.mark_timeout(task[0]["base"], task[1])

        single_stats = scanner.run_task_pool(
            tasks[:1], 1, 0.01, "v38/timeout-single", worker, done,
            progress_every=0, on_timeout=timed_out,
        )
        assert single_stats.completed == 1 and single_stats.skipped_timeout == 0, single_stats
        assert single_stats.deadline_pending == 1 and single_stats.timed_out is True

        # One running request drains to completion; one queued task is
        # actually cancelled/skipped and is the only skipped_timeout item.
        remaining = tasks[1:]
        queued_stats = scanner.run_task_pool(
            remaining, 1, 0.01, "v38/timeout-queued", worker, done,
            progress_every=0, on_timeout=timed_out,
        )
        frozen = tracker.snapshot(base)
        request_count = SlowHandler.attempts
        assert queued_stats.completed == 1 and queued_stats.skipped_timeout == 1, queued_stats
        assert queued_stats.completed + queued_stats.skipped_timeout <= queued_stats.submitted
        assert frozen["scheduled_unique_exact"] == 3
        assert frozen["completed_unique_exact"] + frozen["skipped_by_timeout"] == 3, frozen
        assert frozen["coverage_complete"] is False
        time.sleep(0.25)
        assert tracker.snapshot(base) == frozen
        assert SlowHandler.attempts == request_count
    finally:
        server.shutdown()
        server.server_close()
        scanner.args.min_delay_ms, scanner.args.max_rps_per_host, scanner.args.max_requests_per_host = old


def assert_task_pool_invocation_state_accounting():
    def run_case(tasks, worker, label):
        events = []

        def wrapped(task):
            events.append(("start", task))
            value = worker(task, events)
            events.append(("done", task))
            return value

        def on_result(value):
            events.append(("result", value))

        def on_timeout(task):
            events.append(("timeout", task))

        stats = scanner.run_task_pool(
            tasks, 1, 0.01, label, wrapped, on_result,
            progress_every=0, on_timeout=on_timeout,
        )
        frozen = tuple(events)
        time.sleep(0.05)
        assert tuple(events) == frozen
        return stats, events

    # Started before the deadline, then delayed before any request-slot mark.
    # Its normal result remains completed and receives no timeout callback.
    def delayed_no_attempt(task, _events):
        time.sleep(0.05)
        return task

    normal_stats, normal_events = run_case(
        ["normal"], delayed_no_attempt, "v38/invocation-normal",
    )
    assert normal_stats == scanner.TaskPoolStats(1, 1, 0, 1), normal_stats
    assert normal_events == [
        ("start", "normal"), ("done", "normal"), ("result", "normal"),
    ], normal_events

    # With one worker, the second future remains queued and is the only task
    # eligible for skipped_timeout/on_timeout.
    queued_stats, queued_events = run_case(
        ["running", "queued"], delayed_no_attempt, "v38/invocation-queued",
    )
    assert queued_stats == scanner.TaskPoolStats(2, 1, 1, 2), queued_stats
    assert queued_events == [
        ("start", "running"), ("done", "running"),
        ("result", "running"), ("timeout", "queued"),
    ], queued_events

    # An invocation may mark an attempt after the diagnostic deadline. It is
    # still a drained normal result, never a skipped timeout.
    def delayed_attempt(task, events):
        time.sleep(0.05)
        scanner.mark_phase3_task_request_attempted()
        events.append(("attempt", task))
        return task

    attempted_stats, attempted_events = run_case(
        ["attempted"], delayed_attempt, "v38/invocation-attempted",
    )
    assert attempted_stats == scanner.TaskPoolStats(1, 1, 0, 1), attempted_stats
    assert attempted_events == [
        ("start", "attempted"), ("attempt", "attempted"),
        ("done", "attempted"), ("result", "attempted"),
    ], attempted_events


def assert_coverage_wire_schema_and_stream_recovery():
    coverage = scanner.canonical_api_coverage(scanner._empty_api_coverage_state())
    record = {"base": "http://127.0.0.1:32001", "apis": [], "api_coverage": coverage}
    assert scanner.deserialize_scan_record(json.loads(json.dumps(scanner.serialize_scan_record(record))))["api_coverage"] == coverage
    bad_values = [True, "1", 1.5, -1, 10 ** 20, float("inf"), {"x": 1}]
    for bad in bad_values:
        malformed = copy.deepcopy(record)
        malformed["api_coverage"] = dict(coverage)
        malformed["api_coverage"]["valid_inventory_apis"] = bad
        try:
            scanner.serialize_scan_record(malformed)
        except ValueError:
            pass
        else:
            raise AssertionError(f"malformed coverage accepted: {type(bad).__name__}")
    for field in scanner.TOP_LEVEL_COVERAGE_COUNT_FIELDS:
        for bad in bad_values:
            malformed = copy.deepcopy(record)
            malformed[field] = bad
            try:
                scanner.serialize_scan_record(malformed)
            except ValueError:
                pass
            else:
                raise AssertionError(f"malformed top-level {field} accepted: {type(bad).__name__}")
    malformed_prepare = dict(record)
    malformed_prepare["replay_exact_discovered"] = True
    try:
        scanner.ApiCoverageTracker().prepare(malformed_prepare, [], set(), {})
    except ValueError:
        pass
    else:
        raise AssertionError("tracker accepted malformed replay coverage")

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "coverage.jsonl")
        good_one = scanner.serialize_scan_record(record)
        good_two = scanner.serialize_scan_record({**record, "base": "http://127.0.0.1:32002"})
        bad = copy.deepcopy(good_one)
        bad["base"] = "http://127.0.0.1:32999"
        bad["replay_exact_discovered"] = 1e1000
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(good_one, allow_nan=False) + "\n")
            handle.write(json.dumps(bad) + "\n")
            handle.write(json.dumps(good_two, allow_nan=False) + "\n")
        recovered = list(scanner.StreamedResultSet(path, 3))
        assert [item["base"] for item in recovered] == [good_one["base"], good_two["base"]]


def assert_exact_absent_from_legacy_providers():
    target = exact_target("http://127.0.0.1:33001", exact_count=6, heuristic_count=12)
    exact = {api for api in target["apis"] if scanner.is_independently_exact_api(target, api)}
    heuristic = set(target["apis"]) - exact
    providers = [
        scanner.phase3_seed_apis(target),
        scanner.high_yield_probe_apis(target),
        scanner.business_layer_apis(target),
        scanner.file_layer_apis(target),
    ]
    for provided in providers:
        assert not (set(provided) & exact), (provided, exact)
    for tasks in (
        scanner.phase3_seed_tasks([target]),
        scanner.high_yield_probe_tasks([target]),
        scanner.bound_body_tasks([target], max_per_target=0),
        scanner.bound_param_tasks([target], max_per_target=0),
        scanner.layer_tasks_for_candidates([target], lambda _item: list(exact | heuristic), "custom"),
    ):
        assert all(task[1] not in exact for task in tasks), tasks
    deep_tasks = scanner.layer_tasks_for_candidates([target], lambda _item: sorted(heuristic), "custom")
    assert deep_tasks and all(task[1] in heuristic for task in deep_tasks)
    malformed_config = [
        {**target, "config_rest_candidates": [7, [], {"path": "/guess/config-valid"}]},
        {**target, "base": "http://127.0.0.1:33002", "config_rest_candidates": "bad"},
        {**target, "base": "http://127.0.0.1:33003", "config_rest_candidates": [{"path": "/guess/config-late"}]},
    ]
    config_tasks = scanner.config_rest_phase3_tasks(malformed_config)
    assert [candidate["path"] for _item, candidate in config_tasks] == [
        "/guess/config-valid", "/guess/config-late",
    ]


def assert_metadata_index_scale_and_invalidation():
    def build(size):
        exact = [f"/api/index-exact-{i:05d}" for i in range(size)]
        heuristic = [f"/guess/index-{i:05d}" for i in range(size // 2)]
        return {
            "base": f"http://127.0.0.1:{34000 + size}",
            "apis": exact + heuristic,
            "api_meta": {
                **{api: {"confidence": 0.95, "sources": ["openapi"]} for api in exact},
                **{api: {"confidence": 0.35, "sources": ["baseline"]} for api in heuristic},
            },
            "param_profile": scanner.empty_param_profile(),
        }

    timings = []
    for size in (600, 1200):
        target = build(size)
        start_builds = scanner.API_META_INDEX_BUILD_COUNT
        started = time.monotonic()
        tasks = scanner.exact_api_sweep_plan([target])
        scanner.phase3_heuristic_seed_tasks([target])
        scanner.business_layer_apis(target)
        scanner.file_layer_apis(target)
        timings.append(time.monotonic() - started)
        assert len(tasks) == size
        assert scanner.API_META_INDEX_BUILD_COUNT - start_builds == 4
        assert scanner.is_independently_exact_api(target, target["apis"][-1]) is False
        target["api_meta"][target["apis"][-1]] = {"confidence": 0.95, "sources": ["swagger"]}
        assert scanner.is_independently_exact_api(target, target["apis"][-1]) is True
        before_second_plan = scanner.API_META_INDEX_BUILD_COUNT
        second_tasks = scanner.exact_api_sweep_plan([target])
        assert target["apis"][-1] in [api for _item, api in second_tasks]
        assert scanner.API_META_INDEX_BUILD_COUNT - before_second_plan == 1
    assert timings[1] < max(12.0, timings[0] * 3.5), timings

    source, destination = build(1050), build(2)
    source["base"], destination["base"] = "http://127.0.0.1:35001", "http://127.0.0.1:35002"
    start_builds = scanner.API_META_INDEX_BUILD_COUNT
    scanner.apply_cross_base_replay([source, destination], "global", 0)
    assert len(destination.get("replay_apis", [])) >= 1000
    assert scanner.API_META_INDEX_BUILD_COUNT - start_builds <= 3

    # Metadata snapshots are call-scoped: a same-size in-place provenance
    # change between replay calls must be visible without explicit invalidation.
    replay_path = "/api/index-replay-mutation"
    mutable_source = {
        "base": "http://127.0.0.1:35101",
        "apis": [replay_path],
        "api_meta": {replay_path: {"confidence": 0.35, "sources": ["baseline"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    mutable_destination = {
        "base": "http://127.0.0.1:35102",
        "apis": ["/baseline/local"],
        "api_meta": {"/baseline/local": {"confidence": 0.35, "sources": ["baseline"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    scanner.apply_cross_base_replay([mutable_source, mutable_destination], "global", 0)
    assert replay_path not in mutable_destination.get("replay_apis", [])
    mutable_source["api_meta"][replay_path] = {"confidence": 0.95, "sources": ["openapi"]}
    scanner.apply_cross_base_replay([mutable_source, mutable_destination], "global", 0)
    assert replay_path in mutable_destination.get("replay_apis", [])


def assert_replay_profile_scale():
    def profiled_source(size, port):
        paths = [f"/api/replay-profile-{index:05d}" for index in range(size)]
        profile = scanner.empty_param_profile()
        for index, path in enumerate(paths):
            profile["api_methods"][path] = {"get"}
            profile["api_path_templates"][path] = {path}
            if index % 2:
                profile["api_param_blocked"].add(path)
            else:
                profile["api_params"][path] = {"queryKey"}
                profile["api_param_sources"][path] = {"query": {"queryKey"}}
        return {
            "base": f"http://127.0.0.1:{port}",
            "apis": paths,
            "api_meta": {path: {"confidence": 0.95, "sources": ["openapi"]} for path in paths},
            "param_profile": profile,
        }, paths

    timings = []
    for size in (100, 200, 400):
        source, paths = profiled_source(size, 36000 + size)
        destination = {
            "base": f"http://127.0.0.1:{37000 + size}",
            "apis": ["/baseline/local"],
            "api_meta": {"/baseline/local": {"confidence": 0.35, "sources": ["baseline"]}},
            "param_profile": scanner.empty_param_profile(),
        }
        before = scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT
        started = time.monotonic()
        scanner.apply_cross_base_replay([source, destination], "global", 0)
        timings.append(time.monotonic() - started)
        assert scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT - before == 2
        restored = destination["param_profile"]
        assert "queryKey" in restored["api_params"][paths[0]]
        assert paths[1] in restored["api_param_blocked"]
    assert timings[2] < max(12.0, timings[0] * 5.5), timings

    source, paths = profiled_source(1050, 38100)
    destination = {
        "base": "http://127.0.0.1:38101",
        "apis": ["/baseline/local"],
        "api_meta": {"/baseline/local": {"confidence": 0.35, "sources": ["baseline"]}},
        "param_profile": scanner.empty_param_profile(),
    }
    before = scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT
    scanner.apply_cross_base_replay([source, destination], "global", 0)
    assert scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT - before == 2
    assert len(destination.get("replay_apis", [])) == 1050
    assert paths[-1] in destination["param_profile"]["api_param_blocked"]
    wire = scanner.serialize_scan_record(source)
    assert "_replay_param_profile_index" not in wire


def assert_replay_profile_call_scope_mutation():
    path = "/api/replay-profile-mutation"
    old_name = "oldField"
    new_name = "newField"
    profile = scanner.empty_param_profile()
    profile["api_methods"][path] = {"get"}
    profile["api_params"][path] = {old_name}
    profile["api_param_sources"][path] = {"query": {old_name}}
    source = {
        "base": "http://127.0.0.1:38201",
        "apis": [path],
        "api_meta": {path: {"confidence": 0.95, "sources": ["openapi"]}},
        "param_profile": profile,
    }

    def destination(port):
        return {
            "base": f"http://127.0.0.1:{port}",
            "apis": ["/baseline/local"],
            "api_meta": {"/baseline/local": {"confidence": 0.35, "sources": ["baseline"]}},
            "param_profile": scanner.empty_param_profile(),
        }

    first = destination(38202)
    first_builds = scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT
    scanner.apply_cross_base_replay([source, first], "global", 0)
    assert scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT - first_builds == 2
    assert scanner.api_methods_for(first["param_profile"], path) == {"get"}
    assert first["param_profile"]["api_params"][path] == {old_name}

    # Preserve every root/nested container identity and cardinality while
    # changing the facts. A persistent id/len cache would return stale GET.
    profile["api_methods"][path].clear()
    profile["api_methods"][path].add("delete")
    profile["api_params"][path].clear()
    profile["api_params"][path].add(new_name)
    profile["api_param_sources"][path]["query"].clear()
    profile["api_param_sources"][path]["query"].add(new_name)

    second = destination(38203)
    second_builds = scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT
    scanner.apply_cross_base_replay([source, second], "global", 0)
    assert scanner.REPLAY_PROFILE_INDEX_BUILD_COUNT - second_builds == 2
    restored = second["param_profile"]
    assert scanner.api_methods_for(restored, path) == {"delete"}
    assert restored["api_params"][path] == {new_name}
    assert old_name not in restored["api_params"][path]
    assert scanner.exact_api_sweep_plan([second]) == []
    assert scanner.scheduled_bypass_tests(path, scanner.FAST_BYPASS, restored) == []
    assert scanner.body_probe_bypass_tests(restored, path) == []
    assert scanner.bound_param_tasks([second], max_per_target=0) == []
    assert scanner.bound_body_tasks([second], max_per_target=0) == []
    assert "_replay_param_profile_index" not in source
    assert "_replay_param_profile_index" not in second

    restored["api_params"][path].add("destinationOnly")
    restored["api_methods"][path].add("patch")
    assert source["param_profile"]["api_params"][path] == {new_name}
    assert source["param_profile"]["api_methods"][path] == {"delete"}


def assert_product_string_audit():
    banned = (
        "real engagements", "state grid", "leaveschool", "outapicheckphotos",
        "getbyopenid", "media_server", "gb28181", "seeyon", "tongji.php", "cmcon",
        "/api/oa/", "workflow / oa patterns",
    )
    paths = [
        os.path.join(ROOT, "pipeline", name)
        for name in os.listdir(os.path.join(ROOT, "pipeline"))
        if name.endswith(".py")
    ] + [os.path.join(ROOT, "wordlists", "api_paths.txt")]
    wire = "\n".join(open(path, encoding="utf-8").read().lower() for path in paths)
    assert not [token for token in banned if token in wire]


def main():
    assert_all_exact_loopback()
    assert_replay_unlimited_and_capped()
    assert_same_path_replay_promotion_coverage()
    assert_config_rest_exact_dedup()
    assert_timeout_drains_and_freezes()
    assert_task_pool_invocation_state_accounting()
    assert_coverage_wire_schema_and_stream_recovery()
    assert_exact_absent_from_legacy_providers()
    assert_metadata_index_scale_and_invalidation()
    assert_replay_profile_scale()
    assert_replay_profile_call_scope_mutation()
    assert_product_string_audit()
    print("v38 exact API coverage lab: PASS")


if __name__ == "__main__":
    main()

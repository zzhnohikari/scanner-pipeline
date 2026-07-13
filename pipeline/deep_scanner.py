#!/usr/bin/env python3
"""
v13: 文件专项 + HTML/JS静态参数画像 + URL/参数绑定 + POST body/form fuzz
融合 JSFinder/Webpack_extract/VueCrack/Packer-Fuzzer 技术
"""

import os, re, json, time, ssl, socket, argparse, logging, sys, hashlib, shutil, copy, fcntl, unicodedata, math
from collections import namedtuple
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from urllib.parse import urlparse, urlsplit, urljoin, urlencode, parse_qsl, urlunparse, unquote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener
from urllib.error import HTTPError
from threading import Event, Lock, local

PIPELINE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JS_MAX_BYTES = 2 * 1024 * 1024
MAX_PREFIX_INVENTORY_PREFIXES = 16
MAX_PREFIX_INVENTORY_PATHS = 128
MAX_PREFIX_INVENTORY_PHASE3_SEEDS = 8
API_META_SOURCES = frozenset({
    "api_fuzz", "backend_baseline", "baseline", "business_pattern",
    "extra_wordlist", "html", "js", "js-graph", "js_literal",
    "js_request", "legacy_baseline", "legacy_recovery", "openapi",
    "param_binding", "prefix_inventory", "react_route", "swagger",
    "vue_router",
})
API_META_EXACT_SOURCES = frozenset({
    "extra_wordlist", "html", "js", "js-graph", "js_literal",
    "js_request", "openapi", "param_binding", "react_route", "swagger",
    "vue_router",
})
if PIPELINE_DIR not in sys.path:
    sys.path.insert(0, PIPELINE_DIR)

try:
    import pipeline.input_tools as input_tools
    from pipeline.path_safety import validate_root_relative_path as _validate_root_relative_path
    from pipeline.js_extractor import (
        _direct_request_callee_allowed,
        _extract_call_args,
        _explicit_js_object_method,
        _is_code_position,
        _is_request_method_receiver,
        _is_standalone_callable_context,
        _iter_request_calls,
        _js_lexical_context,
        _normalize_callee,
        _request_options_method_truth,
        _source_static_request_trust_ambiguous,
        _split_args,
        METHOD_TRUTH_ABSENT,
        METHOD_TRUTH_AMBIGUOUS,
        METHOD_TRUTH_METHOD,
        build_js_graph,
        remove_profile_values,
    )
    from pipeline.js_advanced_inventory import ast_parser_status, parse_html_discovery
    from pipeline.classifier import classify_response
    from pipeline.openapi_inventory import parse_openapi_inventory
    from pipeline.http_utils import (
        decode_http_body as _decode_http_body,
        http_accept_encoding,
        maybe_decompress_http_body as _maybe_decompress_http_body_impl,
        read_http_response as _read_http_response,
        read_limited,
    )
except ImportError:
    import input_tools
    from path_safety import validate_root_relative_path as _validate_root_relative_path
    from js_extractor import (
        _direct_request_callee_allowed,
        _extract_call_args,
        _explicit_js_object_method,
        _is_code_position,
        _is_request_method_receiver,
        _is_standalone_callable_context,
        _iter_request_calls,
        _js_lexical_context,
        _normalize_callee,
        _request_options_method_truth,
        _source_static_request_trust_ambiguous,
        _split_args,
        METHOD_TRUTH_ABSENT,
        METHOD_TRUTH_AMBIGUOUS,
        METHOD_TRUTH_METHOD,
        build_js_graph,
        remove_profile_values,
    )
    from js_advanced_inventory import ast_parser_status, parse_html_discovery
    from classifier import classify_response
    from openapi_inventory import parse_openapi_inventory
    from http_utils import (
        decode_http_body as _decode_http_body,
        http_accept_encoding,
        maybe_decompress_http_body as _maybe_decompress_http_body_impl,
        read_http_response as _read_http_response,
        read_limited,
    )

def build_parser():
    parser = argparse.ArgumentParser(description='JS/API 未授权访问扫描器 v13')
    parser.add_argument('--input', default='/tmp/v7_targets.json', help='目标JSON文件')
    parser.add_argument('--input-format', choices=['targets','hostport','masscan','httpx-json'], default='targets', help='输入格式: targets(JSON) / hostport / masscan / httpx-json')
    parser.add_argument('--port-scanner', choices=['none','masscan','naabu','auto'], default='none', help='可选外部端口发现器,用于大批IP/CIDR: none/masscan/naabu/auto')
    parser.add_argument('--http-prober', choices=['internal','httpx','auto'], default='internal', help='HTTP确认层: internal使用内置Phase1,httpx调用外部httpx,auto优先httpx')
    parser.add_argument('--scan-ports', default='80,443,8080,8443,8001,81,82,88,3000,4000,5000,7000,8000,8002,8003,8008,8081,8088,8089,8888,9000,9090,9443,10000,10080,10443,4433,4443', help='外部端口发现器使用的端口列表')
    parser.add_argument('--scan-rate', type=int, default=1000, help='masscan/naabu端口发现速率')
    parser.add_argument('--masscan-bin', default='', help='masscan二进制路径,默认从PATH查找')
    parser.add_argument('--naabu-bin', default='', help='naabu二进制路径,默认从PATH查找')
    parser.add_argument('--httpx-bin', default='', help='httpx二进制路径,默认从PATH查找')
    parser.add_argument('--httpx-extra-args', default='', help='透传给httpx的附加参数,例如 \"-follow-redirects -retries 1\"')
    parser.add_argument('--outdir', default='/tmp/v13_scan_results', help='输出目录')
    parser.add_argument('--workers', type=int, default=50, help='并发数')
    parser.add_argument('--timeout', type=int, default=12, help='HTTP超时(秒)')
    parser.add_argument('--phase2-timeout', type=int, default=180, help='Phase 2 JS/API提取软超时(秒),超时目标用baseline兜底')
    parser.add_argument('--phase3a-timeout', type=int, default=240, help='Phase 3a 快筛软超时(秒),超时后先进入候选/补筛流程')
    parser.add_argument('--exact-api-max', type=int, default=0, help='每目标独立精确来源API安全首扫上限;0=不限制')
    parser.add_argument('--exact-sweep-timeout', type=int, default=0, help='全量精确API安全首扫软超时(秒);0=不限制且不受phase3a超时影响')
    parser.add_argument('--rescue-timeout', type=int, default=180, help='Phase 3a baseline补筛软超时(秒)')
    parser.add_argument('--disable-rescue-baseline', action='store_true', help='关闭Phase 3a baseline补筛')
    parser.add_argument('--phase3b-layer-timeout', type=int, default=300, help='Phase 3b 每个分层软超时(秒)')
    parser.add_argument('--limit', type=int, default=0, help='限制目标数量,0=全部')
    parser.add_argument('--dry-run', action='store_true', help='只提取API,不测试')
    parser.add_argument('--full-bypass', action='store_true', help='启用FULL绕过方法,默认仍命中断路')
    parser.add_argument('--collect-all-variants', action='store_true', help='命中后继续收集所有绕过/参数变体,隐含--full-bypass,小批目标补证据用')
    parser.add_argument('--debug', action='store_true', help='调试日志')
    parser.add_argument('--no-proxy', action='store_true', help='绕过系统代理(ClashX等)')
    parser.add_argument('--skip-port-probe', action='store_true', help='跳过TCP connect预检,仍保留HTTP/scheme确认')
    parser.add_argument('--allow-unverified-url', action='store_true', help='显式URL的HTTP/scheme确认失败时仍保留输入URL')
    parser.add_argument('--expand-api-ports', default='', help='对显式host/URL目标额外探测同主机的API后端口(逗号分隔,如8080,8443,8000,8001);空=关闭(默认)。适合单目标/小批量深挖前后端分离站点;大批量会放大请求并可能命中无关本地服务,请配合--expand-api-ports-max-targets')
    parser.add_argument('--no-expand-api-ports', action='store_true', help='强制关闭同主机API端口扇出')
    parser.add_argument('--expand-api-ports-max-targets', type=int, default=0, help='目标数超过该阈值时自动跳过端口扇出;0=不限制。分布式模式下建议传 --expand-api-ports-max-targets 0')
    parser.add_argument('--replay-scope', choices=['none','host','global'], default='host', help='跨base回放API清单范围: none=各base独立(旧行为); host=同主机名不同端口共享(默认,命中前后端分离未授权); global=所有目标共享(跨实例,请求量大)')
    parser.add_argument('--replay-max-apis', type=int, default=0, help='每个base回放注入的独立精确API上限(确定性排序);0=不限制')
    parser.add_argument('--config-service-base-mode', choices=['off','inventory','same-host'], default='same-host', help='静态配置服务基址处理: off=仅保留提取结果; inventory=只展示; same-host=同主机安全GET探测(默认)')
    parser.add_argument('--config-service-base-max-per-target', type=int, default=8, help='每个前端目标参与REST约定探测的配置服务基址上限;0=不限制')
    parser.add_argument('--config-rest-max-suffixes', type=int, default=8, help='每个配置服务基址最多生成的只读REST后缀数;0=全部')
    parser.add_argument('--fresh', action='store_true', help='扫描前清理输出目录中的旧JSON报告/checkpoint')
    parser.add_argument('--resume', action='store_true', help='报告阶段合并输出目录中的历史checkpoint(默认只统计本轮结果)')
    parser.add_argument('--disable-file-hunter', action='store_true', help='关闭下载/预览/导出接口专项检测')
    parser.add_argument('--enable-file-baseline', action='store_true', help='启用硬编码文件下载baseline路径(默认关闭)')
    parser.add_argument('--enable-backend-baseline', action='store_true', help='启用小型通用合成REST baseline(默认关闭);部署专用路径请使用--extra-api-wordlist')
    parser.add_argument('--extra-api-wordlist', action='append', default=[], help='额外API路径字典文件,可重复传入;每行一个/path或完整URL,#开头注释')
    parser.add_argument('--file-max-probes', type=int, default=36, help='每个疑似文件接口最多探测次数')
    parser.add_argument('--disable-api-fuzz', action='store_true', help='关闭Phase 2.5 API字典模糊发现(对JS零发现目标注入内置字典)')
    parser.add_argument('--api-fuzz-wordlist', default='', help='Phase 2.5额外API字典文件路径(默认使用内置wordlists/api_paths.txt)')
    parser.add_argument('--disable-param-harvest', action='store_true', help='关闭HTML/JS静态参数画像')
    parser.add_argument('--param-max-probes', type=int, default=12, help='每个接口最多静态参数模板探测次数')
    parser.add_argument('--param-probe-mode', choices=['targeted','broad'], default='targeted', help='静态参数探测模式: targeted仅高价值接口,broad全部接口')
    parser.add_argument('--js-max-download', type=int, default=0, help='每个目标最多下载的外链JS数量，0=全部下载')
    parser.add_argument('--js-max-bytes', type=int, default=DEFAULT_JS_MAX_BYTES, help='单个JS/module/lazy响应最大解压后字节数;0=使用安全默认2MiB')
    parser.add_argument('--js-ast-mode', choices=['auto','off','required'], default='auto', help='Phase 2 JS AST: auto=可用时启用并回退正则(默认),off=关闭,required=缺少esprima时失败')
    parser.add_argument('--js-ast-max-bytes', type=int, default=750000, help='单个JS进入AST解析的最大字节数')
    parser.add_argument('--js-ast-max-nodes', type=int, default=20000, help='单个JS AST最大访问节点数')
    parser.add_argument('--js-ast-max-depth', type=int, default=64, help='单个JS AST最大递归深度')
    parser.add_argument('--js-ast-max-expressions', type=int, default=4000, help='单个JS AST最大表达式求值次数')
    parser.add_argument('--js-advanced-max-assets', type=int, default=64, help='每目标由AST/import map/manifest/source map新增的同源JS资产上限,0=不限')
    parser.add_argument('--advanced-inventory-max-declarations', type=int, default=64, help='每类高级inventory持久化声明上限;eligible记录可替换inventory-only记录,0=不限')
    parser.add_argument('--import-map-mode', choices=['off','explicit'], default='explicit', help='只解析HTML显式声明的import map(默认explicit)')
    parser.add_argument('--import-map-max-count', type=int, default=8, help='每目标显式import map上限,0=不限')
    parser.add_argument('--import-map-max-bytes', type=int, default=131072, help='单个import map最大字节数')
    parser.add_argument('--import-map-max-entries', type=int, default=128, help='单个import map最大imports/scopes条目数,0=不限')
    parser.add_argument('--asset-manifest-mode', choices=['off','explicit'], default='explicit', help='只跟随HTML/JS显式引用的asset manifest(默认explicit)')
    parser.add_argument('--asset-manifest-max-count', type=int, default=8, help='每目标显式asset manifest抓取上限,0=不限')
    parser.add_argument('--asset-manifest-max-bytes', type=int, default=262144, help='单个asset manifest最大字节数')
    parser.add_argument('--asset-manifest-max-nodes', type=int, default=2048, help='单个asset manifest最大JSON遍历节点数')
    parser.add_argument('--asset-manifest-max-entries', type=int, default=256, help='单个asset manifest最大JS条目数,0=不限')
    parser.add_argument('--source-map-mode', choices=['off','explicit'], default='off', help='Source Map v3: off=关闭(默认),explicit=仅跟随sourceMappingURL')
    parser.add_argument('--source-map-max-count', type=int, default=4, help='每目标显式source map处理上限,0=不限')
    parser.add_argument('--source-map-max-bytes', type=int, default=524288, help='单个source map最大字节数')
    parser.add_argument('--source-map-max-sources', type=int, default=32, help='单个source map最多处理sourcesContent数量,0=不限')
    parser.add_argument('--source-map-max-ratio', type=float, default=8.0, help='sourcesContent总字节/map字节最大比例,0=不限')
    parser.add_argument('--phase3a-param-rescue', action='store_true', help='3a阶段对有绑定参数的高价值API做小流量参数补筛')
    parser.add_argument('--phase3a-param-rescue-max-apis', type=int, default=10, help='每个目标最多参与3a参数补筛的API数,0=不限制')
    parser.add_argument('--phase3a-body-max-apis', type=int, default=4, help='每个目标在3a body-fast阶段最多参与POST/JSON参数探测的API数,0=不限制')
    parser.add_argument('--min-delay-ms', type=int, default=0, help='Phase 3每主机请求最小间隔毫秒，0=不限制')
    parser.add_argument('--max-rps-per-host', type=float, default=0.0, help='Phase 3每主机最大请求速率，0=不限制；与--min-delay-ms取更保守值')
    parser.add_argument('--max-requests-per-host', type=int, default=0, help='Phase 3每主机最大请求数硬上限，0=不限制')
    parser.add_argument('--unauth-matrix', action='store_true', help='dry-run时输出未授权/IDOR矩阵预览，不发送额外请求')
    parser.add_argument('--include-delete-method', action='store_true', help='默认跳过JS/OpenAPI中明确标注为HTTP DELETE方法的接口；显式开启后才纳入扫描')
    parser.add_argument('--allow-active-post', action='store_true', help='显式允许对已观测到且有body参数的动作型POST接口发送请求；默认仅探测明确的只读型POST')
    parser.add_argument('--post-every-api', action='store_true', help='显式授权每条独立精确API在GET之外发送一次POST；无body证据时发送零长度body，不授权PUT/PATCH/DELETE或文件上传')
    parser.add_argument('--redact-raw-findings', action='store_true', help='写出checkpoint/report前移除finding中的raw原始响应字段，避免敏感正文落盘')
    parser.add_argument('--capture-finding-evidence', action='store_true', default=True, help='漏洞产出后复核一次并保存完整HTTP请求/响应证据包到outdir/evidence')
    parser.add_argument('--no-capture-finding-evidence', dest='capture_finding_evidence', action='store_false', help='关闭漏洞证据复核与原始HTTP包落盘')
    parser.add_argument('--evidence-max-body-bytes', type=int, default=262144, help='每条证据响应体最大保存字节数')
    parser.add_argument('--phase12-workers', type=int, default=0, help='单独限制Phase 1/2线程池大小，0=沿用当前--workers派生行为；Phase 3仍使用--workers')
    parser.add_argument('--legacy-recovery', action='store_true', help='启用低置信 legacy baseline 恢复候选，默认关闭以避免膨胀')
    parser.add_argument('--compare-inventory', default='', help='dry-run后与旧 apis.json/phase2_inventory.jsonl 做安全聚合差异报告')
    parser.add_argument('--compare-output', default='', help='inventory diff 输出路径，默认写到 outdir/inventory_diff.json')
    parser.add_argument('--include-samples', action='store_true', help='inventory diff 中包含少量路径样本；默认不输出具体host/path')
    parser.add_argument('--validate-from-report', default='', help='从既有 report.json 中提取端点做保守聚焦复核')
    parser.add_argument('--validate-plan-only', action='store_true', help='配合 --validate-from-report 只生成复核计划，不发请求')
    return parser

def parse_cli(argv=None):
    return build_parser().parse_args(argv)

args = parse_cli() if __name__ == "__main__" else parse_cli([])
if args.collect_all_variants:
    args.full_bypass = True

log = logging.getLogger('scanner')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG if args.debug else logging.WARNING)

TCP_TIMEOUT = 1.5; HTTP_TIMEOUT = args.timeout; API_TIMEOUT = max(6, args.timeout//2)
WORKERS = args.workers; PHASE12_WORKERS = max(1, int(args.phase12_workers)) if int(getattr(args, 'phase12_workers', 0) or 0) > 0 else 0
SSL_RETRIES = 2; OUTDIR = args.outdir
PHASE3_RATE_LOCK = Lock()
PHASE3_RATE_STATE = {}
CATCH_ALL_LOCK = Lock()
CATCH_ALL_BUILD_LOCK = Lock()
CATCH_ALL_BASELINES = {}
CATCH_ALL_STATS = {
    "catch_all_baseline_attempted": 0,
    "catch_all_baseline_stable": 0,
    "catch_all_baseline_unstable": 0,
    "catch_all_baseline_unavailable": 0,
    "catch_all_baseline_skipped_budget": 0,
    "catch_all_suppressed": 0,
}
API_COVERAGE_LOCK = Lock()
PHASE3_TASK_CONTEXT = local()
_TaskPoolStatsBase = namedtuple("TaskPoolStats", "submitted completed skipped_timeout deadline_pending")
class TaskPoolStats(_TaskPoolStatsBase):
    __slots__ = ()

    @property
    def timed_out(self):
        return bool(self.deadline_pending)

_TaskInvocationResult = namedtuple(
    "TaskInvocationResult",
    "value error attempted invocation_started cancelled_before_invocation",
)
API_META_INDEX_BUILD_COUNT = 0
REPLAY_PROFILE_INDEX_BUILD_COUNT = 0
API_META_INDEX_CONTEXT = local()


def _payload_shape(value, depth=0):
    if depth >= 4:
        return "bounded"
    if isinstance(value, dict):
        return tuple(
            (str(key), _payload_shape(value[key], depth + 1))
            for key in sorted(value, key=str)[:16]
        )
    if isinstance(value, (list, tuple)):
        return ("list", _payload_shape(value[0], depth + 1)) if value else ("list",)
    return "scalar"


def phase3_probe_mode(method, content_type=None, headers=None, query_suffix="", payload=None):
    safe_headers = tuple(sorted(
        (str(key).strip().lower(), str(value).strip())
        for key, value in (headers or {}).items()
        if str(key).strip().lower() in ("authorization", "content-type")
    ))
    return (
        str(method or "GET").upper(),
        str(content_type or "").split(";", 1)[0].strip().lower(),
        safe_headers,
        tuple(sorted({key for key, _value in parse_qsl(str(query_suffix or "").lstrip("?"), keep_blank_values=True)})),
        _payload_shape(payload) if isinstance(payload, dict) else (),
    )


class Phase3OpportunityLedger:
    """Run-local exact first-opportunity modes observed at request boundary."""

    def __init__(self):
        self._lock = Lock()
        self._exact_attempted = set()

    def mark_exact_attempted(self, base, path, mode):
        clean = _canonical_api_path(path, preserve_query=False)
        if not clean:
            return
        with self._lock:
            self._exact_attempted.add((str(base or ""), clean, mode))

    def exact_mode_attempted(self, base, path, mode):
        clean = _canonical_api_path(path, preserve_query=False)
        if not clean:
            return False
        with self._lock:
            return (str(base or ""), clean, mode) in self._exact_attempted


ACTIVE_PHASE3_OPPORTUNITY_LEDGER = Phase3OpportunityLedger()


def _empty_api_coverage_state(valid_inventory=0):
    return {
        "valid_inventory_apis": int(valid_inventory),
        "independently_exact_discovered": 0,
        "safe_eligible_exact": 0,
        "scheduled_unique_exact": 0,
        "attempted_unique_exact": 0,
        "completed_unique_exact": 0,
        "exact_get_eligible": 0,
        "exact_get_scheduled": 0,
        "exact_get_attempted": 0,
        "exact_get_completed": 0,
        "exact_get_skipped_by_request_budget": 0,
        "exact_get_skipped_by_timeout": 0,
        "exact_get_skipped_by_exact_cap": 0,
        "exact_post_eligible": 0,
        "exact_post_scheduled": 0,
        "exact_post_attempted": 0,
        "exact_post_completed": 0,
        "exact_post_empty_body_eligible": 0,
        "exact_post_empty_body_scheduled": 0,
        "exact_post_empty_body_attempted": 0,
        "exact_post_empty_body_completed": 0,
        "exact_post_bound_body_eligible": 0,
        "exact_post_bound_body_scheduled": 0,
        "exact_post_bound_body_attempted": 0,
        "exact_post_bound_body_completed": 0,
        "exact_post_skipped_by_request_budget": 0,
        "exact_post_skipped_by_timeout": 0,
        "exact_post_skipped_by_exact_cap": 0,
        "skipped_by_safety": {},
        "skipped_by_request_budget": 0,
        "skipped_by_timeout": 0,
        "skipped_by_exact_cap": 0,
        "replay_exact_discovered": 0,
        "replay_exact_scheduled": 0,
        "replay_exact_attempted": 0,
        "replay_exact_completed": 0,
        "replay_skipped_by_cap": 0,
        "heuristic_scheduled": 0,
        "heuristic_attempted": 0,
        "coverage_complete": True,
        "incomplete_reasons": [],
    }


MAX_API_COVERAGE_COUNT = 1_000_000_000
TOP_LEVEL_COVERAGE_COUNT_FIELDS = (
    "replay_exact_discovered", "replay_exact_scheduled", "replay_scheduled",
    "replay_skipped_by_cap", "replay_promoted_api_count", "cross_replay_added",
)
API_COVERAGE_SAFETY_REASONS = frozenset({
    "delete_only", "action_post_not_enabled", "post_not_safely_bound",
    "unsupported_unsafe_method", "unsupported_method",
})
API_COVERAGE_INCOMPLETE_REASONS = frozenset({
    "exact_api_max", "max_requests_per_host", "exact_sweep_timeout",
    "eligible_exact_incomplete", "replay_max_apis", "exact_post_max",
    "exact_post_request_budget", "exact_post_timeout",
    "eligible_exact_post_incomplete", "exact_get_max",
    "exact_get_request_budget", "exact_get_timeout",
    "eligible_exact_get_incomplete",
})
API_COVERAGE_NUMERIC_FIELDS = tuple(
    key for key, value in _empty_api_coverage_state().items()
    if isinstance(value, int) and not isinstance(value, bool)
)


def _coverage_nonnegative_int(value, field):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"api_coverage {field} must be an integer")
    if value < 0 or value > MAX_API_COVERAGE_COUNT:
        raise ValueError(f"api_coverage {field} is out of range")
    return value


def canonical_api_coverage(value):
    """Validate and canonicalize the finite aggregate coverage wire schema."""
    if not isinstance(value, dict):
        raise ValueError("api_coverage must be an object")
    allowed = set(_empty_api_coverage_state()) | {"targets"}
    if any(not isinstance(key, str) or key not in allowed for key in value):
        raise ValueError("api_coverage contains unsupported fields")
    out = _empty_api_coverage_state()
    for field in API_COVERAGE_NUMERIC_FIELDS:
        if field in value:
            out[field] = _coverage_nonnegative_int(value[field], field)
    if "targets" in value:
        out["targets"] = _coverage_nonnegative_int(value["targets"], "targets")

    raw_safety = value.get("skipped_by_safety", {})
    if not isinstance(raw_safety, dict):
        raise ValueError("api_coverage skipped_by_safety must be an object")
    safety = {}
    for reason, count in raw_safety.items():
        if reason not in API_COVERAGE_SAFETY_REASONS:
            raise ValueError("api_coverage contains an unsupported safety reason")
        safety[reason] = _coverage_nonnegative_int(count, f"skipped_by_safety.{reason}")
    out["skipped_by_safety"] = {key: safety[key] for key in sorted(safety) if safety[key]}

    raw_reasons = value.get("incomplete_reasons", [])
    if not isinstance(raw_reasons, (list, tuple)) or any(
        not isinstance(reason, str) or reason not in API_COVERAGE_INCOMPLETE_REASONS
        for reason in raw_reasons
    ):
        raise ValueError("api_coverage contains unsupported incomplete reasons")
    out["incomplete_reasons"] = sorted(set(raw_reasons))
    complete = value.get("coverage_complete", not out["incomplete_reasons"])
    if not isinstance(complete, bool) or complete != (not out["incomplete_reasons"]):
        raise ValueError("api_coverage coverage_complete is inconsistent")
    out["coverage_complete"] = complete

    if not (
        out["completed_unique_exact"] <= out["attempted_unique_exact"]
        <= out["scheduled_unique_exact"] <= out["safe_eligible_exact"]
        <= out["independently_exact_discovered"]
    ):
        raise ValueError("api_coverage exact counts are inconsistent")
    if (
        out["completed_unique_exact"]
        + out["skipped_by_request_budget"]
        + out["skipped_by_timeout"]
        > out["scheduled_unique_exact"]
    ):
        raise ValueError("api_coverage exact outcomes exceed scheduled work")
    if out["heuristic_attempted"] > out["heuristic_scheduled"]:
        raise ValueError("api_coverage heuristic counts are inconsistent")
    if not (
        out["exact_get_completed"] <= out["exact_get_attempted"]
        <= out["exact_get_scheduled"] <= out["exact_get_eligible"]
        <= out["independently_exact_discovered"]
    ):
        raise ValueError("api_coverage exact GET counts are inconsistent")
    if not (
        out["exact_post_completed"] <= out["exact_post_attempted"]
        <= out["exact_post_scheduled"] <= out["exact_post_eligible"]
        <= out["independently_exact_discovered"]
    ):
        raise ValueError("api_coverage exact POST counts are inconsistent")
    for body_kind in ("empty_body", "bound_body"):
        if not (
            out[f"exact_post_{body_kind}_completed"]
            <= out[f"exact_post_{body_kind}_attempted"]
            <= out[f"exact_post_{body_kind}_scheduled"]
            <= out[f"exact_post_{body_kind}_eligible"]
        ):
            raise ValueError("api_coverage exact POST body counts are inconsistent")
    for stage in ("eligible", "scheduled", "attempted", "completed"):
        if (
            out[f"exact_post_empty_body_{stage}"]
            + out[f"exact_post_bound_body_{stage}"]
            != out[f"exact_post_{stage}"]
        ):
            raise ValueError("api_coverage exact POST body totals are inconsistent")
    if (
        out["exact_post_completed"]
        + out["exact_post_skipped_by_request_budget"]
        + out["exact_post_skipped_by_timeout"]
        > out["exact_post_scheduled"]
    ):
        raise ValueError("api_coverage exact POST outcomes exceed scheduled work")
    if out["exact_post_skipped_by_exact_cap"] > out["exact_post_eligible"]:
        raise ValueError("api_coverage exact POST cap exceeds eligible work")
    if out["exact_get_scheduled"] + out["exact_get_skipped_by_exact_cap"] != out["exact_get_eligible"]:
        raise ValueError("api_coverage exact GET scheduling is inconsistent")
    if out["exact_post_scheduled"] + out["exact_post_skipped_by_exact_cap"] != out["exact_post_eligible"]:
        raise ValueError("api_coverage exact POST scheduling is inconsistent")
    if not (
        out["exact_get_eligible"] == out["exact_post_eligible"]
        and out["exact_get_scheduled"] == out["exact_post_scheduled"]
        and out["exact_get_skipped_by_exact_cap"] == out["exact_post_skipped_by_exact_cap"]
    ):
        raise ValueError("api_coverage exact dual-method plans are inconsistent")
    dual_method_coverage = bool(
        out["exact_get_eligible"] or out["exact_post_eligible"]
    )
    if dual_method_coverage and (
        out["completed_unique_exact"] > out["exact_get_completed"]
        or out["completed_unique_exact"] > out["exact_post_completed"]
    ):
        raise ValueError("api_coverage exact path completion exceeds method completion")
    if (
        out["exact_get_completed"]
        + out["exact_get_skipped_by_request_budget"]
        + out["exact_get_skipped_by_timeout"]
        > out["exact_get_scheduled"]
    ):
        raise ValueError("api_coverage exact GET outcomes exceed scheduled work")
    reason_fields = (
        ("exact_get_skipped_by_exact_cap", "exact_get_max"),
        ("exact_get_skipped_by_request_budget", "exact_get_request_budget"),
        ("exact_get_skipped_by_timeout", "exact_get_timeout"),
        ("exact_post_skipped_by_exact_cap", "exact_post_max"),
        ("exact_post_skipped_by_request_budget", "exact_post_request_budget"),
        ("exact_post_skipped_by_timeout", "exact_post_timeout"),
    )
    for field, reason in reason_fields:
        if bool(out[field]) != (reason in out["incomplete_reasons"]):
            raise ValueError("api_coverage exact method reason is inconsistent")
    if (
        (out["exact_get_eligible"] != out["exact_get_completed"])
        != ("eligible_exact_get_incomplete" in out["incomplete_reasons"])
    ):
        raise ValueError("api_coverage exact GET completeness is inconsistent")
    if (
        (out["exact_post_eligible"] != out["exact_post_completed"])
        != ("eligible_exact_post_incomplete" in out["incomplete_reasons"])
    ):
        raise ValueError("api_coverage exact POST completeness is inconsistent")
    if out["replay_exact_scheduled"] > out["replay_exact_discovered"]:
        raise ValueError("api_coverage replay counts are inconsistent")
    if not (
        out["replay_exact_completed"] <= out["replay_exact_attempted"]
        <= out["replay_exact_scheduled"]
    ):
        raise ValueError("api_coverage replay outcomes are inconsistent")
    safety_total = sum(out["skipped_by_safety"].values())
    if safety_total + out["safe_eligible_exact"] != out["independently_exact_discovered"]:
        raise ValueError("api_coverage safety counts are inconsistent")
    if bool(out["replay_skipped_by_cap"]) != ("replay_max_apis" in out["incomplete_reasons"]):
        raise ValueError("api_coverage replay cap reason is inconsistent")
    return out


def canonicalize_top_level_coverage_counts(record):
    for field in TOP_LEVEL_COVERAGE_COUNT_FIELDS:
        if field in record:
            record[field] = _coverage_nonnegative_int(record[field], field)
    discovered = record.get("replay_exact_discovered")
    skipped = record.get("replay_skipped_by_cap")
    if discovered is not None and skipped is not None and skipped > discovered:
        raise ValueError("top-level replay coverage counts are inconsistent")
    return record


class ApiCoverageTracker:
    """Thread-safe aggregate-only Phase 3 coverage accounting.

    Internal endpoint identities are sets used only during the run. Snapshots
    contain counts and finite reason names, never endpoint samples.
    """

    def __init__(self):
        self._states = {}

    def prepare(
        self, target, exact_apis, replay_exact, safety_skips, cap_skips=0,
        post_body_kinds=None, dual_scheduled_apis=None, post_cap_skips=0,
    ):
        base = str(target.get("base") or "")
        valid_inventory = len(_canonical_api_list(target.get("apis") or []))
        replay_discovered = _coverage_nonnegative_int(
            target.get("replay_exact_discovered", 0), "replay_exact_discovered"
        )
        replay_skipped = _coverage_nonnegative_int(
            target.get("replay_skipped_by_cap", 0), "replay_skipped_by_cap"
        )
        cap_skips = _coverage_nonnegative_int(cap_skips, "skipped_by_exact_cap")
        post_cap_skips = _coverage_nonnegative_int(
            post_cap_skips, "exact_post_skipped_by_exact_cap"
        )
        exact_set = set(exact_apis)
        canonical_post_kinds = {}
        if post_body_kinds is not None:
            if not isinstance(post_body_kinds, dict):
                raise ValueError("post_body_kinds must be a mapping")
            for api, body_kind in post_body_kinds.items():
                clean = _canonical_api_path(api, preserve_query=False)
                if clean in exact_set and body_kind in ("empty", "bound"):
                    canonical_post_kinds[clean] = body_kind
        dual_scheduled = {
            clean for clean in (
                _canonical_api_path(api, preserve_query=False)
                for api in (dual_scheduled_apis or [])
            ) if clean in canonical_post_kinds
        }
        with API_COVERAGE_LOCK:
            state = _empty_api_coverage_state(valid_inventory)
            state.update({
                "_exact": exact_set,
                "_eligible": exact_set - set(safety_skips),
                "_scheduled_exact": set(),
                "_attempted_exact": set(),
                "_completed_exact": set(),
                "_post_body_kinds": canonical_post_kinds,
                "_get_eligible": set(canonical_post_kinds),
                "_scheduled_get": set(dual_scheduled),
                "_attempted_get": set(),
                "_completed_get": set(),
                "_get_budget": set(),
                "_get_timeout": set(),
                "_post_eligible": set(canonical_post_kinds),
                "_scheduled_post": set(dual_scheduled),
                "_attempted_post": set(),
                "_completed_post": set(),
                "_post_budget": set(),
                "_post_timeout": set(),
                "_scheduled_heuristic": set(),
                "_attempted_heuristic": set(),
                "_replay": set(replay_exact),
                "_replay_discovered_count": max(
                    len(set(replay_exact)), replay_discovered
                ),
                "_scheduled_replay": set(),
                "_attempted_replay": set(),
                "_completed_replay": set(),
                "_budget": set(),
                "_timeout": set(),
            })
            counts = {}
            for reason in safety_skips.values():
                counts[reason] = counts.get(reason, 0) + 1
            state["skipped_by_safety"] = counts
            state["skipped_by_exact_cap"] = cap_skips
            state["exact_get_skipped_by_exact_cap"] = post_cap_skips
            state["exact_post_skipped_by_exact_cap"] = post_cap_skips
            state["replay_skipped_by_cap"] = replay_skipped
            self._states[base] = state

    def mark_scheduled(self, base, api, kind):
        clean = _canonical_api_path(api, preserve_query=False)
        if not clean:
            return
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if not state:
                return
            if kind == "exact":
                state["_scheduled_exact"].add(clean)
                if clean in state["_replay"]:
                    state["_scheduled_replay"].add(clean)
            elif kind == "heuristic":
                state["_scheduled_heuristic"].add(clean)

    def mark_post_scheduled(self, base, api, body_kind):
        clean = _canonical_api_path(api, preserve_query=False)
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if (
                state and clean in state["_post_eligible"]
                and state["_post_body_kinds"].get(clean) == body_kind
            ):
                state["_scheduled_post"].add(clean)

    def mark_get_scheduled(self, base, api):
        clean = _canonical_api_path(api, preserve_query=False)
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if state and clean in state["_get_eligible"]:
                state["_scheduled_get"].add(clean)

    def mark_attempted(self, base, api, kind, method="", body_kind=""):
        clean = _canonical_api_path(api, preserve_query=False)
        if not clean:
            return
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if not state:
                return
            if kind == "exact":
                state["_attempted_exact"].add(clean)
                if clean in state["_replay"]:
                    state["_attempted_replay"].add(clean)
                if str(method or "").lower() == "post" and clean in state["_scheduled_post"]:
                    if state["_post_body_kinds"].get(clean) == body_kind:
                        state["_attempted_post"].add(clean)
                elif str(method or "").lower() == "get" and clean in state["_scheduled_get"]:
                    state["_attempted_get"].add(clean)
            elif kind == "heuristic":
                state["_attempted_heuristic"].add(clean)

    def mark_completed(self, base, api):
        clean = _canonical_api_path(api, preserve_query=False)
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if state and clean and clean in state["_attempted_exact"]:
                if clean in state["_attempted_get"]:
                    state["_completed_get"].add(clean)
                if clean in state["_attempted_post"]:
                    state["_completed_post"].add(clean)
                dual_required = clean in state["_get_eligible"] or clean in state["_post_eligible"]
                dual_complete = (
                    clean in state["_attempted_get"] and clean in state["_attempted_post"]
                )
                if not dual_required or dual_complete:
                    state["_completed_exact"].add(clean)
                    if clean in state["_replay"]:
                        state["_completed_replay"].add(clean)

    def mark_budget(self, base, api, method=""):
        clean = _canonical_api_path(api, preserve_query=False)
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if state and clean and clean in state["_eligible"] and clean not in state["_attempted_exact"]:
                state["_budget"].add(clean)
            if (
                state and str(method or "").lower() == "post"
                and clean in state["_scheduled_post"] and clean not in state["_attempted_post"]
            ):
                state["_post_budget"].add(clean)
            if (
                state and str(method or "").lower() == "get"
                and clean in state["_scheduled_get"] and clean not in state["_attempted_get"]
            ):
                state["_get_budget"].add(clean)

    def mark_timeout(self, base, api):
        clean = _canonical_api_path(api, preserve_query=False)
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if (
                state and clean
                and clean not in state["_completed_exact"]
                and clean not in state["_budget"]
            ):
                state["_timeout"].add(clean)
            if (
                state and clean in state["_scheduled_post"]
                and clean not in state["_completed_post"]
                and clean not in state["_attempted_post"]
                and clean not in state["_post_budget"]
            ):
                state["_post_timeout"].add(clean)
            if (
                state and clean in state["_scheduled_get"]
                and clean not in state["_completed_get"]
                and clean not in state["_attempted_get"]
                and clean not in state["_get_budget"]
            ):
                state["_get_timeout"].add(clean)

    def mark_method_timeout(self, base, api, method):
        clean = _canonical_api_path(api, preserve_query=False)
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            lower = str(method or "").lower()
            if lower == "post" and (
                state and clean in state["_scheduled_post"]
                and clean not in state["_completed_post"]
                and clean not in state["_attempted_post"]
                and clean not in state["_post_budget"]
            ):
                state["_post_timeout"].add(clean)
            if lower == "get" and (
                state and clean in state["_scheduled_get"]
                and clean not in state["_completed_get"]
                and clean not in state["_attempted_get"]
                and clean not in state["_get_budget"]
            ):
                state["_get_timeout"].add(clean)

    def snapshot(self, base):
        with API_COVERAGE_LOCK:
            state = self._states.get(str(base or ""))
            if not state:
                return _empty_api_coverage_state()
            out = {key: copy.deepcopy(value) for key, value in state.items() if not key.startswith("_")}
            out.update({
                "independently_exact_discovered": len(state["_exact"]),
                "safe_eligible_exact": len(state["_eligible"]),
                "scheduled_unique_exact": len(state["_scheduled_exact"]),
                "attempted_unique_exact": len(state["_attempted_exact"]),
                "completed_unique_exact": len(state["_completed_exact"]),
                "exact_get_eligible": len(state["_get_eligible"]),
                "exact_get_scheduled": len(state["_scheduled_get"]),
                "exact_get_attempted": len(state["_attempted_get"]),
                "exact_get_completed": len(state["_completed_get"]),
                "exact_get_skipped_by_request_budget": len(state["_get_budget"]),
                "exact_get_skipped_by_timeout": len(state["_get_timeout"]),
                "exact_post_eligible": len(state["_post_eligible"]),
                "exact_post_scheduled": len(state["_scheduled_post"]),
                "exact_post_attempted": len(state["_attempted_post"]),
                "exact_post_completed": len(state["_completed_post"]),
                "skipped_by_request_budget": len(state["_budget"]),
                "skipped_by_timeout": len(state["_timeout"]),
                "replay_exact_discovered": int(state["_replay_discovered_count"]),
                "replay_exact_scheduled": len(state["_scheduled_replay"]),
                "replay_exact_attempted": len(state["_attempted_replay"]),
                "replay_exact_completed": len(state["_completed_replay"]),
                "heuristic_scheduled": len(state["_scheduled_heuristic"]),
                "heuristic_attempted": len(state["_attempted_heuristic"]),
            })
            for body_kind, field_kind in (("empty", "empty_body"), ("bound", "bound_body")):
                eligible = {
                    api for api, kind in state["_post_body_kinds"].items()
                    if kind == body_kind
                }
                out[f"exact_post_{field_kind}_eligible"] = len(eligible)
                out[f"exact_post_{field_kind}_scheduled"] = len(eligible & state["_scheduled_post"])
                out[f"exact_post_{field_kind}_attempted"] = len(eligible & state["_attempted_post"])
                out[f"exact_post_{field_kind}_completed"] = len(eligible & state["_completed_post"])
            out["exact_post_skipped_by_request_budget"] = len(state["_post_budget"])
            out["exact_post_skipped_by_timeout"] = len(state["_post_timeout"])
            reasons = []
            if out["skipped_by_exact_cap"]:
                reasons.append("exact_api_max")
            if out["skipped_by_request_budget"]:
                reasons.append("max_requests_per_host")
            if out["skipped_by_timeout"]:
                reasons.append("exact_sweep_timeout")
            if out["replay_skipped_by_cap"]:
                reasons.append("replay_max_apis")
            if out["safe_eligible_exact"] != out["completed_unique_exact"]:
                reasons.append("eligible_exact_incomplete")
            if out["exact_get_skipped_by_exact_cap"]:
                reasons.append("exact_get_max")
            if out["exact_get_skipped_by_request_budget"]:
                reasons.append("exact_get_request_budget")
            if out["exact_get_skipped_by_timeout"]:
                reasons.append("exact_get_timeout")
            if out["exact_get_eligible"] != out["exact_get_completed"]:
                reasons.append("eligible_exact_get_incomplete")
            if out["exact_post_skipped_by_exact_cap"]:
                reasons.append("exact_post_max")
            if out["exact_post_skipped_by_request_budget"]:
                reasons.append("exact_post_request_budget")
            if out["exact_post_skipped_by_timeout"]:
                reasons.append("exact_post_timeout")
            if out["exact_post_eligible"] != out["exact_post_completed"]:
                reasons.append("eligible_exact_post_incomplete")
            out["incomplete_reasons"] = sorted(set(reasons))
            out["coverage_complete"] = not out["incomplete_reasons"]
            return canonical_api_coverage(out)

    def global_snapshot(self):
        snapshots = [self.snapshot(base) for base in sorted(self._states)]
        out = _empty_api_coverage_state()
        out["targets"] = len(snapshots)
        out["skipped_by_safety"] = {}
        out["incomplete_reasons"] = []
        for item in snapshots:
            for key, value in item.items():
                if key in ("coverage_complete", "incomplete_reasons", "skipped_by_safety"):
                    continue
                if isinstance(value, int):
                    out[key] = int(out.get(key) or 0) + value
            for reason, count in item.get("skipped_by_safety", {}).items():
                out["skipped_by_safety"][reason] = out["skipped_by_safety"].get(reason, 0) + count
            out["incomplete_reasons"].extend(item.get("incomplete_reasons", []))
        out["incomplete_reasons"] = sorted(set(out["incomplete_reasons"]))
        out["coverage_complete"] = all(item.get("coverage_complete") for item in snapshots)
        return canonical_api_coverage(out)
PHASE2_INVENTORY_NAME = "phase2_inventory.jsonl"
PHASE2_FULL_NAME = "phase2_full.jsonl"
API_COVERAGE_CHECKPOINT_NAME = "api_coverage.json"
RAW_FIELD_KEYS = {"raw", "raw_body", "body_raw", "response_raw", "raw_response", "request_raw", "raw_request"}

class StreamedResultSet:
    """Lazy iterable over a JSONL file of per-target scan results.

    Replaces the old in-memory `api_results: list[dict]` so 200+ targets
    don't all sit in RAM at once. Supports ``len()``, ``for … in``, and
    ``filtered(predicate)``.  List-like indexing (``[i]``) is deliberately
    NOT provided — it encourages materialising the whole file.
    """

    def __init__(self, path, count):
        self._path = path
        self._count = count

    def __len__(self):
        return self._count

    def __iter__(self):
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield deserialize_scan_record(json.loads(line))
                except (json.JSONDecodeError, TypeError, ValueError, OverflowError) as exc:
                    log.warning(
                        "Skipping malformed Phase2 JSONL record at %s:%d (%s)",
                        self._path, line_number, type(exc).__name__,
                    )
                    continue

    def filtered(self, predicate):
        """Return a new StreamedResultSet (same file) yielding only matches.

        *count* is reset to 0 because we can't know the filtered size ahead
        of time — callers that need an accurate len should materialise.
        """
        parent = self

        class _Filtered:
            def __len__(_s):
                return 0  # unknown; fall back to iteration

            def __iter__(_s):
                for rec in parent:
                    if predicate(rec):
                        yield rec

        return _Filtered()

    def materialize(self):
        """Read every record into a plain list. Use only when you genuinely
        need random access (e.g. cross-base replay)."""
        return list(iter(self))

class _JsonlWriter:
    """Thread-safe append-only JSONL writer."""
    def __init__(self, path):
        self._path = path
        self._lock = Lock()
        self._count = 0
        with open(self._path, "w", encoding="utf-8"):
            pass

    def write(self, record):
        line = json.dumps(
            serialize_scan_record(record), ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ) + "\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)
            self._count += 1

    @property
    def count(self):
        return self._count

OUTDIR_LOCK_HANDLE = None


def acquire_outdir_lock():
    """Hold an exclusive process lock before truncating or rewriting outputs."""
    global OUTDIR_LOCK_HANDLE
    if OUTDIR_LOCK_HANDLE is not None:
        return OUTDIR_LOCK_HANDLE
    os.makedirs(OUTDIR, exist_ok=True)
    lock_path = os.path.join(OUTDIR, ".scanner.lock")
    handle = open(lock_path, "a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        handle.close()
        raise RuntimeError(f"output directory is already in use: {OUTDIR}") from exc
    handle.seek(0)
    handle.truncate()
    handle.write(json.dumps({
        "pid": os.getpid(),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }))
    handle.flush()
    OUTDIR_LOCK_HANDLE = handle
    return handle


def prepare_outdir():
    os.makedirs(OUTDIR, exist_ok=True)
    if not args.fresh:
        return
    checkpoint_re = re.compile(r'^(?:https?___|[a-zA-Z0-9_.-]+_\\d+).*\\.json$')
    for name in os.listdir(OUTDIR):
        if name == ".scanner.lock":
            continue
        path = os.path.join(OUTDIR, name)
        if name == "evidence" and os.path.isdir(path):
            try:
                shutil.rmtree(path)
            except Exception as e:
                log.debug(f"Remove old evidence dir failed: {e}")
            continue
        if (
            name in ("report.json", "report.md", "apis.json", API_COVERAGE_CHECKPOINT_NAME, PHASE2_INVENTORY_NAME)
            or name == PHASE2_FULL_NAME
            or name.startswith(PHASE2_FULL_NAME + ".")
            or checkpoint_re.match(name)
        ):
            try:
                os.remove(path)
            except Exception as e:
                log.debug(f"Remove old output {name} failed: {e}")

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

class _SameHostRedirectHandler(HTTPRedirectHandler):
    """Follow redirects only while they remain on the target hostname."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source_host = (urlparse(req.full_url).hostname or "").lower()
        target_host = (urlparse(urljoin(req.full_url, newurl)).hostname or "").lower()
        if not source_host or source_host != target_host:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _exact_http_origin_key(url):
    try:
        parsed = urlparse(str(url or ""))
        if (
            parsed.scheme.lower() not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (TypeError, ValueError):
        return None
    return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), port


class _ExactOriginRedirectHandler(HTTPRedirectHandler):
    """Follow an advanced-inventory redirect only within the exact origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved = urljoin(req.full_url, newurl)
        if _exact_http_origin_key(req.full_url) != _exact_http_origin_key(resolved):
            return None
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def _build_url_opener(redirect_handler):
    handlers = [HTTPSHandler(context=ssl_ctx), redirect_handler]
    if args.no_proxy:
        handlers.insert(0, ProxyHandler({}))
    return build_opener(*handlers)


SCOPED_URL_OPENER = _build_url_opener(_SameHostRedirectHandler())
NO_REDIRECT_URL_OPENER = _build_url_opener(_NoRedirectHandler())
EXACT_ORIGIN_URL_OPENER = _build_url_opener(_ExactOriginRedirectHandler())


def scoped_urlopen(req, timeout, follow_redirects=True):
    opener = SCOPED_URL_OPENER if follow_redirects else NO_REDIRECT_URL_OPENER
    return opener.open(req, timeout=timeout)

# 绕过系统代理 (ClashX 等 macOS 系统级代理)
if args.no_proxy:
    for _proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(_proxy_var, None)
    os.environ["NO_PROXY"] = "*"
    import urllib.request as _ur
    _proxy_handler = _ur.ProxyHandler({})
    _no_proxy_opener = _ur.build_opener(_proxy_handler)
    _ur.install_opener(_no_proxy_opener)

# ===== 正则（从参考项目继承） =====
LINKFINDER_RE = re.compile(r"""
  (?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|
  ((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|
  ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|
  ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|
  ([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)))(?:"|')
""", re.VERBOSE)

WEBPACK_CHUNK_RE = re.compile(r'''\{[^{}]{0,5000}\}\s*\[[^\]]{0,50}\]\s*\+\s*"[^"]*\.js"''')
SENSITIVE_FIELD_RE = re.compile(r'''(?:secret|password|token|apiKey|accessKey|privateKey)\s*[:=]\s*["']([^"']{8,200})["']''', re.I)
INTERNAL_IP_RE = re.compile(r'''(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})''')
JDBC_RE = re.compile(r'''jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+''', re.I)
COMMON_LIBS = re.compile(r'(?:jquery|bootstrap|vue\.min|vue\.runtime|react\.min|react\.production|angular\.min|axios\.min|lodash|moment|echarts|swiper|polyfill|fontawesome|materialize|foundation|modernizr|d3\.min|three\.min|popper|zepto|hammer|gsap|anime|datatable|select2|cropper|sweetalert|tinymce|ckeditor|quill|summernote|codemirror|ace-editor|monaco|crypto-js|socket\.io|pdf\.js|jspdf|leaflet|mapbox|openlayers|fabric|highlight|prism|markdown|marked|showdown|chunk-vendors|chunk-common|vendor\.\w{8}\.|vendors\.\w{8}\.|core-js|regenerator|webpack\.runtime|babel|polyfill|h265web|ZLMRTC|missile)', re.I)
VUE_INSTANCE_RE = re.compile(r'''__vue_app__|__vue__|createApp|createRouter|new Vue\(|useRouter|useRoute''')
VUE_ROUTER_RE = re.compile(r'''(?:path|route)\s*:\s*["']([^"']{1,200})["']''', re.I)
REACT_ROUTE_RE = re.compile(r'<Route\s+(?:path|to)\s*=\s*["\x27]([^"\x27]{1,200})["\x27]', re.I)
MODULE_ASSET_RE = re.compile(r'(?:^/@vite/client$|^/@id/|^/src/|^src/|\.(?:js|mjs|ts|tsx|jsx|vue)(?:[?#]|$))', re.I)
STATIC_ASSET_RE = re.compile(r'\.(?:css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|pdf|doc|docx|xls|xlsx|zip|rar|7z)(?:[?#]|$)', re.I)
API_ROOT_SEGMENT_RE = re.compile(r"^(?:api|[a-z0-9]{1,24}-api)$", re.I)
API_PREFIX_RE = re.compile(
    r'''["']?(?:baseURL|baseUrl|baseApi|apiBase|apiPrefix|apiUrl|apiURL|api_url|apiHost|api_host|'''
    r'''contextPath|serverBase|serverUrl|serverURL|proxyPrefix|VUE_APP_BASE_API|'''
    r'''VUE_APP_API_BASE|VUE_APP_API_URL|REACT_APP_API_URL|REACT_APP_BASE_API|'''
    r'''NEXT_PUBLIC_API_URL|API_BASE_URL|API_BASE|API_URL|BASE_API)["']?\s*[:=]\s*["']((?:https?:)?//[^"']{1,220}|/[^"']{1,160})["']''',
    re.I)
PUBLIC_PATH_RE = re.compile(r'''["']?(?:publicPath|assetsPublicPath)["']?\s*[:=]\s*["']((?:https?:)?//[^"']{1,220}|/[^"']{1,160})["']''', re.I)
QUERY_PARAM_RE = re.compile(r'''[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=''')
OBJECT_PARAM_RE = re.compile(r'''["']?([a-zA-Z_][a-zA-Z0-9_]{1,40})["']?\s*:\s*["']?([a-zA-Z0-9_\-./:@]{1,120})["']?''')
FORM_FIELD_RE = re.compile(r'''(?:name|v-model|prop|field)\s*=\s*["']([a-zA-Z_][a-zA-Z0-9_.\-\[\]]{1,60})["']''', re.I)
REQUEST_BODY_RE = re.compile(r'''(?:params|data|body)\s*:\s*\{([^{}]{1,2000})\}''', re.I)
NESTED_OBJECT_RE = re.compile(r'''["']?([a-zA-Z_][a-zA-Z0-9_]{1,40})["']?\s*:\s*(\{[^{}]{1,1200}\})''')
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
SAFE_POST_HINTS = (
    "list", "query", "search", "page", "detail", "info", "get", "find", "select",
    "tree", "stats", "stat", "count", "check", "verify", "captcha", "code",
    "export", "download", "preview", "result", "records", "rows", "top", "audit",
)
ACTIVE_POST_HINTS = (
    "delete", "remove", "del", "update", "save", "create", "add", "insert", "edit",
    "modify", "submit", "upload", "import", "logout", "reset", "password",
    "grant", "bind", "unbind", "disable", "enable", "approve", "pay",
    "cancel", "start", "stop", "clear", "sync",
)

def _js_method_group():
    return "get|post|put|patch|delete" if getattr(args, "include_delete_method", False) else "get|post|put|patch"

def _js_method_constants(content):
    return {}

def _request_call_method_truth(text, call_start=0):
    content = str(text or "")
    lexical = _js_lexical_context(content)
    opening = next(
        (index for index in range(max(0, int(call_start)), len(content)) if content[index] == "(" and _is_code_position(lexical, index)),
        -1,
    )
    if opening < 0:
        return METHOD_TRUTH_AMBIGUOUS, ""
    callee_text = content[max(0, int(call_start)):opening]
    method_call = re.match(
        r'''\s*(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*'''
        r'''(?P<method>get|post|put|patch|delete)\s*$''',
        callee_text,
        re.I,
    )
    if method_call and _is_request_method_receiver(
        method_call.group("receiver"),
        content,
        max(0, int(call_start)) + method_call.start("receiver"),
        lexical,
    ):
        return METHOD_TRUTH_METHOD, method_call.group("method").lower()
    args_text, _ = _extract_call_args(content, opening)
    call_args = _split_args(args_text)
    if not call_args:
        return METHOD_TRUTH_AMBIGUOUS, ""
    if call_args[0].strip().startswith("{"):
        return _request_options_method_truth(call_args[0])
    if len(call_args) == 1:
        return METHOD_TRUTH_ABSENT, ""
    return _request_options_method_truth(call_args[1])

def _has_delete_method_hint(text, method_constants=None):
    state, method = _request_call_method_truth(text)
    return state == METHOD_TRUTH_METHOD and method == "delete"

def _explicit_method_hint(text, method_constants=None):
    return _explicit_js_object_method(text, method_constants)

def _skip_param_binding_for_method_truth(text, call_start=0):
    state, method = _request_call_method_truth(text, call_start)
    if state == METHOD_TRUTH_AMBIGUOUS:
        return True
    return not getattr(args, "include_delete_method", False) and state == METHOD_TRUTH_METHOD and method == "delete"

def _method_filter_key(path):
    try:
        clean = normalize_extracted_api(path)
    except NameError:
        value = str(path or "").split("?", 1)[0].split("#", 1)[0].rstrip("/")
        clean = validate_root_relative_path(value) if value.startswith("/") else ""
    if not clean:
        return ""
    return clean.split("?", 1)[0].rstrip("/")

def _should_skip_delete_method_path(path, method_map):
    if getattr(args, "include_delete_method", False):
        return False
    key = _method_filter_key(path)
    if not key:
        return False
    methods = set(method_map.get(key, set()))
    if "delete" not in methods:
        return False
    return not (methods - {"delete"})

def _mark_explicit_method(method_map, path, method):
    key = _method_filter_key(path)
    if not key:
        return
    method_map.setdefault(key, set()).add((method or "").lower())

def explicit_js_method_map(content, return_blocked=False):
    """Map JS-discovered API paths to explicit HTTP methods when recoverable."""
    method_map = {}
    blocked_paths = set()
    constants = js_string_constants(content or "")
    method_constants = _js_method_constants(content or "")
    lexical = _js_lexical_context(content)
    def resolve_path_expr(expr):
        expr = (expr or "").strip().rstrip(",")
        if not expr:
            return ""
        params_concat = re.match(
            r'''^["']([^"']+)["']\s*\+\s*new\s+URLSearchParams\b''', expr
        )
        if params_concat:
            return params_concat.group(1)
        if expr[0:1] in ("'", '"', "`") and expr[-1:] == expr[0]:
            return expr[1:-1]
        if expr in constants:
            return constants.get(expr, "")
        if "+" in expr:
            parts = []
            for part in expr.split("+"):
                value = resolve_path_expr(part)
                if not value:
                    return ""
                parts.append(value)
            return "".join(parts)
        return ""
    def block_path(path):
        key = _method_filter_key(path)
        if key:
            blocked_paths.add(key)
    for m in re.finditer(
        r'''(?P<receiver>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*'''
        r'''(?P<method>get|post|put|patch|delete)\s*\(\s*'''
        r'''(?:["'](?P<literal>[^"']{2,300})["']|(?P<ident>[A-Za-z_$][\w$]*)(?:\s*\+\s*["'](?P<suffix>[A-Za-z0-9_.$@%+=,;&?~!()/\-\u4e00-\u9fff]{1,160})["'])?)''',
        content or "",
        re.I,
    ):
        if not _is_request_method_receiver(m.group("receiver"), content, m.start("receiver"), lexical):
            continue
        method = m.group("method").lower()
        if m.group("literal"):
            _mark_explicit_method(method_map, m.group("literal"), method)
            continue
        base = constants.get(m.group("ident"), "")
        if not base:
            continue
        path = join_api_parts(base, m.group("suffix") or "")
        if not path and not m.group("suffix"):
            path = base
        _mark_explicit_method(method_map, path, method)

    # Destructive syntax is only method metadata when its receiver is trusted.
    # Property/alias receivers remain ordinary inventory.
    for m in re.finditer(
        r'''(?P<receiver>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*delete\s*\(\s*'''
        r'''(?:["'](?P<literal>[^"']{2,300})["']|(?P<ident>[A-Za-z_$][\w$]*)(?:\s*\+\s*["'](?P<suffix>[A-Za-z0-9_.$@%+=,;&?~!()/\-\u4e00-\u9fff]{1,160})["'])?)''',
        content or "",
        re.I,
    ):
        if not _is_request_method_receiver(m.group("receiver"), content, m.start("receiver"), lexical):
            continue
        if m.group("literal"):
            path = m.group("literal")
        else:
            base = constants.get(m.group("ident"), "")
            path = join_api_parts(base, m.group("suffix") or "") if base else ""
            if base and not path and not m.group("suffix"):
                path = base
        if path:
            _mark_explicit_method(method_map, path, "delete")

    for m in re.finditer(r'''(?P<callee>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(''', content or "", re.I):
        if not _direct_request_callee_allowed(
            content, m.group("callee"), m.start("callee"), lexical
        ):
            continue
        args_text, _ = _extract_call_args(content, content.find("(", m.start()))
        args = _split_args(args_text)
        if not args or not args[0].strip().startswith("{"):
            continue
        first = args[0].strip()
        state, method = _request_options_method_truth(first)
        url_m = re.search(r'''(?:url|path)\s*:\s*([^,\n}]{1,400})''', first, re.I)
        path = resolve_path_expr(url_m.group(1)) if url_m else ""
        if state == METHOD_TRUTH_METHOD and method == "delete" and path:
            _mark_explicit_method(method_map, path, "delete")
        elif state == METHOD_TRUTH_AMBIGUOUS:
            block_path(path)

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
        path = resolve_path_expr(m.group("path"))
        if method == "delete" and path:
            _mark_explicit_method(method_map, path, "delete")
        elif raw_method[:1] not in ("'", '"') and path:
            block_path(path)

    for m in _iter_request_calls(content, lexical):
        args_text, _ = _extract_call_args(content, content.find("(", m.start()))
        args = _split_args(args_text)
        if not args:
            continue
        callee = _normalize_callee(m.group("callee")).lower()
        fetch_default = callee in {
            "fetch", "window.fetch", "globalthis.fetch", "axios",
            "uni.request", "wx.request", "$.ajax", "$.getjson",
        }
        first = args[0].strip()
        if first.startswith("{"):
            url_m = re.search(r'''(?:url|path)\s*:\s*([^,\n}]{1,400})''', first, re.I)
            path = resolve_path_expr(url_m.group(1)) if url_m else ""
            state, method = _request_options_method_truth(first)
        else:
            path = resolve_path_expr(first)
            if len(args) == 1:
                state, method = (METHOD_TRUTH_ABSENT, "")
            else:
                state, method = _request_options_method_truth(args[1])
        if state == METHOD_TRUTH_METHOD and path:
            _mark_explicit_method(method_map, path, method)
        elif state == METHOD_TRUTH_ABSENT and fetch_default and path:
            _mark_explicit_method(method_map, path, "get")
        elif state == METHOD_TRUTH_AMBIGUOUS:
            block_path(path)

    blocked_paths.difference_update(method_map)
    return (method_map, blocked_paths) if return_blocked else method_map

def _param_source_from_prop(prop, method=""):
    prop = (prop or "").lower()
    method = (method or "").lower()
    if prop == "params":
        return "query"
    if prop in ("form", "formdata"):
        return "form"
    if method == "get":
        return "query"
    if prop in ("data", "body"):
        return "json"
    return "json"

def _extract_url_body_sources(text):
    """Extract (url, body_text, source) from common JS request styles."""
    pairs = []
    text = str(text or "")
    lexical = _js_lexical_context(text)
    if _source_static_request_trust_ambiguous(text, lexical):
        return pairs
    source_methods = explicit_js_method_map(text)
    obj = r'''\{(?:[^{}]|\{[^{}]*\})*\}'''
    # Pattern 1: request({url:"/api/x", ..., data:{...}})
    for m in re.finditer(r'''request\s*\(\s*\{\s*url\s*:\s*["']([^"']{2,200})["'].*?(data|params|body)\s*:\s*(''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        pairs.append((m.group(1), m.group(3), _param_source_from_prop(m.group(2))))
    # Pattern 2: fetch("/api/x", {body:JSON.stringify({...})})
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["'].*?body\s*:\s*JSON\.stringify\s*\((''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        pairs.append((m.group(1), m.group(2), "json"))
    # Pattern 3: fetch("/api/x?"+new URLSearchParams({...}))
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["']\s*\+\s*new\s+URLSearchParams\s*\((''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        pairs.append((m.group(1), m.group(2), "query"))
    # Pattern 4: fetch("/api/x", {body:qs.stringify({...})})
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["'].*?body\s*:\s*(?:qs\.)?stringify\s*\((''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        pairs.append((m.group(1), m.group(2), "form"))
    # Pattern 4b: fetch("/api/x", {body:new URLSearchParams({...})})
    for m in re.finditer(r'''fetch\s*\(\s*["']([^"']{2,200})["'].*?body\s*:\s*new\s+URLSearchParams\s*\((''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        pairs.append((m.group(1), m.group(2), "form"))
    # Pattern 5: exact trusted receiver methods only. Property receivers such
    # as this.http are ordinary inventory and cannot bind active parameters.
    method_call = (
        r'''(?<![\w$])(?P<receiver>http|axios|request|service)\s*\.\s*'''
        r'''(?P<method>%s)\s*\(\s*["'](?P<path>[^"']{2,200})["']\s*,\s*'''
        r'''(?P<body>%s)''' % (_js_method_group(), obj)
    )
    for m in re.finditer(method_call, text):
        if not _is_request_method_receiver(m.group("receiver"), text, m.start("receiver"), lexical):
            continue
        body = m.group("body")
        if m.group("method") == "get":
            # The second argument is request configuration. Only an actual
            # object-literal ``params`` value is path-local query evidence;
            # ``{params: formal}`` requires lexical AST forwarding proof.
            nested = re.search(r'''params\s*:\s*(''' + obj + r''')''', body)
            if not nested:
                continue
            body = nested.group(1)
            source = "query"
        else:
            source = "json"
        pairs.append((m.group("path"), body, source))
    # Pattern 6: request("/api/x", {params:{...}}) / axios("/api/x", {data:{...}})
    for m in re.finditer(r'''(?:request|axios)\s*\(\s*["']([^"']{2,200})["']\s*,\s*\{.*?(data|params|body)\s*:\s*(''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        pairs.append((m.group(1), m.group(3), _param_source_from_prop(m.group(2))))
    # Pattern 7: axios({url:"/api/x", params:{...}}) / uni.request({url:"/api/x", data:{...}})
    for m in re.finditer(r'''(?:axios|request|uni\.request|wx\.request|\w+\.request)\s*\(\s*\{.*?url\s*:\s*["']([^"']{2,200})["'].*?(data|params|body)\s*:\s*(''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        pairs.append((m.group(1), m.group(3), _param_source_from_prop(m.group(2))))
    # Pattern 8: $.ajax({url:"/api/x", data:{...}}) / $.getJSON({url:"/api/x", data:{...}})
    for m in re.finditer(r'''\$\.(?:ajax|post|get|getJSON)\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']{2,200})["'].*?data\s*:\s*(''' + obj + r''')''', text, re.I):
        if _skip_param_binding_for_method_truth(text, m.start()):
            continue
        source = "query" if re.search(r'''(?:type|method)\s*:\s*["']?GET["']?''', m.group(0), re.I) else "form"
        pairs.append((m.group(1), m.group(2), source))
    # Pattern 9: $.get("/api/x", {...}) / $.post("/api/x", {...}) / $.getJSON("/api/x", {...})
    for m in re.finditer(r'''\$\.(get|post|getJSON)\s*\(\s*["']([^"']{2,200})["']\s*,\s*(''' + obj + r''')''', text, re.I):
        source = "form" if m.group(1).lower() == "post" else "query"
        pairs.append((m.group(2), m.group(3), source))
    # Pattern 10: const fd = new FormData(); fd.append("docId", ...); axios.post("/api/x", fd)
    for m in re.finditer(r'''(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*new\s+FormData\s*\(\s*\)\s*;([\s\S]{0,1500}?)(?:axios|request|http|service)\.post\s*\(\s*["']([^"']{2,200})["']\s*,\s*\1''', text, re.I):
        fd_name, middle, url_path = m.group(1), m.group(2), m.group(3)
        keys = re.findall(r'''%s\.append\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']''' % re.escape(fd_name), middle)
        if keys:
            pairs.append((url_path, "{" + ",".join(f"{k}:1" for k in keys) + "}", "form"))
    # Pattern 11: window.open("/api/x?param="+value) / location.href="/api/x?id="+id
    for m in re.finditer(r'''(?:window\.open|location\.href)\s*\(\s*["']([^"']{2,200}\?(?:[a-zA-Z_][a-zA-Z0-9_]*=)["']\s*\+)''', text, re.I):
        url_part = m.group(1).rstrip('"+ ')
        pairs.append((url_part.split("?")[0], "", "query"))
    def same_source_method_compatible(url_path, source):
        key = _method_filter_key(url_path)
        methods = set(source_methods.get(key, set())) if key else set()
        if source in ("json", "form"):
            return bool(methods & {"post", "put", "patch"})
        if source == "query":
            if "get" in methods:
                return True
            return bool(
                "post" in methods
                and is_safe_post_path(url_path)
                and not is_action_like_post_path(url_path)
            )
        return False

    return [
        (url_path, body_text, source)
        for url_path, body_text, source in pairs
        if same_source_method_compatible(url_path, source)
    ]

def _extract_url_body_pairs(text):
    return [(url, body) for url, body, _source in _extract_url_body_sources(text)]
FILE_SEED_RE = re.compile(r'''["']([a-zA-Z0-9_\-./]{1,120}\.(?:pdf|doc|docx|xls|xlsx|csv|zip|rar|7z|jpg|jpeg|png|gif|txt))["']''', re.I)
NUMERIC_ID_RE = re.compile(r'''(?:id|Id|ID|fileId|docId|recordId|userId|deptId|orgId|attachId)\s*[:=]\s*["']?(\d{1,12})["']?''')
COMMON_PARAM_HINTS = {
    "id","ids","page","pageNum","pageNo","current","size","pageSize","limit","count",
    "keyword","keywords","query","search","name","username","userId","deptId","orgId",
    "tenantId","type","status","startTime","endTime","beginTime","endDate","startDate",
    "fileId","fileName","filePath","path","url","key","objectKey","ossKey","downloadUrl",
    "recordId","docId","documentId","attachId","attachmentId","templateId"
}
PARAM_PROBE_KEYWORDS = (
    "download","export","preview","file","attach","attachment","document","template",
    "list","query","search","page","detail","info","get","find","select",
    "user","person","people","device","camera","record","report","log","alarm"
)

WEB_PORTS = [80,443,8080,8443,8001,81,82,88,3000,4000,5000,7000,8000,8002,8003,8008,8081,8088,8089,8888,9000,9090,9443,10000,10080,10443,4433,4443]
HTTPS_PORTS = {443, 8443, 9443, 10443, 4433, 4443}

FAST_BYPASS = [
    ("GET_no_auth","GET",None,None,{}),
    ("POST_JSON_no_auth","POST","application/json",lambda p: json.dumps(p).encode(),{}),
]
FULL_BYPASS = FAST_BYPASS + [
    ("GET_empty_bearer","GET",None,None,{"Authorization":"Bearer "}),
    ("GET_admin_token","GET",None,None,{"Authorization":"Bearer admin-token"}),
    ("POST_FORM_no_auth","POST","application/x-www-form-urlencoded",lambda p: urlencode(p).encode(),{}),
    ("POST_JWT_none","POST","application/json",lambda p: json.dumps(p).encode(),{"Authorization":"Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."}),
]
CONFIG_REST_SUFFIXES = ("", "/users", "/profile", "/list", "/page", "/all", "/tree", "/info")

BASELINE_PATHS = [
    "/api/status", "/api/health", "/api/version", "/api/config",
    "/api/users", "/api/roles", "/api/logs",
    "/swagger-ui.html","/swagger/index.html","/swagger-ui/index.html",
    "/v2/api-docs","/v3/api-docs","/druid/index.html","/druid/datasource.json",
    "/druid/sql.json","/druid/websession.json","/druid/wall.json","/druid/basic.json",
    "/druid/stat.json","/actuator","/actuator/env",
]
HIGH_YIELD_BASELINE_PATHS = [
    "/api/status",
    "/api/health",
    "/druid/basic.json",
    "/druid/stat.json",
    "/druid/sql.json",
    "/druid/wall.json",
    "/v3/api-docs",
    "/actuator/env",
    "/swagger-ui/index.html",
    "/swagger/index.html",
]
BACKEND_BASELINE_PATHS = [
    # Generic synthetic REST shapes. Deployment-specific paths belong in an
    # operator-owned --extra-api-wordlist, never in bundled product defaults.
    "/api/v1/status",
    "/api/v1/health",
    "/api/v1/users",
    "/api/v1/search",
    "/rest/status",
    "/rest/users",
]
SWAGGER_DOC_PATHS = ["/v2/api-docs", "/v3/api-docs", "/openapi.json", "/swagger.json"]
AUTH_FAIL_MSGS = [
    "缺少请求授权令牌","token无效","未登录","请登录","Unauthorized","Forbidden",
    "登录已过期","重新登录","请重新登录","无权限访问","没有权限","权限不足",
    "认证失败","身份认证失败","登录超时","会话过期","session expired",
    "access denied","permission denied","not authorized","no permission",
]
FRAMEWORK_NOT_FOUND_RE = re.compile(
    r"controller not exists|method not exists|class not exists|module not exists|route not found|"
    r"not exists:app[\\\\/]controller",
    re.I,
)
CAPTCHA_RE = re.compile(
    r"captcha|verifycode|verify_code|verificationcode|validcode|validatecode|"
    r"checkcode|check_code|checknum|randcode|vcode|codeimg|login_code|"
    r"kaptcha|authcode|auth_code|securitycode|seccode",
    re.I,
)
PUBLIC_DOWNLOAD_RE = re.compile(
    r"downloadca|cert|certificate|ca\.|rootca|client|plugin|setup|installer|"
    r"authenticator|webplugin|控件|客户端|证书|插件",
    re.I,
)

FILE_ENDPOINT_KEYWORDS = [
    "download","downLoad","file","files","export","preview","view","read",
    "attachment","attach","upload","resource","document","doc","image",
    "photo","avatar","template","import","excel","word","pdf"
]
FILE_ENDPOINT_WORDS = {k.lower() for k in FILE_ENDPOINT_KEYWORDS}
FILE_ENDPOINT_PREFIXES = ("download", "export", "preview", "upload", "attach", "attachment", "import")
FILE_PARAM_NAMES = [
    "id","ids","fileId","file_id","attachId","attachmentId","docId","documentId",
    "templateId","recordId","path","filePath","url","fileUrl","name","fileName",
    "key","objectKey","downloadUrl","resourceId","avatar","src",
    "photoId","photoIds"
]
FILE_SEED_VALUES = [
    "1","2","3","10","100","1000","test","demo","default",
    "1.pdf","test.pdf","demo.pdf","1.xlsx","test.xlsx","1.docx","test.docx",
    "1.jpg","test.jpg","1.png","test.png","template.xlsx","template.docx"
]
FILE_BASELINE_PATHS = [
    "/api/file/download","/api/file/preview","/api/file/view","/api/file/get",
    "/api/common/download","/api/common/download/resource",
    "/api/attachment/download","/api/attach/download","/api/document/download",
    "/api/export","/api/template/download",
]
if args.enable_file_baseline and not args.disable_file_hunter:
    BASELINE_PATHS = BASELINE_PATHS + FILE_BASELINE_PATHS
FILE_CT_HINTS = [
    "application/octet-stream","application/pdf","application/zip","application/x-zip",
    "application/msword","application/vnd.ms-excel","application/vnd.openxmlformats",
    "image/jpeg","image/png","image/gif","application/x-msdownload"
]

# ===== 工具函数 =====
def tcp_check(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TCP_TIMEOUT)
        r = s.connect_ex((str(host), int(port)))
        s.close()
        return r == 0
    except Exception as e:
        log.debug(f"TCP {host}:{port} failed: {e}")
        return False

def _maybe_decompress_http_body(body, headers=None):
    return _maybe_decompress_http_body_impl(body, headers, log=log)

def decode_http_body(body, headers=None):
    return _decode_http_body(body, headers, log=log)

def read_http_response(resp, max_size=1_000_000, include_metadata=False):
    return _read_http_response(resp, max_size=max_size, log=log, include_metadata=include_metadata)

def http_get(url, timeout=HTTP_TIMEOUT, max_size=1_000_000, retries=SSL_RETRIES, include_metadata=False):
    for attempt in range(retries + 1):
        try:
            req = Request(url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36","Accept":"text/html,application/javascript,application/json,*/*","Accept-Encoding":http_accept_encoding()})
            resp = scoped_urlopen(req, timeout=timeout * (attempt + 1))
            response = read_http_response(resp, max_size=max_size, include_metadata=include_metadata)
            text = response[2]
            base = (resp.getcode(), resp.url, text, resp.headers.get("Content-Type", ""))
            return base + (response[3],) if include_metadata else base
        except HTTPError as e:
            try:
                response = read_http_response(e, max_size=max_size, include_metadata=include_metadata)
                base = (e.code, e.url, response[2][:100000], e.headers.get("Content-Type", ""))
                return base + (response[3],) if include_metadata else base
            except:
                base = (e.code, e.url, "", "")
                return base + ({"content_truncated": False},) if include_metadata else base
        except Exception as e:
            if 'SSL' in str(e) or 'handshake' in str(e).lower() or 'timed out' in str(e).lower():
                if attempt < retries:
                    log.debug(f"SSL retry {attempt+1} for {url}")
                    time.sleep(1)
                    continue
            log.debug(f"HTTP GET {url} failed: {e}")
            if attempt == retries:
                base = (None, None, "", "")
                return base + ({"content_truncated": False},) if include_metadata else base
    base = (None, None, "", "")
    return base + ({"content_truncated": False},) if include_metadata else base


def exact_origin_http_get(url, timeout=HTTP_TIMEOUT, max_size=1_000_000, include_metadata=False):
    """GET for advanced inventory without changing ordinary crawler redirects."""
    origin = _exact_http_origin_key(url)
    if not origin:
        base = (None, None, "", "")
        return base + ({"content_truncated": False},) if include_metadata else base
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/javascript,application/json,text/javascript,*/*",
            "Accept-Encoding": http_accept_encoding(),
        })
        resp = EXACT_ORIGIN_URL_OPENER.open(req, timeout=timeout)
        if _exact_http_origin_key(resp.url) != origin:
            resp.close()
            base = (None, None, "", "")
            return base + ({"content_truncated": False},) if include_metadata else base
        response = read_http_response(resp, max_size=max_size, include_metadata=include_metadata)
        base = (resp.getcode(), resp.url, response[2], resp.headers.get("Content-Type", ""))
        return base + (response[3],) if include_metadata else base
    except HTTPError as exc:
        # A rejected cross-origin redirect arrives here without following it.
        base = (exc.code, exc.url, "", exc.headers.get("Content-Type", "") if exc.headers else "")
        return base + ({"content_truncated": False},) if include_metadata else base
    except Exception as exc:
        log.debug(f"Advanced exact-origin GET failed: {type(exc).__name__}")
        base = (None, None, "", "")
        return base + ({"content_truncated": False},) if include_metadata else base

def phase2_page_quality(html):
    html = html or ""
    if not html:
        return 0
    head = html[:200_000]
    lower = head.lower()
    score = 0
    if re.search(r"<title[^>]*>[^<]{1,200}</title>", head, re.I):
        score += 20
    script_count = len(re.findall(r"<script\b", head, re.I))
    score += min(script_count, 30) * 3
    js_ref_count = len(re.findall(r"\.(?:js|mjs|ts|vue)(?:[?#\"']|$)", head, re.I))
    score += min(js_ref_count, 30) * 2
    if any(marker in lower for marker in ("id=\"app\"", "id='app'", "__webpack", "__vite", "/@vite/client", "vue", "react")):
        score += 10
    if len(html) > 2_000:
        score += 5
    if len(html) > 10_000:
        score += 5
    return score

def refresh_sparse_phase2_page(page_url, status, final_url, html, content_type):
    if status is None or phase2_page_quality(html) >= 10:
        return status, final_url, html, content_type
    best = (status, final_url, html, content_type)
    best_score = phase2_page_quality(html)
    parsed = urlparse(page_url)
    fallback_urls = [page_url]
    if parsed.scheme and parsed.netloc:
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        fallback_urls.extend([
            origin + "/",
            origin + "/index.html",
        ])
        if path and path != "/":
            fallback_urls.append(urljoin(page_url if page_url.endswith("/") else page_url + "/", "index.html"))
    for retry_url in dict.fromkeys(fallback_urls):
        time.sleep(0.2)
        candidate = http_get(retry_url, retries=1)
        candidate_score = phase2_page_quality(candidate[2])
        if candidate[0] is not None and candidate_score > best_score:
            best, best_score = candidate, candidate_score
        if best_score >= 10:
            break
    return best

def compact_url(url, max_len=120):
    if len(url) <= max_len:
        return url
    keep_head = max_len // 2
    keep_tail = max_len - keep_head - 3
    return url[:keep_head] + "..." + url[-keep_tail:]

def input_item(url, title="", score=0):
    return input_tools.input_item(url, title, score)

def dedupe_targets(items):
    return input_tools.dedupe_targets(items)

def parse_masscan_item(obj):
    return input_tools.parse_masscan_item(obj)

def resolve_tool(name, override=""):
    return input_tools.resolve_tool(name, override)

def require_tool(name, override=""):
    return input_tools.require_tool(name, override)

def command_env():
    return input_tools.command_env(no_proxy=args.no_proxy)

def run_command(cmd, label):
    return input_tools.run_command(cmd, label, no_proxy=args.no_proxy, debug=args.debug, log=log)

def write_target_lines(path, targets):
    return input_tools.write_target_lines(path, targets)

def run_port_discovery(targets):
    return input_tools.run_port_discovery(
        targets,
        port_scanner=args.port_scanner,
        masscan_bin=args.masscan_bin,
        naabu_bin=args.naabu_bin,
        scan_ports=args.scan_ports,
        scan_rate=args.scan_rate,
        no_proxy=args.no_proxy,
        debug=args.debug,
        log=log,
    )

def run_httpx_probe(targets):
    return input_tools.run_httpx_probe(
        targets,
        http_prober=args.http_prober,
        httpx_bin=args.httpx_bin,
        httpx_extra_args=args.httpx_extra_args,
        http_timeout=HTTP_TIMEOUT,
        no_proxy=args.no_proxy,
        debug=args.debug,
        log=log,
    )

def load_targets(path, input_format):
    return input_tools.load_targets(path, input_format)

def target_url_with_scheme(raw):
    raw = (raw or "").strip()
    if not raw:
        return "", "", None
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return raw, parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)
    if "://" in raw:
        return raw, "", None
    host = raw
    port = None
    if raw.count(":") == 1:
        left, right = raw.rsplit(":", 1)
        if left and right.isdigit():
            host, port = left.strip("[]"), int(right)
    if port:
        scheme = "https" if port in HTTPS_PORTS else "http"
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        return (f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"), host, port
    return "", raw.strip("[]"), None

def format_base_url(host, port, scheme):
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"

def scheme_candidates_for_port(port):
    guessed = "https" if port in HTTPS_PORTS else "http"
    other = "http" if guessed == "https" else "https"
    return [guessed, other]

def evidence_max_body_bytes():
    try:
        return max(0, int(getattr(args, "evidence_max_body_bytes", 262144) or 0))
    except Exception:
        return 262144

def evidence_body_bytes(body):
    body = body or b""
    limit = evidence_max_body_bytes()
    return body[:limit] if limit >= 0 else body

def evidence_payload_hash(data):
    if data in (None, b"", ""):
        return ""
    if isinstance(data, bytes):
        raw = data
    else:
        raw = str(data).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:16]

def safe_evidence_filename(url, method="GET", test="", data=None):
    parsed = urlparse(url if "://" in str(url or "") else "http://" + str(url or ""))
    query_keys = sorted(k for k, _v in parse_qsl(parsed.query, keep_blank_values=True))
    query_hash = hashlib.sha256((parsed.query or "").encode("utf-8", errors="replace")).hexdigest()[:16] if parsed.query else ""
    canonical = {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path or "/",
        "query_keys": query_keys,
        "query_hash": query_hash,
        "method": str(method or "GET").upper(),
        "test": str(test or ""),
        "payload_hash": evidence_payload_hash(data),
    }
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:18]
    path_label = re.sub(r"[^A-Za-z0-9]+", "_", f"{parsed.netloc}{parsed.path or '/'}").strip("_")[:80] or "root"
    test_label = re.sub(r"[^A-Za-z0-9]+", "_", str(test or "probe")).strip("_")[:40] or "probe"
    method_label = re.sub(r"[^A-Za-z0-9]+", "_", str(method or "GET").upper()).strip("_") or "GET"
    return f"{method_label}_{test_label}_{path_label}_{digest}.json"

def ensure_private_evidence_dir():
    evidence_dir = os.path.join(OUTDIR, "evidence")
    os.makedirs(evidence_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(evidence_dir, 0o700)
    except Exception as e:
        log.debug(f"chmod evidence dir failed: {e}")
    return evidence_dir

def write_private_json(path, obj):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2, default=str)
    finally:
        try:
            os.chmod(path, 0o600)
        except Exception as e:
            log.debug(f"chmod evidence file failed: {e}")

def request_target_from_url(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    path = parsed.path or "/"
    if parsed.params:
        path += ";" + parsed.params
    if parsed.query:
        path += "?" + parsed.query
    return path

def host_header_from_url(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or parsed.netloc or parsed.path.split("/", 1)[0]
    if parsed.port:
        return f"{host}:{parsed.port}"
    return host

def format_raw_request_packet(url, method="GET", headers=None, body=None):
    method_text = re.sub(r"[^A-Z0-9_-]", "", str(method or "GET").upper()) or "GET"
    header_lines = []
    seen = set()
    for key, value in (headers or {}).items():
        name = str(key or "").strip()
        if not name:
            continue
        seen.add(name.lower())
        header_lines.append(f"{name}: {value}")
    if "host" not in seen:
        header_lines.insert(0, f"Host: {host_header_from_url(url)}")
    lines = [f"{method_text} {request_target_from_url(url)} HTTP/1.1", *header_lines]
    if body not in (None, b"", ""):
        if isinstance(body, bytes):
            body_text = body.decode("utf-8", errors="replace")
        else:
            body_text = str(body)
        lines.extend(["", body_text])
    return "\r\n".join(lines)

def format_raw_response_packet(resp, body_bytes):
    reason = getattr(resp, "reason", "") or "OK"
    lines = [f"HTTP/1.1 {resp.getcode()} {reason}"]
    for key, value in resp.headers.items():
        lines.append(f"{key}: {value}")
    body_text = (body_bytes or b"").decode("utf-8", errors="replace")
    if body_text:
        lines.extend(["", body_text])
    return "\r\n".join(lines)

def build_evidence_request(finding):
    url = str(finding.get("evidence_url") or finding.get("url") or "")
    method = str(finding.get("method") or "GET").upper()
    test_name = str(finding.get("test") or "")
    headers = {"User-Agent":"Mozilla/5.0","Accept":"application/json,text/html,*/*","Accept-Encoding":http_accept_encoding()}
    data = None
    for name, bypass_method, ct, bf, bypass_headers in FULL_BYPASS:
        if name == test_name and bypass_method == method:
            headers.update(bypass_headers)
            if method in ("POST","PUT","PATCH") and bf:
                data = bf({})
            if data and ct:
                headers["Content-Type"] = ct
            break
    return url, method, headers, data

def capture_finding_evidence_for_target(target):
    if not getattr(args, "capture_finding_evidence", True):
        return 0
    if getattr(args, "dry_run", False):
        return 0
    findings = target.get("findings") or []
    if not findings:
        return 0
    evidence_dir = ensure_private_evidence_dir()
    saved = 0
    for finding in findings:
        url, method, headers, data = build_evidence_request(finding)
        if not url:
            continue
        try:
            allowed, limit_reason = acquire_phase3_request_slot(url)
            if not allowed:
                finding["evidence_capture_error"] = limit_reason
                continue
            req = Request(url, data=data, headers=headers, method=method)
            raw_request = format_raw_request_packet(url, method, headers, data)
            try:
                resp = scoped_urlopen(req, timeout=API_TIMEOUT)
                raw_body = evidence_body_bytes(read_limited(resp, max_size=max(1, evidence_max_body_bytes())))
                raw_response = format_raw_response_packet(resp, raw_body)
                status_code = resp.getcode()
            except HTTPError as e:
                raw_body = evidence_body_bytes(read_limited(e, max_size=max(1, evidence_max_body_bytes())))
                raw_response = format_raw_response_packet(e, raw_body)
                status_code = e.code
            evidence = {
                "base": target.get("base", ""),
                "url": url,
                "method": method,
                "test": finding.get("test", ""),
                "risk": finding.get("risk", ""),
                "status": status_code,
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "raw_request": raw_request,
                "raw_response": raw_response,
                "finding": {k: v for k, v in finding.items() if k not in RAW_FIELD_KEYS and not str(k).startswith("raw_")},
                "findings": [{
                    **{k: v for k, v in finding.items() if k not in RAW_FIELD_KEYS and not str(k).startswith("raw_")},
                    "raw_request": raw_request,
                    "raw_response": raw_response,
                }],
            }
            out_path = os.path.join(evidence_dir, safe_evidence_filename(url, method, finding.get("test", ""), data))
            write_private_json(out_path, evidence)
            finding["evidence_file"] = os.path.relpath(out_path, OUTDIR)
            finding["evidence_status"] = status_code
            saved += 1
        except Exception as e:
            finding["evidence_capture_error"] = str(e)[:200]
            log.debug(f"Evidence capture failed for {url}: {e}")
    return saved

def save_finding_evidence(target_base, finding, url, method, headers, data, resp, body_bytes):
    if not getattr(args, "capture_finding_evidence", True):
        return ""
    if getattr(args, "dry_run", False):
        return ""
    try:
        evidence_dir = ensure_private_evidence_dir()
        saved_body = evidence_body_bytes(body_bytes)
        raw_request = format_raw_request_packet(url, method, headers, data)
        raw_response = format_raw_response_packet(resp, saved_body)
        evidence = {
            "base": target_base,
            "url": url,
            "method": method,
            "test": finding.get("test", ""),
            "risk": finding.get("risk", ""),
            "status": resp.getcode(),
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "raw_request": raw_request,
            "raw_response": raw_response,
            "finding": {k: v for k, v in finding.items() if k not in RAW_FIELD_KEYS and not str(k).startswith("raw_")},
            "findings": [{
                **{k: v for k, v in finding.items() if k not in RAW_FIELD_KEYS and not str(k).startswith("raw_")},
                "raw_request": raw_request,
                "raw_response": raw_response,
            }],
        }
        out_path = os.path.join(evidence_dir, safe_evidence_filename(url, method, finding.get("test", ""), data))
        write_private_json(out_path, evidence)
        rel = os.path.relpath(out_path, OUTDIR)
        finding["evidence_file"] = rel
        finding["evidence_status"] = resp.getcode()
        return rel
    except Exception as e:
        finding["evidence_capture_error"] = str(e)[:200]
        log.debug(f"Evidence save failed for {url}: {e}")
        return ""

def reachable_base_url(host, port, preferred_url=None):
    def quick_http_ok(base):
        try:
            req = Request(base, headers={"User-Agent":"Mozilla/5.0","Accept":"text/html,application/json"})
            resp = scoped_urlopen(req, timeout=min(2, HTTP_TIMEOUT), follow_redirects=False)
            resp.read(1)
            return True
        except HTTPError:
            return True
        except Exception as e:
            log.debug(f"Scheme probe {base} failed: {e}")
            return False
    if not args.skip_port_probe and not tcp_check(host, port):
        return None
    if preferred_url:
        if quick_http_ok(preferred_url):
            return preferred_url
        parsed = urlparse(preferred_url)
        if parsed.scheme in ("http", "https"):
            other_scheme = "http" if parsed.scheme == "https" else "https"
            netloc = parsed.netloc or urlparse(format_base_url(host, port, other_scheme)).netloc
            other = urlunparse((other_scheme, netloc, parsed.path or "", parsed.params or "", parsed.query or "", parsed.fragment or ""))
            if quick_http_ok(other):
                return other
        if args.allow_unverified_url:
            return preferred_url
        return None
    for scheme in scheme_candidates_for_port(port):
        base = format_base_url(host, port, scheme)
        if quick_http_ok(base):
            return base
    return None

def is_file_endpoint(path):
    parts = re.split(r'[^A-Za-z0-9]+', path.split("?", 1)[0])
    for part in parts:
        if not part:
            continue
        lowered = part.lower()
        if lowered in FILE_ENDPOINT_WORDS:
            return True
        if any(lowered.startswith(p) or lowered.endswith(p) for p in FILE_ENDPOINT_PREFIXES):
            return True
        words = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', part).lower().split()
        if any(w in FILE_ENDPOINT_WORDS for w in words):
            return True
    return False

def file_magic(raw):
    if raw.startswith(b"%PDF-"): return "PDF"
    if raw.startswith(b"PK\x03\x04"): return "ZIP/OOXML"
    if raw.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"): return "OLE"
    if raw.startswith(b"\xff\xd8\xff"): return "JPEG"
    if raw.startswith(b"\x89PNG\r\n\x1a\n"): return "PNG"
    if raw.startswith(b"GIF87a") or raw.startswith(b"GIF89a"): return "GIF"
    if raw.startswith(b"Rar!\x1a\x07"): return "RAR"
    if raw.startswith(b"7z\xbc\xaf\x27\x1c"): return "7Z"
    if raw.startswith(b"MZ"): return "PE"
    return ""

def looks_like_login_or_error(raw, content_type):
    head = raw[:4096].decode("utf-8", errors="ignore").lower()
    if "text/html" in content_type.lower() and any(x in head for x in ["login", "登录", "请登录", "unauthorized", "forbidden"]):
        return True
    if any(x in head for x in ["缺少请求授权令牌", "token无效", "未登录", "请登录", "unauthorized", "forbidden"]):
        return True
    return False

def looks_like_captcha(url, content_disp=""):
    return bool(CAPTCHA_RE.search((url or "") + " " + (content_disp or "")))

def is_strong_download_endpoint(url):
    p = urlparse(url).path.lower()
    return any(x in p for x in ("/download", "/export", "/preview", "/attach", "/attachment", "/document", "/template"))

def looks_like_public_download(url, content_disp="", magic="", content_type=""):
    text = " ".join([url or "", content_disp or "", magic or "", content_type or ""])
    path = urlparse(url).path.lower()
    if PUBLIC_DOWNLOAD_RE.search(text):
        return True
    return path.endswith((".apk", ".exe", ".msi", ".dmg", ".pkg", ".crt", ".cer", ".pem"))

def check_file_response(raw, headers, url, method, test_name, status_code=None):
    if not raw or len(raw) < 32:
        return None
    if status_code is not None and not (200 <= int(status_code) < 300):
        return None
    content_type = headers.get("Content-Type", "") if headers else ""
    content_disp = headers.get("Content-Disposition", "") if headers else ""
    if looks_like_captcha(url, content_disp):
        return None
    magic = file_magic(raw)
    file_endpoint = is_file_endpoint(url)
    image_file = magic in ("JPEG", "PNG", "GIF")
    if image_file and not content_disp and not is_strong_download_endpoint(url):
        return None
    if image_file and len(raw) < 2048 and not content_disp:
        return None
    score = 0
    reasons = []
    if content_disp:
        score += 3; reasons.append("content_disposition")
    if magic:
        score += 3; reasons.append(f"magic:{magic}")
    if any(x in content_type.lower() for x in FILE_CT_HINTS):
        score += 2; reasons.append(f"content_type:{content_type[:80]}")
    if len(raw) > 2048:
        score += 1; reasons.append("size>2KB")
    if file_endpoint:
        score += 1; reasons.append("file_endpoint")
    if looks_like_login_or_error(raw, content_type):
        score -= 5; reasons.append("auth_or_login_hint")
    if "text/html" in content_type.lower() and not magic and not content_disp:
        score -= 3; reasons.append("html_without_file_signal")
    if score < 4:
        return None
    public_download = looks_like_public_download(url, content_disp, magic, content_type)
    risk = "LOW" if public_download else "HIGH" if score >= 6 else "MEDIUM"
    finding = {
        "url": url,
        "method": method,
        "test": test_name,
        "risk": risk,
        "file_leak": True,
        "public_download_intel": public_download,
        "file_score": score,
        "file_reasons": reasons,
        "content_type": content_type[:120],
        "content_disposition": content_disp[:200],
        "file_magic": magic,
        "body_size": len(raw),
        "raw": raw[:160].hex(),
    }
    apply_finding_semantics(finding)
    return finding

def file_query_suffixes(path):
    suffixes = ["", "?page=1&count=10", "?page=1&size=10"]
    if args.disable_file_hunter:
        return suffixes
    if not is_file_endpoint(path):
        return suffixes
    limit = max(0, int(getattr(args, "file_max_probes", 0) or 0))
    probes = []
    for name in FILE_PARAM_NAMES:
        for value in FILE_SEED_VALUES:
            probes.append(f"?{name}={value}")
            if limit > 0 and len(probes) >= limit:
                return suffixes + probes
    return suffixes + probes

def empty_param_profile():
    return {
        "names": set(),
        "seeds": set(),
        "file_seeds": set(),
        "api_params": {},
        "api_param_sources": {},
        "api_param_shapes": {},
        "api_methods": {},
        "api_param_specs": {},
        "api_content_types": {},
        "api_path_templates": {},
        "api_param_blocked": set(),
    }

def normalize_param_name(name):
    name = (name or "").strip().strip("[]")
    if "." in name:
        name = name.split(".")[-1]
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]{0,40}$", name):
        return ""
    return name

def _validated_profile_api_path(api_path):
    path = str(api_path or "").split("?", 1)[0].split("#", 1)[0].rstrip("/")
    return validate_root_relative_path(path) if path else ""

def add_param_name(profile, name, api_path=None, source="query"):
    name = normalize_param_name(name)
    if not name:
        return
    profile["names"].add(name)
    if api_path:
        api_path = _validated_profile_api_path(api_path)
        if api_path:
            profile["api_params"].setdefault(api_path, set()).add(name)
            source = source if source in ("query", "json", "form") else "query"
            profile.setdefault("api_param_sources", {}).setdefault(api_path, {}).setdefault(source, set()).add(name)

def add_param_shape(profile, api_path, source, parent, names):
    if not api_path or source not in ("json", "form"):
        return
    parent = normalize_param_name(parent)
    clean_names = [normalize_param_name(n) for n in names]
    clean_names = [n for n in clean_names if n]
    if not parent or not clean_names:
        return
    api_path = _validated_profile_api_path(api_path)
    if not api_path:
        return
    shapes = profile.setdefault("api_param_shapes", {}).setdefault(api_path, {}).setdefault(source, {})
    shapes.setdefault(parent, set()).update(clean_names)


def add_api_method(profile, api_path, method):
    api_path = _validated_profile_api_path(api_path)
    method = str(method or "").lower()
    if api_path and method in HTTP_METHODS:
        profile.setdefault("api_methods", {}).setdefault(api_path, set()).add(method)

def add_api_param(profile, api_path, name, source="query"):
    add_param_name(profile, name, api_path=api_path, source=source)


def _clean_profile_api_path(api_path):
    return _validated_profile_api_path(api_path)


def _safe_scalar_text(value, max_length=160):
    if value is None or isinstance(value, (dict, list, tuple, set, frozenset)):
        return ""
    if isinstance(value, float) and not math.isfinite(value):
        return ""
    if not isinstance(value, (str, int, float, bool)):
        return ""
    text = str(value).strip()
    if not text or len(text) > max_length or any(ord(ch) < 32 for ch in text):
        return ""
    return text


def _json_scalar_sort_key(value):
    type_rank = {
        str: 0,
        bool: 1,
        int: 2,
        float: 3,
    }.get(type(value), 9)
    return (
        type_rank,
        json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")),
    )


def _canonical_json_scalars(values, limit):
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    unique = {}
    for value in values:
        if isinstance(value, str):
            if not value or len(value) > 160 or any(ord(ch) < 32 for ch in value):
                continue
        elif isinstance(value, bool):
            pass
        elif isinstance(value, int):
            if len(str(abs(value))) > 160:
                continue
        elif isinstance(value, float):
            if not math.isfinite(value):
                continue
        else:
            continue
        key = _json_scalar_sort_key(value)
        unique[key] = value
    ordered = [unique[key] for key in sorted(unique)]
    return ordered[:limit] if limit > 0 else []


def _safe_bool_value(value, default):
    if isinstance(value, float) and not math.isfinite(value):
        return bool(default)
    return bool(value)


def _safe_param_spec(spec, source=""):
    if not isinstance(spec, dict):
        return {}
    name = _safe_scalar_text(spec.get("name"), 160)
    if not name:
        return {}
    location = _safe_scalar_text(source or spec.get("in"), 80)
    spec_type = _safe_scalar_text(spec.get("type") or "string", 80) or "string"
    out = {
        "name": name,
        "in": location,
        "required": _safe_bool_value(spec.get("required"), False),
        "type": spec_type,
        "auto_materialize": _safe_bool_value(spec.get("auto_materialize", True), True),
        "safe": _safe_bool_value(spec.get("safe", True), True),
        "sensitive": _safe_bool_value(spec.get("sensitive", False), False),
        "leaf": _safe_bool_value(spec.get("leaf", True), True),
        "array": _safe_bool_value(spec.get("array", False), False),
    }
    parent = _safe_scalar_text(spec.get("parent"), 160)
    if parent:
        out["parent"] = parent
    if out["auto_materialize"] and not out["sensitive"]:
        seed = _safe_scalar_text(spec.get("seed"), 160)
        if seed:
            out["seed"] = seed
        candidates = {
            text
            for text in (_safe_scalar_text(value, 160) for value in _set_like_values(spec.get("seed_candidates")))
            if text
        }
        candidates.discard(seed)
        if candidates:
            out["seed_candidates"] = sorted(candidates)[:8]
        enum = _canonical_json_scalars(spec.get("enum"), 20)
        if enum:
            out["enum"] = enum
    return out


def _merge_param_spec(dst, src):
    dst = _safe_param_spec(dst, source=dst.get("in", "")) if isinstance(dst, dict) else {}
    src = _safe_param_spec(src, source=src.get("in", "")) if isinstance(src, dict) else {}
    if not dst:
        return copy.deepcopy(src)
    if not src:
        return copy.deepcopy(dst)
    text_choice = lambda key, default="": min(
        (value for value in (dst.get(key), src.get(key)) if isinstance(value, str) and value),
        default=default,
    )
    merged = {
        "name": text_choice("name"),
        "in": text_choice("in"),
        "required": bool(dst.get("required") or src.get("required")),
        "type": text_choice("type", "string"),
        "auto_materialize": bool(dst.get("auto_materialize", True) and src.get("auto_materialize", True)),
        "safe": bool(dst.get("safe", True) and src.get("safe", True)),
        "sensitive": bool(dst.get("sensitive") or src.get("sensitive")),
        "leaf": bool(dst.get("leaf", True) and src.get("leaf", True)),
        "array": bool(dst.get("array") or src.get("array")),
    }
    parent = text_choice("parent")
    if parent:
        merged["parent"] = parent
    if merged["auto_materialize"] and not merged["sensitive"]:
        primary_seeds = sorted({
            value for value in (dst.get("seed"), src.get("seed"))
            if isinstance(value, str) and value
        })
        if primary_seeds:
            merged["seed"] = primary_seeds[0]
        candidates = {
            value
            for value in (
                primary_seeds[1:]
                + list(dst.get("seed_candidates") or [])
                + list(src.get("seed_candidates") or [])
            )
            if isinstance(value, str) and value and value != merged.get("seed")
        }
        if candidates:
            merged["seed_candidates"] = sorted(candidates)[:8]
        enum = _canonical_json_scalars(
            list(dst.get("enum") or []) + list(src.get("enum") or []),
            20,
        )
        if enum:
            merged["enum"] = enum
    return merged


def add_api_param_spec(profile, api_path, source, spec):
    api_path = _clean_profile_api_path(api_path)
    source = str(source or "").lower()
    if not api_path or source not in ("query", "json", "form", "path", "header"):
        return
    clean = _safe_param_spec(spec, source=source)
    if not clean:
        return
    name = clean["name"]
    specs = profile.setdefault("api_param_specs", {}).setdefault(api_path, {}).setdefault(source, {})
    specs[name] = _merge_param_spec(specs.get(name), clean)
    if (
        source not in ("query", "json", "form")
        or not clean.get("leaf", True)
        or not clean.get("auto_materialize", True)
        or clean.get("sensitive")
    ):
        return
    add_param_name(profile, name, api_path=api_path, source=source)
    seed = clean.get("seed")
    if seed is not None:
        add_seed(profile, seed)
    parent = str(clean.get("parent") or "").split(".")[-1].replace("[]", "")
    child = name.split(".")[-1].replace("[]", "")
    if source in ("json", "form") and parent and child and parent != child:
        add_param_shape(profile, api_path, source, parent, [child])


def add_api_content_type(profile, api_path, content_type):
    api_path = _clean_profile_api_path(api_path)
    content_type = str(content_type or "").split(";", 1)[0].strip().lower()
    if api_path and content_type and len(content_type) <= 120:
        profile.setdefault("api_content_types", {}).setdefault(api_path, set()).add(content_type)


def add_api_path_template(profile, api_path, template):
    api_path = _clean_profile_api_path(api_path)
    template = _validated_profile_api_path(template)
    if api_path and template:
        profile.setdefault("api_path_templates", {}).setdefault(api_path, set()).add(template)

def add_seed(profile, value, file_hint=False):
    value = str(value or "").strip().strip('"\'')
    if not value or len(value) > 120:
        return
    if value.lower() in ("null", "true", "false", "undefined"):
        return
    if not file_hint and (value.startswith("/") or "://" in value):
        return
    # Unquoted JS identifiers such as deptId/kw/docId are variable names, not useful seed values.
    if not file_hint and re.match(r"^[a-zA-Z_$][a-zA-Z0-9_$]{1,40}$", value):
        if value.lower() not in ("admin", "test", "demo", "default", "camera", "rtsp", "pdf", "xlsx", "docx", "jpg", "png"):
            return
    if not file_hint and "." in value:
        if not re.search(r"\.(?:pdf|doc|docx|xls|xlsx|csv|zip|rar|7z|jpg|jpeg|png|gif|txt)$", value, re.I):
            return
    if file_hint or re.search(r"\.(?:pdf|doc|docx|xls|xlsx|csv|zip|rar|7z|jpg|jpeg|png|gif|txt)$", value, re.I):
        profile["file_seeds"].add(value)
    elif re.match(r"^[a-zA-Z0-9_\-./:@]{1,120}$", value):
        profile["seeds"].add(value)

def merge_param_profiles(dst, src):
    clean_dst = _canonical_param_profile(dst)
    clean_src = _canonical_param_profile(src)
    dst_blocked = set(clean_dst.get("api_param_blocked") or ())
    src_blocked = set(clean_src.get("api_param_blocked") or ())
    independently_bound = {
        path for path, names in clean_dst.get("api_params", {}).items()
        if names and path not in dst_blocked
    }
    independently_bound.update(
        path for path, names in clean_src.get("api_params", {}).items()
        if names and path not in src_blocked
    )
    dst.clear()
    dst.update(clean_dst)
    src = clean_src
    dst["names"].update(src.get("names", set()))
    dst["seeds"].update(src.get("seeds", set()))
    dst["file_seeds"].update(src.get("file_seeds", set()))
    for path, names in src.get("api_params", {}).items():
        dst["api_params"].setdefault(path, set()).update(names)
    for path, sources in src.get("api_param_sources", {}).items():
        dst_sources = dst.setdefault("api_param_sources", {}).setdefault(path, {})
        for source, names in sources.items():
            dst_sources.setdefault(source, set()).update(names)
    for path, sources in src.get("api_param_shapes", {}).items():
        dst_shapes = dst.setdefault("api_param_shapes", {}).setdefault(path, {})
        for source, parents in sources.items():
            dst_source_shapes = dst_shapes.setdefault(source, {})
            for parent, names in parents.items():
                dst_source_shapes.setdefault(parent, set()).update(names)
    for path, methods in src.get("api_methods", {}).items():
        dst.setdefault("api_methods", {}).setdefault(path, set()).update(methods)
    for path, sources in src.get("api_param_specs", {}).items():
        dst_sources = dst.setdefault("api_param_specs", {}).setdefault(path, {})
        for source, specs in (sources or {}).items():
            dst_specs = dst_sources.setdefault(source, {})
            for name, spec in (specs or {}).items():
                clean = _safe_param_spec(spec, source=source)
                if clean:
                    dst_specs[name] = _merge_param_spec(dst_specs.get(name), clean)
    for path, content_types in src.get("api_content_types", {}).items():
        dst.setdefault("api_content_types", {}).setdefault(path, set()).update(content_types or set())
    for path, templates in src.get("api_path_templates", {}).items():
        dst.setdefault("api_path_templates", {}).setdefault(path, set()).update(templates or set())
    for api in src.get("_apis_from_params", set()):
        dst.setdefault("_apis_from_params", set()).add(api)
    dst.setdefault("api_param_blocked", set()).update(src.get("api_param_blocked", set()))
    dst["api_param_blocked"].difference_update(independently_bound)
    return dst

def extract_param_profile(content):
    profile = empty_param_profile()
    if not content or args.disable_param_harvest:
        return profile
    sample = content[:1_500_000]
    # 从URL-body配对中提取的路径也加入API集合
    for url_path, body_text in _extract_url_body_pairs(sample):
        clean_path = _validated_profile_api_path(url_path)
        if clean_path:
            profile.setdefault("_apis_from_params", set()).add(clean_path)
    for m in QUERY_PARAM_RE.finditer(sample):
        add_param_name(profile, m.group(1))
    for m in FORM_FIELD_RE.finditer(sample):
        add_param_name(profile, m.group(1))
    for m in FILE_SEED_RE.finditer(sample):
        add_seed(profile, m.group(1), file_hint=True)
    for m in NUMERIC_ID_RE.finditer(sample):
        add_seed(profile, m.group(1))
    # URL+body 配对提取: 将参数绑定到具体URL
    for url_path, body_text, source in _extract_url_body_sources(sample):
        if url_path and body_text:
            for key, value in OBJECT_PARAM_RE.findall(body_text):
                add_param_name(profile, key, api_path=url_path, source=source)
                add_seed(profile, value)
            for parent, nested in NESTED_OBJECT_RE.findall(body_text):
                child_names = []
                for key, value in OBJECT_PARAM_RE.findall(nested):
                    child_names.append(key)
                    add_param_name(profile, key, api_path=url_path, source=source)
                    add_seed(profile, value)
                add_param_shape(profile, url_path, source, parent, child_names)
    # 全局 body 提取 (无URL上下文)
    for m in REQUEST_BODY_RE.finditer(sample):
        for key, value in OBJECT_PARAM_RE.findall(m.group(1)):
            add_param_name(profile, key)
            add_seed(profile, value)
    # 从表达式提取字面种子值: pageNum: p.pageNum||1 → "1", pageSize: 20 → "20"
    for m in re.finditer(r'''(?:[|?&]|\|\||&&|,\s*)\s*(\d{1,6})\s*(?:[,\s\)\}\]])''', sample):
        add_seed(profile, m.group(1))
    for m in re.finditer(r'''["']([a-zA-Z0-9_\-]{1,40})["']\s*[:=]\s*(\d{1,6})''', sample):
        add_seed(profile, m.group(2))
    for m in OBJECT_PARAM_RE.finditer(sample):
        key, value = m.group(1), m.group(2)
        if key in COMMON_PARAM_HINTS or key.endswith(("Id", "ID", "Name", "Path", "Key")):
            add_param_name(profile, key)
            add_seed(profile, value)
    for api in extract_apis(sample):
        for q in QUERY_PARAM_RE.finditer(api):
            add_param_name(profile, q.group(1), api)
    for api_path, methods in explicit_js_method_map(sample).items():
        for method in methods:
            add_api_method(profile, api_path, method)
    return profile

def path_param_candidates(path):
    clean = _validated_profile_api_path(path)
    return [clean] if clean and clean != "/" else []

def bound_param_names(profile, path):
    names = []
    for candidate in path_param_candidates(path):
        bound = profile.get("api_params", {}).get(candidate, set())
        for name in sorted(bound):
            if name not in names:
                names.append(name)
    return names

def bound_param_names_by_source(profile, path, source):
    names = []
    for candidate in path_param_candidates(path):
        sources = profile.get("api_param_sources", {}).get(candidate, {})
        for name in sorted(sources.get(source, set())):
            if name not in names:
                names.append(name)
    return names

def bound_param_shapes_by_source(profile, path, source):
    merged = {}
    for candidate in path_param_candidates(path):
        sources = profile.get("api_param_shapes", {}).get(candidate, {})
        for parent, names in sources.get(source, {}).items():
            merged.setdefault(parent, set()).update(names)
    return merged


def bound_param_specs_by_source(profile, path, source):
    merged = {}
    for candidate in path_param_candidates(path):
        sources = profile.get("api_param_specs", {}).get(candidate, {})
        for name, spec in (sources.get(source, {}) or {}).items():
            clean = _safe_param_spec(spec, source=source)
            if clean:
                merged[name] = _merge_param_spec(merged.get(name), clean)
    return [merged[name] for name in sorted(merged)]


def api_content_types_for(profile, path):
    content_types = set()
    for candidate in path_param_candidates(path):
        content_types.update(str(value).lower() for value in (profile or {}).get("api_content_types", {}).get(candidate, set()) if str(value).strip())
    return content_types


def is_json_content_type(content_type):
    value = str(content_type or "").split(";", 1)[0].strip().lower()
    return value in ("application/json", "text/json") or value.endswith("+json")


def is_urlencoded_content_type(content_type):
    return str(content_type or "").split(";", 1)[0].strip().lower() == "application/x-www-form-urlencoded"

def prioritized_param_names(profile, path):
    names = bound_param_names(profile, path)
    clean = path.split("?")[0].rstrip("/")
    p = clean.lower()
    # Source-wide harvested names are inventory only. Active variants require
    # path-local evidence or one of the bounded endpoint-shape defaults below;
    # otherwise an unrelated or rejected wrapper object could influence a GET.
    if is_file_endpoint(clean):
        for name in FILE_PARAM_NAMES:
            if name not in names:
                names.append(name)
    if any(x in p for x in ("list", "query", "search", "page")):
        for name in ("pageNum", "pageNo", "page", "current", "pageSize", "size", "limit", "keyword", "name"):
            if name not in names:
                names.append(name)
    return names[:40]

def should_param_probe(path, profile):
    if args.disable_param_harvest or not profile:
        return False
    clean = path.split("?")[0].rstrip("/")
    if args.disable_file_hunter and is_file_endpoint(clean):
        return False
    if args.param_probe_mode == "broad":
        return True
    p = clean.lower()
    if is_file_endpoint(clean) or any(k in p for k in PARAM_PROBE_KEYWORDS):
        return True
    for candidate in path_param_candidates(clean):
        if profile.get("api_params", {}).get(candidate):
            return True
    return False

def param_seed_value(name, seeds):
    lname = name.lower()
    if lname in ("pagenum", "pageno", "page", "current"):
        return "1"
    if lname in ("pagesize", "size", "limit", "count"):
        return "10"
    if lname in ("keyword", "keywords", "query", "search", "name", "username"):
        return "test"
    if lname in ("format",):
        return "xlsx"
    if lname in ("filetype", "doctype", "documenttype"):
        return "pdf"
    if lname in ("status",):
        return "1"
    if lname in ("type", "devicetype"):
        return "camera"
    if lname in ("protocol", "stream"):
        return "rtsp"
    if lname.endswith(("id", "ids")) or lname in ("id", "deptid", "orgid", "userid", "deviceid", "channelid", "fileid"):
        return "1"
    for seed in seeds:
        if seed and not seed.startswith("/") and "://" not in seed:
            return seed
    return "1"


def param_spec_seed_value(spec, name, seeds):
    if not isinstance(spec, dict) or not spec.get("auto_materialize", True) or spec.get("sensitive"):
        return None
    values = []
    if spec.get("seed") is not None:
        values.append(spec.get("seed"))
    values.extend(spec.get("seed_candidates") or [])
    values.extend(spec.get("enum") or [])
    for value in values:
        if isinstance(value, (dict, list, tuple, set)):
            continue
        text = str(value).strip()
        if text and len(text) <= 160 and not any(ord(ch) < 32 for ch in text):
            return text
    return param_seed_value(name, seeds)

def param_seed_pool(profile, path):
    seeds = ["1", "2", "10", "100", "test"]
    dynamic = [s for s in sorted(profile.get("seeds", set())) if not s.startswith("/") and "://" not in s][:20]
    file_dynamic = sorted(profile.get("file_seeds", set()))[:20]
    if is_file_endpoint(path):
        return list(dict.fromkeys(file_dynamic + FILE_SEED_VALUES + dynamic + seeds))
    return list(dict.fromkeys(dynamic + seeds))

def build_param_payload(names, seeds, max_names=6):
    payload = {}
    for name in names[:max_names]:
        payload[name] = param_seed_value(name, seeds)
    return payload

def build_nested_payload(shapes, seeds, max_parents=4, max_children=6):
    payload = {}
    used = 0
    for parent in sorted(shapes):
        children = sorted(shapes[parent])
        if not children:
            continue
        payload[parent] = {}
        for child in children[:max_children]:
            payload[parent][child] = param_seed_value(child, seeds)
        used += 1
        if used >= max_parents:
            break
    return payload


def _set_spec_payload_value(payload, dotted_name, value):
    parts = [part for part in str(dotted_name or "").split(".") if part]
    if not parts:
        return False
    current = payload
    for idx, raw_part in enumerate(parts):
        is_array = raw_part.endswith("[]")
        part = raw_part[:-2] if is_array else raw_part
        part = normalize_param_name(part)
        if not part:
            return False
        last = idx == len(parts) - 1
        if is_array:
            if last:
                current[part] = [value]
                return True
            existing = current.get(part)
            if not isinstance(existing, list) or not existing or not isinstance(existing[0], dict):
                existing = [{}]
                current[part] = existing
            current = existing[0]
            continue
        if last:
            if not isinstance(current.get(part), (dict, list)):
                current[part] = value
            return True
        existing = current.get(part)
        if not isinstance(existing, dict):
            existing = {}
            current[part] = existing
        current = existing
    return False


def build_spec_payload(specs, seeds, max_fields=10):
    payload = {}
    ordered = sorted(
        (spec for spec in specs or [] if spec.get("leaf", True) and spec.get("auto_materialize", True) and not spec.get("sensitive")),
        key=lambda spec: (not bool(spec.get("required")), str(spec.get("name") or "")),
    )
    used = 0
    for spec in ordered:
        name = str(spec.get("name") or "")
        leaf = normalize_param_name(name.split(".")[-1].replace("[]", ""))
        if not leaf:
            continue
        value = param_spec_seed_value(spec, leaf, seeds)
        if value is None:
            continue
        if _set_spec_payload_value(payload, name, value):
            used += 1
        if used >= max_fields:
            break
    return payload

def param_query_suffixes(path, profile):
    if not should_param_probe(path, profile):
        return []
    specs = bound_param_specs_by_source(profile or {}, path, "query")
    spec_by_name = {
        normalize_param_name(str(spec.get("name") or "").split(".")[-1].replace("[]", "")): spec
        for spec in specs
        if spec.get("auto_materialize", True) and not spec.get("sensitive")
    }
    spec_by_name = {name: spec for name, spec in spec_by_name.items() if name}
    names = list(spec_by_name) if spec_by_name else prioritized_param_names(profile, path)
    if not names:
        return []
    seeds = param_seed_pool(profile, path)
    limit = max(0, int(getattr(args, "param_max_probes", 0) or 0))
    probes = []
    # 组合fuzz只使用URL绑定参数, 避免全局参数池污染真实前端流量形态。
    bound_names = bound_param_names(profile, path)
    if bound_names and len(bound_names) >= 2:
        combo_parts = []
        for bn in bound_names[:5]:
            sv = param_spec_seed_value(spec_by_name.get(bn, {}), bn, seeds) if bn in spec_by_name else param_seed_value(bn, seeds)
            if sv is not None:
                combo_parts.append((bn, sv))
        if combo_parts:
            probes.append("?" + urlencode(combo_parts))
    for name in names:
        values = []
        if name in spec_by_name:
            value = param_spec_seed_value(spec_by_name[name], name, seeds)
            if value is not None:
                values.append(value)
        else:
            values.extend(seeds)
        for value in values:
            probes.append("?" + urlencode([(name, value)]))
            if limit > 0 and len(probes) >= limit:
                return probes
    return probes

def query_suffixes(path, profile=None, allow_param_probe=True):
    profile = profile or {}
    clean = _validated_profile_api_path(path)
    if clean and clean in set(profile.get("api_param_blocked") or set()):
        return [""]
    suffixes = file_query_suffixes(path)
    if allow_param_probe:
        for qs in param_query_suffixes(path, profile):
            if qs not in suffixes:
                suffixes.append(qs)
    return suffixes

def body_param_payloads(path, profile, body_type, allow_param_probe=True):
    if not allow_param_probe or not should_param_probe(path, profile or {}):
        return []
    profile = profile or {}
    seeds = param_seed_pool(profile, path)
    limit = max(0, int(getattr(args, "param_max_probes", 0) or 0))
    specs = bound_param_specs_by_source(profile, path, body_type)
    names = bound_param_names_by_source(profile, path, body_type)
    has_documented_profile = bool(api_content_types_for(profile, path) or specs)
    if not names and not has_documented_profile and body_type == "form":
        names = bound_param_names_by_source(profile, path, "json")
    if not names and not has_documented_profile and body_type == "json":
        names = bound_param_names_by_source(profile, path, "form")
    if not names:
        return []
    payloads = []
    structured = build_spec_payload(specs, seeds)
    if structured:
        payloads.append(structured)
    if specs:
        for spec in specs:
            single = build_spec_payload([spec], seeds, max_fields=1)
            if single and single not in payloads:
                payloads.append(single)
            if limit > 0 and len(payloads) >= limit:
                break
        return payloads
    shapes = bound_param_shapes_by_source(profile, path, body_type)
    nested = build_nested_payload(shapes, seeds)
    if nested:
        payloads.append(nested)
    combo = build_param_payload(names, seeds)
    if combo:
        payloads.append(combo)
    for name in names:
        payloads.append({name: param_seed_value(name, seeds)})
        if limit > 0 and len(payloads) >= limit:
            break
    return payloads


def exact_path_local_query_suffix(path, profile):
    """Build one deterministic query using only exact path-local query facts."""
    profile = profile or {}
    if exact_path_params_blocked(profile, path):
        return ""
    specs = bound_param_specs_by_source(profile, path, "query")
    spec_by_name = {}
    for spec in specs:
        name = normalize_param_name(str(spec.get("name") or "").split(".")[-1].replace("[]", ""))
        if name:
            spec_by_name[name] = spec
    body_names = set(bound_param_names_by_source(profile, path, "json"))
    body_names.update(bound_param_names_by_source(profile, path, "form"))
    path_names = set(bound_param_names_by_source(profile, path, "path"))
    untyped_path_local = set(bound_param_names(profile, path)) - body_names - path_names
    names = (
        set(bound_param_names_by_source(profile, path, "query"))
        | untyped_path_local
        | set(spec_by_name)
    )
    parts = []
    for name in sorted(names)[:10]:
        value = param_spec_seed_value(spec_by_name.get(name, {}), name, ("1",))
        if value is not None:
            parts.append((name, value))
    return "?" + urlencode(parts) if parts else ""


def _merge_missing_payload(target, source):
    for key in sorted(source or {}):
        if key not in target:
            target[key] = copy.deepcopy(source[key])


def _encode_exact_json(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _encode_exact_form(payload):
    return urlencode(sorted((str(key), str(value)) for key, value in payload.items())).encode()


def _encode_exact_empty(_payload):
    return b""


def exact_path_params_blocked(profile, path):
    clean = _validated_profile_api_path(path)
    return bool(
        clean and clean in _set_like_values((profile or {}).get("api_param_blocked"))
    )


def exact_post_body_opportunity(profile, path):
    """Return one bounded POST body opportunity using path-local facts only."""
    if is_file_endpoint(path):
        return {
            "body_kind": "empty",
            "content_type": None,
            "body_func": _encode_exact_empty,
            "payload": {},
        }
    profile = profile or {}
    if exact_path_params_blocked(profile, path):
        return {
            "body_kind": "empty",
            "content_type": None,
            "body_func": _encode_exact_empty,
            "payload": {},
        }
    documented = api_content_types_for(profile, path)
    for source in ("json", "form"):
        specs = bound_param_specs_by_source(profile, path, source)
        names = bound_param_names_by_source(profile, path, source)
        shapes = bound_param_shapes_by_source(profile, path, source)
        if not (specs or names or shapes):
            continue
        if source == "json":
            payload = build_spec_payload(specs, ("1",), max_fields=10)
            _merge_missing_payload(payload, build_nested_payload(shapes, ("1",)))
            for name in sorted(names)[:10]:
                payload.setdefault(name, param_seed_value(name, ("1",)))
            matching = sorted(value for value in documented if is_json_content_type(value))
            content_type = matching[0] if matching else "application/json"
            encoder = _encode_exact_json
        else:
            spec_by_name = {}
            for spec in specs:
                name = normalize_param_name(str(spec.get("name") or "").split(".")[-1].replace("[]", ""))
                if name:
                    spec_by_name[name] = spec
            flat_names = set(names) | set(spec_by_name)
            for children in shapes.values():
                flat_names.update(children)
            payload = {
                name: param_spec_seed_value(spec_by_name.get(name, {}), name, ("1",))
                for name in sorted(flat_names)[:10]
            }
            payload = {key: value for key, value in payload.items() if value is not None}
            matching = sorted(value for value in documented if is_urlencoded_content_type(value))
            content_type = matching[0] if matching else "application/x-www-form-urlencoded"
            encoder = _encode_exact_form
        if payload:
            return {
                "body_kind": "bound",
                "content_type": content_type,
                "body_func": encoder,
                "payload": payload,
            }
    return {
        "body_kind": "empty",
        "content_type": None,
        "body_func": _encode_exact_empty,
        "payload": {},
    }


def exact_post_body_kind(profile, path):
    return exact_post_body_opportunity(profile, path)["body_kind"]


def exact_dual_method_bypass_tests(profile, path, get_tests=None):
    get_test = next(
        (
            item for item in (get_tests or [])
            if str(item[1] or "GET").upper() == "GET" and not item[4]
        ),
        ("GET_no_auth", "GET", None, None, {}),
    )
    post = exact_post_body_opportunity(profile, path)
    post_name = "POST_EXACT_BOUND_no_auth" if post["body_kind"] == "bound" else "POST_EXACT_EMPTY_no_auth"
    return [
        get_test,
        (post_name, "POST", post["content_type"], post["body_func"], {}),
    ]


def request_variants(
    path, method, content_type, body_func, param_profile=None,
    allow_param_probe=True, exact_dual_method=False,
):
    if exact_dual_method:
        query_suffix = exact_path_local_query_suffix(path, param_profile or {})
        if str(method or "GET").upper() == "POST":
            opportunity = exact_post_body_opportunity(param_profile or {}, path)
            return [(query_suffix, copy.deepcopy(opportunity["payload"]))]
        return [(query_suffix, None)]
    if method in ("POST", "PUT", "PATCH") and body_func:
        body_type = "form" if is_urlencoded_content_type(content_type) else "json"
        profile = param_profile or {}
        payloads = body_param_payloads(path, profile, body_type, allow_param_probe)
        documented = bool(api_content_types_for(profile, path) or bound_param_specs_by_source(profile, path, body_type))
        variants = [] if documented else [("", {"page": "1", "size": "10"})]
        for payload in payloads:
            item = ("", payload)
            if item not in variants:
                variants.append(item)
        return variants
    return [(qs, None) for qs in query_suffixes(path, param_profile, allow_param_probe=allow_param_probe)]

def has_body_bound_params(profile, path):
    if not profile:
        return False
    safe_specs = [
        spec
        for source in ("json", "form")
        for spec in bound_param_specs_by_source(profile, path, source)
        if spec.get("leaf", True) and spec.get("auto_materialize", True) and not spec.get("sensitive")
    ]
    return bool(
        bound_param_names_by_source(profile, path, "json")
        or bound_param_names_by_source(profile, path, "form")
        or safe_specs
    )

def has_bound_params(profile, path):
    if not profile:
        return False
    return bool(bound_param_names(profile, path) or has_body_bound_params(profile, path))

def api_methods_for(profile, path):
    profile = profile or {}
    methods_by_path = profile.get("api_methods") or {}
    clean = _validated_profile_api_path(path)
    return {
        str(method).lower() for method in methods_by_path.get(clean, set())
        if clean and str(method).lower() in HTTP_METHODS
    }

def _path_words(path):
    return [p for p in re.split(r"[^a-z0-9]+", str(path or "").lower()) if p]

def is_safe_post_path(path):
    words = _path_words(path)
    lowered = "/" + "/".join(words)
    return any(hint in words or hint in lowered for hint in SAFE_POST_HINTS)

def is_action_like_post_path(path):
    words = _path_words(path)
    lowered = "/" + "/".join(words)
    return any(hint in words or hint in lowered for hint in ACTIVE_POST_HINTS)

def scheduled_bypass_tests(
    path, bypass_tests, param_profile=None, exact_dual_method=False,
):
    """Filter probe methods by observed API method metadata.

    Unknown endpoints are probed with GET only.  POST is only sent when it was
    explicitly observed on a read-style path, or when the operator opts into
    active POST probing with --allow-active-post.  DELETE-only paths are not
    probed by default even if a literal path escaped into the inventory.
    """
    if exact_dual_method:
        out, seen_methods = [], set()
        for item in bypass_tests or []:
            upper = str(item[1] or "GET").upper()
            if upper not in ("GET", "POST") or upper in seen_methods:
                continue
            seen_methods.add(upper)
            out.append(item)
        return out
    methods = api_methods_for(param_profile, path)
    # --include-delete-method is an inventory/extraction opt-in only.  A
    # DELETE-only endpoint must not be actively probed with GET or DELETE by the
    # unauth scanner unless a future, explicit active DELETE option is added.
    if methods and methods <= {"delete"}:
        return []
    allow_active = bool(getattr(args, "allow_active_post", False))
    destructive_post = is_action_like_post_path(path)
    explicit_post_only = methods == {"post"}
    explicit_post_allowed = (
        "post" in methods
        and has_body_bound_params(param_profile, path)
        and (allow_active or (is_safe_post_path(path) and not destructive_post))
    )
    if explicit_post_only and not explicit_post_allowed:
        return []
    out = []
    for name, method, ct, bf, headers in bypass_tests or []:
        upper = str(method or "GET").upper()
        lower = upper.lower()
        if upper == "GET":
            # Unknown paths remain GET-only, but once an endpoint has explicit
            # method metadata, do not invent a GET for POST/DELETE/PUT-only
            # routes.  --include-delete-method is inventory-only, not active
            # DELETE probing permission.
            if methods and "get" not in methods:
                continue
            out.append((name, method, ct, bf, headers))
            continue
        if lower in ("post", "put", "patch"):
            if lower in methods and explicit_post_allowed:
                documented = api_content_types_for(param_profile or {}, path)
                if not documented:
                    out.append((name, method, ct, bf, headers))
                    continue
                matching = []
                if is_json_content_type(ct):
                    matching = sorted(value for value in documented if is_json_content_type(value))
                elif is_urlencoded_content_type(ct):
                    matching = sorted(value for value in documented if is_urlencoded_content_type(value))
                for documented_type in matching:
                    suffix = re.sub(r"[^A-Za-z0-9]+", "_", documented_type).strip("_")
                    out.append((name + ("_" + suffix if suffix else ""), method, documented_type, bf, headers))
            continue
    return out

def body_probe_bypass_tests(profile, path):
    tests = []
    documented = api_content_types_for(profile or {}, path)
    json_types = sorted(value for value in documented if is_json_content_type(value))
    form_types = sorted(value for value in documented if is_urlencoded_content_type(value))
    if bound_param_names_by_source(profile, path, "json") or bound_param_specs_by_source(profile, path, "json"):
        for content_type in (json_types or (["application/json"] if not documented else [])):
            tests.append(("POST_JSON_no_auth","POST",content_type,lambda p: json.dumps(p).encode(),{}))
    if bound_param_names_by_source(profile, path, "form") or bound_param_specs_by_source(profile, path, "form"):
        for content_type in (form_types or (["application/x-www-form-urlencoded"] if not documented else [])):
            tests.append(("POST_FORM_no_auth","POST",content_type,lambda p: urlencode(p).encode(),{}))
    return tests

def static_priority_apis(t, limit=30):
    apis = [api for api in _canonical_api_list(t.get("apis", [])) if not is_initial_screen_only_api(t, api)]
    picked = [api for api in apis if -api_priority(api)[0] >= 70]
    paths = {api.split("?")[0].rstrip("/"): api for api in apis}
    suffix_picked = []
    for api in picked:
        clean = api.split("?")[0].rstrip("/")
        parts = [p for p in clean.strip("/").split("/") if p]
        for idx in range(1, min(3, len(parts))):
            suffix = "/" + "/".join(parts[idx:])
            if suffix in paths and -api_priority(suffix)[0] >= 70:
                suffix_picked.append(paths[suffix])
    return unique_apis(sorted(picked, key=api_priority)[:limit] + suffix_picked)

def _canonical_seed_path(api):
    return _canonical_api_path(api, preserve_query=False)


def _canonical_api_path(value, preserve_query=True):
    """Return a validated root-relative API identity, retaining safe query text."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        return ""
    raw = value.strip()
    if not raw or "#" in raw:
        return ""
    path, separator, query = raw.partition("?")
    clean = validate_root_relative_path(path.rstrip("/") or "/")
    if not clean:
        return ""
    if not separator or not preserve_query:
        return clean
    # Existing JS-derived query semantics remain in-memory only when they
    # match the scanner's bounded, value-safe extraction grammar.
    safe_parts = []
    for part in query.split("&")[:8]:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,40}=[A-Za-z0-9_.:@%+,-]{0,160}", part):
            safe_parts.append(part)
        else:
            return ""
    return clean + ("?" + "&".join(safe_parts) if safe_parts else "")


def _canonical_api_list(values):
    out, seen = [], set()
    if isinstance(values, (str, bytes, dict)) or values is None:
        return out
    try:
        for value in values:
            canonical = _canonical_api_path(value, preserve_query=False)
            if not canonical or canonical in seen:
                continue
            seen.add(canonical)
            out.append(canonical)
    except TypeError:
        return []
    return out

def _bounded_canonical_seed(items, target, limit=16, excluded=None):
    best = {}
    excluded = set(excluded or ())
    for item in items or []:
        canonical = _canonical_seed_path(item)
        if not canonical or canonical in excluded:
            continue
        current = best.get(canonical)
        if current is None or (api_test_order(target, item), str(item)) < (api_test_order(target, current), str(current)):
            best[canonical] = item
    ordered = sorted(best.values(), key=lambda item: (api_test_order(target, item), str(item)))
    return ordered[:limit] if limit > 0 else ordered

def _normalize_api_meta_sources(sources):
    if not isinstance(sources, (list, set, frozenset)) or len(sources) > 256:
        return []
    if any(not isinstance(source, str) or not source or len(source) > 80 for source in sources):
        return []
    return sorted({source for source in sources if isinstance(source, str) and source in API_META_SOURCES})


def _invalidate_api_meta_index(target):
    # Compatibility no-op: metadata indexes are call-scoped and never stored
    # on records, so the next top-level call always observes current content.
    return None


def _build_api_meta_index(target):
    global API_META_INDEX_BUILD_COUNT
    if not isinstance(target, dict):
        return {"items": {}, "sources": {}, "states": {}}
    raw_meta = target.get("api_meta")
    allowed = set(_canonical_api_list(target.get("apis") or []))
    allowed.update(_canonical_api_list(target.get("replay_apis") or []))
    allowed.update(_canonical_api_list(target.get("replay_promoted_apis") or []))
    if isinstance(raw_meta, dict):
        allowed.update(
            clean for clean in (
                _canonical_api_path(key, preserve_query=False)
                for key in raw_meta if isinstance(key, str)
            ) if clean
        )
    items = _safe_api_meta_record(raw_meta, allowed) if "api_meta" in target else {}
    sources = {
        api: _normalize_api_meta_sources((items.get(api) or {}).get("sources"))
        for api in sorted(allowed)
    }
    states = {
        api: (
            "absent" if api not in items
            else "inert" if sources.get(api) == ["prefix_inventory"]
            else "known"
        )
        for api in sorted(allowed)
    }
    index = {
        "items": items,
        "sources": sources,
        "states": states,
    }
    API_META_INDEX_BUILD_COUNT += 1
    return index


@contextmanager
def api_meta_index_scope(targets):
    previous = getattr(API_META_INDEX_CONTEXT, "indexes", None)
    indexes = dict(previous or {})
    for target in targets or []:
        if isinstance(target, dict) and id(target) not in indexes:
            indexes[id(target)] = _build_api_meta_index(target)
    API_META_INDEX_CONTEXT.indexes = indexes
    try:
        yield
    finally:
        if previous is None:
            try:
                del API_META_INDEX_CONTEXT.indexes
            except AttributeError:
                pass
        else:
            API_META_INDEX_CONTEXT.indexes = previous


def _api_meta_index(target):
    indexes = getattr(API_META_INDEX_CONTEXT, "indexes", {})
    if isinstance(target, dict) and id(target) in indexes:
        return indexes[id(target)]
    return _build_api_meta_index(target)


def _api_meta_item(target, api):
    canonical = _canonical_api_path(api, preserve_query=False)
    if not canonical:
        return {}
    return (_api_meta_index(target).get("items") or {}).get(canonical, {})


def _api_meta_sources_for_seed(target, api):
    canonical = _canonical_api_path(api, preserve_query=False)
    if not canonical:
        return []
    return list((_api_meta_index(target).get("sources") or {}).get(canonical, []))


def _canonical_api_meta_map(target, apis):
    allowed = set(_canonical_api_list(apis or []))
    items = _api_meta_index(target).get("items") or {}
    return {api: copy.deepcopy(items[api]) for api in sorted(allowed) if api in items}


def _canonical_api_sources_map(target, apis):
    allowed = set(_canonical_api_list(apis or []))
    sources = _api_meta_index(target).get("sources") or {}
    return {api: list(sources.get(api, [])) for api in sorted(allowed)}

def _phase3_seed_candidates_scoped(t):
    if t.get("config_service_synthetic"):
        return []
    apis = _canonical_api_list(t.get("apis", []))
    sources_by_api = _canonical_api_sources_map(t, apis)
    exact_apis = [api for api in apis if sources_by_api.get(api) != ["prefix_inventory"]]
    prefix_inventory_apis = [api for api in apis if sources_by_api.get(api) == ["prefix_inventory"]]
    # Reserve a small, source-aware quota for paths proven by actual request
    # sinks. This prevents route/string-heavy bundles from crowding real HTTP
    # calls out of the initial Phase 3a layer without raising every JS literal.
    request_sink_seed = [
        api for api in exact_apis
        if "js_request" in sources_by_api.get(api, [])
    ]
    request_sink_seed = _bounded_canonical_seed(request_sink_seed, t, 16)
    request_sink_canonicals = {_canonical_seed_path(item) for item in request_sink_seed}
    # Operator-supplied paths are already normalized and explicitly opted in.
    # Keep every inventory path, canonicalize query variants, and place this
    # bucket before generic ranking/baselines. Existing request budgets remain
    # the transmission bound because --extra-api-wordlist has no count limit.
    extra_wordlist_seed = [
        api for api in exact_apis
        if "extra_wordlist" in sources_by_api.get(api, [])
    ]
    extra_wordlist_seed = _bounded_canonical_seed(
        extra_wordlist_seed, t, 0, excluded=request_sink_canonicals
    )
    extra_wordlist_canonicals = {
        _canonical_seed_path(item) for item in extra_wordlist_seed
    }
    # A separate bounded quota keeps already-extracted generic API-root paths
    # visible even when minified/ambiguous receivers correctly fail closed.
    # This never generates or guesses a prefix.
    api_root_seed = []
    for api in exact_apis:
        path = urlparse(api if "://" in str(api or "") else "http://local" + (api if str(api or "").startswith("/") else "/" + str(api or ""))).path
        first = next(iter(part for part in path.split("/") if part), "").lower()
        if API_ROOT_SEGMENT_RE.fullmatch(first):
            api_root_seed.append(api)
    reserved_canonicals = request_sink_canonicals | extra_wordlist_canonicals
    api_root_seed = _bounded_canonical_seed(
        api_root_seed, t, 16, excluded=reserved_canonicals
    )
    generic_seed = sorted(
        list(exact_apis[:30])
        + [api for api in static_priority_apis(t) if not is_initial_screen_only_api(t, api)]
        + configured_backend_baseline_paths()
        + BASELINE_PATHS,
        key=lambda item: api_test_order(t, item),
    )
    prefix_order = t.get("prefix_inventory_paths")
    if not isinstance(prefix_order, (list, tuple)):
        prefix_order = []
    prefix_set = set(prefix_inventory_apis)
    prefix_candidates = [
        api for api in prefix_order
        if isinstance(api, str) and api in prefix_set and is_initial_screen_only_api(t, api)
    ]
    ordered_prefix_set = set(prefix_candidates)
    prefix_candidates.extend(sorted(
        (api for api in prefix_inventory_apis if api not in ordered_prefix_set),
        key=lambda item: (api_test_order(t, item), str(item)),
    ))
    prefix_inventory_seed = []
    prefix_seen = set()
    for api in prefix_candidates:
        canonical = _canonical_seed_path(api)
        if not canonical or canonical in prefix_seen:
            continue
        prefix_seen.add(canonical)
        prefix_inventory_seed.append(api)
        if len(prefix_inventory_seed) >= MAX_PREFIX_INVENTORY_PHASE3_SEEDS:
            break
    seed_buckets = (
        request_sink_seed,
        extra_wordlist_seed,
        api_root_seed,
        generic_seed,
        prefix_inventory_seed,
    )
    seen, out = set(), []
    for bucket in seed_buckets:
        for api in bucket:
            clean = _canonical_seed_path(api)
            if not clean or clean in seen:
                continue
            seen.add(clean)
            out.append(api)
    return out


def phase3_seed_candidates(target):
    with api_meta_index_scope([target]):
        return _phase3_seed_candidates_scoped(target)


def phase3_seed_apis(target):
    """Legacy heuristic initial provider; exact paths belong to exact sweep."""
    with api_meta_index_scope([target]):
        return [
            api for api in _phase3_seed_candidates_scoped(target)
            if not is_independently_exact_api(target, api)
        ]

def unique_apis(items):
    best = {}
    for api in items:
        api = _canonical_api_path(api, preserve_query=False)
        clean = api
        if not clean:
            continue
        current = best.get(clean)
        if current is None or api_priority(api) < api_priority(current):
            best[clean] = api
    return sorted(best.values(), key=api_priority)

def unique_apis_keep_order(items):
    seen, out = set(), []
    for api in items:
        api = _canonical_api_path(api, preserve_query=False)
        clean = api
        if not clean or clean in seen:
            continue
        seen.add(clean)
        out.append(api)
    return out

def drop_prefixed_duplicates(apis):
    apis = _canonical_api_list(apis)
    paths = {_canonical_api_path(api, preserve_query=False) for api in apis}
    out = []
    for api in apis:
        clean = _canonical_api_path(api, preserve_query=False)
        parts = [p for p in clean.strip("/").split("/") if p]
        duplicate = False
        for idx in range(1, min(3, len(parts))):
            suffix = "/" + "/".join(parts[idx:])
            # Preserve concrete query-bearing URLs, especially JS-derived file
            # downloads, because stripping them can remove required object IDs.
            if is_file_endpoint(api):
                continue
            if suffix in paths and api_priority(suffix) <= api_priority(clean):
                duplicate = True
                break
        if not duplicate:
            out.append(api)
    return out

def _business_layer_apis_scoped(t):
    all_apis = drop_prefixed_duplicates([
        api for api in t.get("apis", [])
        if not is_initial_screen_only_api(t, api) and not is_independently_exact_api(t, api)
    ])
    apis = [api for api in all_apis[:80] if not is_file_endpoint(api)]
    bound = [api for api in all_apis if has_body_bound_params(t.get("param_profile"), api)]
    priority = static_priority_apis(t, limit=30)
    return unique_apis_keep_order(bound + priority + sorted(apis, key=lambda api: api_test_order(t, api)))

def business_layer_apis(target):
    with api_meta_index_scope([target]):
        out = _business_layer_apis_scoped(target)
        return [api for api in out if not is_independently_exact_api(target, api)]


def _file_layer_apis_scoped(t):
    all_apis = drop_prefixed_duplicates([
        api for api in t.get("apis", [])
        if not is_initial_screen_only_api(t, api) and not is_independently_exact_api(t, api)
    ])
    apis = [api for api in all_apis[:80] if is_file_endpoint(api)]
    bound_files = [api for api in all_apis if is_file_endpoint(api) and (has_body_bound_params(t.get("param_profile"), api) or should_param_probe(api, t.get("param_profile")))]
    return unique_apis(sorted(apis + bound_files, key=lambda api: api_test_order(t, api)))


def file_layer_apis(target):
    with api_meta_index_scope([target]):
        return [api for api in _file_layer_apis_scoped(target) if not is_independently_exact_api(target, api)]

def _target_priority_scoped(t):
    apis = _canonical_api_list(t.get("apis") or [])
    best_api = api_priority(apis[0])[0] if apis else 0
    graph_bonus = min(int(t.get("js_graph_edges") or 0), 200)
    js_bonus = min(int(t.get("js_count") or 0), 80)
    param_bonus = min(len((t.get("param_profile") or {}).get("api_params", {}) or {}), 80)
    confidence_bonus = int(max([api_confidence_for(t, api) for api in apis] or [0.0]) * 30)
    fallback_penalty = 25 if t.get("fallback") == "empty_http_response" else 0
    return (best_api - graph_bonus - js_bonus - param_bonus - confidence_bonus + fallback_penalty, t.get("base", ""))


def target_priority(target):
    with api_meta_index_scope([target]):
        return _target_priority_scoped(target)

def target_host(t):
    host = urlparse(t.get("base", "")).hostname or t.get("base", "")
    return str(host or "").lower()

def api_score_value(api):
    return -api_priority(api)[0]

API_CONFIDENCE_TIERS = {
    "swagger": 0.95,
    "openapi": 0.95,
    "js_request": 0.96,
    "param_binding": 0.85,
    "js-graph": 0.80,
    "js_literal": 0.75,
    "business_pattern": 0.55,
    "backend_baseline": 0.50,
    "extra_wordlist": 0.50,
    "baseline": 0.35,
    "legacy_recovery": 0.30,
    "legacy_baseline": 0.30,
    "prefix_inventory": 0.25,
}


LEGACY_RECOVERY_PATHS = [
    # Swagger/OpenAPI/doc UIs and descriptors seen in older scanner output.
    "/swagger-ui.html", "/swagger/index.html", "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/openapi.json", "/openapi.yaml", "/doc.html", "/docs", "/knife4j/doc.html",
    # Common old-style action and file-ish candidates; intentionally small.
    "/download.action", "/file/download.action", "/export.action",
    "/api/file/download", "/api/common/download", "/api/attachment/download", "/api/export",
]
LEGACY_ALLOWED_DOT_EXTS = (".action", ".do", ".json", ".yaml", ".html")

def is_safe_legacy_recovery_path(path):
    path = normalize_extracted_api(path)
    if not path:
        return False
    lowered = path.lower().split("?", 1)[0]
    if any(ch in lowered for ch in ("{", "}", "[", "]", "\\")):
        return False
    # Exclude dot-path artifacts such as /foo.bar.baz unless it is a reviewed legacy extension.
    basename = lowered.rsplit("/", 1)[-1]
    if "." in basename and not basename.endswith(LEGACY_ALLOWED_DOT_EXTS):
        return False
    return lowered in {p.lower() for p in LEGACY_RECOVERY_PATHS}

def legacy_recovery_candidates():
    return [p for p in LEGACY_RECOVERY_PATHS if is_safe_legacy_recovery_path(p)]

def mark_legacy_recovery_meta(meta, apis):
    legacy = set(legacy_recovery_candidates())
    for api in apis or []:
        clean = str(api).split("#", 1)[0].rstrip("/") or str(api)
        if clean in legacy:
            add_api_meta(meta, clean, "legacy_recovery", 0.30)

def add_api_meta(meta, api, source, confidence=None):
    if not isinstance(meta, dict):
        return
    if not api or api.startswith(("SENSITIVE:", "INTERNAL_IP:", "JDBC:")):
        return
    clean = _canonical_api_path(api, preserve_query=False)
    if not clean:
        return
    if source not in API_META_SOURCES:
        candidate = _inert_api_meta_item()
    else:
        conf = confidence if confidence is not None else API_CONFIDENCE_TIERS[source]
        candidate = {"confidence": conf, "sources": [source]}
    existing = [meta[clean]] if clean in meta else []
    meta[clean] = _merge_api_meta_items(existing + [candidate])

def infer_api_meta(meta, api):
    clean = api.split("#", 1)[0].rstrip("/") or api
    if clean in meta:
        return
    lowered = clean.lower()
    if any(x in lowered for x in ("swagger", "api-docs", "openapi")):
        add_api_meta(meta, clean, "openapi")
    elif clean in BASELINE_PATHS:
        add_api_meta(meta, clean, "baseline")
    elif api_score_value(clean) >= 70:
        add_api_meta(meta, clean, "business_pattern")
    else:
        add_api_meta(meta, clean, "baseline")

def api_confidence_for(t, api):
    meta = _api_meta_item(t, api)
    try:
        return float(meta.get("confidence") or 0.70)
    except Exception:
        return 0.70

def api_test_order(t, api):
    return (-api_confidence_for(t, api), api_priority(api))

def is_prefix_inventory_api(target, api):
    return _api_meta_sources_for_seed(target or {}, api) == ["prefix_inventory"]


def is_initial_screen_only_api(target, api):
    clean = _canonical_api_path(api, preserve_query=False)
    return bool(clean and (_api_meta_index(target).get("states") or {}).get(clean) == "inert")


def _api_meta_source_state(target, api):
    clean = _canonical_api_path(api, preserve_query=False)
    if not clean:
        return "absent"
    return (_api_meta_index(target).get("states") or {}).get(clean, "absent")

def api_probe_policy(target, api, param_profile=None):
    if is_initial_screen_only_api(target, api):
        return empty_param_profile(), True
    return param_profile if param_profile is not None else (target or {}).get("param_profile"), False


def is_independently_exact_api(target, api):
    return bool(set(_api_meta_sources_for_seed(target or {}, api)) & API_META_EXACT_SOURCES)


def api_coverage_kind(target, api):
    return "exact" if is_independently_exact_api(target, api) else "heuristic"


def exact_api_safety_reason(target, api):
    """Return an aggregate skip reason, or an empty string when safely eligible."""
    # Callers have already proven exact provenance, so this path cannot carry
    # the prefix/inert single-screen policy. Avoid rebuilding the full API set
    # for every exact path; the all-exact sweep must remain linearithmic.
    profile = (target or {}).get("param_profile")
    methods = api_methods_for(profile, api)
    if not methods or "get" in methods:
        return ""
    if methods <= {"delete"}:
        return "delete_only"
    if "post" in methods:
        if is_action_like_post_path(api) and not bool(getattr(args, "allow_active_post", False)):
            return "action_post_not_enabled"
        tests = list(FAST_BYPASS)
        tests.extend(body_probe_bypass_tests(profile, api))
        if scheduled_bypass_tests(api, tests, profile):
            return ""
        return "post_not_safely_bound"
    if methods & {"put", "patch", "delete"}:
        return "unsupported_unsafe_method"
    return "unsupported_method"


def _exact_api_sweep_plan_scoped(api_results, max_per_target=0, tracker=None):
    """Build a deterministic all-exact first-opportunity queue.

    The per-target cap applies only when explicitly non-zero. Safety-ineligible
    exact paths remain accounted but are never converted to GET.
    """
    per_target = []
    for target in ordered_targets_for_phase3(api_results):
        if target.get("config_service_synthetic"):
            if tracker:
                tracker.prepare(target, [], set(), {}, cap_skips=0)
            continue
        with api_meta_index_scope([target]):
            replay = set(_canonical_api_list(
                list(target.get("replay_apis") or [])
                + list(target.get("replay_promoted_apis") or [])
            ))
            inventory = _canonical_api_list(list(target.get("apis") or []) + list(replay))
            index = _api_meta_index(target)
            meta_by_api = index.get("items") or {}
            indexed_sources = index.get("sources") or {}
            sources_by_api = {api: indexed_sources.get(api, []) for api in inventory}
            exact = sorted(
                (api for api in inventory if set(sources_by_api.get(api, [])) & API_META_EXACT_SOURCES),
                key=lambda api: (
                    -float((meta_by_api.get(api) or {}).get("confidence") or 0.0),
                    api_priority(api),
                    api,
                ),
            )
            dual_method = bool(getattr(args, "post_every_api", False))
            safety_skips = {} if dual_method else {
                api: reason for api in exact
                for reason in (exact_api_safety_reason(target, api),) if reason
            }
            eligible = [api for api in exact if api not in safety_skips]
            cap_skips = 0
            if max_per_target and max_per_target > 0 and len(eligible) > max_per_target:
                cap_skips = len(eligible) - max_per_target
                eligible = eligible[:max_per_target]
            if tracker:
                post_body_kinds = {
                    api: exact_post_body_kind(target.get("param_profile"), api)
                    for api in exact
                } if dual_method else {}
                tracker.prepare(
                    target, exact, replay & set(exact), safety_skips,
                    cap_skips=cap_skips, post_body_kinds=post_body_kinds,
                    dual_scheduled_apis=eligible if dual_method else (),
                    post_cap_skips=cap_skips if dual_method else 0,
                )
            per_target.append([(target, api) for api in eligible])
    tasks = []
    index = 0
    while True:
        added = False
        for group in per_target:
            if index < len(group):
                tasks.append(group[index])
                added = True
        if not added:
            break
        index += 1
    return tasks


def exact_api_sweep_plan(api_results, max_per_target=0, tracker=None):
    records = list(api_results)
    with api_meta_index_scope(records):
        return _exact_api_sweep_plan_scoped(records, max_per_target=max_per_target, tracker=tracker)


def phase3_heuristic_seed_tasks(api_results):
    """Initial heuristic screen excluding paths owned by the exact sweep."""
    def provider(target):
        return [api for api in phase3_seed_apis(target) if not is_independently_exact_api(target, api)]
    return round_robin_tasks(api_results, provider, allow_prefix_inventory=True)


def config_rest_phase3_tasks(api_results):
    """Config-service convention tasks not already owned by exact sweep."""
    tasks = []
    for target in api_results:
        raw_candidates = target.get("config_rest_candidates") or []
        if not isinstance(raw_candidates, (list, tuple)):
            log.debug("Skipping malformed config_rest_candidates container")
            continue
        with api_meta_index_scope([target]):
            for candidate in raw_candidates:
                if not isinstance(candidate, dict):
                    log.debug("Skipping malformed config-rest candidate")
                    continue
                path = candidate.get("path")
                if not _canonical_api_path(path, preserve_query=False):
                    continue
                if is_independently_exact_api(target, path):
                    continue
                tasks.append((target, candidate))
    return tasks

def ordered_targets_for_phase3(items):
    groups = {}
    for t in items:
        groups.setdefault(target_host(t), []).append(t)
    ordered_groups = []
    for host, targets in groups.items():
        ordered = sorted(targets, key=target_priority)
        ordered_groups.append((target_priority(ordered[0]), host, ordered))
    ordered_groups.sort(key=lambda x: (x[0], x[1]))
    out = []
    index = 0
    while True:
        added = False
        for _, _, targets in ordered_groups:
            if index < len(targets):
                out.append(targets[index])
                added = True
        if not added:
            break
        index += 1
    return out

def _phase3_task_api_allowed(target, api, allow_prefix_inventory=False):
    clean = _canonical_api_path(api, preserve_query=False)
    if not clean:
        return False
    if is_initial_screen_only_api(target, clean):
        return bool(allow_prefix_inventory and not api.split("?", 1)[1:])
    return True


def _round_robin_tasks_scoped(targets, api_provider, layer="", max_per_target=0, allow_prefix_inventory=False):
    per_target = []
    for t in ordered_targets_for_phase3(targets):
        with api_meta_index_scope([t]):
            apis = []
            for api in api_provider(t):
                if is_independently_exact_api(t, api):
                    continue
                if not _phase3_task_api_allowed(t, api, allow_prefix_inventory=allow_prefix_inventory):
                    continue
                clean = _canonical_api_path(api, preserve_query=False)
                if clean:
                    apis.append(clean)
        if max_per_target and max_per_target > 0:
            apis = apis[:max_per_target]
        if not apis:
            continue
        per_target.append([(t, api, layer) if layer else (t, api) for api in apis])
    tasks, seen = [], set()
    index = 0
    while True:
        added = False
        for group in per_target:
            if index >= len(group):
                continue
            task = group[index]
            if len(task) == 3:
                key = (task[0]["base"], task[1], task[2])
            else:
                key = (task[0]["base"], task[1])
            if key not in seen:
                seen.add(key)
                tasks.append(task)
            added = True
        if not added:
            break
        index += 1
    return tasks


def round_robin_tasks(targets, api_provider, layer="", max_per_target=0, allow_prefix_inventory=False):
    records = list(targets)
    with api_meta_index_scope(records):
        return _round_robin_tasks_scoped(
            records, api_provider, layer=layer,
            max_per_target=max_per_target,
            allow_prefix_inventory=allow_prefix_inventory,
        )

def phase3_seed_tasks(api_results):
    return round_robin_tasks(api_results, phase3_seed_apis, allow_prefix_inventory=True)

def _high_yield_probe_apis_scoped(t):
    if t.get("config_service_synthetic"):
        return []
    return unique_apis([
        api for api in HIGH_YIELD_BASELINE_PATHS + configured_backend_baseline_paths() + static_priority_apis(t, limit=12)
        if not is_independently_exact_api(t, api)
    ])


def high_yield_probe_apis(target):
    with api_meta_index_scope([target]):
        return _high_yield_probe_apis_scoped(target)

def high_yield_probe_tasks(api_results, exclude_bases=None):
    exclude_bases = exclude_bases or set()
    targets = [t for t in api_results if t["base"] not in exclude_bases]
    return round_robin_tasks(targets, high_yield_probe_apis, max_per_target=8)

def bound_body_tasks(api_results, max_per_target=4):
    def provider(t):
        out = []
        for api in t["apis"]:
            if is_initial_screen_only_api(t, api) or is_independently_exact_api(t, api):
                continue
            clean_api = api.split("?")[0].rstrip("/")
            if not clean_api:
                continue
            if not has_body_bound_params(t.get("param_profile"), clean_api):
                continue
            if not should_param_probe(clean_api, t.get("param_profile")):
                continue
            out.append(clean_api)
        return unique_apis(out)
    return round_robin_tasks(api_results, provider, max_per_target=max_per_target)

def bound_param_tasks(api_results, max_per_target=4):
    def provider(t):
        out = []
        for api in t["apis"]:
            if is_initial_screen_only_api(t, api) or is_independently_exact_api(t, api):
                continue
            clean_api = api.split("?")[0].rstrip("/")
            if not clean_api:
                continue
            if not has_bound_params(t.get("param_profile"), clean_api):
                continue
            if not should_param_probe(clean_api, t.get("param_profile")):
                continue
            out.append(clean_api)
        return unique_apis(out)
    return round_robin_tasks(api_results, provider, max_per_target=max_per_target)

def configured_backend_param_tasks(api_results):
    configured = configured_backend_baseline_paths()
    if not configured:
        return []
    configured_clean = {api.split("?")[0].rstrip("/") for api in configured}
    def provider(t):
        out = []
        for api in t["apis"]:
            if is_initial_screen_only_api(t, api) or is_independently_exact_api(t, api):
                continue
            clean_api = api.split("?")[0].rstrip("/")
            if not clean_api:
                continue
            if clean_api in configured_clean:
                out.append(clean_api)
        return unique_apis(out)
    return round_robin_tasks(api_results, provider)

def layer_tasks_for_candidates(candidates, api_provider, layer_name, collect_all=False):
    def provider(t):
        if t.get("config_service_synthetic"):
            return []
        hit_paths = finding_endpoint_paths(t.get("findings", []), high_value_only=True) if not collect_all else set()
        out = []
        for api in api_provider(t):
            if is_initial_screen_only_api(t, api) or is_independently_exact_api(t, api):
                continue
            clean_api = api.split("?")[0].rstrip("/")
            keep_bound_body = has_body_bound_params(t.get("param_profile"), clean_api)
            if clean_api and clean_api in hit_paths and not keep_bound_body:
                continue
            out.append(api)
        return unique_apis_keep_order(out)
    return round_robin_tasks(candidates, provider, layer=layer_name)

def normalize_extracted_api(path):
    path = (path or "").strip().strip('"\'`')
    if not path or path.startswith(("data:", "javascript:", "mailto:", "#")):
        return ""
    if path.startswith(("http:", "https:", "//")):
        return ""
    query = ""
    if "?" in path:
        path, query = path.split("?", 1)
        query = query.split("#", 1)[0]
    else:
        path = path.split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    path = path.rstrip("/")
    path = validate_root_relative_path(path)
    if not path:
        return ""
    if not (2 < len(path) < 250):
        return ""
    if "\ufffd" in path or re.search(r"[\x00-\x1f\x7f\s]", path):
        return ""
    if not re.search(r"[A-Za-z0-9]", path):
        return ""
    if re.search(r"[^\w./{}:$@%+=,;&?~!()\\[\\]\-\u4e00-\u9fff]", path, re.UNICODE):
        return ""
    if os.path.splitext(path)[1].lower() in ('.js','.mjs','.ts','.tsx','.jsx','.vue','.css','.png','.jpg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map','.html','.pdf'):
        return ""
    if query:
        safe_parts = []
        for part in query.split("&")[:8]:
            if re.match(r"^[A-Za-z_][A-Za-z0-9_.-]{0,40}=[A-Za-z0-9_.:@%+,-]{0,160}$", part):
                safe_parts.append(part)
        if safe_parts:
            return path + "?" + "&".join(safe_parts)
    return path


def validate_root_relative_path(value, max_decode_depth=4):
    return _validate_root_relative_path(value, max_decode_depth=max_decode_depth)


def normalize_wordlist_api(line):
    raw_value = str(line or "").rstrip("\r\n")
    if "\ufffd" in raw_value or re.search(r"[\x00-\x1f\x7f]", raw_value) or "\\" in raw_value:
        return ""
    value = raw_value.strip(" ").strip('"\'`')
    if not value or value.startswith("#"):
        return ""
    if value.startswith("//"):
        return ""
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", value)
    if scheme_match:
        if scheme_match.group(1).lower() not in ("http", "https"):
            return ""
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme.lower() not in ("http", "https")
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                return ""
            parsed.port
        except (TypeError, ValueError):
            return ""
        path = parsed.path or "/"
    else:
        try:
            parsed = urlsplit(value)
        except ValueError:
            return ""
        if parsed.scheme or parsed.netloc:
            return ""
        path = parsed.path
    if not path:
        return ""
    if not path.startswith("/"):
        path = "/" + path
    path = path.rstrip("/")
    path = validate_root_relative_path(path)
    if not path:
        return ""
    if not (2 < len(path) < 250):
        return ""
    if "\ufffd" in path or re.search(r"[\x00-\x1f\x7f\s]", path):
        return ""
    if not re.search(r"[A-Za-z0-9]", path):
        return ""
    if re.search(r"[^\w./{}:$@%+=,;&?~!()\\[\\]\-\u4e00-\u9fff]", path, re.UNICODE):
        return ""
    return path

def load_extra_api_wordlists(paths):
    out = []
    for path in paths or []:
        if not path:
            continue
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    api = normalize_wordlist_api(line)
                    if api:
                        out.append(api)
        except Exception as e:
            log.warning(f"Load extra API wordlist failed: {path}: {e}")
    return unique_apis_keep_order(out)

def configured_backend_baseline_paths():
    items = []
    if args.enable_backend_baseline:
        items.extend(BACKEND_BASELINE_PATHS)
    items.extend(EXTRA_API_WORDLIST_PATHS)
    return unique_apis_keep_order(items)

EXTRA_API_WORDLIST_PATHS = load_extra_api_wordlists(args.extra_api_wordlist)

# Auto-load built-in API wordlist for Phase 2.5 sparse-target fuzz.
# Operators can disable with --disable-api-fuzz or override with --api-fuzz-wordlist.
_BUILTIN_WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists", "api_paths.txt")
if not os.path.exists(_BUILTIN_WORDLIST):
    _BUILTIN_WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "api_paths.txt")
API_FUZZ_WORDLIST_PATHS: list[str] = []
if not args.disable_api_fuzz:
    wl_path = args.api_fuzz_wordlist or _BUILTIN_WORDLIST
    if os.path.exists(wl_path):
        API_FUZZ_WORDLIST_PATHS = load_extra_api_wordlists([wl_path])
        # Keep the built-in sparse-target fuzz list distinct from the explicit
        # backend-baseline opt-in dictionary.  Operator supplied
        # --api-fuzz-wordlist values are still honored verbatim.
        if not args.api_fuzz_wordlist and not args.enable_backend_baseline:
            backend_clean = {p.split("?")[0].rstrip("/") for p in BACKEND_BASELINE_PATHS}
            API_FUZZ_WORDLIST_PATHS = [
                api for api in API_FUZZ_WORDLIST_PATHS
                if api.split("?")[0].rstrip("/") not in backend_clean
            ]

_API_SOURCE_ORDER = {
    "js_request": 11, "swagger": 10, "openapi": 10, "js": 9, "js-graph": 9, "js_literal": 9,
    "html": 8, "vue_router": 7, "react_route": 6, "business_pattern": 6,
    "extra_wordlist": 5, "backend_baseline": 4, "api_fuzz": 4, "param_binding": 3,
    "baseline": 2, "legacy_recovery": 1, "legacy_baseline": 1, "": 0,
}

def backend_probe_param_profile(path):
    profile = empty_param_profile()
    names = {
        "id", "ids", "page", "pageNum", "pageNo", "current", "size", "pageSize",
        "limit", "count", "keyword", "name", "userId", "fileId",
    }
    profile["names"].update(names)
    profile["seeds"].update({"1", "2", "10", "100", "test"})
    clean = path.split("?")[0].rstrip("/")
    for name in names:
        add_api_param(profile, clean, name, source="query")
    return profile

def add_configured_backend_paths(api_set, api_meta):
    """Add only exact configured paths; prefix heuristics are applied once later."""
    backend_paths = set(BACKEND_BASELINE_PATHS) if args.enable_backend_baseline else set()
    extra_paths = set(EXTRA_API_WORDLIST_PATHS)
    configured = backend_paths | extra_paths
    if not configured:
        return api_set
    backend_clean = {_canonical_seed_path(path) for path in backend_paths}
    extra_clean = {_canonical_seed_path(path) for path in extra_paths}
    for api in sorted(configured):
        api_set.add(api)
        clean = _canonical_seed_path(api)
        if clean in backend_clean:
            add_api_meta(api_meta, api, "backend_baseline")
        if clean in extra_clean:
            add_api_meta(api_meta, api, "extra_wordlist")
    return api_set

def valid_sensitive_value(value):
    value = (value or "").strip()
    if len(value) < 8 or len(value) > 200:
        return False
    if re.search(r"\s", value):
        return False
    if any(ch in value for ch in "{}[]();,"):
        return False
    if value.count("+") > 1:
        return False
    alnum = sum(ch.isalnum() for ch in value)
    if alnum < 6:
        return False
    return True

def js_string_constants(content):
    constants = {}
    if not content:
        return constants
    for decl in re.finditer(r'''(?:const|let|var)\s+([^;]{1,400});''', content):
        for m in re.finditer(r'''([A-Za-z_$][\w$]{0,60})\s*=\s*["']([^"']{1,240})["']''', decl.group(1)):
            value = normalize_extracted_api(m.group(2))
            if value:
                constants[m.group(1)] = value.rstrip("/") + ("/" if m.group(2).rstrip().endswith("/") else "")
    return constants

def join_api_parts(left, right):
    left = normalize_extracted_api(left)
    right = (right or "").strip().strip('"\'`')
    if not left or not right or right.startswith(("http:", "https:", "//", "data:", "javascript:", "#")):
        return ""
    joined = left.rstrip("/") + "/" + right.lstrip("/")
    return normalize_extracted_api(joined)

def extract_concatenated_apis(content):
    apis = set()
    constants = js_string_constants(content)
    if not constants:
        return apis
    var_names = "|".join(re.escape(k) for k in sorted(constants, key=len, reverse=True))
    suffix = r'''["']([A-Za-z0-9_.$@%+=,;&?~!()/\-\u4e00-\u9fff]{1,160})["']'''
    patterns = [
        re.compile(r'''(?:url|path)\s*:\s*(%s)\s*\+\s*%s''' % (var_names, suffix), re.I),
        re.compile(r'''\.(?:%s)\s*\(\s*(%s)\s*\+\s*%s''' % (_js_method_group(), var_names, suffix), re.I),
        re.compile(r'''fetch\s*\(\s*(%s)\s*\+\s*%s''' % (var_names, suffix), re.I),
        re.compile(r'''(?:request|axios|service|http)\s*\(\s*\{\s*url\s*:\s*(%s)\s*\+\s*%s''' % (var_names, suffix), re.I),
    ]
    for pat in patterns:
        for m in pat.finditer(content):
            path = join_api_parts(constants.get(m.group(1), ""), m.group(2))
            if path:
                apis.add(path)
    return apis

def _add_api_with_query_base(apis, path):
    if not path:
        return
    apis.add(path)
    if "?" in path:
        base = path.split("?", 1)[0].rstrip("/")
        if base:
            apis.add(base)

def extract_apis(js_content):
    apis = set()
    explicit_methods, blocked_paths = explicit_js_method_map(js_content or "", return_blocked=True)
    for m in LINKFINDER_RE.finditer(js_content):
        path = normalize_extracted_api(m.group(0))
        _add_api_with_query_base(apis, path)
    for m in WEBPACK_CHUNK_RE.finditer(js_content):
        apis.add(m.group(0)[:200])
    for pat in [
        re.compile(r'''(?:url|path|baseURL|apiUrl)\s*:\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''\.(?:%s)\s*\(\s*["']([^"']{2,300})["']''' % _js_method_group(), re.I),
        re.compile(r'''fetch\s*\(\s*["']([^"']{2,300})["']''', re.I),
        re.compile(r'''["'](/(?:api|[a-z0-9]{1,24}-api)/[a-zA-Z][a-zA-Z0-9_/\-.]{2,200})["']''', re.I),
    ]:
        for m in pat.finditer(js_content):
            path = normalize_extracted_api(m.group(1))
            _add_api_with_query_base(apis, path)
    for path in extract_concatenated_apis(js_content):
        _add_api_with_query_base(apis, path)
    # Every static candidate, including runtime/chunk regex output, crosses the
    # same fail-closed root-relative validator before inventory or provenance.
    validated = set()
    for api in apis:
        clean = normalize_extracted_api(api)
        if clean:
            validated.add(clean)
    return {
        api for api in validated
        if not _should_skip_delete_method_path(api, explicit_methods)
        and _method_filter_key(api) not in blocked_paths
    }

def is_module_asset_path(href):
    href = (href or "").strip()
    if not href or href.startswith(("data:", "javascript:", "mailto:", "#")):
        return False
    path = urlparse(href).path if href.startswith(("http://", "https://", "//")) else href.split("?", 1)[0].split("#", 1)[0]
    if STATIC_ASSET_RE.search(path):
        return False
    return bool(MODULE_ASSET_RE.search(path))

def extract_module_urls_from_content(content, base_url):
    urls = set()
    if not content:
        return urls
    patterns = [
        re.compile(r'''(?:import|export)(?:\s+|(?=[\{\*]))(?:[^"']{0,240}?\s*from\s*)?["']([^"']{1,240})["']''', re.I),
        re.compile(r'''import\s*\(\s*["']([^"']{1,240})["']\s*\)''', re.I),
        re.compile(r'''new\s+URL\s*\(\s*["']([^"']{1,240})["']\s*,\s*import\.meta\.url\s*\)''', re.I),
    ]
    for pat in patterns:
        for m in pat.finditer(content):
            spec = m.group(1).strip()
            if not spec.startswith((".", "/", "@")):
                continue
            if spec.startswith("@/"):
                spec = "/src/" + spec[2:]
            if is_module_asset_path(spec) or spec.startswith(("./", "../", "/src/", "/@vite/", "/@id/")):
                urls.add(urljoin(base_url, spec))
    for m in re.finditer(r'''["']([^"']*?(?:^|/)?js/[A-Za-z0-9_.-]+\.js(?:\?[^"']*)?)["']''', content):
        urls.add(urljoin(base_url, m.group(1).strip()))
    return urls

def _normalized_discovery_url(raw_url, base_url):
    raw_url = str(raw_url or "").strip()
    if not raw_url or raw_url.startswith(("data:", "javascript:", "mailto:", "#")):
        return ""
    try:
        parsed = urlparse(urljoin(base_url, raw_url))
    except (TypeError, ValueError):
        return ""
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        return ""
    return urlunparse(parsed._replace(fragment=""))

def extract_js_from_html(html, base_url):
    js_urls = set()
    parsed_html = parse_html_discovery(html)
    import_map_urls = {
        _normalized_discovery_url((script.get("attrs") or {}).get("src"), base_url)
        for script in parsed_html.scripts
        if str((script.get("attrs") or {}).get("type") or "").strip().lower() == "importmap"
        and (script.get("attrs") or {}).get("src")
    }
    def add_js_href(href, module=False):
        href = (href or "").strip()
        if not href:
            return
        path = urlparse(href).path if href.startswith(("http://", "https://", "//")) else href.split("?", 1)[0].split("#", 1)[0]
        if STATIC_ASSET_RE.search(path) and not is_module_asset_path(href):
            return
        normalized = _normalized_discovery_url(href, base_url)
        if normalized and (module or is_module_asset_path(href) or path):
            js_urls.add(normalized)
    bs4_parsed = False
    if HAS_BS4:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for script in soup.find_all('script', src=True):
                script_type = str(script.get('type') or "").lower()
                if script_type.strip() == "importmap":
                    continue
                add_js_href(script.get('src', ''), module=("module" in script_type))
            for link in soup.find_all('link', href=True):
                rels = link.get('rel') or []
                if isinstance(rels, str):
                    rels = re.split(r'\s+', rels.strip())
                rels = {str(r).lower() for r in rels}
                if rels & {"preload", "prefetch", "modulepreload"}:
                    add_js_href(link.get('href', ''))
            bs4_parsed = True
        except Exception as e:
            log.debug(f"BS4 parse failed: {e}")
    if not bs4_parsed:
        for script in parsed_html.scripts:
            attrs = script.get("attrs") or {}
            script_type = str(attrs.get("type") or "").lower().strip()
            if script_type == "importmap":
                continue
            if attrs.get("src"):
                add_js_href(attrs.get("src"), module=("module" in script_type))
        for link in parsed_html.links:
            rels = {part.lower() for part in re.split(r"\s+", str(link.get("rel") or "").strip()) if part}
            if rels & {"preload", "prefetch", "modulepreload"} and link.get("href"):
                add_js_href(link.get("href"), module=("modulepreload" in rels))
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+\.js(?:\?[^"\'<>\s]*)?)[ "\x27>]?', html, re.I):
        add_js_href(m.group(1))
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+)["\x27]?', html, re.I):
        add_js_href(m.group(1))
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+)["\x27]?[^>]*type\s*=\s*["\x27]?module["\x27]?', html, re.I):
        add_js_href(m.group(1), module=True)
    for m in re.finditer(r'<script[^>]+type\s*=\s*["\x27]?module["\x27]?[^>]+src\s*=\s*["\x27]?([^"\'<>\s]+)["\x27]?', html, re.I):
        add_js_href(m.group(1), module=True)
    for m in re.finditer(r'<link[^>]+rel\s*=\s*["\x27]?[^"\'>]*(?:prefetch|preload|modulepreload)[^"\'>]*["\x27]?[^>]+href\s*=\s*["\x27]?([^"\'<>\s]+\.js(?:\?[^"\'<>\s]*)?)["\x27]?', html, re.I):
        add_js_href(m.group(1))
    for m in re.finditer(r'<link[^>]+href\s*=\s*["\x27]?([^"\'<>\s]+\.js(?:\?[^"\'<>\s]*)?)["\x27]?[^>]+rel\s*=\s*["\x27]?[^"\'>]*(?:prefetch|preload|modulepreload)[^"\'>]*["\x27]?', html, re.I):
        add_js_href(m.group(1))
    for pat in [WEBPACK_CHUNK_RE, re.compile(r'''["']([^"']*?(?:static/js|js)/[^"']+\.js)["']'''), re.compile(r'''["']([^"']*?js/[a-zA-Z][a-zA-Z0-9_\-\.]+\.js)["']''')]:
        for m in pat.finditer(html):
            chunk = str(m.group(0)).strip('"\'')
            if "/js/" in chunk: js_urls.add(urljoin(base_url, chunk))
    pp = re.search(r'''__webpack_public_path__\s*=\s*["']([^"']+)["']''', html)
    if pp:
        for m in re.finditer(r'''\{(\d+):\s*["']([^"']+)["']''', html):
            js_urls.add(urljoin(base_url, f"{pp.group(1)}{m.group(2)}.js"))
    js_urls.difference_update(value for value in import_map_urls if value)
    # The regex fallback can stop at the ".js" prefix of ".json" and invent
    # cross-map.js from an import-map src. Remove those parser-known artifacts.
    import_map_js_prefixes = {
        urlunparse(urlparse(value)._replace(
            path=re.sub(r"\.json$", ".js", urlparse(value).path, flags=re.I), query="", fragment=""
        ))
        for value in import_map_urls if value and re.search(r"\.json$", urlparse(value).path, re.I)
    }
    js_urls.difference_update(import_map_js_prefixes)
    return js_urls

def extract_links_from_html(html, base_url):
    links = set()
    parsed_base = urlparse(base_url)
    bs4_parsed = False
    if HAS_BS4:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('#') or href.startswith('javascript:'): continue
                full = _normalized_discovery_url(href, base_url)
                if not full:
                    continue
                if urlparse(full).hostname == parsed_base.hostname and not re.search(r'\.(?:js|css|png|jpg|gif|svg|ico|pdf|doc|zip)(?:\?|$)', full):
                    links.add(full)
            bs4_parsed = True
        except Exception as e:
            log.debug(f"BS4 link extract failed: {e}")
    if not bs4_parsed:
        parsed_html = parse_html_discovery(html)
        for anchor in parsed_html.anchors:
            full = _normalized_discovery_url(anchor.get("href"), base_url)
            if not full:
                continue
            if urlparse(full).hostname == parsed_base.hostname and not re.search(r'\.(?:js|css|png|jpg|gif|svg|ico|pdf|doc|zip)(?:\?|$)', full, re.I):
                links.add(full)
    return links

def origin_from_url(raw_url):
    p = urlparse(raw_url)
    origin = f"{p.scheme}://{p.hostname}"
    if p.port and p.port not in (80,443): origin += f":{p.port}"
    return origin

def path_prefixes_from_url(raw_url):
    """Infer deployment prefixes such as /abcabc from target/final URLs."""
    try:
        path = urlsplit(str(raw_url or "")).path or ""
    except (TypeError, ValueError):
        return set()
    if not path or path == "/": return set()
    if path.endswith("//"):
        return set()
    path = path.rstrip("/")
    if not path or not validate_root_relative_path(path): return set()
    parts = [p for p in path.strip("/").split("/") if p]
    if parts and "." in parts[-1]:
        parts = parts[:-1]
    return set(_bounded_valid_prefixes('/' + '/'.join(parts[:i]) for i in range(1, len(parts)+1)))


def _bounded_valid_prefixes(prefixes):
    valid = set()
    for raw in prefixes or ():
        if not isinstance(raw, str):
            continue
        if raw.endswith("//"):
            continue
        candidate = raw[:-1] if raw.endswith("/") else raw
        if candidate and candidate != "/" and validate_root_relative_path(candidate):
            valid.add(candidate)
    ordered = sorted(valid, key=lambda value: (value.count("/"), len(value), value))
    return tuple(ordered[:MAX_PREFIX_INVENTORY_PREFIXES])


def generate_prefix_inventory(apis, prefixes, api_meta=None):
    """Return bounded prefix-only inventory derived once from exact API paths."""
    exact = tuple(sorted(set(_canonical_api_list(apis))))
    clean_prefixes = _bounded_valid_prefixes(prefixes)
    exact_identities = set(exact)
    ordering_target = {"api_meta": api_meta if isinstance(api_meta, dict) else {}}
    source_paths = [
        path for path in sorted(exact_identities, key=lambda value: (api_test_order(ordering_target, value), value))
        if not any(path == prefix or path.startswith(prefix + "/") for prefix in clean_prefixes)
    ]
    generated = []
    seen = set(exact_identities)
    for path in source_paths:
        for prefix in clean_prefixes:
            candidate = validate_root_relative_path(prefix + path)
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            generated.append(candidate)
            if len(generated) >= MAX_PREFIX_INVENTORY_PATHS:
                return {"prefixes": clean_prefixes, "exact": exact, "generated": tuple(generated)}
    return {"prefixes": clean_prefixes, "exact": exact, "generated": tuple(generated)}


def apply_prefix_inventory(api_set, api_meta, prefixes):
    inventory = generate_prefix_inventory(api_set, prefixes, api_meta=api_meta)
    expanded = set(inventory["exact"])
    if isinstance(api_meta, dict):
        safe_meta = _safe_api_meta_record(api_meta, expanded)
        api_meta.clear()
        api_meta.update(safe_meta)
    for path in inventory["generated"]:
        expanded.add(path)
        add_api_meta(api_meta, path, "prefix_inventory", 0.25)
    return expanded, list(inventory["generated"])

def normalize_api_prefixes(path):
    raw = str(path or "").strip()
    if not raw or raw.startswith("//") or "?" in raw or "#" in raw:
        return set()
    try:
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc:
            if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
                return set()
            if parsed.username is not None or parsed.password is not None or not parsed.hostname:
                return set()
            path = parsed.path
        else:
            path = raw
    except (TypeError, ValueError):
        return set()
    if path.endswith("//"):
        return set()
    path = path[:-1] if path.endswith("/") else path
    if not validate_root_relative_path(path) or path == "/": return set()
    parts = [p for p in path.strip("/").split("/") if p]
    if not parts: return set()
    prefixes = {"/" + "/".join(parts)}
    if len(parts) > 1:
        prefixes.add("/" + "/".join(parts[:-1]))
    for idx, part in enumerate(parts):
        lowered = part.lower()
        if idx == 0 and API_ROOT_SEGMENT_RE.fullmatch(lowered):
            prefixes.add("/" + "/".join(parts[:idx + 1]))
        if idx > 0 and (API_ROOT_SEGMENT_RE.fullmatch(lowered) or lowered in ("gateway", "openapi", "rest")):
            prefixes.add("/" + "/".join(parts[:idx]))
    return set(_bounded_valid_prefixes(prefixes))

def extract_prefixes_from_content(content):
    prefixes = set()
    for m in API_PREFIX_RE.finditer(content):
        prefixes.update(normalize_api_prefixes(m.group(1).strip()))
    for m in PUBLIC_PATH_RE.finditer(content):
        path = m.group(1).strip()
        lowered = path.lower()
        if any(marker in lowered for marker in ("/api", "api-", "-api", "gateway", "openapi")):
            prefixes.update(normalize_api_prefixes(path))
    return set(_bounded_valid_prefixes(prefixes))

def _empty_openapi_inventory():
    return {"apis": [], "methods": {}, "path_templates": [], "external_servers": [], "unresolved_refs": []}


def extract_openapi_inventory(doc_text):
    try:
        return parse_openapi_inventory(doc_text)
    except Exception as exc:
        log.debug(f"OpenAPI inventory parse failed: {exc}")
        return _empty_openapi_inventory()


def merge_openapi_inventory(profile, inventory):
    """Merge safe local OpenAPI operations into the active parameter profile."""
    active_paths = set()
    methods_by_path = {}
    for record in (inventory or {}).get("apis", []) or []:
        if not isinstance(record, dict) or not record.get("local") or not record.get("active"):
            continue
        api_path = _clean_profile_api_path(record.get("path"))
        method = str(record.get("method") or "").lower()
        if not api_path or method not in HTTP_METHODS:
            continue
        active_paths.add(api_path)
        methods_by_path.setdefault(api_path, set()).add(method)
        add_api_method(profile, api_path, method)
        add_api_path_template(profile, api_path, record.get("path_template"))
        for content_type in record.get("content_types") or []:
            add_api_content_type(profile, api_path, content_type)
        for key, source in (
            ("query_params", "query"),
            ("json_params", "json"),
            ("form_params", "form"),
            ("path_params", "path"),
            ("header_params", "header"),
        ):
            for spec in record.get(key) or []:
                add_api_param_spec(profile, api_path, source, spec)
    if getattr(args, "include_delete_method", False):
        return active_paths
    return {
        api_path
        for api_path in active_paths
        if not methods_by_path.get(api_path) or methods_by_path.get(api_path) - {"delete"}
    }


def extract_swagger_inventory(doc_text):
    profile = empty_param_profile()
    apis = merge_openapi_inventory(profile, extract_openapi_inventory(doc_text))
    return apis, profile.get("api_methods", {})

def extract_swagger_apis(doc_text):
    apis, _methods = extract_swagger_inventory(doc_text)
    return apis

def api_priority(path):
    p = path.lower()
    score = 0
    weighted = [
        (180, ["login", "authentication"]),
        (130, ["captcha","statistics","message"]),
        (120, ["rtsp","streamurl","playurl"]),
        (100, ["camera","video","stream","media","play","live","channel","device"]),
        (95, ["phone","mobile","idcard","identity","realname","citizen","resident"]),
        (85, ["user","person","people","email","address"]),
        (75, ["config","system","admin","role","permission","auth","token","password","secret"]),
        (72, ["captcha","statistics","dashboard","screen"]),
        (50, ["file","upload","download","export","import","backup"]),
        (40, ["alarm","alert","message","record","log","history","trace"]),
        (35, ["swagger","api-docs","druid","actuator","openapi"]),
        (25, ["list","query","search","page","all"]),
    ]
    for weight, words in weighted:
        if any(w in p for w in words):
            score += weight
    first_segment = p.lstrip("/").split("/", 1)[0]
    if first_segment == "gateway" or API_ROOT_SEGMENT_RE.fullmatch(first_segment):
        score += 15
    if re.search(r"/(?:get|list|query|search|page|all)(?:/|$)", p):
        score += 10
    if "delete" in p or "remove" in p:
        score -= 30
    return (-score, len(path), path)

def collect_swagger_apis(base):
    return collect_openapi_inventory(base).get("apis", set())

def collect_swagger_inventory(base):
    collected = collect_openapi_inventory(base)
    return collected.get("apis", set()), collected.get("param_profile", {}).get("api_methods", {})


def collect_openapi_inventory(base):
    apis = set()
    profile = empty_param_profile()
    external_servers = []
    unresolved_refs = []
    path_templates = set()
    seen_external = set()
    seen_unresolved = set()
    for doc_path in SWAGGER_DOC_PATHS:
        s, _, doc, _ = http_get(urljoin(base, doc_path), max_size=1_000_000, retries=0)
        if s == 200 and doc:
            inventory = extract_openapi_inventory(doc)
            apis.update(merge_openapi_inventory(profile, inventory))
            path_templates.update(str(value) for value in (inventory.get("path_templates") or []) if str(value).startswith("/"))
            for item in inventory.get("external_servers") or []:
                if not isinstance(item, dict):
                    continue
                key = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
                if key not in seen_external:
                    seen_external.add(key)
                    external_servers.append(item)
            for item in inventory.get("unresolved_refs") or []:
                if not isinstance(item, dict):
                    continue
                key = (str(item.get("ref") or ""), str(item.get("reason") or ""))
                if key not in seen_unresolved:
                    seen_unresolved.add(key)
                    unresolved_refs.append(item)
    return {
        "apis": apis,
        "param_profile": profile,
        "external_servers": sorted(external_servers, key=lambda item: (str(item.get("url") or ""), str(item.get("scope") or ""), str(item.get("path_template") or ""), str(item.get("method") or ""))),
        "unresolved_refs": sorted(unresolved_refs, key=lambda item: (str(item.get("ref") or ""), str(item.get("reason") or ""))),
        "path_templates": sorted(path_templates),
    }

# ===== 响应检测 =====
OBSERVATION_ASSESSMENT = "observation"
EXPOSURE_ASSESSMENT = "exposure_candidate"
CONFIRMED_ASSESSMENT = "confirmed_exposure"
ATTACK_SURFACE_MARKERS = ['swagger','api-docs','druid','/v2/api','/v3/api','openapi','/actuator']
EMPTY_VALUE_STRINGS = {"", "null", "none", "nil", "undefined", "n/a", "na", "-", "--", "—", "无", "暂无"}
VOLATILE_FINGERPRINT_KEYS = {
    "timestamp", "time", "requestid", "traceid", "spanid", "correlationid", "path", "uri"
}

def is_meaningful_scalar(value):
    if value is None:
        return False
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return value.strip().lower() not in EMPTY_VALUE_STRINGS
    if isinstance(value, (list, tuple, set)):
        return any(is_meaningful_scalar(v) for v in value)
    if isinstance(value, dict):
        return any(is_meaningful_scalar(v) for v in value.values())
    return True

def dict_get_ci(obj, *names, default=None):
    if not isinstance(obj, dict):
        return default
    lookup = {str(k).lower(): k for k in obj.keys()}
    for name in names:
        key = lookup.get(str(name).lower())
        if key is not None:
            return obj.get(key)
    return default

def attack_surface_path(url):
    return any(kw in (url or "").lower() for kw in ATTACK_SURFACE_MARKERS)

def apply_finding_semantics(fi):
    """Attach schema-v2 assessment fields. No unauth finding is confirmed yet."""
    if not fi:
        return fi
    if "assessment" not in fi:
        path_intel_only = bool(fi.get("attack_path_intel")) and not (
            fi.get("credential_leak") or fi.get("private_data_signal")
        )
        if fi.get("public_download_intel") or path_intel_only:
            fi["assessment"] = OBSERVATION_ASSESSMENT
        else:
            fi["assessment"] = EXPOSURE_ASSESSMENT
    if fi.get("assessment") == CONFIRMED_ASSESSMENT:
        fi["confirmed"] = True
        fi.setdefault("auth_baseline", "present")
    else:
        fi["confirmed"] = False
        fi.setdefault("auth_baseline", "absent")
    return fi

def is_observation_finding(fi):
    fi = normalize_finding(fi) if fi else fi
    return bool(fi and fi.get("assessment") == OBSERVATION_ASSESSMENT)

def is_candidate_finding(fi):
    fi = normalize_finding(fi) if fi else fi
    return bool(fi and fi.get("assessment") == EXPOSURE_ASSESSMENT)

def is_confirmed_finding(fi):
    fi = normalize_finding(fi) if fi else fi
    return bool(fi and fi.get("confirmed") is True and fi.get("assessment") == CONFIRMED_ASSESSMENT)

def risk_level(fi):
    url = fi.get('url','').lower()
    attack_path = attack_surface_path(url)
    if attack_path:
        fi['attack_path_intel'] = True
    if fi.get('file_leak'):
        if fi.get("public_download_intel"):
            return "LOW"
        score = int(fi.get('file_score') or 0)
        return 'CRITICAL' if score >= 8 else 'HIGH' if score >= 6 else 'MEDIUM'
    score = 0
    if fi.get('credential_leak'): score += 3
    if fi.get('data_count', 0) > 10: score += 2
    if fi.get('data_keys'):
        keys_str = ' '.join(fi['data_keys']).lower()
        sensitive_str = ' '.join(fi.get('sensitive_fields', [])).lower()
        if fi.get("credential_leak") or ("token" in sensitive_str) or ("secret" in sensitive_str):
            if any(k in keys_str for k in ['secret','password','token','key']): score += 3
        if any(k in sensitive_str for k in ['phone','email','address','idcard']):
            if any(k in keys_str for k in ['phone','email','address','idcard','身份证']): score += 3
        if any(k in keys_str for k in ['camera','cameraid','deviceid','stream','streamurl','rtsp','playurl','channel']):
            score += 3
        if any(k in keys_str for k in ['unit_number','unit_name','unit_type','user_name','jurisdiction','inspection','alarm','alert']):
            score += 3
        if any(k in keys_str for k in ['plate','plateno','latitude','longitude','lng','lat','gps']):
            score += 2
    if score >= 5: return 'CRITICAL'
    if score >= 3: return 'HIGH'
    if score >= 1: return 'MEDIUM'
    return 'LOW'

def json_data_keys(obj, max_keys=30, depth=0):
    keys = []
    seen = set()
    def add(key):
        key = str(key)
        if key and key not in seen and len(keys) < max_keys:
            seen.add(key)
            keys.append(key)
    def walk(item, level):
        if level > 4 or len(keys) >= max_keys:
            return
        if isinstance(item, dict):
            for k, v in item.items():
                add(k)
                if isinstance(v, (dict, list)):
                    walk(v, level + 1)
        elif isinstance(item, list):
            for child in item[:5]:
                if isinstance(child, (dict, list)):
                    walk(child, level + 1)
    walk(obj, depth)
    return keys

def json_data_count(obj, depth=0):
    if depth > 4:
        return 0
    if isinstance(obj, list):
        return len(obj)
    if isinstance(obj, dict):
        for value in obj.values():
            count = json_data_count(value, depth + 1)
            if count:
                return count
    return 0

JWT_LIKE_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]*\b")

def has_credential_value(obj, depth=0):
    if depth > 5:
        return False
    if isinstance(obj, str):
        text = obj.strip()
        if not is_meaningful_scalar(text):
            return False
        return bool(JWT_LIKE_RE.search(text) or re.search(r"\b(?:access[_-]?token|refresh[_-]?token|authorization)\b", text, re.I))
    if isinstance(obj, list):
        return any(has_credential_value(item, depth + 1) for item in obj[:20])
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key).lower()
            if any(k in key_s for k in (
                "token", "jwt", "authorization", "session", "password",
                "passwd", "secret", "apikey", "api_key", "accesskey",
                "access_key", "clientsecret", "client_secret",
            )) and is_meaningful_scalar(value):
                return True
            if has_credential_value(value, depth + 1):
                return True
    return False

def is_framework_not_found_json(parsed):
    if not isinstance(parsed, dict):
        return False
    msg = " ".join(str(parsed.get(k, "")) for k in ("msg", "message", "error", "detail", "reason"))
    data = parsed.get("data")
    if isinstance(data, dict):
        msg += " " + " ".join(str(data.get(k, "")) for k in ("msg", "message", "error", "repMsg", "detail", "reason"))
        has_stack = ("trace" in data and ("file" in data or "line" in data)) or ("file" in data and "line" in data)
        return bool(has_stack and FRAMEWORK_NOT_FOUND_RE.search(msg))
    return False

def json_container_value(obj):
    """Return (value, container_name) for case-insensitive data containers."""
    if isinstance(obj, list):
        return obj, "list"
    if not isinstance(obj, dict):
        return (obj, "scalar") if is_meaningful_scalar(obj) else (None, "")
    for key, value in obj.items():
        if str(key).lower() in ("records", "list", "items", "rows") and is_meaningful_scalar(value):
            return value, str(key)
    for key, value in obj.items():
        if str(key).lower() in ("data", "result", "payload", "page", "datas"):
            if isinstance(value, dict):
                nested, nested_name = json_container_value(value)
                if nested is not None and is_meaningful_scalar(nested):
                    return nested, nested_name or str(key)
            if is_meaningful_scalar(value):
                return value, str(key)
    return (obj, "object") if is_meaningful_scalar(obj) else (None, "")

def business_code_value(parsed):
    if not isinstance(parsed, dict):
        return ""
    for key in ("code", "retCode", "statusCode", "status"):
        value = dict_get_ci(parsed, key)
        if isinstance(value, dict):
            value = dict_get_ci(value, "code", "statusCode")
        if value is not None and not isinstance(value, (dict, list)):
            return str(value)
    return ""

def response_finding_summary(f, classifier_summary, parsed, data_source, container):
    f["classifier_verdict"] = classifier_summary.get("verdict")
    f["classifier_confidence"] = classifier_summary.get("confidence")
    f["classifier_reasons"] = classifier_summary.get("reasons", [])
    f["sensitive_fields"] = classifier_summary.get("sensitive_fields", [])
    f["data_signals"] = classifier_summary.get("data_signals", {})
    admitted_payload = classifier_summary.get("verdict") in ("success_data", "sensitive_signal")
    if admitted_payload:
        if container:
            f["data_container"] = container
        if isinstance(data_source, list):
            f["data_count"] = len(data_source)
            if data_source and isinstance(data_source[0], dict):
                f["data_keys"] = json_data_keys(data_source)
        elif isinstance(data_source, dict):
            f["data_keys"] = json_data_keys(data_source)
            count = json_data_count(data_source)
            if count:
                f["data_count"] = count
        elif is_meaningful_scalar(data_source):
            f["data_count"] = 1
            f["data_keys"] = [container or "scalar"]
            f["scalar_payload"] = True
    if has_credential_value(parsed):
        f["credential_leak"] = True
    if f.get("sensitive_fields") or f.get("credential_leak"):
        f["private_data_signal"] = True
    f["risk"] = risk_level(f)
    apply_finding_semantics(f)
    return f

def check_response(body, url, method, test_name, status_code=None, catch_all_match=False):
    if len(body or "") < 2:
        return None
    attack_path = attack_surface_path(url)
    try:
        status_int = int(status_code or 0)
    except Exception:
        status_int = 0
    attack_path_ok = attack_path and (status_code is None or 200 <= status_int < 300)
    parsed = None
    try:
        parsed = json.loads(body)
    except Exception:
        pass
    classifier_summary = classify_response(status_int or 0, body, {}, catch_all_match=catch_all_match)
    verdict = classifier_summary.get("verdict")
    if verdict in ("auth_failed", "http_error", "business_error", "framework_not_found", "catch_all"):
        return None
    admitted_payload = verdict in ("success_data", "sensitive_signal")
    if parsed is not None:
        if isinstance(parsed, (dict, list)):
            data_source, container = json_container_value(parsed)
            if admitted_payload or attack_path_ok:
                f = {
                    "url": url,
                    "method": method,
                    "test": test_name,
                    "code": business_code_value(parsed),
                    "msg": str(dict_get_ci(parsed, "msg", "message", default=""))[:200] if isinstance(parsed, dict) else "",
                }
                if attack_path:
                    f["attack_path_intel"] = True
                response_finding_summary(f, classifier_summary, parsed, data_source, container)
                # Path-only attack-surface intel is an observation. If the path
                # contains meaningful private data/credential, semantics above
                # keep it as an exposure candidate.
                if attack_path and not (f.get("credential_leak") or f.get("private_data_signal")):
                    f["assessment"] = OBSERVATION_ASSESSMENT
                    apply_finding_semantics(f)
                f["raw"] = body[:500]
                return f
    elif attack_path_ok:
        f = {"url": url, "method": method, "test": test_name, "attack_path_intel": True, "risk": "LOW", "raw": body[:500]}
        f["classifier_verdict"] = classifier_summary.get("verdict")
        f["classifier_confidence"] = classifier_summary.get("confidence")
        f["classifier_reasons"] = classifier_summary.get("reasons", [])
        f["assessment"] = OBSERVATION_ASSESSMENT
        apply_finding_semantics(f)
        return f
    return None

def text_has_auth_failure(text):
    text = str(text or "")
    lowered = text.lower()
    return any(str(p).lower() in lowered for p in AUTH_FAIL_MSGS)

def is_auth_failure_json(parsed):
    if not isinstance(parsed, (dict, list)):
        return False
    def walk(obj, depth=0):
        if depth > 4:
            return False
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in ("msg", "message", "error", "errorMsg", "errorMessage", "detail", "reason") and text_has_auth_failure(value):
                    return True
                if isinstance(value, (dict, list)) and walk(value, depth + 1):
                    return True
        elif isinstance(obj, list):
            for item in obj[:10]:
                if isinstance(item, (dict, list)) and walk(item, depth + 1):
                    return True
        return False
    return walk(parsed)


def phase3_host_key(url):
    p = urlparse(url)
    return (p.hostname or p.path.split("/", 1)[0]).lower()

def phase3_rate_delay_seconds():
    delays = []
    if getattr(args, "min_delay_ms", 0) and args.min_delay_ms > 0:
        delays.append(args.min_delay_ms / 1000.0)
    if getattr(args, "max_rps_per_host", 0.0) and args.max_rps_per_host > 0:
        delays.append(1.0 / float(args.max_rps_per_host))
    return max(delays) if delays else 0.0

def _phase3_rate_state_for_host(host):
    return PHASE3_RATE_STATE.setdefault(host, {"count": 0, "last": 0.0, "reserved_controls": 0, "probe_holds": 0})

def _phase3_reserved_total(state):
    return int(state.get("reserved_controls") or 0) + int(state.get("probe_holds") or 0)


def phase3_task_cancelled():
    event = getattr(PHASE3_TASK_CONTEXT, "cancel_event", None)
    return bool(event and event.is_set())


def mark_phase3_task_request_attempted():
    if hasattr(PHASE3_TASK_CONTEXT, "request_attempted"):
        PHASE3_TASK_CONTEXT.request_attempted = True


def phase3_cancelable_sleep(seconds):
    event = getattr(PHASE3_TASK_CONTEXT, "cancel_event", None)
    if event:
        event.wait(max(0.0, float(seconds or 0.0)))
    elif seconds and seconds > 0:
        time.sleep(seconds)

def acquire_phase3_request_slot(url, consume_probe_hold=False):
    """Best-effort per-host Phase 3 limiter. Returns (allowed, reason)."""
    if phase3_task_cancelled():
        return False, "task_pool_timeout"
    host = phase3_host_key(url)
    delay = phase3_rate_delay_seconds()
    while True:
        if phase3_task_cancelled():
            return False, "task_pool_timeout"
        sleep_for = 0.0
        with PHASE3_RATE_LOCK:
            state = _phase3_rate_state_for_host(host)
            cap = int(getattr(args, "max_requests_per_host", 0) or 0)
            using_probe_hold = bool(consume_probe_hold and int(state.get("probe_holds") or 0) > 0)
            if cap > 0 and not using_probe_hold and state["count"] + _phase3_reserved_total(state) >= cap:
                return False, "max_requests_per_host"
            if cap > 0 and using_probe_hold and state["count"] >= cap:
                return False, "max_requests_per_host"
            now = time.time()
            if delay > 0 and state["last"] and now - state["last"] < delay:
                sleep_for = delay - (now - state["last"])
            else:
                if using_probe_hold:
                    state["probe_holds"] = max(0, int(state.get("probe_holds") or 0) - 1)
                state["count"] += 1
                state["last"] = now
                mark_phase3_task_request_attempted()
                return True, ""
        if sleep_for > 0:
            phase3_cancelable_sleep(min(sleep_for, delay or sleep_for))

def reserve_catch_all_control_budget(url, controls=2, retain_probe=1):
    """Atomically reserve catch-all controls while holding one real-probe slot.

    The held probe slot is not counted as a request until the caller consumes it
    through acquire_phase3_request_slot(..., consume_probe_hold=True), but normal
    workers must treat it as unavailable so they cannot starve the real probe
    between the budget check and the two control requests.
    """
    cap = int(getattr(args, "max_requests_per_host", 0) or 0)
    if cap <= 0:
        return ""
    host = phase3_host_key(url)
    needed = int(controls or 0) + int(retain_probe or 0)
    with PHASE3_RATE_LOCK:
        state = _phase3_rate_state_for_host(host)
        available = cap - int(state.get("count") or 0) - _phase3_reserved_total(state)
        if available < needed:
            return ""
        state["reserved_controls"] = int(state.get("reserved_controls") or 0) + int(controls or 0)
        state["probe_holds"] = int(state.get("probe_holds") or 0) + int(retain_probe or 0)
        return host

def release_catch_all_control_budget(host, controls=None, release_probe=True):
    if not host:
        return
    with PHASE3_RATE_LOCK:
        state = PHASE3_RATE_STATE.get(host)
        if not state:
            return
        if controls is None:
            state["reserved_controls"] = 0
        else:
            state["reserved_controls"] = max(0, int(state.get("reserved_controls") or 0) - int(controls or 0))
        if release_probe:
            state["probe_holds"] = max(0, int(state.get("probe_holds") or 0) - 1)

def acquire_catch_all_control_slot(url, reservation_host=""):
    if phase3_task_cancelled():
        return False, "task_pool_timeout"
    cap = int(getattr(args, "max_requests_per_host", 0) or 0)
    if cap <= 0:
        return acquire_phase3_request_slot(url)
    host = phase3_host_key(url)
    if reservation_host and reservation_host != host:
        return False, "catch_all_reservation_host_mismatch"
    delay = phase3_rate_delay_seconds()
    while True:
        if phase3_task_cancelled():
            return False, "task_pool_timeout"
        sleep_for = 0.0
        with PHASE3_RATE_LOCK:
            state = _phase3_rate_state_for_host(host)
            if int(state.get("reserved_controls") or 0) <= 0:
                return False, "catch_all_control_not_reserved"
            if int(state.get("count") or 0) >= cap:
                return False, "max_requests_per_host"
            now = time.time()
            if delay > 0 and state["last"] and now - state["last"] < delay:
                sleep_for = delay - (now - state["last"])
            else:
                state["reserved_controls"] = max(0, int(state.get("reserved_controls") or 0) - 1)
                state["count"] += 1
                state["last"] = now
                mark_phase3_task_request_attempted()
                return True, ""
        if sleep_for > 0:
            phase3_cancelable_sleep(min(sleep_for, delay or sleep_for))

def inc_catch_all_stat(name, delta=1):
    with CATCH_ALL_LOCK:
        CATCH_ALL_STATS[name] = int(CATCH_ALL_STATS.get(name) or 0) + delta

def phase3_budget_available(url, needed):
    cap = int(getattr(args, "max_requests_per_host", 0) or 0)
    if cap <= 0:
        return True
    host = phase3_host_key(url)
    with PHASE3_RATE_LOCK:
        state = PHASE3_RATE_STATE.get(host) or {"count": 0, "reserved_controls": 0, "probe_holds": 0}
        return cap - int(state.get("count") or 0) - _phase3_reserved_total(state) >= needed

def catch_all_scope_for_path(path):
    parts = [p for p in str(path or "").split("?", 1)[0].strip("/").split("/") if p]
    if not parts:
        return ""
    for idx, part in enumerate(parts):
        lowered = part.lower()
        if lowered == "api" or lowered.endswith("-api") or lowered in ("gateway", "openapi", "rest"):
            return "/" + "/".join(parts[:idx + 1])
    return "/" + parts[0]

def catch_all_control_paths(path, scope_override=None):
    scope = catch_all_scope_for_path(path) if scope_override is None else str(scope_override or "")
    prefix = scope.rstrip("/")
    out = []
    for _idx in range(2):
        nonce = os.urandom(16).hex()
        control_path = f"{prefix}/__scanner_not_found_{nonce}" if prefix else f"/__scanner_not_found_{nonce}"
        out.append((control_path, nonce))
    return out

def response_content_family(headers, body):
    ct = ""
    if headers:
        ct = str(headers.get("Content-Type") or headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if ct:
        if "json" in ct:
            return "json"
        if "html" in ct:
            return "html"
        if "text" in ct:
            return "text"
        if any(x in ct for x in ("pdf", "zip", "octet-stream", "image", "video")):
            return "binary"
        return ct
    text = body if isinstance(body, str) else (body.decode("utf-8", "ignore") if isinstance(body, bytes) else "")
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        return "json"
    if stripped.startswith("<"):
        return "html"
    return "text" if stripped else "empty"

def canonicalize_for_catch_all(value, tokens):
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            lower = str(key).lower()
            if lower in VOLATILE_FINGERPRINT_KEYS:
                continue
            out[str(key)] = canonicalize_for_catch_all(child, tokens)
        return out
    if isinstance(value, list):
        return [canonicalize_for_catch_all(item, tokens) for item in value]
    if isinstance(value, str):
        text = value
        for token in tokens or []:
            if token:
                text = text.replace(token, "<scanner-random>")
        return text
    return value

def catch_all_request_tokens(request_url_or_path, extra_tokens=None):
    """Return request-specific strings that dynamic fallback pages may echo."""
    raw = str(request_url_or_path or "").strip()
    tokens = []

    def add(value):
        value = str(value or "")
        if value and value not in tokens:
            tokens.append(value)

    add(raw)
    if raw:
        parsed = urlparse(raw)
        if parsed.scheme or parsed.netloc:
            path = parsed.path or "/"
            target = path + (("?" + parsed.query) if parsed.query else "")
            add(target)
            add(path)
        else:
            target = raw.split("#", 1)[0]
            add(target)
            add(target.split("?", 1)[0])
    for token in extra_tokens or []:
        add(token)
    return sorted(tokens, key=len, reverse=True)

def shape_for_catch_all(value):
    if isinstance(value, dict):
        return {str(k): shape_for_catch_all(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [shape_for_catch_all(value[0])] if value else []
    return type(value).__name__

def stable_json_hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

def catch_all_fingerprint(status, headers, body, tokens=None):
    tokens = tokens or []
    parsed = None
    try:
        parsed = json.loads(body if isinstance(body, str) else body.decode("utf-8", "ignore"))
    except Exception:
        parsed = None
    classifier_summary = classify_response(status or 0, body, headers or {})
    if parsed is not None:
        canonical = canonicalize_for_catch_all(parsed, tokens)
        shape = shape_for_catch_all(canonical)
    else:
        text = body if isinstance(body, str) else (body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body or ""))
        canonical = canonicalize_for_catch_all(text, tokens)
        shape = "text"
    return {
        "status": int(status or 0),
        "content_family": response_content_family(headers, body),
        "business_state": classifier_summary.get("business_state") or classifier_summary.get("verdict") or "",
        "canonical_hash": stable_json_hash(canonical),
        "shape_hash": stable_json_hash(shape),
    }

def catch_all_fingerprint_core(fp):
    return (
        fp.get("status"),
        fp.get("content_family"),
        fp.get("business_state"),
        fp.get("canonical_hash"),
    )

def fetch_catch_all_control(url, method, headers, data, reservation_host=""):
    if phase3_task_cancelled():
        return None, "task_pool_timeout"
    allowed, reason = acquire_catch_all_control_slot(url, reservation_host=reservation_host)
    if not allowed:
        return None, reason
    try:
        req = Request(url, data=data, headers=headers, method=method)
        resp = scoped_urlopen(req, timeout=API_TIMEOUT)
        _raw, body_bytes, body = read_http_response(resp)
        return (resp.getcode(), dict(resp.headers), body), ""
    except HTTPError as e:
        try:
            raw = read_limited(e)
            body = decode_http_body(raw, e.headers)
        except Exception:
            body = ""
        return (e.code, dict(e.headers), body), ""
    except Exception as e:
        return None, str(e)[:120]

def get_catch_all_baseline(base_url, path, method, headers, data, scope_override=None):
    scope = catch_all_scope_for_path(path) if scope_override is None else str(scope_override or "").rstrip("/")
    cache_key = (base_url.rstrip("/"), scope, str(method or "GET").upper())
    with CATCH_ALL_BUILD_LOCK:
        if cache_key in CATCH_ALL_BASELINES:
            return CATCH_ALL_BASELINES[cache_key], ""
        # Need budget for two controls plus the actual probe. Reserve the two
        # controls atomically and hold one probe slot so other workers cannot
        # consume it before this caller sends the real request.
        sample_url = urljoin(base_url, (scope.rstrip("/") or "") + "/__scanner_budget_check")
        reservation_host = reserve_catch_all_control_budget(sample_url, controls=2, retain_probe=1)
        if int(getattr(args, "max_requests_per_host", 0) or 0) > 0 and not reservation_host:
            inc_catch_all_stat("catch_all_baseline_skipped_budget")
            CATCH_ALL_BASELINES[cache_key] = None
            return None, ""
        controls = catch_all_control_paths(path, scope_override=scope)
        inc_catch_all_stat("catch_all_baseline_attempted")
        fps = []
        for control_path, nonce in controls:
            control_url = urljoin(base_url, control_path)
            result, error = fetch_catch_all_control(control_url, method, headers, data, reservation_host=reservation_host)
            if not result:
                release_catch_all_control_budget(reservation_host, controls=None, release_probe=True)
                inc_catch_all_stat("catch_all_baseline_unavailable")
                CATCH_ALL_BASELINES[cache_key] = None
                return None, ""
            status, resp_headers, body = result
            fps.append(catch_all_fingerprint(
                status,
                resp_headers,
                body,
                tokens=catch_all_request_tokens(control_url, extra_tokens=[nonce]),
            ))
        if len(fps) == 2 and catch_all_fingerprint_core(fps[0]) == catch_all_fingerprint_core(fps[1]):
            baseline = {"fingerprint": fps[0], "scope": scope}
            CATCH_ALL_BASELINES[cache_key] = baseline
            inc_catch_all_stat("catch_all_baseline_stable")
            return baseline, reservation_host
        release_catch_all_control_budget(reservation_host, controls=None, release_probe=True)
        inc_catch_all_stat("catch_all_baseline_unstable")
        CATCH_ALL_BASELINES[cache_key] = None
        return None, ""

def response_matches_catch_all(baseline, status, headers, body, request_url_or_path=""):
    if not baseline:
        return False
    fp = catch_all_fingerprint(
        status,
        headers,
        body,
        tokens=catch_all_request_tokens(request_url_or_path),
    )
    matched = catch_all_fingerprint_core(fp) == catch_all_fingerprint_core(baseline.get("fingerprint") or {})
    if matched:
        inc_catch_all_stat("catch_all_suppressed")
    return matched

def catch_all_probe_allowed(baseline, require_stable=False):
    """Guessed endpoints can require a stable fallback baseline before probing."""
    return bool(baseline) or not require_stable


def attach_finding_provenance(finding, provenance):
    if not finding or not provenance:
        return finding
    for key, value in provenance.items():
        if value not in (None, "", [], {}):
            finding[key] = value
    return finding

# ===== API 测试（双模式） =====
def test_api(
    base_url,
    path,
    bypass_tests,
    short_circuit=True,
    param_profile=None,
    allow_param_probe=True,
    require_stable_catch_all=False,
    catch_all_scope=None,
    single_variant=False,
    finding_provenance=None,
    coverage_tracker=None,
    coverage_kind="",
    opportunity_ledger=None,
    exact_dual_method=False,
):
    raw_path = str(path or "")
    path_identity = raw_path.split("?", 1)[0].split("#", 1)[0]
    validated_path = validate_root_relative_path(path_identity)
    if not validated_path:
        return []
    clean = validated_path.rstrip("/")
    if not clean and validated_path.startswith("/"):
        clean = "/"
    exact_dual_method = bool(
        exact_dual_method
        and coverage_kind == "exact"
        and getattr(args, "post_every_api", False)
    )
    try:
        url_base = urljoin(base_url, clean)
    except (TypeError, ValueError):
        return []
    base_origin = _exact_http_origin_key(base_url)
    if not base_origin or _exact_http_origin_key(url_base) != base_origin:
        return []
    bypass_tests = scheduled_bypass_tests(
        clean, bypass_tests, param_profile, exact_dual_method=exact_dual_method,
    )
    if not bypass_tests:
        return []
    findings = []
    opportunity_ledger = opportunity_ledger or ACTIVE_PHASE3_OPPORTUNITY_LEDGER
    for name, method, ct, bf, headers in bypass_tests:
        upper_method = str(method or "GET").upper()
        variants = [("", None)] if single_variant and not exact_dual_method else request_variants(
            clean, method, ct, bf, param_profile,
            allow_param_probe=allow_param_probe,
            exact_dual_method=exact_dual_method,
        )
        for qs, payload in variants:
            body_kind = ""
            if exact_dual_method and upper_method == "POST":
                body_kind = exact_post_body_kind(param_profile, clean)
            probe_mode = phase3_probe_mode(method, ct, headers, qs, payload)
            if (
                (coverage_kind != "exact" or exact_dual_method)
                and opportunity_ledger.exact_mode_attempted(base_url, clean, probe_mode)
            ):
                continue
            if phase3_task_cancelled():
                if coverage_tracker and coverage_kind == "exact" and exact_dual_method:
                    coverage_tracker.mark_method_timeout(base_url, clean, upper_method)
                    if upper_method == "GET":
                        coverage_tracker.mark_method_timeout(base_url, clean, "POST")
                return findings
            url = url_base + qs
            try:
                data = None
                if exact_dual_method and upper_method == "POST" and body_kind == "empty":
                    data = None
                elif upper_method in ("POST", "PUT", "PATCH") and bf:
                    body_payload = payload if payload is not None else {"page": "1", "size": "10"}
                    data = bf(body_payload)
                h = {"User-Agent":"Mozilla/5.0","Accept":"application/json","Accept-Encoding":http_accept_encoding()}
                h.update(headers)
                if data is not None and ct: h["Content-Type"] = ct
                catch_all_baseline, catch_all_probe_hold = get_catch_all_baseline(
                    base_url, clean, method, h, data, scope_override=catch_all_scope
                )
                if not catch_all_probe_allowed(catch_all_baseline, require_stable=require_stable_catch_all):
                    release_catch_all_control_budget(catch_all_probe_hold, controls=0, release_probe=True)
                    log.debug(f"Phase3 request skipped for {url}: stable catch-all baseline required")
                    continue
                allowed, limit_reason = acquire_phase3_request_slot(url, consume_probe_hold=bool(catch_all_probe_hold))
                if not allowed:
                    release_catch_all_control_budget(catch_all_probe_hold, controls=0, release_probe=True)
                    if limit_reason == "task_pool_timeout":
                        if coverage_tracker and coverage_kind == "exact" and exact_dual_method:
                            coverage_tracker.mark_method_timeout(base_url, clean, upper_method)
                            if upper_method == "GET":
                                coverage_tracker.mark_method_timeout(base_url, clean, "POST")
                        return findings
                    if coverage_tracker and coverage_kind == "exact" and limit_reason == "max_requests_per_host":
                        coverage_tracker.mark_budget(base_url, clean, method=upper_method)
                    log.debug(f"Phase3 request skipped for {url}: {limit_reason}")
                    continue
                if coverage_tracker and coverage_kind:
                    coverage_tracker.mark_attempted(
                        base_url, clean, coverage_kind,
                        method=upper_method, body_kind=body_kind,
                    )
                if coverage_kind == "exact":
                    opportunity_ledger.mark_exact_attempted(base_url, clean, probe_mode)
                req = Request(url, data=data, headers=h, method=method)
                resp = scoped_urlopen(req, timeout=API_TIMEOUT)
                _, body_bytes, body = read_http_response(resp)
                catch_all_match = response_matches_catch_all(
                    catch_all_baseline, resp.getcode(), resp.headers, body, request_url_or_path=url
                )
                if catch_all_match:
                    continue
                if not args.disable_file_hunter:
                    ff = check_file_response(body_bytes, resp.headers, url, method, name, resp.getcode())
                    if ff:
                        attach_finding_provenance(ff, finding_provenance)
                        save_finding_evidence(base_url, ff, url, method, h, data, resp, body_bytes)
                        findings.append(ff)
                        if short_circuit and should_short_circuit_finding(ff): return findings
                f = check_response(body, url, method, name, resp.getcode(), catch_all_match=catch_all_match)
                if f:
                    attach_finding_provenance(f, finding_provenance)
                    save_finding_evidence(base_url, f, url, method, h, data, resp, body_bytes)
                    findings.append(f)
                    if short_circuit and should_short_circuit_finding(f): return findings
            except HTTPError as e:
                if e.code not in (404,403,405):
                    try:
                        raw = read_limited(e)
                        body_bytes = _maybe_decompress_http_body(raw, e.headers)
                        b = decode_http_body(raw, e.headers)
                        catch_all_match = response_matches_catch_all(
                            catch_all_baseline, e.code, e.headers, b, request_url_or_path=url
                        )
                        if catch_all_match:
                            continue
                        if not args.disable_file_hunter:
                            ff = check_file_response(body_bytes, e.headers, url, method, name, e.code)
                            if ff:
                                attach_finding_provenance(ff, finding_provenance)
                                save_finding_evidence(base_url, ff, url, method, h, data, e, body_bytes)
                                findings.append(ff)
                                if short_circuit and should_short_circuit_finding(ff): return findings
                        f = check_response(b, url, method, name, e.code, catch_all_match=catch_all_match)
                        if f:
                            attach_finding_provenance(f, finding_provenance)
                            save_finding_evidence(base_url, f, url, method, h, data, e, body_bytes)
                            findings.append(f)
                            if short_circuit and should_short_circuit_finding(f): return findings
                    except: pass
            except Exception as e:
                log.debug(f"API {url} {method} failed: {e}")
    return findings

def normalized_endpoint(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path.rstrip('/')}"

def file_entity_key(fi):
    return "|".join([
        normalized_endpoint(fi.get("url", "")),
        str(fi.get("content_disposition", "")),
        str(fi.get("file_magic", "")),
        str(fi.get("body_size", "")),
    ])

def normalize_finding(fi):
    if fi.get("file_leak") and "public_download_intel" not in fi:
        public_download = looks_like_public_download(
            fi.get("url", ""),
            fi.get("content_disposition", ""),
            fi.get("file_magic", ""),
            fi.get("content_type", ""),
        )
        fi["public_download_intel"] = public_download
        if public_download:
            fi["risk"] = "LOW"
    if fi.get("attack_path_intel") is None and attack_surface_path(fi.get("url", "")):
        fi["attack_path_intel"] = True
    apply_finding_semantics(fi)
    return fi

def finding_key(fi):
    fi = normalize_finding(fi)
    if fi.get("file_leak"):
        return "FILE|" + file_entity_key(fi)
    return "|".join([
        normalized_endpoint(fi.get("url", "")),
        str(fi.get("risk", "")),
        str(fi.get("code", "")),
        ",".join(sorted(map(str, fi.get("data_keys", []))))[:200],
        "cred" if fi.get("credential_leak") else "",
        "intel" if fi.get("attack_path_intel") else "",
    ])

def risk_rank(risk):
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(str(risk or "").upper(), 0)

def finding_value_score(fi):
    score = risk_rank(fi.get("risk")) * 1000
    score += int(fi.get("data_count") or 0)
    score += len(fi.get("data_keys") or []) * 5
    if fi.get("credential_leak"):
        score += 500
    if fi.get("file_leak"):
        score += int(fi.get("file_score") or 0) * 20
    return score

def merge_finding_details(dst, src):
    if finding_value_score(src) > finding_value_score(dst):
        keep = {
            "tests": dst.get("tests"),
            "methods": dst.get("methods"),
            "sample_urls": dst.get("sample_urls"),
            "variant_count": dst.get("variant_count"),
            "evidence_file": dst.get("evidence_file"),
            "evidence_status": dst.get("evidence_status"),
        }
        dst.clear()
        dst.update(src)
        for key, value in keep.items():
            if value is not None:
                dst[key] = value
    tests = set(dst.get("tests") or ([dst.get("test")] if dst.get("test") else []))
    if src.get("test"):
        tests.add(src.get("test"))
    if tests:
        dst["tests"] = sorted(tests)
    methods = set(dst.get("methods") or ([dst.get("method")] if dst.get("method") else []))
    if src.get("method"):
        methods.add(src.get("method"))
    if methods:
        dst["methods"] = sorted(methods)
    urls = list(dst.get("sample_urls") or ([dst.get("url")] if dst.get("url") else []))
    if src.get("url") and src.get("url") not in urls:
        urls.append(src.get("url"))
    if urls:
        dst["sample_urls"] = urls[:8]
    dst["variant_count"] = int(dst.get("variant_count") or 1) + int(src.get("variant_count") or 1)
    if int(src.get("data_count") or 0) > int(dst.get("data_count") or 0):
        dst["data_count"] = src.get("data_count")
    if src.get("credential_leak"):
        dst["credential_leak"] = True
    if src.get("attack_path_intel"):
        dst["attack_path_intel"] = True
    if src.get("evidence_file") and (not dst.get("evidence_file") or finding_value_score(src) >= finding_value_score(dst)):
        dst["evidence_file"] = src.get("evidence_file")
        if src.get("evidence_status"):
            dst["evidence_status"] = src.get("evidence_status")
    if src.get("evidence_capture_error") and not dst.get("evidence_capture_error"):
        dst["evidence_capture_error"] = src.get("evidence_capture_error")
    dst["risk"] = risk_level(dst)
    return dst

def merge_findings(existing, new_items):
    seen = {finding_key(fi): fi for fi in existing}
    for fi in new_items or []:
        fi = normalize_finding(fi)
        key = finding_key(fi)
        if not key:
            continue
        if key not in seen:
            fi.setdefault("tests", [fi.get("test")] if fi.get("test") else [])
            fi.setdefault("methods", [fi.get("method")] if fi.get("method") else [])
            fi.setdefault("sample_urls", [fi.get("url")] if fi.get("url") else [])
            fi.setdefault("variant_count", 1)
            seen[key] = fi
            existing.append(fi)
        else:
            merge_finding_details(seen[key], fi)
    return existing

def useful_findings(findings):
    return [
        normalize_finding(f)
        for f in findings
        if is_candidate_finding(f) and (
            f.get("data_count") or f.get("data_keys") or f.get("credential_leak") or f.get("file_leak")
        )
    ]

def observation_findings(findings):
    return [
        normalize_finding(f)
        for f in findings
        if is_observation_finding(f) and (
            f.get("attack_path_intel") or f.get("public_download_intel") or f.get("file_leak")
        )
    ]

def should_short_circuit_finding(fi):
    if is_observation_finding(fi):
        return False
    return bool(
        high_value_finding(fi)
        or fi.get("credential_leak")
        or (fi.get("file_leak") and not fi.get("public_download_intel"))
    )

def high_value_finding(fi):
    if is_observation_finding(fi):
        return False
    if fi.get("public_download_intel"):
        return False
    if fi.get("credential_leak"):
        return True
    keys = " ".join(fi.get("data_keys", [])).lower()
    sensitive = " ".join(fi.get("sensitive_fields", [])).lower()
    url = fi.get("url", "").lower()
    text = keys + " " + url
    private_text = sensitive + " " + ("credential" if fi.get("credential_leak") else "")
    if any(k in keys for k in ["phone","mobile","idcard","身份证","email","address","password","secret","token","apikey","accesskey"]):
        if not any(k in private_text for k in ["phone","mobile","idcard","email","address","token","secret","credential"]):
            text = url
    return any(k in text for k in [
        "phone","mobile","idcard","身份证","email","address",
        "camera","stream","rtsp","deviceid","playurl",
        "password","secret","token","apikey","accesskey","config",
        "unit_number","unit_name","unit_type","user_name","jurisdiction",
        "inspection","alarm","alert",
    ])

def report_stats(candidate_targets, observation_targets=None, confirmed_targets=None):
    observation_targets = observation_targets or []
    confirmed_targets = confirmed_targets or []
    all_findings = [normalize_finding(fi) for v in candidate_targets for fi in v.get("findings", [])]
    all_observations = [normalize_finding(fi) for v in observation_targets for fi in v.get("observations", [])]
    confirmed_findings = [fi for v in confirmed_targets for fi in v.get("findings", []) if is_confirmed_finding(fi)]
    js_intel_count = sum(len(v.get("sensitive") or v.get("js_intel") or []) for v in candidate_targets)
    raw_events = sum(int(fi.get("variant_count") or 1) for fi in all_findings)
    aggregated_findings = len(all_findings)
    unique_endpoint_keys = {normalized_endpoint(fi.get("url", "")) for fi in all_findings}
    data_findings = [fi for fi in all_findings if fi.get("data_count") or fi.get("data_keys")]
    file_findings = [fi for fi in all_findings if fi.get("file_leak")]
    public_downloads = [fi for fi in all_observations if fi.get("public_download_intel")]
    merged_variants = max(0, raw_events - aggregated_findings)
    return {
        "raw_events": raw_events,
        "aggregated_findings": aggregated_findings,
        "raw_findings": raw_events,
        "unique_endpoints": len(unique_endpoint_keys),
        "merged_variants": merged_variants,
        "data_findings": len(data_findings),
        "unique_data_endpoints": len({normalized_endpoint(fi.get("url", "")) for fi in data_findings}),
        "file_leaks": len(file_findings),
        "public_download_intel": len(public_downloads),
        "high_value_findings": sum(1 for fi in all_findings if high_value_finding(fi)),
        "js_intel": js_intel_count,
        "confirmed_findings": len(confirmed_findings),
        "exposure_candidates": len(all_findings),
        "observations": len(all_observations),
        "catch_all_suppressed": int(CATCH_ALL_STATS.get("catch_all_suppressed") or 0),
        "catch_all": dict(CATCH_ALL_STATS),
    }


def build_unauth_matrix_preview(base, apis, param_profile=None, limit=20):
    """Build a no-network unauth/IDOR planning matrix for high-value endpoints."""
    profile = param_profile or {}
    preview = []
    for api in sorted(unique_apis(apis or []), key=api_priority)[:limit]:
        clean = api.split("?", 1)[0].rstrip("/") or api
        methods = ["GET"]
        if has_body_bound_params(profile, clean) or any(w in clean.lower() for w in ("save", "update", "create", "query", "search")):
            methods.append("POST")
        variants = []
        q_names = sorted(bound_param_names_by_source(profile, clean, "query") or bound_param_names(profile, clean))[:8]
        if q_names:
            variants.append({"style": "query", "method": "GET", "param_names": q_names})
        else:
            variants.append({"style": "query", "method": "GET", "param_names": []})
        json_names = sorted(bound_param_names_by_source(profile, clean, "json"))[:8]
        form_names = sorted(bound_param_names_by_source(profile, clean, "form"))[:8]
        if json_names:
            variants.append({"style": "json", "method": "POST", "param_names": json_names})
        if form_names:
            variants.append({"style": "form", "method": "POST", "param_names": form_names})
        preview.append({
            "path": clean,
            "priority": -api_priority(clean)[0],
            "methods": methods,
            "variants": variants,
            "active_probe": False,
            "reason": "dry_run_preview_only",
        })
    return preview


def _hash_text(value):
    return hashlib.sha256(str(value or "").encode("utf-8", "ignore")).hexdigest()[:12]

def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:12]

def categorize_api_path(path, sources=None, confidence=0.0):
    lowered = str(path or "").lower()
    sources = set(sources or [])
    if any(x in lowered for x in ("swagger", "api-docs", "openapi", "doc.html", "/docs", "knife4j")):
        return "swagger_openapi_doc"
    if is_file_endpoint(lowered) or lowered.endswith(LEGACY_ALLOWED_DOT_EXTS):
        if any(w in lowered for w in ("download", "export", "file", "attach", "upload")):
            return "file_or_action"
    basename = lowered.rsplit("/", 1)[-1]
    if "." in basename and not basename.endswith(LEGACY_ALLOWED_DOT_EXTS):
        return "dot_path_artifact"
    if "legacy_recovery" in sources or "legacy_baseline" in sources or confidence <= 0.35:
        return "low_confidence"
    if any(x in lowered for x in ("chunk", "static/js", "/assets/")):
        return "lazy_or_static"
    if api_score_value(lowered) >= 70:
        return "high_priority"
    return "other"

def _iter_inventory_records(path):
    with open(path, encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return []
    records = []
    if text[0] == "[":
        records = json.loads(text)
    else:
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return [r for r in records if isinstance(r, dict)]

def _inventory_api_map(records):
    out = {}
    for rec in records or []:
        base = str(rec.get("base") or rec.get("url") or "")
        api_conf = rec.get("api_confidence") or {}
        api_sources = rec.get("api_sources") or {}
        for api in _canonical_api_list(rec.get("apis") or []):
            clean = _canonical_api_path(api, preserve_query=False)
            if not clean:
                continue
            out.setdefault(clean, {"bases": set(), "sources": set(), "confidence": 0.0})
            out[clean]["bases"].add(base)
            try:
                out[clean]["confidence"] = max(out[clean]["confidence"], float(api_conf.get(api, api_conf.get(clean, 0.0)) or 0.0))
            except Exception:
                pass
            for src in api_sources.get(api, api_sources.get(clean, [])) or []:
                out[clean]["sources"].add(str(src))
    return out

def _category_counts(paths, meta_map):
    counts = {}
    for path in paths:
        meta = meta_map.get(path, {})
        cat = categorize_api_path(path, meta.get("sources"), meta.get("confidence", 0.0))
        counts[cat] = counts.get(cat, 0) + 1
    return dict(sorted(counts.items()))

def compare_inventory_files(current_path, old_path, include_samples=False, sample_limit=10):
    current = _inventory_api_map(_iter_inventory_records(current_path))
    old = _inventory_api_map(_iter_inventory_records(old_path))
    cur_paths, old_paths = set(current), set(old)
    common = cur_paths & old_paths
    old_only = old_paths - cur_paths
    new_only = cur_paths - old_paths
    report = {
        "ok": True,
        "safe_default": not include_samples,
        "counts": {"current": len(cur_paths), "old": len(old_paths), "common": len(common), "old_only": len(old_only), "new_only": len(new_only)},
        "old_only_categories": _category_counts(old_only, old),
        "new_only_categories": _category_counts(new_only, current),
        "coverage": {
            "current_high_priority": sum(1 for p in cur_paths if api_score_value(p) >= 70),
            "current_file": sum(1 for p in cur_paths if is_file_endpoint(p)),
            "current_swagger_doc": sum(1 for p in cur_paths if categorize_api_path(p, current.get(p, {}).get("sources"), current.get(p, {}).get("confidence", 0.0)) == "swagger_openapi_doc"),
            "current_legacy_low_confidence": sum(1 for p in cur_paths if "legacy_recovery" in current.get(p, {}).get("sources", set()) or current.get(p, {}).get("confidence", 1.0) <= 0.35),
        },
        "inputs": {"current_sha256_12": _hash_file(current_path), "old_sha256_12": _hash_file(old_path)},
    }
    if include_samples:
        report["samples"] = {
            "old_only": sorted(old_only)[:sample_limit],
            "new_only": sorted(new_only)[:sample_limit],
        }
    return report

def write_inventory_diff(current_path, old_path, output_path, include_samples=False):
    report = compare_inventory_files(current_path, old_path, include_samples=include_samples)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return report

def _validate_safety_args():
    # Coerce to conservative caps; never loosen user-supplied safer values.
    args.redact_raw_findings = True
    if not args.max_rps_per_host or args.max_rps_per_host > 0.5:
        args.max_rps_per_host = 0.5
    if not args.min_delay_ms or args.min_delay_ms < 2000:
        args.min_delay_ms = 2000
    if not args.max_requests_per_host or args.max_requests_per_host > 40:
        args.max_requests_per_host = 40
    if not PHASE12_WORKERS or PHASE12_WORKERS > 4:
        globals()["PHASE12_WORKERS"] = 2
    if args.workers > 4:
        args.workers = 4
        globals()["WORKERS"] = 4

def build_validate_plan_from_report(report_path, max_items=40):
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    tasks = []
    for host in report.get("findings") or []:
        base = host.get("url") or host.get("base") or ""
        for fi in host.get("findings") or []:
            urls = list(fi.get("sample_urls") or [])
            if fi.get("url"):
                urls.insert(0, fi.get("url"))
            if not urls:
                continue
            for u in urls[:3]:
                p = urlparse(u)
                if not p.scheme or not p.netloc:
                    continue
                tasks.append({"base": f"{p.scheme}://{p.netloc}", "path": (p.path or "/") + (("?" + p.query) if p.query else ""), "source_risk": fi.get("risk", ""), "attack_path_intel": bool(fi.get("attack_path_intel"))})
                break
        if len(tasks) >= max_items:
            break
    seen, out = set(), []
    for task in tasks:
        key = (task["base"], task["path"])
        if key not in seen:
            seen.add(key); out.append(task)
    return out[:max_items]

def run_validate_from_report(report_path, outdir, plan_only=False):
    _validate_safety_args()
    plan = build_validate_plan_from_report(report_path)
    os.makedirs(outdir, exist_ok=True)
    plan_path = os.path.join(outdir, "validate_plan.json")
    safe_plan = [{"target_hash": _hash_text(item["base"]), "path_hash": _hash_text(item["path"]), "category": categorize_api_path(item["path"]), "source_risk": item.get("source_risk", "")} for item in plan]
    with open(plan_path, "w", encoding="utf-8") as f:
        json.dump({"ok": True, "plan_only": bool(plan_only), "task_count": len(plan), "tasks": safe_plan}, f, ensure_ascii=False, indent=2)
    if plan_only:
        return {"ok": True, "plan_only": True, "task_count": len(plan), "plan_path": plan_path}
    results = []
    for item in plan:
        findings = test_api(item["base"], item["path"], FAST_BYPASS, short_circuit=True, param_profile=empty_param_profile(), allow_param_probe=False)
        safe_findings = []
        for fi in maybe_redact_raw_findings(useful_findings(findings)):
            safe_findings.append({
                "risk": fi.get("risk", ""),
                "method": fi.get("method", ""),
                "test": fi.get("test", ""),
                "data_count": fi.get("data_count", 0),
                "data_keys": fi.get("data_keys", []),
                "classifier_verdict": fi.get("classifier_verdict", ""),
                "sensitive_fields": fi.get("sensitive_fields", []),
                "attack_path_intel": bool(fi.get("attack_path_intel")),
                "file_leak": bool(fi.get("file_leak")),
            })
        results.append({"target_hash": _hash_text(item["base"]), "path_hash": _hash_text(item["path"]), "finding_count": len(findings), "findings": safe_findings})
    summary = {"ok": True, "plan_only": False, "task_count": len(plan), "results": results, "safety": {"redact_raw_findings": True, "max_rps_per_host": args.max_rps_per_host, "min_delay_ms": args.min_delay_ms, "max_requests_per_host": args.max_requests_per_host, "workers": WORKERS, "phase12_workers": PHASE12_WORKERS}}
    out_path = os.path.join(outdir, "validate_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)
    summary["report_path"] = out_path
    summary["plan_path"] = plan_path
    return summary

def target_filename(base):
    return re.sub(r'[^a-zA-Z0-9]', '_', base) + ".json"

def _set_like_values(value):
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set()
    try:
        return set(value)
    except (TypeError, ValueError):
        return set()


def _profile_string_set(value, lower=False, predicate=None, limit=4096):
    raw = _set_like_values(value)
    if any(not isinstance(item, str) for item in raw):
        return set()
    out = set()
    for item in raw:
        text = item.lower() if lower else item
        if not text or len(text) > 500 or any(ord(ch) < 32 for ch in text):
            continue
        if predicate is None or predicate(text):
            out.add(text)
    if limit <= 0:
        return set()
    return set(sorted(out)[:limit])


def _canonical_param_profile(profile):
    out = empty_param_profile()
    if not isinstance(profile, dict):
        return out
    out["names"] = {
        name for name in (normalize_param_name(value) for value in _profile_string_set(profile.get("names"))) if name
    }
    out["seeds"] = _profile_string_set(profile.get("seeds"))
    out["file_seeds"] = _profile_string_set(profile.get("file_seeds"))

    api_params = profile.get("api_params")
    if isinstance(api_params, dict):
        for path, names in api_params.items():
            clean = _clean_profile_api_path(path) if isinstance(path, str) else ""
            values = {name for name in (normalize_param_name(v) for v in _profile_string_set(names)) if name}
            if clean and values:
                out["api_params"][clean] = values

    api_sources = profile.get("api_param_sources")
    if isinstance(api_sources, dict):
        for path, sources in api_sources.items():
            clean = _clean_profile_api_path(path) if isinstance(path, str) else ""
            if not clean or not isinstance(sources, dict):
                continue
            for source, names in sources.items():
                if source not in ("query", "json", "form", "path", "header"):
                    continue
                values = {name for name in (normalize_param_name(v) for v in _profile_string_set(names)) if name}
                if values:
                    out["api_param_sources"].setdefault(clean, {})[source] = values

    api_shapes = profile.get("api_param_shapes")
    if isinstance(api_shapes, dict):
        for path, sources in api_shapes.items():
            clean = _clean_profile_api_path(path) if isinstance(path, str) else ""
            if not clean or not isinstance(sources, dict):
                continue
            for source, parents in sources.items():
                if source not in ("json", "form") or not isinstance(parents, dict):
                    continue
                for parent, names in parents.items():
                    parent_name = normalize_param_name(parent) if isinstance(parent, str) else ""
                    values = {name for name in (normalize_param_name(v) for v in _profile_string_set(names)) if name}
                    if parent_name and values:
                        out["api_param_shapes"].setdefault(clean, {}).setdefault(source, {})[parent_name] = values

    api_methods = profile.get("api_methods")
    if isinstance(api_methods, dict):
        for path, methods in api_methods.items():
            clean = _clean_profile_api_path(path) if isinstance(path, str) else ""
            values = _profile_string_set(methods, lower=True, predicate=lambda value: value in HTTP_METHODS)
            if clean and values:
                out["api_methods"][clean] = values

    api_specs = profile.get("api_param_specs")
    if isinstance(api_specs, dict):
        for path, sources in api_specs.items():
            clean = _clean_profile_api_path(path) if isinstance(path, str) else ""
            if not clean or not isinstance(sources, dict):
                continue
            for source, specs in sources.items():
                if source not in ("query", "json", "form", "path", "header") or not isinstance(specs, dict):
                    continue
                for name, spec in specs.items():
                    if not isinstance(name, str):
                        continue
                    safe = _safe_param_spec(spec, source=source)
                    if safe:
                        out["api_param_specs"].setdefault(clean, {}).setdefault(source, {})[name] = safe

    api_types = profile.get("api_content_types")
    if isinstance(api_types, dict):
        for path, values in api_types.items():
            clean = _clean_profile_api_path(path) if isinstance(path, str) else ""
            safe = _profile_string_set(values, lower=True, predicate=lambda value: len(value) <= 120)
            if clean and safe:
                out["api_content_types"][clean] = safe

    api_templates = profile.get("api_path_templates")
    if isinstance(api_templates, dict):
        for path, values in api_templates.items():
            clean = _clean_profile_api_path(path) if isinstance(path, str) else ""
            safe = {
                validated for validated in (
                    _validated_profile_api_path(value)
                    for value in _profile_string_set(values)
                ) if validated
            }
            if clean and safe:
                out["api_path_templates"][clean] = safe

    out["_apis_from_params"] = {
        clean for clean in (
            _validated_profile_api_path(value)
            for value in _profile_string_set(
                profile.get("apis_from_params", profile.get("_apis_from_params"))
            )
        ) if clean
    }
    out["api_param_blocked"] = {
        clean for clean in (
            _validated_profile_api_path(value)
            for value in _profile_string_set(profile.get("api_param_blocked"))
        ) if clean
    }
    return out


def _profile_wire_shape_valid(profile):
    if not isinstance(profile, dict):
        return False
    def string_list(value):
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    for key in (
        "names", "seeds", "file_seeds", "apis_from_params", "_apis_from_params",
        "api_param_blocked",
    ):
        if key in profile and not string_list(profile.get(key)):
            return False
    simple_maps = ("api_params", "api_methods", "api_content_types", "api_path_templates")
    for key in simple_maps:
        value = profile.get(key, {})
        if not isinstance(value, dict) or any(not isinstance(path, str) or not string_list(items) for path, items in value.items()):
            return False
    nested_maps = ("api_param_sources",)
    for key in nested_maps:
        value = profile.get(key, {})
        if not isinstance(value, dict):
            return False
        for path, sources in value.items():
            if not isinstance(path, str) or not isinstance(sources, dict) or any(
                not isinstance(source, str) or not string_list(items) for source, items in sources.items()
            ):
                return False
    shapes = profile.get("api_param_shapes", {})
    if not isinstance(shapes, dict):
        return False
    for path, sources in shapes.items():
        if not isinstance(path, str) or not isinstance(sources, dict):
            return False
        for source, parents in sources.items():
            if not isinstance(source, str) or not isinstance(parents, dict) or any(
                not isinstance(parent, str) or not string_list(items) for parent, items in parents.items()
            ):
                return False
    specs = profile.get("api_param_specs", {})
    if not isinstance(specs, dict):
        return False
    for path, sources in specs.items():
        if not isinstance(path, str) or not isinstance(sources, dict):
            return False
        for source, items in sources.items():
            if not isinstance(source, str) or not isinstance(items, dict) or any(
                not isinstance(name, str) or not isinstance(spec, dict) for name, spec in items.items()
            ):
                return False
    return True


def serialize_param_profile(profile):
    profile = _canonical_param_profile(profile)
    return {
        "names": sorted(profile.get("names", set())),
        "seeds": sorted(profile.get("seeds", set())),
        "file_seeds": sorted(profile.get("file_seeds", set())),
        "api_params": {path: sorted(names) for path, names in sorted(profile.get("api_params", {}).items())},
        "api_param_sources": {
            path: {source: sorted(names) for source, names in sorted(sources.items())}
            for path, sources in sorted(profile.get("api_param_sources", {}).items())
        },
        "api_param_shapes": {
            path: {
                source: {parent: sorted(names) for parent, names in sorted(parents.items())}
                for source, parents in sorted(sources.items())
            }
            for path, sources in sorted(profile.get("api_param_shapes", {}).items())
        },
        "api_methods": {
            path: sorted(methods)
            for path, methods in sorted(profile.get("api_methods", {}).items())
        },
        "api_param_specs": {
            path: {
                source: {
                    name: _safe_param_spec(spec, source=source)
                    for name, spec in sorted((specs or {}).items())
                    if _safe_param_spec(spec, source=source)
                }
                for source, specs in sorted((sources or {}).items())
            }
            for path, sources in sorted(profile.get("api_param_specs", {}).items())
        },
        "api_content_types": {
            path: sorted(str(value) for value in (content_types or []) if str(value).strip())
            for path, content_types in sorted(profile.get("api_content_types", {}).items())
        },
        "api_path_templates": {
            path: sorted(str(value) for value in (templates or []) if str(value).startswith("/"))
            for path, templates in sorted(profile.get("api_path_templates", {}).items())
        },
        "apis_from_params": sorted(profile.get("_apis_from_params", set())),
        "api_param_blocked": sorted(profile.get("api_param_blocked", set())),
    }

def deserialize_param_profile(profile):
    return _canonical_param_profile(profile)

def _safe_api_meta_record(meta, allowed_paths=None):
    safe_meta = {}
    allowed = set(allowed_paths) if allowed_paths is not None else None
    if not isinstance(meta, dict):
        for api in sorted(allowed or ()):
            safe_meta[api] = _inert_api_meta_item()
        return safe_meta
    for api in sorted(key for key in meta if isinstance(key, str)):
        clean = _canonical_api_path(api, preserve_query=False)
        if not clean or (allowed is not None and clean not in allowed):
            continue
        safe_item = _canonical_api_meta_item(meta.get(api))
        if safe_item and safe_item.get("sources"):
            existing = [safe_meta[clean]] if clean in safe_meta else []
            safe_meta[clean] = _merge_api_meta_items(existing + [safe_item])
    return safe_meta


def _inert_api_meta_item():
    return {"confidence": API_CONFIDENCE_TIERS["prefix_inventory"], "sources": ["prefix_inventory"]}


def _canonical_api_meta_item(item):
    if not isinstance(item, dict):
        return _inert_api_meta_item()
    confidence = item.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        confidence = 0.0
    else:
        try:
            if confidence < 0 or confidence > 1:
                confidence = 0.0
            else:
                confidence = float(confidence)
                if not math.isfinite(confidence):
                    confidence = 0.0
        except (OverflowError, TypeError, ValueError):
            confidence = 0.0
    confidence = round(confidence, 6)
    raw_sources = item.get("sources")
    source_collection_valid = isinstance(raw_sources, (list, set, frozenset)) and bool(raw_sources) and all(
        isinstance(source, str) and source and len(source) <= 80 for source in raw_sources
    )
    sources = _normalize_api_meta_sources(raw_sources)
    if not source_collection_valid or not sources:
        return _inert_api_meta_item()
    exact_sources = set(sources) & API_META_EXACT_SOURCES
    if exact_sources:
        sources = [source for source in sources if source != "prefix_inventory"]
    elif "prefix_inventory" in sources:
        sources = ["prefix_inventory"]
        confidence = min(confidence, API_CONFIDENCE_TIERS["prefix_inventory"])
    return {
        "confidence": confidence,
        "sources": sources,
    }


def _merge_api_meta_items(items):
    confidence = 0.0
    sources = set()
    valid = False
    for raw in items or []:
        item = _canonical_api_meta_item(raw)
        if not item:
            continue
        valid = True
        confidence = max(confidence, item["confidence"])
        sources.update(item["sources"])
    if not valid:
        return {}
    if sources & API_META_EXACT_SOURCES:
        sources.discard("prefix_inventory")
    elif "prefix_inventory" in sources:
        sources = {"prefix_inventory"}
        confidence = min(confidence, API_CONFIDENCE_TIERS["prefix_inventory"])
    return {"confidence": round(confidence, 6), "sources": sorted(sources)}


def serialize_scan_record(record):
    if not isinstance(record, dict):
        raise ValueError("scan record root must be an object")
    out = dict(record or {})
    out.pop("_api_meta_index", None)
    out.pop("_replay_param_profile_index", None)
    apis = _canonical_api_list(out.get("apis") or [])
    out["apis"] = apis
    replay_apis = _canonical_api_list(out.get("replay_apis") or [])
    if "replay_apis" in out:
        out["replay_apis"] = replay_apis
    replay_promoted_apis = _canonical_api_list(out.get("replay_promoted_apis") or [])
    if "replay_promoted_apis" in out:
        out["replay_promoted_apis"] = replay_promoted_apis
    if "prefix_inventory_paths" in out:
        out["prefix_inventory_paths"] = [
            path for path in _canonical_api_list(out.get("prefix_inventory_paths") or []) if path in set(apis)
        ]
    allowed_paths = set(apis) | set(replay_apis) | set(replay_promoted_apis)
    if "param_profile" in out:
        out["param_profile"] = serialize_param_profile(out.get("param_profile"))
    if "sensitive" in out:
        out["sensitive"] = sorted(out.get("sensitive") or [])
    if "js_intel" in out:
        out["js_intel"] = sorted(out.get("js_intel") or [])
    if "api_meta" in out:
        out["api_meta"] = _safe_api_meta_record(out.get("api_meta"), allowed_paths)
    if "api_coverage" in out:
        out["api_coverage"] = canonical_api_coverage(out.get("api_coverage"))
    return canonicalize_top_level_coverage_counts(out)

def deserialize_scan_record(record):
    if not isinstance(record, dict):
        raise ValueError("scan record root must be an object")
    out = dict(record or {})
    out.pop("_api_meta_index", None)
    out.pop("_replay_param_profile_index", None)
    if "param_profile" in out:
        if not _profile_wire_shape_valid(out.get("param_profile")):
            raise ValueError("scan record param_profile has invalid shape")
        out["param_profile"] = deserialize_param_profile(out.get("param_profile"))
    if "base" in out and not isinstance(out.get("base"), str):
        raise ValueError("scan record base must be a string")
    if "apis" in out and (
        not isinstance(out.get("apis"), list)
        or any(not isinstance(api, str) for api in out.get("apis"))
    ):
        raise ValueError("scan record apis must be a string list")
    out["apis"] = _canonical_api_list(out.get("apis") or [])
    replay_apis = _canonical_api_list(out.get("replay_apis") or [])
    if "replay_apis" in out:
        out["replay_apis"] = replay_apis
    replay_promoted_apis = _canonical_api_list(out.get("replay_promoted_apis") or [])
    if "replay_promoted_apis" in out:
        out["replay_promoted_apis"] = replay_promoted_apis
    if "prefix_inventory_paths" in out:
        out["prefix_inventory_paths"] = [
            path for path in _canonical_api_list(out.get("prefix_inventory_paths") or []) if path in set(out["apis"])
        ]
    allowed_paths = set(out["apis"]) | set(replay_apis) | set(replay_promoted_apis)
    if "api_meta" in out:
        out["api_meta"] = _safe_api_meta_record(out.get("api_meta"), allowed_paths)
    if "api_coverage" in out:
        out["api_coverage"] = canonical_api_coverage(out.get("api_coverage"))
    return canonicalize_top_level_coverage_counts(out)

def _phase2_inventory_record_scoped(t, api_limit=None, param_name_limit=None, seed_limit=None, file_seed_limit=None, include_param_profile=True):
    profile = serialize_param_profile(t.get("param_profile"))
    names = profile.get("names", [])
    seeds = profile.get("seeds", [])
    file_seeds = profile.get("file_seeds", [])
    apis = _canonical_api_list(t.get("apis") or [])
    visible_apis = apis if api_limit is None else apis[:api_limit]
    record = {
        "base": t["base"],
        "title": t.get("title", ""),
        "api_count": len(apis),
        "apis": visible_apis,
        "api_confidence": {
            api: round(api_confidence_for(t, api), 2)
            for api in visible_apis
        },
        "api_sources": {
            api: _api_meta_sources_for_seed(t, api)
            for api in visible_apis
        },
        "js_discovered": t.get("js_discovered", t.get("js_count", 0)),
        "js_app_candidates": t.get("js_app_candidates", t.get("js_count", 0)),
        "js_attempted": t.get("js_attempted", t.get("js_count", 0)),
        "js_count": t.get("js_count", 0),
        "js_graph_edges": t.get("js_graph_edges", 0),
        "lazy_chunks_discovered": t.get("lazy_chunks_discovered", 0),
        "lazy_chunks_attempted": t.get("lazy_chunks_attempted", 0),
        "lazy_chunks_downloaded": t.get("lazy_chunks_downloaded", 0),
        "js_intel": sorted(t.get("sensitive") or t.get("js_intel") or []),
        "fallback": t.get("fallback", ""),
        "openapi_external_server_count": len(t.get("openapi_external_servers") or []),
        "openapi_external_servers": list(t.get("openapi_external_servers") or []),
        "openapi_unresolved_ref_count": len(t.get("openapi_unresolved_refs") or []),
        "openapi_unresolved_refs": list(t.get("openapi_unresolved_refs") or []),
        "openapi_path_template_count": len(t.get("openapi_path_templates") or []),
        "openapi_path_templates": list(t.get("openapi_path_templates") or []),
        "config_service_base_count": len(t.get("config_service_bases") or []),
        "config_service_bases": list(t.get("config_service_bases") or []),
        "config_service_synthetic": bool(t.get("config_service_synthetic")),
        "config_rest_candidate_count": len(t.get("config_rest_candidates") or []),
        "config_rest_candidates": list(t.get("config_rest_candidates") or []),
        "js_advanced_stats": dict(t.get("js_advanced_stats") or {}),
        "js_resource_inventory_count": len(t.get("js_resource_inventory") or []),
        "js_resource_inventory": list(t.get("js_resource_inventory") or []),
        "import_map_count": len(t.get("import_map_inventory") or []),
        "import_map_inventory": list(t.get("import_map_inventory") or []),
        "asset_manifest_count": len(t.get("asset_manifest_inventory") or []),
        "asset_manifest_inventory": list(t.get("asset_manifest_inventory") or []),
        "source_map_count": len(t.get("source_map_inventory") or []),
        "source_map_inventory": list(t.get("source_map_inventory") or []),
        "replay_api_count": len(_canonical_api_list(t.get("replay_apis") or [])),
        "replay_apis": _canonical_api_list(t.get("replay_apis") or []),
        "replay_promoted_api_count": len(_canonical_api_list(t.get("replay_promoted_apis") or [])),
        "replay_promoted_apis": _canonical_api_list(t.get("replay_promoted_apis") or []),
        "param_name_count": len(names),
        "param_names": names if param_name_limit is None else names[:param_name_limit],
        "seed_value_count": len(seeds),
        "seed_values": seeds if seed_limit is None else seeds[:seed_limit],
        "file_seed_count": len(file_seeds),
        "file_seed_values": file_seeds if file_seed_limit is None else file_seeds[:file_seed_limit],
    }
    if getattr(args, "unauth_matrix", False):
        record["unauth_matrix_preview"] = build_unauth_matrix_preview(t.get("base", ""), apis, t.get("param_profile"), limit=20)
    if include_param_profile:
        record["param_profile"] = profile
    return record


def phase2_inventory_record(target, api_limit=None, param_name_limit=None, seed_limit=None, file_seed_limit=None, include_param_profile=True):
    with api_meta_index_scope([target]):
        return _phase2_inventory_record_scoped(
            target,
            api_limit=api_limit,
            param_name_limit=param_name_limit,
            seed_limit=seed_limit,
            file_seed_limit=file_seed_limit,
            include_param_profile=include_param_profile,
        )


def _sanitize_persisted_finding_url(value):
    text = str(value or "")
    if not text:
        return text
    try:
        parsed = urlsplit(text)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    except (TypeError, ValueError):
        return text.split("?", 1)[0].split("#", 1)[0]


def redact_raw_finding_fields(obj):
    """Copy findings without raw payload fields or query-bearing URLs."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            lowered = str(key).lower()
            if lowered in RAW_FIELD_KEYS:
                continue
            if lowered in ("url", "evidence_url") and isinstance(value, str):
                out[key] = _sanitize_persisted_finding_url(value)
            elif lowered == "sample_urls" and isinstance(value, (list, tuple)):
                out[key] = [
                    _sanitize_persisted_finding_url(item) if isinstance(item, str)
                    else redact_raw_finding_fields(item)
                    for item in value
                ]
            else:
                out[key] = redact_raw_finding_fields(value)
        return out
    if isinstance(obj, list):
        return [redact_raw_finding_fields(item) for item in obj]
    return obj

def maybe_redact_raw_findings(obj):
    if getattr(args, "redact_raw_findings", False):
        return redact_raw_finding_fields(obj)
    return obj

def write_phase2_inventory(t):
    with open(os.path.join(OUTDIR, PHASE2_INVENTORY_NAME), "a") as f:
        json.dump(phase2_inventory_record(t), f, ensure_ascii=False)
        f.write("\n")

def write_target_result(t):
    findings = t.get("findings", [])
    if not findings:
        return
    t["finding_count"] = len(findings)
    t["raw_event_count"] = sum(int(fi.get("variant_count") or 1) for fi in findings)
    if t.get("sensitive") and not t.get("js_intel"):
        t["js_intel"] = sorted(t.get("sensitive", []))
    out = serialize_scan_record({
        k: v for k, v in t.items() if k not in ("_f", "_f3a_real", "_deep", "_seen_tasks")
    })
    out = maybe_redact_raw_findings(out)
    with open(os.path.join(OUTDIR, target_filename(t["base"])), "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2, default=str)

def load_checkpoint_results():
    items = []
    for name in os.listdir(OUTDIR):
        if not name.endswith(".json") or name in ("report.json", "apis.json"):
            continue
        path = os.path.join(OUTDIR, name)
        try:
            with open(path) as f:
                item = json.load(f)
            if item.get("base") and item.get("findings"):
                item = maybe_redact_raw_findings(item)
                item["finding_count"] = len(item.get("findings", []))
                item["raw_event_count"] = sum(int(fi.get("variant_count") or 1) for fi in item.get("findings", []))
                items.append(item)
        except Exception as e:
            log.debug(f"Load checkpoint {path} failed: {e}")
    return items


def _phase25_sparse_api_fuzz(phase2_path, api_results, wordlist, outdir, inventory_name):
    """Phase 2.5: Inject wordlist APIs into targets where JS extraction found nothing.

    A target is "sparse" when js_count==0 AND no API came from a non-baseline
    source (js/html/swagger/vue_router/react_route).  The wordlist APIs are
    added with source ``api_fuzz`` (confidence 0.45) so they participate in
    Phase 3 probing but don't override higher-confidence discoveries.

    Returns the path to the augmented JSONL file.
    """
    if not wordlist:
        return phase2_path

    # Collect sparse bases
    sparse_bases: set[str] = set()
    for t in api_results:
        js_count = int(t.get("js_count") or 0)
        api_meta = t.get("api_meta") or {}
        max_source_conf = 0
        for meta in api_meta.values():
            src_list = (meta or {}).get("sources") or []
            for src in (src_list if isinstance(src_list, list) else [src_list]):
                conf = _API_SOURCE_ORDER.get(str(src), 0)
                if conf > max_source_conf:
                    max_source_conf = conf
        if js_count == 0 and max_source_conf <= 4:  # only baseline (2) or backend_baseline (4)
            sparse_bases.add(t.get("base", ""))

    if not sparse_bases:
        return phase2_path

    augmented = phase2_path + ".fuzz"
    writer = _JsonlWriter(augmented)
    injected = 0

    for t in api_results:
        base = t.get("base", "")
        if base in sparse_bases:
            existing_apis = set(_canonical_api_list(t.get("apis") or []))
            new_apis = []
            for wl_api in _canonical_api_list(wordlist):
                if wl_api not in existing_apis:
                    new_apis.append(wl_api)
                    existing_apis.add(wl_api)
            if new_apis:
                apis = _canonical_api_list(list(t.get("apis") or []) + new_apis)
                t = dict(t)
                t["apis"] = apis
                t["api_meta"] = dict(t.get("api_meta") or {})
                for api in new_apis:
                    add_api_meta(t["api_meta"], api, "api_fuzz", 0.45)
                _invalidate_api_meta_index(t)
                injected += len(new_apis)
        writer.write(t)

    if injected:
        print(f"  Phase 2.5: injected {injected} APIs into {len(sparse_bases)} sparse bases (js=0, no custom APIs)")
        # Rewrite inventory from the augmented authoritative stream.  Older
        # code only bumped api_count, leaving sampled apis/api_sources/
        # api_confidence stale.  If an existing inventory record was bounded
        # (api_count > len(apis)), preserve that sample size while regenerating
        # the sample and metadata from the augmented record.
        inv_path = os.path.join(outdir, inventory_name)
        if os.path.exists(inv_path):
            sample_limits = {}
            with open(inv_path, "r", encoding="utf-8") as fin:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    b = rec.get("base", "")
                    sampled = rec.get("apis") if isinstance(rec.get("apis"), list) else []
                    try:
                        api_count = int(rec.get("api_count") or 0)
                    except (TypeError, ValueError):
                        api_count = 0
                    if sampled and api_count > len(sampled):
                        sample_limits[b] = len(sampled)
            inv_fuzz = inv_path + ".fuzz"
            with open(inv_fuzz, "w", encoding="utf-8") as fout:
                for rec in StreamedResultSet(augmented, writer.count):
                    limit = sample_limits.get(rec.get("base", ""))
                    fout.write(json.dumps(phase2_inventory_record(rec, api_limit=limit), ensure_ascii=False) + "\n")
            os.replace(inv_fuzz, inv_path)
        return augmented
    return phase2_path


def baseline_api_result(url, fallback="phase2_timeout"):
    base = origin_from_url(url)
    page_url = url
    prefixes = path_prefixes_from_url(page_url)
    apis = set(BASELINE_PATHS)
    api_meta = {}
    for api in apis:
        add_api_meta(api_meta, api, "baseline")
    apis = add_configured_backend_paths(apis, api_meta)
    apis, prefix_inventory_paths = apply_prefix_inventory(apis, api_meta, prefixes)
    return {"base":base,"title":"","apis":sorted(apis, key=lambda api: api_test_order({"api_meta": api_meta}, api)),"api_meta":api_meta,"prefix_inventory_paths":prefix_inventory_paths,"sensitive":[],"js_count":0,"param_profile":empty_param_profile(),"fallback":fallback,"config_service_bases":[]}

def add_task(tasks, seen, t, api, layer):
    key = (t["base"], api, layer)
    if key in seen:
        return
    seen.add(key)
    tasks.append((t, api, layer))

def finding_endpoint_paths(findings, high_value_only=False):
    paths = set()
    for fi in findings or []:
        if high_value_only and not high_value_finding(fi):
            continue
        url = fi.get("url", "")
        if not url:
            continue
        path = urlparse(url).path.rstrip("/")
        if path:
            paths.add(path)
    return paths

def run_task_pool(tasks, worker_count, timeout, label, fn, on_result, progress_every=500, on_timeout=None):
    if not tasks:
        return TaskPoolStats(0, 0, 0, 0)
    cancel_event = Event()
    pool = ThreadPoolExecutor(max_workers=worker_count)
    completed = 0
    futures = {}
    processed = set()
    deadline_pending = set()
    started = time.time()

    def invoke(task):
        PHASE3_TASK_CONTEXT.cancel_event = cancel_event
        PHASE3_TASK_CONTEXT.request_attempted = False
        invocation_started = False
        try:
            if cancel_event.is_set():
                return _TaskInvocationResult(None, None, False, False, True)
            invocation_started = True
            try:
                value = fn(task)
                error = None
            except Exception as exc:
                value = None
                error = exc
            return _TaskInvocationResult(
                value, error,
                bool(getattr(PHASE3_TASK_CONTEXT, "request_attempted", False)),
                invocation_started,
                False,
            )
        finally:
            for field in ("cancel_event", "request_attempted"):
                try:
                    delattr(PHASE3_TASK_CONTEXT, field)
                except AttributeError:
                    pass

    def consume(future):
        nonlocal completed
        if future.cancelled():
            return "skipped"
        try:
            result = future.result()
            if result.cancelled_before_invocation or not result.invocation_started:
                return "skipped"
            if result.error is not None:
                raise result.error
            on_result(result.value)
            completed += 1
            if progress_every and completed % progress_every == 0:
                print(f"    [{completed}/{len(tasks)}] {label}")
            return "completed"
        except Exception as e:
            completed += 1
            log.debug(f"{label} failed: {e}")
            return "completed"

    try:
        futures = {pool.submit(invoke, task): task for task in tasks}
        pending = set(futures)
        while pending:
            remaining = max(0, timeout - (time.time() - started)) if timeout else None
            if timeout and remaining <= 0:
                deadline_pending = set(pending)
                break
            wait_time = 5 if remaining is None else min(5, remaining)
            done_set, pending = wait(pending, timeout=wait_time)
            if not done_set:
                continue
            for f in done_set:
                consume(f)
                processed.add(f)
        if deadline_pending:
            print(f"  {label} soft-timeout: {len(deadline_pending)} tasks draining")
            cancel_event.set()
            for f in deadline_pending:
                f.cancel()
    finally:
        # Python cannot interrupt an HTTP operation already inside urlopen.
        # The cancellation event prevents every subsequent control/probe slot;
        # wait=True guarantees no worker can mutate state after this returns.
        pool.shutdown(wait=True, cancel_futures=True)

    skipped_timeout_futures = []
    for f in futures:
        if f in processed:
            continue
        if consume(f) == "skipped":
            skipped_timeout_futures.append(f)
    if skipped_timeout_futures and on_timeout:
        for f in skipped_timeout_futures:
            try:
                on_timeout(futures[f])
            except Exception as e:
                log.debug(f"{label} timeout accounting failed: {e}")
    return TaskPoolStats(
        len(tasks), completed, len(skipped_timeout_futures), len(deadline_pending)
    )

def _clean_api_path(path):
    return _canonical_api_path(path, preserve_query=False)

def _profile_path_values(mapping, api):
    if not isinstance(mapping, dict):
        return
    clean = _validated_profile_api_path(api)
    if clean and clean in mapping:
        yield mapping.get(clean)


def _ensure_set_field(container, key):
    if not isinstance(container, dict):
        return set()
    values = _set_like_values(container.get(key))
    container[key] = values
    return values


def _ensure_mapping_field(container, key):
    if not isinstance(container, dict):
        return {}
    value = container.get(key)
    if not isinstance(value, dict):
        value = {}
        container[key] = value
    return value


def _replay_param_profile_index(target):
    """Build a validated replay snapshot for one top-level replay operation."""
    global REPLAY_PROFILE_INDEX_BUILD_COUNT
    if not isinstance(target, dict):
        return {"profile": empty_param_profile(), "blocked": frozenset()}
    canonical = _canonical_param_profile(target.get("param_profile"))
    index = {
        "profile": canonical,
        "blocked": frozenset(canonical.get("api_param_blocked") or ()),
    }
    REPLAY_PROFILE_INDEX_BUILD_COUNT += 1
    return index


def carry_replay_param_profile(dst_target, src_target, api, src_index=None):
    """Copy only the replayed API's parameter/method profile to a sibling base."""
    if is_initial_screen_only_api(src_target, api):
        return False
    src_index = src_index or _replay_param_profile_index(src_target)
    src = src_index.get("profile") or {}
    if not isinstance(src, dict) or not src:
        return False
    dst = dst_target.get("param_profile")
    if not isinstance(dst, dict):
        dst = empty_param_profile()
        dst_target["param_profile"] = dst
    clean = _validated_profile_api_path(api)
    if not clean:
        return False
    copied = False

    dst_api_params = _ensure_mapping_field(dst, "api_params")
    had_destination_params = bool(_set_like_values(dst_api_params.get(clean)))
    for names in _profile_path_values(src.get("api_params"), clean):
        names = _set_like_values(names)
        if names:
            _ensure_set_field(dst_api_params, clean).update(names)
            copied = True

    dst_param_sources = _ensure_mapping_field(dst, "api_param_sources")
    for sources in _profile_path_values(src.get("api_param_sources"), clean):
        if not isinstance(sources, dict):
            continue
        dst_sources = _ensure_mapping_field(dst_param_sources, clean)
        for source, names in sources.items():
            names = _set_like_values(names)
            if names:
                _ensure_set_field(dst_sources, source).update(names)
                copied = True

    dst_param_shapes = _ensure_mapping_field(dst, "api_param_shapes")
    for shapes in _profile_path_values(src.get("api_param_shapes"), clean):
        if not isinstance(shapes, dict):
            continue
        dst_shapes = _ensure_mapping_field(dst_param_shapes, clean)
        for source, parents in shapes.items():
            if not isinstance(parents, dict):
                continue
            dst_source = _ensure_mapping_field(dst_shapes, source)
            for parent, names in parents.items():
                names = _set_like_values(names)
                if names:
                    _ensure_set_field(dst_source, parent).update(names)
                    copied = True

    dst_methods = _ensure_mapping_field(dst, "api_methods")
    for methods in _profile_path_values(src.get("api_methods"), clean):
        methods = {str(m).lower() for m in _set_like_values(methods) if str(m).lower() in HTTP_METHODS}
        if methods:
            _ensure_set_field(dst_methods, clean).update(methods)
            copied = True

    dst_param_specs = _ensure_mapping_field(dst, "api_param_specs")
    for specs in _profile_path_values(src.get("api_param_specs"), clean):
        if not isinstance(specs, dict):
            continue
        dst_specs_by_source = _ensure_mapping_field(dst_param_specs, clean)
        for source, source_specs in specs.items():
            if not isinstance(source_specs, dict):
                continue
            dst_specs = _ensure_mapping_field(dst_specs_by_source, source)
            for name, spec in source_specs.items():
                clean_spec = _safe_param_spec(spec, source=source)
                if clean_spec:
                    dst_specs[name] = _merge_param_spec(dst_specs.get(name), clean_spec)
                    copied = True

    dst_content_types = _ensure_mapping_field(dst, "api_content_types")
    for content_types in _profile_path_values(src.get("api_content_types"), clean):
        values = {str(value).lower() for value in _set_like_values(content_types) if str(value).strip()}
        if values:
            _ensure_set_field(dst_content_types, clean).update(values)
            copied = True

    dst_templates = _ensure_mapping_field(dst, "api_path_templates")
    for templates in _profile_path_values(src.get("api_path_templates"), clean):
        values = {
            valid for valid in (
                _validated_profile_api_path(value) for value in _set_like_values(templates)
            ) if valid
        }
        if values:
            _ensure_set_field(dst_templates, clean).update(values)
            copied = True

    src_blocked = src_index.get("blocked") or frozenset()
    dst_blocked = _ensure_set_field(dst, "api_param_blocked")
    has_destination_params = bool(_set_like_values(dst_api_params.get(clean)))
    profile_mutated = False
    if clean in src_blocked and not had_destination_params:
        dst_blocked.add(clean)
        copied = True
    elif has_destination_params and clean in dst_blocked:
        dst_blocked.discard(clean)
        profile_mutated = True

    return copied

def _apply_cross_base_replay_scoped(api_results, scope, max_apis):
    """按 host/global 计算各 base 缺失的、其它同组 base 挖到的 API,存入 replay_apis。

    命中前后端分离/多端口部署场景: 前端页面(如 :443)JS 挖出的接口清单会回放到
    同主机的裸后端(如 :8080),后端若未做鉴权即可被 Phase 3 命中。

    只写入 delta(本 base 自己没有的路径)到 t["replay_apis"],不修改 t["apis"],
    从而完全保留每个 base 原有的 seed/param/body 探测逻辑;回放作为额外探测层执行。
    返回 (新增回放API总数, 受影响的base数)。
    """
    if scope == "none" or len(api_results) < 2:
        return 0, 0

    def group_key(base):
        if scope == "global":
            return "*"
        return (urlparse(base).hostname or "").lower()

    groups = {}
    for t in api_results:
        groups.setdefault(group_key(t["base"]), []).append(t)

    total_added, touched = 0, 0
    for members in groups.values():
        if len(members) < 2:
            continue
        # Prefix-only paths are target-local guesses, not replay evidence.
        # A remote exact observation of the same path remains eligible and can
        # replace a destination's local prefix-only policy.
        union = unique_apis([
            api for t in members for api in t.get("apis", [])
            if is_independently_exact_api(t, api)
        ])
        merged_meta_candidates = {}
        sources_by_api = {}
        for t in members:
            for api in t.get("apis", []):
                if not is_independently_exact_api(t, api):
                    continue
                sources_by_api.setdefault(_clean_api_path(api), []).append(t)
            raw_meta = t.get("api_meta") or {}
            if isinstance(raw_meta, dict):
                for k, v in raw_meta.items():
                    clean_key = _clean_api_path(k) if isinstance(k, str) else ""
                    if clean_key:
                        merged_meta_candidates.setdefault(clean_key, []).append(v)
        merged_meta_by_clean = {}
        for key, values in sorted(merged_meta_candidates.items()):
            merged = _merge_api_meta_items(values)
            if merged:
                merged_meta_by_clean[key] = merged
        profile_indexes = {id(member): _replay_param_profile_index(member) for member in members}
        for t in members:
            local_paths = set(_canonical_api_list(t.get("apis", [])))
            own = {
                _canonical_api_path(api, preserve_query=False) for api in t.get("apis", [])
                if is_independently_exact_api(t, api)
            }
            delta = [a for a in union if _clean_api_path(a) not in own]
            replay_discovered = len(delta)
            if max_apis and max_apis > 0:
                delta = delta[:max_apis]
            if replay_discovered:
                t["replay_exact_discovered"] = replay_discovered
                t["replay_skipped_by_cap"] = max(0, replay_discovered - len(delta))
            if not delta:
                continue
            # A same-path local prefix guess is promoted in place. Only truly
            # missing paths need the separate replay layer, avoiding duplicate
            # seed and replay transmissions after exact evidence wins.
            t["replay_apis"] = [api for api in delta if _canonical_api_path(api, preserve_query=False) not in local_paths]
            t["replay_promoted_apis"] = [
                api for api in delta if _canonical_api_path(api, preserve_query=False) in local_paths
            ]
            meta = _safe_api_meta_record(t.get("api_meta"), set(_canonical_api_list(t.get("apis") or [])) | set(delta))
            t["api_meta"] = meta
            for api in delta:
                clean_api = _clean_api_path(api)
                copied_meta = merged_meta_by_clean.get(clean_api)
                if copied_meta:
                    existing = [meta[key] for key in dict.fromkeys((api, clean_api)) if key in meta]
                    merged = _merge_api_meta_items(existing + [copied_meta])
                    meta[api] = copy.deepcopy(merged)
                    meta[clean_api] = copy.deepcopy(merged)
                for src in sources_by_api.get(_clean_api_path(api), []):
                    carry_replay_param_profile(t, src, api, src_index=profile_indexes[id(src)])
            _invalidate_api_meta_index(t)
            t["cross_replay_added"] = len(delta)
            total_added += len(delta)
            touched += 1
    return total_added, touched


def apply_cross_base_replay(api_results, scope, max_apis):
    with api_meta_index_scope(api_results):
        return _apply_cross_base_replay_scoped(api_results, scope, max_apis)


def _http_origin_parts(raw_url):
    try:
        parsed = urlparse(str(raw_url or "").strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if scheme not in ("http", "https") or not host:
        return None
    effective_port = port or (443 if scheme == "https" else 80)
    display_host = "[" + host + "]" if ":" in host else host
    origin = f"{scheme}://{display_host}"
    if port is not None and port != (443 if scheme == "https" else 80):
        origin += f":{port}"
    return scheme, host, effective_port, origin


def _sanitize_config_source_url(raw_url):
    parts = _http_origin_parts(raw_url)
    if not parts:
        return ""
    parsed = urlparse(str(raw_url or ""))
    path = parsed.path or "/"
    if re.search(r"[\x00-\x20\x7f]", path):
        return ""
    return parts[3] + path


def _clean_config_service_base(raw):
    item = dict(raw or {})
    raw_url = str(item.get("url") or "")
    parts = _http_origin_parts(raw_url)
    if not parts:
        return None
    parsed = urlparse(raw_url)
    prefix = re.sub(r"/{2,}", "/", parsed.path or "").rstrip("/")
    if prefix and (not prefix.startswith("/") or any(part in (".", "..") for part in prefix.split("/"))):
        return None
    keys = sorted({str(value) for value in (item.get("config_keys") or []) if str(value)}, key=lambda value: (value.casefold(), value))
    if item.get("config_key"):
        keys = sorted(set(keys + [str(item["config_key"])]), key=lambda value: (value.casefold(), value))
    assets = sorted({
        clean for clean in (
            _sanitize_config_source_url(value)
            for value in ([item.get("source_asset")] + list(item.get("source_assets") or []))
        ) if clean
    })
    pages = sorted({
        clean for clean in (
            _sanitize_config_source_url(value)
            for value in ([item.get("source_page")] + list(item.get("source_pages") or []))
        ) if clean
    })
    return {
        "url": parts[3] + prefix,
        "origin": parts[3],
        "path_prefix": prefix,
        "config_key": keys[0] if keys else "",
        "config_keys": keys,
        "source": "js_config_base",
        "source_asset": assets[0] if assets else "",
        "source_assets": assets,
        "source_page": pages[0] if pages else "",
        "source_pages": pages,
        "source_origin": _http_origin_parts(pages[0])[3] if pages and _http_origin_parts(pages[0]) else "",
        "confidence": round(float(item.get("confidence") or 0.0), 2),
        "same_host": item.get("same_host"),
        "active_eligible": bool(item.get("active_eligible")),
        "active_scope_recommendation": str(item.get("active_scope_recommendation") or "inventory_only"),
    }


def _merge_candidate_item(store, candidate):
    path = candidate["path"]
    item = store.setdefault(path, {
        **candidate,
        "config_keys": set(),
        "config_source_assets": set(),
        "config_source_pages": set(),
        "discovered_from_bases": set(),
        "config_service_bases": set(),
    })
    item["confidence"] = max(float(item.get("confidence") or 0.0), float(candidate.get("confidence") or 0.0))
    item["config_keys"].update(candidate.get("config_keys") or [])
    item["config_source_assets"].update(candidate.get("config_source_assets") or [])
    item["config_source_pages"].update(candidate.get("config_source_pages") or [])
    item["discovered_from_bases"].add(candidate.get("discovered_from_base") or "")
    item["config_service_bases"].add(candidate.get("config_service_base") or "")


def _finalize_candidate_items(store):
    out = []
    for path in sorted(store):
        item = dict(store[path])
        for key in ("config_keys", "config_source_assets", "config_source_pages", "discovered_from_bases", "config_service_bases"):
            item[key] = sorted(value for value in item.get(key, set()) if value)
        item["config_key"] = item["config_keys"][0] if item["config_keys"] else ""
        item["config_source_asset"] = item["config_source_assets"][0] if item["config_source_assets"] else ""
        item["config_source_page"] = item["config_source_pages"][0] if item["config_source_pages"] else ""
        item["discovered_from_base"] = item["discovered_from_bases"][0] if item["discovered_from_bases"] else ""
        item["config_service_base"] = item["config_service_bases"][0] if item["config_service_bases"] else ""
        item["confidence"] = round(float(item.get("confidence") or 0.45), 2)
        out.append(item)
    return out


def _config_rest_candidates_for_base(item, source_base, max_suffixes):
    suffixes = list(CONFIG_REST_SUFFIXES)
    if max_suffixes > 0:
        suffixes = suffixes[:max_suffixes]
    prefix = str(item.get("path_prefix") or "").rstrip("/")
    out = []
    for suffix in suffixes:
        path = (prefix + suffix) or "/"
        out.append({
            "path": path,
            "source": "rest_convention",
            "confidence": 0.45,
            "config_service_prefix": prefix,
            "config_service_base": item.get("url") or (item.get("origin", "") + prefix),
            "config_keys": list(item.get("config_keys") or []),
            "config_source_assets": list(item.get("source_assets") or []),
            "config_source_pages": list(item.get("source_pages") or []),
            "discovered_from_base": source_base,
        })
    return out


def config_service_origin_live(origin):
    """One no-follow liveness request to the exact declared scheme/origin."""
    try:
        req = Request(origin.rstrip("/") + "/", headers={"User-Agent":"Mozilla/5.0","Accept":"application/json,text/html,*/*"}, method="GET")
        resp = scoped_urlopen(req, timeout=min(3, HTTP_TIMEOUT), follow_redirects=False)
        resp.read(1)
        return True
    except HTTPError:
        return True
    except Exception as exc:
        log.debug(f"Config service origin unavailable {origin}: {exc}")
        return False


def _phase2_inventory_sample_limits(path):
    limits = {}
    if not os.path.exists(path):
        return limits
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            try:
                rec = json.loads(line)
            except (TypeError, ValueError):
                continue
            sampled = rec.get("apis") if isinstance(rec.get("apis"), list) else []
            try:
                count = int(rec.get("api_count") or 0)
            except (TypeError, ValueError):
                count = 0
            if sampled and count > len(sampled):
                limits[rec.get("base", "")] = len(sampled)
    return limits


def rewrite_phase2_inventory_from_stream(stream, outdir, inventory_name):
    path = os.path.join(outdir, inventory_name)
    limits = _phase2_inventory_sample_limits(path)
    tmp = path + ".config.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        for rec in stream:
            handle.write(json.dumps(
                phase2_inventory_record(rec, api_limit=limits.get(rec.get("base", ""))),
                ensure_ascii=False,
            ) + "\n")
    os.replace(tmp, path)


def augment_config_service_stream(phase2_path, api_results, outdir, inventory_name):
    """Two-pass disk-stream augmentation for config-derived REST candidates."""
    existing_by_origin = {}
    sources = []
    for record in api_results:
        base_parts = _http_origin_parts(record.get("base"))
        if base_parts:
            key = base_parts[:3]
            current = existing_by_origin.get(key)
            if current is None or record.get("base", "") < current:
                existing_by_origin[key] = record.get("base", "")
        cleaned = []
        for raw in record.get("config_service_bases") or []:
            item = _clean_config_service_base(raw)
            if item:
                cleaned.append(item)
        sources.append((record.get("base", ""), record.get("title", ""), sorted(cleaned, key=lambda item: item["url"])))

    attachments = {}
    synthetic_groups = {}
    mode = str(getattr(args, "config_service_base_mode", "same-host") or "same-host")
    max_bases = max(0, int(getattr(args, "config_service_base_max_per_target", 8) or 0))
    max_suffixes = max(0, int(getattr(args, "config_rest_max_suffixes", 8) or 0))
    if mode == "same-host":
        for source_base, title, items in sources:
            source_parts = _http_origin_parts(source_base)
            if not source_parts:
                continue
            eligible = []
            for item in items:
                dest_parts = _http_origin_parts(item.get("origin"))
                if dest_parts and dest_parts[1] == source_parts[1]:
                    eligible.append((item, dest_parts))
            bounded = eligible[:max_bases] if max_bases > 0 else eligible
            for item, dest_parts in bounded:
                dest_key = dest_parts[:3]
                dest_base = existing_by_origin.get(dest_key)
                if dest_base:
                    candidate_store = attachments.setdefault(dest_base, {})
                    for candidate in _config_rest_candidates_for_base(item, source_base, max_suffixes):
                        _merge_candidate_item(candidate_store, candidate)
                    continue
                group = synthetic_groups.setdefault(dest_key, {
                    "origin": item["origin"], "title": title, "bases": {}, "candidates": {},
                })
                group["bases"][item["url"]] = item
                for candidate in _config_rest_candidates_for_base(item, source_base, max_suffixes):
                    _merge_candidate_item(group["candidates"], candidate)

    live_synthetic = []
    for key in sorted(synthetic_groups):
        group = synthetic_groups[key]
        if not config_service_origin_live(group["origin"]):
            continue
        live_synthetic.append({
            "base": group["origin"],
            "title": group.get("title") or "config service",
            "apis": [],
            "api_meta": {},
            "sensitive": [],
            "js_count": 0,
            "param_profile": empty_param_profile(),
            "fallback": "config_service_base",
            "config_service_synthetic": True,
            "config_service_bases": [group["bases"][url] for url in sorted(group["bases"])],
            "config_rest_candidates": _finalize_candidate_items(group["candidates"]),
        })

    augmented = phase2_path + ".config"
    writer = _JsonlWriter(augmented)
    for record in api_results:
        candidate_store = attachments.get(record.get("base", ""))
        if candidate_store:
            record = dict(record)
            record["config_rest_candidates"] = _finalize_candidate_items(candidate_store)
        writer.write(record)
    for record in sorted(live_synthetic, key=lambda item: item["base"]):
        writer.write(record)

    stream = StreamedResultSet(augmented, writer.count)
    rewrite_phase2_inventory_from_stream(stream, outdir, inventory_name)
    return augmented, writer.count, sum(len(_finalize_candidate_items(store)) for store in attachments.values()) + sum(len(item["config_rest_candidates"]) for item in live_synthetic), len(live_synthetic)


# ===== 主流程 =====
def main():
    parser_state = ast_parser_status()
    if args.js_ast_mode == "required" and not parser_state.get("available"):
        print("ERROR: --js-ast-mode required needs esprima; install requirements-ast.txt", file=sys.stderr)
        return 2
    try:
        acquire_outdir_lock()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    prepare_outdir()
    print("="*60)
    mode = "FULL绕过+全变体" if args.collect_all_variants else "FULL绕过+命中断路" if args.full_bypass else "FAST绕过+命中断路"
    print(f"v13: URL参数绑定+POST body/form增强 | {mode} | 风险分级 | Markdown报告")
    if args.debug: print(f"  debug=ON workers={WORKERS} timeout={HTTP_TIMEOUT}s")
    print("="*60)

    if args.validate_from_report:
        print("\n[Validate-from-report] conservative focused recheck...")
        summary = run_validate_from_report(args.validate_from_report, OUTDIR, plan_only=args.validate_plan_only)
        print(f"  tasks={summary.get('task_count')} plan={summary.get('plan_path')}")
        if summary.get("report_path"):
            print(f"  report={summary.get('report_path')}")
        return

    targets = dedupe_targets(load_targets(args.input, args.input_format))
    if args.limit > 0: targets = targets[:args.limit]
    print(f"\n[*] 目标: {len(targets)} | 输入: {args.input} ({args.input_format}) | 输出: {OUTDIR}")
    targets = run_port_discovery(targets)

    # Phase 1: HTTP/scheme normalization
    expand_ports = []
    if not args.no_expand_api_ports and args.expand_api_ports.strip():
        cap = args.expand_api_ports_max_targets
        if cap and cap > 0 and len(targets) > cap:
            print(f"  端口扇出跳过: 目标数 {len(targets)} > 阈值 {cap} (改用 --port-scanner 预检)")
        else:
            for tok in args.expand_api_ports.split(','):
                tok = tok.strip()
                if tok.isdigit():
                    p = int(tok)
                    if p not in expand_ports:
                        expand_ports.append(p)
    live = run_httpx_probe(targets)
    if live is None:
        print(f"\n[Phase 1] HTTP确认+scheme规范化{' (skip TCP)' if args.skip_port_probe else ''}...")
        if expand_ports:
            print(f"  同主机API端口扇出: {expand_ports}")
        live, done = [], 0
        def probe(t_url):
            normalized, host, port = target_url_with_scheme(t_url)
            if normalized and host and port:
                bases = []
                base = reachable_base_url(host, port, normalized)
                if base:
                    bases.append(base)
                for xp in expand_ports:
                    if xp == port:
                        continue
                    xbase = reachable_base_url(host, xp)
                    if xbase and xbase not in bases:
                        bases.append(xbase)
                return bases
            elif host:
                bases = []
                for port in WEB_PORTS:
                    base = reachable_base_url(host, port)
                    if base:
                        bases.append(base)
                return bases
            return []
        with ThreadPoolExecutor(max_workers=PHASE12_WORKERS or WORKERS*4) as pool:
            futures = {pool.submit(probe, t[0]): t for t in targets}
            for f in as_completed(futures):
                done += 1
                if done % 50 == 0: print(f"  [{done}/{len(targets)}] {len(live)} live")
                try:
                    r = f.result()
                    for item in r or []:
                        if item and item not in live:
                            live.append(item)
                except Exception as e:
                    log.debug(f"Probe failed: {e}")
        print(f"  存活: {len(live)}")
    else:
        print(f"\n[Phase 1] HTTP确认+scheme规范化: 使用httpx结果")
        print(f"  存活: {len(live)}")

    # Phase 2: JS爬取
    print(f"\n[Phase 2] JS爬取+API提取...")
    bypass_used = FULL_BYPASS if args.full_bypass else FAST_BYPASS
    backend_baseline_count = len(configured_backend_baseline_paths())
    api_fuzz_count = len(API_FUZZ_WORDLIST_PATHS) if not args.disable_api_fuzz else 0
    print(f"  绕过: {'FULL(6种)' if args.full_bypass else 'FAST(2种,短路)'} | dry-run={args.dry_run} | file-hunter={not args.disable_file_hunter} | file-baseline={args.enable_file_baseline and not args.disable_file_hunter} | backend-baseline={args.enable_backend_baseline}({backend_baseline_count}) | extra-wordlist={len(EXTRA_API_WORDLIST_PATHS)} | api-fuzz={api_fuzz_count} | param-harvest={not args.disable_param_harvest}")
    ast_display = (parser_state.get("name") + " " + parser_state.get("version", "")).strip() if parser_state.get("available") else "unavailable; regex fallback"
    print(f"  Phase2 advanced: ast={args.js_ast_mode}({ast_display}) import-map={args.import_map_mode} manifest={args.asset_manifest_mode} source-map={args.source_map_mode}")
    if args.min_delay_ms or args.max_rps_per_host or args.max_requests_per_host:
        print(f"  Phase3 safety: min_delay_ms={args.min_delay_ms} max_rps_per_host={args.max_rps_per_host} max_requests_per_host={args.max_requests_per_host}")
    if PHASE12_WORKERS:
        print(f"  Phase1/2 workers capped: {PHASE12_WORKERS}")
    if args.redact_raw_findings:
        print("  Finding raw redaction: ON")

    with open(os.path.join(OUTDIR, PHASE2_INVENTORY_NAME), "w", encoding="utf-8"):
        pass
    api_writer = _JsonlWriter(os.path.join(OUTDIR, PHASE2_FULL_NAME))
    done = 0
    def crawl(url):
        base = origin_from_url(url)
        page_url = url
        path_prefixes = path_prefixes_from_url(page_url)
        param_profile = empty_param_profile()
        status, final_url, html, ct = http_get(page_url, retries=0)
        status, final_url, html, ct = refresh_sparse_phase2_page(page_url, status, final_url, html, ct)
        if final_url:
            original_host = (urlparse(page_url).hostname or "").lower()
            final_host = (urlparse(final_url).hostname or "").lower()
            if original_host and final_host and original_host != final_host:
                # A cross-host redirect proves the original service is live but
                # must not silently move extraction/probing into another scope.
                html, ct, final_url = "", "", None
        openapi_inventory = collect_openapi_inventory(base)
        swagger_apis = set(openapi_inventory.get("apis") or set())
        merge_param_profiles(param_profile, openapi_inventory.get("param_profile") or empty_param_profile())
        openapi_external_servers = list(openapi_inventory.get("external_servers") or [])
        openapi_unresolved_refs = list(openapi_inventory.get("unresolved_refs") or [])
        openapi_path_templates = list(openapi_inventory.get("path_templates") or [])
        api_meta = {}
        for api in swagger_apis:
            add_api_meta(api_meta, api, "swagger")
        if status is None:
            return baseline_api_result(url, fallback="request_failure")
        if not html:
            apis = set(BASELINE_PATHS) | swagger_apis
            for api in BASELINE_PATHS:
                add_api_meta(api_meta, api, "baseline")
            apis = add_configured_backend_paths(apis, api_meta)
            if args.legacy_recovery:
                for api in legacy_recovery_candidates():
                    apis.add(api)
                    add_api_meta(api_meta, api, "legacy_recovery", 0.30)
            apis, prefix_inventory_paths = apply_prefix_inventory(apis, api_meta, path_prefixes)
            if args.legacy_recovery:
                mark_legacy_recovery_meta(api_meta, apis)
            for api in apis:
                infer_api_meta(api_meta, api)
            return {
                "base":base,"title":"","apis":sorted(apis, key=api_priority),"api_meta":api_meta,"sensitive":[],"js_count":0,
                "param_profile":param_profile,"prefix_inventory_paths":prefix_inventory_paths,"fallback":"empty_http_response",
                "openapi_external_servers":openapi_external_servers,"openapi_unresolved_refs":openapi_unresolved_refs,
                "openapi_path_templates":openapi_path_templates,"config_service_bases":[],
            }
        merge_param_profiles(param_profile, extract_param_profile(html))
        title = ""
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        if m: title = m.group(1)[:200]
        if final_url:
            page_url = final_url
            path_prefixes.update(path_prefixes_from_url(final_url))
        all_apis = set()
        js_limit = args.js_max_download
        js_max_bytes = args.js_max_bytes if args.js_max_bytes > 0 else DEFAULT_JS_MAX_BYTES
        js_graph = build_js_graph(
            page_url=page_url,
            html=html,
            fetch_text=lambda resource_url, max_size=500_000: http_get(resource_url, max_size=max_size, retries=0, include_metadata=True),
            fetch_advanced_text=lambda resource_url, max_size=500_000: exact_origin_http_get(resource_url, max_size=max_size, include_metadata=True),
            js_limit=js_limit,
            js_max_bytes=js_max_bytes,
            extract_js_from_html=extract_js_from_html,
            extract_links_from_html=extract_links_from_html,
            extract_apis=extract_apis,
            extract_module_urls_from_content=extract_module_urls_from_content,
            extract_prefixes_from_content=extract_prefixes_from_content,
            extract_param_profile=extract_param_profile,
            empty_param_profile=empty_param_profile,
            merge_param_profiles=merge_param_profiles,
            common_libs=COMMON_LIBS,
            valid_sensitive_value=valid_sensitive_value,
            vue_instance_re=VUE_INSTANCE_RE,
            vue_router_re=VUE_ROUTER_RE,
            react_route_re=REACT_ROUTE_RE,
            include_delete_method=args.include_delete_method,
            ast_mode=args.js_ast_mode,
            ast_limits={
                "max_bytes": max(0, args.js_ast_max_bytes),
                "max_nodes": max(1, args.js_ast_max_nodes),
                "max_depth": max(1, args.js_ast_max_depth),
                "max_expressions": max(1, args.js_ast_max_expressions),
                "max_assets": max(0, args.js_advanced_max_assets),
            },
            import_maps=args.import_map_mode == "explicit",
            manifest_inventory=args.asset_manifest_mode == "explicit",
            advanced_limits={
                "max_new_assets": max(0, args.js_advanced_max_assets),
                "inventory_max_declarations": max(0, args.advanced_inventory_max_declarations),
                "import_map_max_count": max(0, args.import_map_max_count),
                "import_map_max_bytes": max(1, args.import_map_max_bytes),
                "import_map_max_entries": max(0, args.import_map_max_entries),
                "manifest_max_count": max(0, args.asset_manifest_max_count),
                "manifest_max_bytes": max(1, args.asset_manifest_max_bytes),
                "manifest_max_nodes": max(1, args.asset_manifest_max_nodes),
                "manifest_max_entries": max(0, args.asset_manifest_max_entries),
            },
            source_map_mode=args.source_map_mode,
            source_map_limits={
                "max_count": max(0, args.source_map_max_count),
                "max_bytes": max(1, args.source_map_max_bytes),
                "max_sources": max(0, args.source_map_max_sources),
                "max_ratio": max(0.0, args.source_map_max_ratio),
            },
        )
        all_apis.update(js_graph.api_paths())
        for endpoint in js_graph.apis:
            add_api_meta(api_meta, endpoint.path, endpoint.source, endpoint.confidence)
        all_apis.update(
            item for item in js_graph.sensitive
            if not any(value and value in item for value in js_graph.redacted_values)
        )
        path_prefixes.update(js_graph.prefixes)
        merge_param_profiles(param_profile, js_graph.param_profile)
        remove_profile_values(param_profile, js_graph.redacted_values)
        # 将参数画像提取到的URL补充进API集合
        for extra_api in param_profile.get("_apis_from_params", set()):
            if extra_api.startswith("/"):
                all_apis.add(extra_api)
                add_api_meta(api_meta, extra_api, "param_binding")
        all_apis.update(swagger_apis)
        if args.legacy_recovery:
            for api in legacy_recovery_candidates():
                all_apis.add(api)
                add_api_meta(api_meta, api, "legacy_recovery", 0.30)
        for api in BASELINE_PATHS:
            add_api_meta(api_meta, api, "baseline")
        all_apis.update(BASELINE_PATHS)
        all_apis = add_configured_backend_paths(all_apis, api_meta)
        all_apis, prefix_inventory_paths = apply_prefix_inventory(all_apis, api_meta, path_prefixes)
        if args.legacy_recovery:
            mark_legacy_recovery_meta(api_meta, all_apis)
        clean = sorted((a for a in all_apis if not a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:"))), key=lambda api: api_test_order({"api_meta": api_meta}, api))
        for api in clean:
            infer_api_meta(api_meta, api)
        sensitive = [a for a in all_apis if a.startswith(("SENSITIVE:","INTERNAL_IP:","JDBC:"))]
        if not clean: return None
        return {
            "base":base,"title":title,"apis":clean,"api_meta":{api: api_meta.get(api.split("#", 1)[0].rstrip("/") or api, {}) for api in clean},"sensitive":sensitive,
            "js_count":js_graph.stats.get("js_count", 0),
            "js_discovered":js_graph.stats.get("js_discovered", 0),
            "js_app_candidates":js_graph.stats.get("js_app_candidates", 0),
            "js_attempted":js_graph.stats.get("js_attempted", 0),
            "js_graph_edges":js_graph.stats.get("edges", 0),
            "lazy_chunks_discovered": js_graph.stats.get("lazy_chunks_discovered", 0),
            "lazy_chunks_attempted": js_graph.stats.get("lazy_chunks_attempted", 0),
            "lazy_chunks_downloaded": js_graph.stats.get("lazy_chunks_downloaded", 0),
            "param_profile":param_profile,
            "prefix_inventory_paths":prefix_inventory_paths,
            "openapi_external_servers":openapi_external_servers,
            "openapi_unresolved_refs":openapi_unresolved_refs,
            "openapi_path_templates":openapi_path_templates,
            "config_service_bases":js_graph.config_service_bases,
            "js_advanced_stats": {
                key: value for key, value in js_graph.stats.items()
                if key.startswith(("ast_", "advanced_", "import_", "asset_manifest_", "source_map_", "content_", "js_max_"))
            },
            "js_resource_inventory":js_graph.js_resource_inventory,
            "import_map_inventory":js_graph.import_map_inventory,
            "asset_manifest_inventory":js_graph.asset_manifest_inventory,
            "source_map_inventory":js_graph.source_map_inventory,
        }

    pool = ThreadPoolExecutor(max_workers=PHASE12_WORKERS or WORKERS)
    try:
        futures = {pool.submit(crawl, u): u for u in live}
        pending = set(futures)
        phase2_start = time.time()
        while pending:
            remaining = max(0, args.phase2_timeout - (time.time() - phase2_start))
            if remaining <= 0:
                break
            done_set, pending = wait(pending, timeout=min(5, remaining))
            if not done_set:
                continue
            for f in done_set:
                done += 1
                try:
                    r = f.result()
                    if r:
                        api_writer.write(r)
                        write_phase2_inventory(r)
                except Exception as e:
                    log.debug(f"Crawl failed: {e}")
                if done % 10 == 0 or done == len(live): print(f"  [{done}/{len(live)}] {api_writer.count} with APIs")
        if pending:
            print(f"  Phase 2 soft-timeout: {len(pending)} hosts fallback to baseline")
            for f in pending:
                url = futures[f]
                f.cancel()
                done += 1
                fallback = baseline_api_result(url)
                api_writer.write(fallback)
                write_phase2_inventory(fallback)
            print(f"  [{done}/{len(live)}] {api_writer.count} with APIs")
    finally:
        # Drain the bounded in-flight crawl before Phase 2 snapshots are made;
        # queued futures were cancelled above and their fallback is persisted.
        pool.shutdown(wait=True, cancel_futures=True)
    print(f"  Phase 2 DONE: {api_writer.count} hosts")
    print(f"  Phase 2 full results: {OUTDIR}/{PHASE2_FULL_NAME}")
    print(f"  Phase 2 inventory: {OUTDIR}/{PHASE2_INVENTORY_NAME}")

    # Replace the in-memory list with a disk-backed stream. Large scans
    # (200+ targets × hundreds of APIs each) would otherwise keep every
    # result dict and its API lists in RAM until Phase 3 finishes.
    phase2_path = os.path.join(OUTDIR, PHASE2_FULL_NAME)
    api_results = StreamedResultSet(phase2_path, api_writer.count)
    del api_writer  # free the writer lock

    # ── Phase 2.5: API dictionary fuzz for sparse (JS-free) targets ──
    if API_FUZZ_WORDLIST_PATHS:
        phase2_path = _phase25_sparse_api_fuzz(
            phase2_path, api_results, API_FUZZ_WORDLIST_PATHS, OUTDIR, PHASE2_INVENTORY_NAME
        )
        api_results = StreamedResultSet(phase2_path, len(api_results) if hasattr(api_results, '__len__') else 0)
        print(f"  Phase 2.5 API fuzz: {len(API_FUZZ_WORDLIST_PATHS)} wordlist paths")

    if args.replay_scope != "none":
        # Materialise is unavoidable here — cross-base replay needs all
        # results at once to compute group-level API unions. Use the SAME
        # materialised records for both mutation and persistence; otherwise
        # re-iterating StreamedResultSet reloads the pre-replay JSONL and drops
        # replay_apis before Phase 3 can consume them.
        replay_records = api_results.materialize() if hasattr(api_results, "materialize") else list(api_results)
        added, touched = apply_cross_base_replay(replay_records, args.replay_scope, args.replay_max_apis)
        if touched:
            # Re-write results with replay_apis added so Phase 3 sees them.
            _replay_path = phase2_path + ".replay"
            _w = _JsonlWriter(_replay_path)
            for t in replay_records:
                _w.write(t)
            phase2_path = _replay_path
            api_results = StreamedResultSet(phase2_path, _w.count)
        del replay_records
        if touched:
            print(f"  跨base回放: scope={args.replay_scope} 注入 {added} 条API到 {touched} 个base (前后端分离/多端口未授权)")

    phase2_path, config_count, config_candidate_count, config_synthetic_count = augment_config_service_stream(
        phase2_path, api_results, OUTDIR, PHASE2_INVENTORY_NAME
    )
    api_results = StreamedResultSet(phase2_path, config_count)
    if args.config_service_base_mode == "same-host":
        print(f"  Config service REST: {config_candidate_count} candidates, {config_synthetic_count} verified sibling origins")

    if args.dry_run:
        print(f"\n[Dry-run] 跳过测试, 输出API列表")
        with open(os.path.join(OUTDIR, "apis.json"), "w") as f:
            json.dump([
                phase2_inventory_record(
                    t,
                    api_limit=50,
                    param_name_limit=80,
                    seed_limit=40,
                    file_seed_limit=40,
                    include_param_profile=False,
                )
                for t in api_results
            ], f, ensure_ascii=False, indent=2)
        current_inventory = os.path.join(OUTDIR, "apis.json")
        print(f"  API列表: {current_inventory}")
        if args.compare_inventory:
            diff_path = args.compare_output or os.path.join(OUTDIR, "inventory_diff.json")
            diff = write_inventory_diff(current_inventory, args.compare_inventory, diff_path, include_samples=args.include_samples)
            print(f"  Inventory diff: {diff_path} common={diff['counts']['common']} old_only={diff['counts']['old_only']} new_only={diff['counts']['new_only']}")
        return

    # Phase 3: 两阶段测试
    phase3_mode = "FULL绕过+全变体" if args.collect_all_variants else "FULL绕过+命中断路" if args.full_bypass else "FAST绕过+命中断路"
    print(f"\n[Phase 3] 未授权测试 ({phase3_mode})...")
    if bool(getattr(args, "post_every_api", False)):
        print("  WARNING: --post-every-api authorized; each independently exact API gets one GET and one POST opportunity")
    target_map = {}
    for t in api_results:
        target_map[t["base"]] = t; t["_f"] = []
    coverage_tracker = ApiCoverageTracker()
    globals()["ACTIVE_PHASE3_OPPORTUNITY_LEDGER"] = Phase3OpportunityLedger()

    exact_tasks = exact_api_sweep_plan(
        api_results,
        max_per_target=max(0, int(getattr(args, "exact_api_max", 0) or 0)),
        tracker=coverage_tracker,
    )
    for target, api in exact_tasks:
        coverage_tracker.mark_scheduled(target["base"], api, "exact")
        if bool(getattr(args, "post_every_api", False)):
            coverage_tracker.mark_get_scheduled(target["base"], api)
            coverage_tracker.mark_post_scheduled(
                target["base"], api,
                exact_post_body_kind(target.get("param_profile"), api),
            )
    print(f"  3a/exact: {len(exact_tasks)} independently exact safe tasks")
    if exact_tasks:
        t_start = time.time()
        def test_exact(task):
            target, api = task
            profile = target.get("param_profile")
            dual_method = bool(getattr(args, "post_every_api", False))
            single_variant = False if dual_method else (
                not has_bound_params(profile, api) and not is_file_endpoint(api)
            )
            if dual_method:
                tests = exact_dual_method_bypass_tests(profile, api, bypass_used)
            else:
                tests = list(bypass_used)
                for extra in body_probe_bypass_tests(profile, api):
                    if not any(existing[:3] == extra[:3] for existing in tests):
                        tests.append(extra)
            findings = test_api(
                target["base"], api, tests,
                short_circuit=False if dual_method else not args.collect_all_variants,
                param_profile=profile,
                allow_param_probe=True,
                single_variant=single_variant,
                coverage_tracker=coverage_tracker,
                coverage_kind="exact",
                exact_dual_method=dual_method,
            )
            return target["base"], api, findings
        def handle_exact(result):
            base_url, api, findings = result
            coverage_tracker.mark_completed(base_url, api)
            if findings:
                target_map[base_url]["_f"].extend(findings)
        def timeout_exact(task):
            target, api = task
            coverage_tracker.mark_timeout(target["base"], api)
        run_task_pool(
            exact_tasks,
            WORKERS * 2,
            max(0, int(getattr(args, "exact_sweep_timeout", 0) or 0)),
            "3a/exact",
            test_exact,
            handle_exact,
            on_timeout=timeout_exact,
        )
        print(f"  3a/exact 耗时: {time.time()-t_start:.0f}s")

    config_rest_tasks = config_rest_phase3_tasks(api_results)
    if config_rest_tasks:
        for target, candidate in config_rest_tasks:
            coverage_tracker.mark_scheduled(target["base"], candidate.get("path"), "heuristic")
        print(f"  3a/config-rest: {len(config_rest_tasks)} safe GET tasks")
        t_start = time.time()
        def test_config_rest(task):
            t, candidate = task
            provenance = {
                "discovery_source": candidate.get("source") or "rest_convention",
                "discovery_confidence": candidate.get("confidence") or 0.45,
                "config_service_prefix": candidate.get("config_service_prefix") or "",
                "config_service_base": candidate.get("config_service_base") or "",
                "config_keys": candidate.get("config_keys") or [],
                "config_key": candidate.get("config_key") or "",
                "config_source_asset": candidate.get("config_source_asset") or "",
                "config_source_assets": candidate.get("config_source_assets") or [],
                "config_source_page": candidate.get("config_source_page") or "",
                "config_source_pages": candidate.get("config_source_pages") or [],
                "discovered_from_base": candidate.get("discovered_from_base") or "",
            }
            return t["base"], test_api(
                t["base"],
                candidate["path"],
                [("CONFIG_REST_GET_no_auth", "GET", None, None, {})],
                short_circuit=True,
                param_profile=empty_param_profile(),
                allow_param_probe=False,
                require_stable_catch_all=True,
                catch_all_scope=candidate.get("config_service_prefix") or "",
                single_variant=True,
                finding_provenance=provenance,
                coverage_tracker=coverage_tracker,
                coverage_kind="heuristic",
            )
        def handle_config_rest(result):
            base_url, findings = result
            if findings:
                target_map[base_url]["_f"].extend(findings)
        run_task_pool(config_rest_tasks, WORKERS, args.phase3a_timeout, "3a/config-rest", test_config_rest, handle_config_rest)
        print(f"  3a/config-rest 耗时: {time.time()-t_start:.0f}s")

    flat_tasks = phase3_heuristic_seed_tasks(api_results)
    for target, api in flat_tasks:
        coverage_tracker.mark_scheduled(target["base"], api, "heuristic")
    print(f"  3a/fast: {len(flat_tasks)} tasks on {len(target_map)} hosts")
    t_start = time.time()
    def test_flat(task):
        t, api = task
        profile, single_variant = api_probe_policy(t, api)
        return t["base"], test_api(
            t["base"], api, FAST_BYPASS,
            short_circuit=True,
            param_profile=profile,
            allow_param_probe=False,
            single_variant=single_variant,
            coverage_tracker=coverage_tracker,
            coverage_kind="heuristic",
        )
    def handle_flat(result):
        base_url, findings = result
        if findings:
            target_map[base_url]["_f"].extend(findings)
    run_task_pool(flat_tasks, WORKERS * 2, args.phase3a_timeout, "3a/fast", test_flat, handle_flat)
    print(f"  3a/fast 耗时: {time.time()-t_start:.0f}s")

    replay_tasks = [
        (t, api) for t in api_results for api in _canonical_api_list(t.get("replay_apis", []))
        if _phase3_task_api_allowed(t, api) and not is_independently_exact_api(t, api)
    ]
    if replay_tasks:
        for target, api in replay_tasks:
            coverage_tracker.mark_scheduled(target["base"], api, api_coverage_kind(target, api))
        print(f"  3a/replay: {len(replay_tasks)} cross-base tasks")
        t_start = time.time()
        def test_replay(task):
            t, api = task
            profile, single_variant = api_probe_policy(t, api)
            replay_bypass = list(FAST_BYPASS)
            for extra in body_probe_bypass_tests(profile, api):
                if not any(existing[0] == extra[0] and existing[1] == extra[1] and existing[2] == extra[2] for existing in replay_bypass):
                    replay_bypass.append(extra)
            return t["base"], test_api(t["base"], api, replay_bypass, short_circuit=True, param_profile=profile, allow_param_probe=True, single_variant=single_variant, coverage_tracker=coverage_tracker, coverage_kind=api_coverage_kind(t, api))
        def handle_replay(result):
            base_url, findings = result
            if findings:
                target_map[base_url]["_f"].extend(findings)
        run_task_pool(replay_tasks, WORKERS*2, args.phase3a_timeout, "3a/replay", test_replay, handle_replay)
        print(f"  3a/replay 耗时: {time.time()-t_start:.0f}s")

    max_body_apis = max(0, int(getattr(args, "phase3a_body_max_apis", 0) or 0))
    body_fast_tasks = bound_body_tasks(api_results, max_per_target=max_body_apis or 0)
    if body_fast_tasks:
        for target, api in body_fast_tasks:
            coverage_tracker.mark_scheduled(target["base"], api, api_coverage_kind(target, api))
        print(f"  3a/body-fast: {len(body_fast_tasks)} bound POST tasks")
        t_start = time.time()
        def test_body_fast(task):
            t, api = task
            profile, single_variant = api_probe_policy(t, api)
            tests = body_probe_bypass_tests(profile, api)
            return t["base"], test_api(t["base"], api, tests, short_circuit=True, param_profile=profile, allow_param_probe=True, single_variant=single_variant, coverage_tracker=coverage_tracker, coverage_kind=api_coverage_kind(t, api))
        def handle_body_fast(result):
            base_url, findings = result
            if findings:
                target_map[base_url]["_f"].extend(findings)
        run_task_pool(body_fast_tasks, WORKERS, args.phase3a_timeout, "3a/body-fast", test_body_fast, handle_body_fast)
        print(f"  3a/body-fast 耗时: {time.time()-t_start:.0f}s")

    if args.phase3a_param_rescue:
        max_rescue_apis = max(0, args.phase3a_param_rescue_max_apis)
        rescue_param_tasks = bound_param_tasks(api_results, max_per_target=max_rescue_apis or 0)
        if rescue_param_tasks:
            for target, api in rescue_param_tasks:
                coverage_tracker.mark_scheduled(target["base"], api, api_coverage_kind(target, api))
            print(f"  3a/param-rescue: {len(rescue_param_tasks)} bound-param tasks")
            t_start = time.time()
            def test_param_rescue(task):
                t, api = task
                profile, single_variant = api_probe_policy(t, api)
                return t["base"], test_api(t["base"], api, FAST_BYPASS, short_circuit=True, param_profile=profile, allow_param_probe=True, single_variant=single_variant, coverage_tracker=coverage_tracker, coverage_kind=api_coverage_kind(t, api))
            def handle_param_rescue(result):
                base_url, findings = result
                if findings:
                    target_map[base_url]["_f"].extend(findings)
            run_task_pool(rescue_param_tasks, WORKERS, args.phase3a_timeout, "3a/param-rescue", test_param_rescue, handle_param_rescue)
            print(f"  3a/param-rescue 耗时: {time.time()-t_start:.0f}s")

    backend_param_tasks = configured_backend_param_tasks(api_results)
    if backend_param_tasks:
        for target, api in backend_param_tasks:
            coverage_tracker.mark_scheduled(target["base"], api, api_coverage_kind(target, api))
        print(f"  3a/backend-param: {len(backend_param_tasks)} configured backend-param tasks")
        t_start = time.time()
        def test_backend_param(task):
            t, api = task
            profile, single_variant = api_probe_policy(t, api, backend_probe_param_profile(api))
            if not single_variant:
                merge_param_profiles(profile, t.get("param_profile") or empty_param_profile())
            return t["base"], test_api(t["base"], api, FAST_BYPASS, short_circuit=True, param_profile=profile, allow_param_probe=True, single_variant=single_variant, coverage_tracker=coverage_tracker, coverage_kind=api_coverage_kind(t, api))
        def handle_backend_param(result):
            base_url, findings = result
            if findings:
                target_map[base_url]["_f"].extend(findings)
        run_task_pool(backend_param_tasks, WORKERS, args.phase3a_timeout, "3a/backend-param", test_backend_param, handle_backend_param)
        print(f"  3a/backend-param 耗时: {time.time()-t_start:.0f}s")

    candidates = []
    for base, t in target_map.items():
        obs = observation_findings(t["_f"])
        if obs:
            t["observations"] = merge_findings(t.get("observations", []), obs)
        real = useful_findings(t["_f"])
        t.pop("_f", None)
        if real:
            t["_f3a_real"] = real
            t["findings"] = merge_findings(t.get("findings", []), real)
            write_target_result(t)
            candidates.append(t)
    if not args.disable_rescue_baseline:
        candidate_bases = {t["base"] for t in candidates}
        rescue_tasks = high_yield_probe_tasks(api_results, exclude_bases=candidate_bases)
        if rescue_tasks:
            for target, api in rescue_tasks:
                coverage_tracker.mark_scheduled(target["base"], api, api_coverage_kind(target, api))
            rescue_bypass = FULL_BYPASS if args.full_bypass else FAST_BYPASS
            rescue_label = "FULL" if args.full_bypass else "FAST"
            print(f"  3a/rescue-baseline: {len(rescue_tasks)} {rescue_label} tasks for {len(api_results)-len(candidate_bases)} non-candidates")
            t_start = time.time()
            def test_rescue(task):
                t, api = task
                profile, single_variant = api_probe_policy(t, api)
                return t["base"], test_api(t["base"], api, rescue_bypass, short_circuit=True, param_profile=profile, allow_param_probe=False, single_variant=single_variant, coverage_tracker=coverage_tracker, coverage_kind=api_coverage_kind(t, api))
            def handle_rescue(result):
                base_url, findings = result
                obs = observation_findings(findings)
                if obs:
                    target_map[base_url]["observations"] = merge_findings(target_map[base_url].get("observations", []), obs)
                real = useful_findings(findings)
                if real and base_url not in candidate_bases:
                    t = target_map[base_url]
                    t["_f3a_real"] = real
                    t["findings"] = merge_findings(t.get("findings", []), real)
                    write_target_result(t)
                    candidates.append(t)
                    candidate_bases.add(base_url)
            run_task_pool(rescue_tasks, WORKERS, args.rescue_timeout, "3a/rescue-baseline", test_rescue, handle_rescue)
            print(f"  3a/rescue-baseline 耗时: {time.time()-t_start:.0f}s")
    observation_targets = [t for t in target_map.values() if t.get("observations")]
    print(f"  3a: {len(candidates)} exposure candidates | observations={len(observation_targets)}")

    candidate_targets = []
    if candidates:
        cand_map = {}
        for t in candidates:
            cand_map[t["base"]] = t

        layers = [
            ("baseline", lambda t: unique_apis(BASELINE_PATHS + static_priority_apis(t))),
            ("business", business_layer_apis),
            ("file", file_layer_apis if not args.disable_file_hunter else lambda t: []),
        ]
        print("  3b: 分层 deep test (baseline -> business -> file)")
        for layer_name, api_provider in layers:
            layer_tasks = layer_tasks_for_candidates(candidates, api_provider, layer_name, collect_all=args.collect_all_variants)
            if not layer_tasks:
                continue
            for target, api, _layer in layer_tasks:
                coverage_tracker.mark_scheduled(target["base"], api, api_coverage_kind(target, api))
            print(f"  3b/{layer_name}: {len(layer_tasks)} tasks")
            t_start = time.time()
            def test_deep_flat(task):
                t, api, layer = task
                profile, single_variant = api_probe_policy(t, api)
                return t["base"], test_api(t["base"], api, bypass_used, short_circuit=not args.collect_all_variants, param_profile=profile, single_variant=single_variant, coverage_tracker=coverage_tracker, coverage_kind=api_coverage_kind(t, api))
            def handle_deep(result):
                base_url, findings = result
                if findings:
                    t = cand_map[base_url]
                    obs = observation_findings(findings)
                    if obs:
                        t["observations"] = merge_findings(t.get("observations", []), obs)
                    merge_findings(t.setdefault("findings", []), useful_findings(findings))
                    write_target_result(t)
            run_task_pool(layer_tasks, WORKERS, args.phase3b_layer_timeout, f"3b/{layer_name}", test_deep_flat, handle_deep)
            print(f"  3b/{layer_name} 耗时: {time.time()-t_start:.0f}s")

        for t in candidates:
            all_f = t.get("findings", [])
            if all_f:
                unique = merge_findings([], all_f)
                t["findings"] = unique
                t["finding_count"] = len(unique)
                t["raw_event_count"] = sum(int(fi.get("variant_count") or 1) for fi in unique)
                write_target_result(t)
                candidate_targets.append(t)
                print(f"\n  [candidate] {t['base']} | {t['title'][:50]}")
                for fi in unique[:4]:
                    risk = fi.get('risk','?')
                    print(f"      [{risk}] {fi.get('method','')} {compact_url(fi.get('url',''))}")
                    for k in ["data_count","data_keys","credential_leak","file_leak","file_score","file_magic","content_type","content_disposition","body_size"]:
                        if k in fi: print(f"        {k}: {str(fi[k])[:100]}")
    observation_targets = [t for t in target_map.values() if t.get("observations")]
    confirmed_targets = [t for t in candidate_targets if any(is_confirmed_finding(fi) for fi in t.get("findings", []))]
    print(f"\n  Phase 3 DONE: confirmed={len(confirmed_targets)} candidates={len(candidate_targets)} observations={len(observation_targets)}")

    for base, target in sorted(target_map.items()):
        target["api_coverage"] = coverage_tracker.snapshot(base)
        write_target_result(target)
    api_coverage = coverage_tracker.global_snapshot()
    api_inventory_total = int(api_coverage.get("valid_inventory_apis") or 0)
    api_coverage_by_target = [
        {"target_id": _hash_text(base), "coverage": coverage_tracker.snapshot(base)}
        for base in sorted(target_map)
    ]
    with open(os.path.join(OUTDIR, API_COVERAGE_CHECKPOINT_NAME), "w", encoding="utf-8") as f:
        json.dump({
            "schema_version": 1,
            "api_inventory_total": api_inventory_total,
            "api_coverage": api_coverage,
            "api_coverage_by_target": api_coverage_by_target,
        }, f, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)

    # Phase 4: 报告 (JSON + Markdown)
    print(f"\n[Phase 4] 报告生成")
    by_base = {}
    if args.resume:
        by_base.update({v["base"]: v for v in load_checkpoint_results()})
    for v in candidate_targets:
        by_base[v["base"]] = v
    candidate_targets = sorted(by_base.values(), key=lambda x: x.get("base", ""))
    observation_targets = sorted(observation_targets, key=lambda x: x.get("base", ""))
    confirmed_targets = sorted([t for t in candidate_targets if any(is_confirmed_finding(fi) for fi in t.get("findings", []))], key=lambda x: x.get("base", ""))
    stats = report_stats(candidate_targets, observation_targets, confirmed_targets)
    stats["api_inventory_total"] = api_inventory_total
    stats["api_coverage"] = api_coverage
    report = {"scan_time":time.strftime("%Y-%m-%d %H:%M:%S"),"targets":len(targets),"live":len(live),
              "schema_version":2,"apis":len(api_results),"vulnerable":len(confirmed_targets),
              "api_inventory_total":api_inventory_total,"api_coverage":api_coverage,
              "api_coverage_by_target":api_coverage_by_target,
              "candidate_targets":len(candidate_targets),"observation_targets":len(observation_targets),
              "raw_events":stats["raw_events"],"aggregated_findings":stats["aggregated_findings"],
              "stats":stats,"findings":[],"observations":[]}
    for v in candidate_targets:
        report["findings"].append({
            "url":v["base"],"title":v.get("title",""),
            "js_intel": sorted(v.get("sensitive") or v.get("js_intel") or [])[:100],
            "raw_events":v.get("raw_event_count", sum(int(fi.get("variant_count") or 1) for fi in v.get("findings", []))),
            "aggregated_findings":v.get("finding_count", len(v.get("findings", []))),
            "findings":v.get("findings",[]),
        })
    for v in observation_targets:
        report["observations"].append({
            "url":v["base"],"title":v.get("title",""),
            "observations":v.get("observations", []),
        })
    report = maybe_redact_raw_findings(report)
    with open(os.path.join(OUTDIR,"report.json"),"w") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)

    # Markdown
    file_leak_count = stats["file_leaks"]
    md = [f"# 扫描报告 v13 / schema v2\n\n**时间**: {report['scan_time']} | **目标**: {report['targets']} | **存活**: {report['live']} | **API**: {report['apis']} | **确认漏洞**: {report['vulnerable']} | **候选目标**: {report['candidate_targets']} | **观察目标**: {report['observation_targets']} | **文件类候选**: {file_leak_count}\n"]
    md.append(
        "\n## 统计口径\n\n"
        f"- raw_events: {stats['raw_events']}（原始命中事件口径，含同端点多 query / 多绕过命中）\n"
        f"- aggregated_findings: {stats['aggregated_findings']}（聚合后报告口径，每条保留最高价值代表命中）\n"
        f"- unique_endpoints: {stats['unique_endpoints']}（按 URL path 去重端点）\n"
        f"- merged_variants: {stats['merged_variants']}（被聚合进代表 finding 的命中事件）\n"
        f"- 数据类发现: {stats['data_findings']} / 去重数据端点: {stats['unique_data_endpoints']}\n"
        f"- 高价值发现: {stats['high_value_findings']}\n"
        f"- 文件类发现: {stats['file_leaks']} / 公开下载情报: {stats['public_download_intel']}\n"
        f"- confirmed_findings: {stats['confirmed_findings']} / exposure_candidates: {stats['exposure_candidates']} / observations: {stats['observations']}\n"
        f"- catch_all_suppressed: {stats['catch_all_suppressed']}\n"
        f"- JS 情报: {stats['js_intel']}\n"
    )
    coverage_reasons = ", ".join(api_coverage.get("incomplete_reasons") or []) or "none"
    md.append(
        "\n## API 覆盖（仅聚合计数）\n\n"
        f"- api_inventory_total: {api_inventory_total}\n"
        f"- independently_exact_discovered: {api_coverage['independently_exact_discovered']}\n"
        f"- safe_eligible_exact: {api_coverage['safe_eligible_exact']}\n"
        f"- scheduled_unique_exact: {api_coverage['scheduled_unique_exact']}\n"
        f"- attempted_unique_exact: {api_coverage['attempted_unique_exact']}\n"
        f"- completed_unique_exact: {api_coverage['completed_unique_exact']}\n"
        f"- exact_get_eligible/scheduled/attempted/completed: {api_coverage['exact_get_eligible']}/{api_coverage['exact_get_scheduled']}/{api_coverage['exact_get_attempted']}/{api_coverage['exact_get_completed']}\n"
        f"- exact_get_skipped budget/timeout/cap: {api_coverage['exact_get_skipped_by_request_budget']}/{api_coverage['exact_get_skipped_by_timeout']}/{api_coverage['exact_get_skipped_by_exact_cap']}\n"
        f"- exact_post_eligible/scheduled/attempted/completed: {api_coverage['exact_post_eligible']}/{api_coverage['exact_post_scheduled']}/{api_coverage['exact_post_attempted']}/{api_coverage['exact_post_completed']}\n"
        f"- exact_post_empty_body eligible/scheduled/attempted/completed: {api_coverage['exact_post_empty_body_eligible']}/{api_coverage['exact_post_empty_body_scheduled']}/{api_coverage['exact_post_empty_body_attempted']}/{api_coverage['exact_post_empty_body_completed']}\n"
        f"- exact_post_bound_body eligible/scheduled/attempted/completed: {api_coverage['exact_post_bound_body_eligible']}/{api_coverage['exact_post_bound_body_scheduled']}/{api_coverage['exact_post_bound_body_attempted']}/{api_coverage['exact_post_bound_body_completed']}\n"
        f"- exact_post_skipped budget/timeout/cap: {api_coverage['exact_post_skipped_by_request_budget']}/{api_coverage['exact_post_skipped_by_timeout']}/{api_coverage['exact_post_skipped_by_exact_cap']}\n"
        f"- skipped_by_safety: {json.dumps(api_coverage['skipped_by_safety'], ensure_ascii=False, sort_keys=True)}\n"
        f"- skipped_by_request_budget: {api_coverage['skipped_by_request_budget']}\n"
        f"- skipped_by_timeout: {api_coverage['skipped_by_timeout']}\n"
        f"- replay_exact_discovered/scheduled/attempted/completed/skipped_by_cap: {api_coverage['replay_exact_discovered']}/{api_coverage['replay_exact_scheduled']}/{api_coverage['replay_exact_attempted']}/{api_coverage['replay_exact_completed']}/{api_coverage['replay_skipped_by_cap']}\n"
        f"- heuristic_scheduled/attempted: {api_coverage['heuristic_scheduled']}/{api_coverage['heuristic_attempted']}\n"
        f"- coverage_complete: {str(api_coverage['coverage_complete']).lower()} (reasons: {coverage_reasons})\n"
        "- legacy report.apis remains the target/base record count.\n"
    )
    if candidate_targets:
        md.append("\n## 暴露候选汇总（未做登录态对比，均非 confirmed）\n\n| # | 风险 | URL | 标题 | raw_events | aggregated_findings |\n|---|------|-----|------|------------|---------------------|")
        for i, v in enumerate(candidate_targets):
            risks = [fi.get('risk','LOW') for fi in v.get('findings',[])]
            top = 'CRITICAL' if 'CRITICAL' in risks else 'HIGH' if 'HIGH' in risks else 'MEDIUM' if 'MEDIUM' in risks else 'LOW'
            raw_event_count = v.get("raw_event_count", sum(int(fi.get("variant_count") or 1) for fi in v.get("findings", [])))
            md.append(f"| {i+1} | {top} | {v['base']} | {v.get('title','')[:30]} | {raw_event_count} | {v.get('finding_count',0)} |")
        md.append("\n## 详细发现\n")
        for i, v in enumerate(candidate_targets):
            md.append(f"### [{i+1}] {v['base']} — {v.get('title','')}")
            js_intel = sorted(v.get("sensitive") or v.get("js_intel") or [])[:10]
            if js_intel:
                md.append("- JS 情报:")
                for item in js_intel:
                    md.append(f"  - `{item}`")
            for fi in v.get('findings',[])[:5]:
                display_fi = maybe_redact_raw_findings(fi)
                md.append(f"- `{display_fi.get('method','')}` [{display_fi.get('risk','?')}] {display_fi.get('url','')}")
                if display_fi.get('data_count'): md.append(f"  - 数据量: {display_fi['data_count']}")
                if display_fi.get('data_keys'): md.append(f"  - 字段: {', '.join(display_fi['data_keys'][:8])}")
                if display_fi.get('variant_count', 1) > 1: md.append(f"  - 聚合命中: {display_fi.get('variant_count')} 个变体")
                if display_fi.get('tests'): md.append(f"  - 绕过方法: {', '.join(display_fi.get('tests', [])[:8])}")
                if display_fi.get('credential_leak'): md.append(f"  - ⚠️ 凭证泄露")
                if display_fi.get('file_leak'):
                    label = "公开下载情报" if display_fi.get("public_download_intel") else "文件泄露"
                    md.append(f"  - {label}: 评分 {display_fi.get('file_score')} | 类型: {display_fi.get('content_type','')[:80]} | 魔数: {display_fi.get('file_magic') or '-'} | 大小: {display_fi.get('body_size')}")
                    if display_fi.get('content_disposition'): md.append(f"  - 文件名/下载头: {display_fi.get('content_disposition')[:160]}")
            md.append("")
    else:
        md.append("\n未发现确认漏洞或暴露候选。\n")

    bypass_counts = {}
    for v in candidate_targets:
        for fi in v.get('findings',[]):
            tests = fi.get('tests') or ([fi.get('test')] if fi.get('test') else ["?"])
            for t in tests:
                bypass_counts[t] = bypass_counts.get(t,0)+1
    if bypass_counts:
        md.append("\n## 绕过方法统计\n\n| 方法 | 命中次数 |\n|------|----------|")
        for t, c in sorted(bypass_counts.items(), key=lambda x:-x[1]): md.append(f"| {t} | {c} |")
    with open(os.path.join(OUTDIR,"report.md"),"w") as f:
        f.write('\n'.join(md))

    print(f"  报告: {OUTDIR}/report.json, {OUTDIR}/report.md")
    elapsed = time.time() - t_start if 't_start' in dir() else 0
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE: {len(targets)}→{len(live)}→{len(api_results)}→confirmed:{len(confirmed_targets)} candidates:{len(candidate_targets)} observations:{len(observation_targets)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    raise SystemExit(main() or 0)

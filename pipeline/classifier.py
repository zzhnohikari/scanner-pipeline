"""Safe response classifier for unauth/IDOR-style API triage.

The classifier is the admission gate for Phase 3 findings.  It returns compact
signals only and intentionally never returns raw response bodies/snippets.
"""

import ipaddress
import json
import re
from typing import Any, Dict, Iterable, List, Tuple

AUTH_FAIL_PHRASES = [
    "unauthorized", "forbidden", "not authorized", "permission denied",
    "access denied", "login required", "please login", "not logged in",
    "token invalid", "invalid token", "token expired", "missing token",
    "no token", "jwt expired", "signature invalid",
    "未登录", "请登录", "登录已过期", "登录超时", "无权限", "未授权",
    "权限不足", "token失效", "令牌无效", "缺少令牌", "请先登录",
]

SUCCESS_CODES = {"0", "200", "20000", "success", "true", "ok"}
AUTH_FAIL_CODES = {"401", "403", "10031", "40001", "500002", "unauthorized", "forbidden"}
ERROR_STATES = {"false", "error", "fail", "failed", "failure", "nok", "no"}
DATA_KEYS = {"data", "records", "list", "items", "rows", "result", "payload", "page", "datas"}
LIST_KEYS = {"records", "list", "items", "rows"}
COUNT_KEYS = {"total", "count", "pagetotal", "totalcount", "recordstotal", "totalelements"}
ENVELOPE_MESSAGE_KEYS = {"msg", "message", "error", "errormsg", "errormessage", "detail", "reason", "repmsg"}
VOLATILE_OR_ERROR_KEYS = {"path", "uri", "time", "timestamp", "requestid", "traceid", "spanid", "correlationid", "error", "status", "msg", "message"}
ENVELOPE_OR_METADATA_KEYS = {
    "code", "status", "statuscode", "retcode", "state", "success",
    "msg", "message", "error", "errormsg", "errormessage", "detail",
    "reason", "repmsg", "path", "uri", "time", "timestamp", "requestid",
    "traceid", "spanid", "correlationid",
    "total", "count", "pagetotal", "totalcount", "recordstotal",
    "totalelements", "pageno", "pagenum", "pageindex", "pagesize",
    "page", "pages", "size", "limit", "offset", "current",
}
EMPTY_VALUE_STRINGS = {"", "null", "none", "nil", "undefined", "n/a", "na", "-", "--", "—", "无", "暂无"}
SENSITIVE_FIELD_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("phone", re.compile(r"phone|mobile|tel|手机号|电话", re.I)),
    ("idCard", re.compile(r"idcard|identity|cert(?:ificate)?no|身份证", re.I)),
    ("address", re.compile(r"address|addr|location|住址|地址", re.I)),
    ("token", re.compile(r"(?:^|_)(?:token|jwt|session)(?:$|_)|accessToken|appToken|refreshToken", re.I)),
    ("secret", re.compile(r"password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|密钥|密码", re.I)),
    ("appToken", re.compile(r"apptoken", re.I)),
    ("accessToken", re.compile(r"accesstoken", re.I)),
    ("openid", re.compile(r"openid", re.I)),
    ("unionid", re.compile(r"unionid", re.I)),
    ("orderId", re.compile(r"orderid|order_no|orderno|订单", re.I)),
    ("bankCard", re.compile(r"bankcard|bank_card|cardno|银行卡", re.I)),
    ("rtsp", re.compile(r"rtsp|streamurl|playurl|liveurl", re.I)),
    ("fileUrl", re.compile(r"fileurl|downloadurl|attachment|ossurl|file_path|filepath", re.I)),
]
INTERNAL_IP_RE = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
RTSP_RE = re.compile(r"rtsp://[^\s'\"<>]{3,200}", re.I)
FILE_URL_RE = re.compile(r"https?://[^\s'\"<>]+\.(?:pdf|docx?|xlsx?|zip|rar|7z|jpg|jpeg|png|mp4|mov)(?:\?[^\s'\"<>]*)?", re.I)
JWT_LIKE_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]*\b")
FRAMEWORK_NOT_FOUND_RE = re.compile(
    r"controller not exists|method not exists|class not exists|module not exists|route not found|not found|404",
    re.I,
)


def _safe_json_load(body: Any) -> Any:
    if isinstance(body, (dict, list)):
        return body
    if isinstance(body, bytes):
        body = body.decode("utf-8", "ignore")
    if not isinstance(body, str):
        return None
    text = body.strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _lower_key_map(obj: Dict[str, Any]) -> Dict[str, str]:
    return {str(k).lower(): str(k) for k in obj.keys()}


def _get_ci(obj: Any, key: str, default: Any = None) -> Any:
    if not isinstance(obj, dict):
        return default
    actual = _lower_key_map(obj).get(key.lower())
    return obj.get(actual) if actual is not None else default


def _is_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        return value.strip().lower() not in EMPTY_VALUE_STRINGS
    if isinstance(value, (list, tuple, set)):
        return any(_is_meaningful_value(v) for v in value)
    if isinstance(value, dict):
        return any(_is_meaningful_value(v) for v in value.values())
    return True


def _iter_items(obj: Any, depth: int = 0) -> Iterable[Tuple[str, Any]]:
    if depth > 5:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield str(key), value
            if isinstance(value, (dict, list)):
                yield from _iter_items(value, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:20]:
            if isinstance(item, (dict, list)):
                yield from _iter_items(item, depth + 1)


def _envelope_message_text(parsed: Any) -> str:
    """Return message-like text from envelopes/wrappers only.

    Business records under data/result/list/items/rows are intentionally skipped
    so record.message='Access Denied for user X' remains valid data.
    """
    parts: List[str] = []

    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 3 or not isinstance(obj, dict):
            return
        for key, value in obj.items():
            lower = str(key).lower()
            if lower in DATA_KEYS:
                # Data/result/list/items/rows are business payload containers,
                # not auth wrappers.  Do not inspect record-level message/error
                # fields here; otherwise a legitimate row such as
                # {"message": "Access Denied for user X", "phone": "..."}
                # would be rejected before data/credential admission.
                continue
            if lower in ENVELOPE_MESSAGE_KEYS and not isinstance(value, (dict, list)):
                parts.append(str(value))
            elif lower in {"status", "meta", "response", "errorinfo"} and isinstance(value, dict):
                walk(value, depth + 1)

    walk(parsed)
    return " ".join(parts)[:2000]


def _has_auth_phrase(text: str) -> bool:
    lowered = (text or "").lower()
    return any(p.lower() in lowered for p in AUTH_FAIL_PHRASES)


def _business_code(parsed: Any) -> str:
    if not isinstance(parsed, dict):
        return ""
    for key in ("code", "retCode", "statusCode"):
        value = _get_ci(parsed, key)
        if value is not None:
            return str(value)
    status = _get_ci(parsed, "status")
    if isinstance(status, dict):
        for key in ("code", "statusCode"):
            value = _get_ci(status, key)
            if value is not None:
                return str(value)
    if status is not None and not isinstance(status, (dict, list)):
        return str(status)
    return ""


def _business_state(parsed: Any) -> str:
    if not isinstance(parsed, dict):
        return ""
    success = _get_ci(parsed, "success")
    if isinstance(success, bool):
        return "success" if success else "error"
    if success is not None and str(success).strip().lower() in SUCCESS_CODES:
        return "success"
    if success is not None and str(success).strip().lower() in ERROR_STATES:
        return "error"
    code = _business_code(parsed).strip()
    lowered = code.lower()
    if lowered in AUTH_FAIL_CODES:
        return "auth"
    if lowered in SUCCESS_CODES:
        return "success"
    if lowered in ERROR_STATES:
        return "error"
    try:
        return "error" if int(float(code)) >= 400 else ("success" if int(float(code)) in (0, 200, 20000) else "")
    except Exception:
        return ""


def _explicit_business_error(parsed: Any) -> bool:
    if not isinstance(parsed, dict):
        return False
    success = _get_ci(parsed, "success")
    if isinstance(success, bool) and success is False:
        return True
    if success is not None and str(success).strip().lower() in ERROR_STATES:
        return True
    for key in ("code", "retCode", "statusCode", "status", "state"):
        value = _get_ci(parsed, key)
        if isinstance(value, dict):
            value = _get_ci(value, "code")
        if value is None or isinstance(value, (dict, list)):
            continue
        lowered = str(value).strip().lower()
        if lowered in ERROR_STATES:
            return True
        try:
            if int(float(lowered)) >= 400:
                return True
        except Exception:
            pass
    return False


def _framework_not_found(parsed: Any, status_int: int = 0) -> bool:
    if not isinstance(parsed, dict):
        return False
    text = _envelope_message_text(parsed)
    if status_int == 404 and text:
        return True
    if FRAMEWORK_NOT_FOUND_RE.search(text or ""):
        data = _get_ci(parsed, "data")
        if isinstance(data, dict):
            lower_keys = {str(k).lower() for k in data.keys()}
            if {"trace", "file", "line"} & lower_keys:
                return True
        return True
    return False


def _nonempty_data_signal(obj: Any, depth: int = 0) -> Tuple[bool, Dict[str, Any]]:
    if depth > 5:
        return False, {}
    if isinstance(obj, list):
        meaningful = 0
        first_signal: Dict[str, Any] = {}
        for item in obj:
            ok, signal = _nonempty_data_signal(item, depth + 1)
            if ok:
                meaningful += 1
                if not first_signal:
                    first_signal = signal
        if meaningful:
            signal = dict(first_signal or {})
            signal.setdefault("container", "list")
            signal["count"] = meaningful
            return True, signal
        return False, {}
    if not isinstance(obj, dict):
        return (_is_meaningful_value(obj), {"container": "scalar", "count": 1} if _is_meaningful_value(obj) else {})

    for key, value in obj.items():
        lower = str(key).lower()
        if lower in LIST_KEYS and isinstance(value, list):
            child_ok, child = _nonempty_data_signal(value, depth + 1)
            if child_ok:
                child["container"] = str(key)
                return True, child
    for key, value in obj.items():
        lower = str(key).lower()
        if lower not in DATA_KEYS:
            continue
        if isinstance(value, list):
            child_ok, child = _nonempty_data_signal(value, depth + 1)
            if child_ok:
                child["container"] = str(key)
                return True, child
            continue
        if isinstance(value, dict):
            child_ok, child = _nonempty_data_signal(value, depth + 1)
            if child_ok:
                child.setdefault("container", str(key))
                return True, child
            meaningful = [
                str(k) for k, v in value.items()
                if str(k).lower() not in ENVELOPE_OR_METADATA_KEYS and _is_meaningful_value(v)
            ]
            if meaningful:
                return True, {"container": str(key), "keys": sorted(meaningful)[:20]}
            continue
        elif lower not in ENVELOPE_OR_METADATA_KEYS and _is_meaningful_value(value):
            return True, {"container": str(key), "count": 1, "scalar": True}

    meaningful_root = [
        str(k) for k, v in obj.items()
        if str(k).lower() not in ENVELOPE_OR_METADATA_KEYS
        and str(k).lower() not in DATA_KEYS
        and str(k).lower() not in LIST_KEYS
        and _is_meaningful_value(v)
    ]
    if meaningful_root:
        return True, {"container": "object", "keys": sorted(meaningful_root)[:20]}
    return False, {}


def _sensitive_fields(parsed: Any) -> List[str]:
    found = set()
    for key, value in _iter_items(parsed):
        if not _is_meaningful_value(value):
            continue
        for name, pattern in SENSITIVE_FIELD_PATTERNS:
            if pattern.search(key):
                found.add(name)
    return sorted(found)


def _text_signals(body: Any) -> List[str]:
    if isinstance(body, bytes):
        text = body.decode("utf-8", "ignore")
    elif isinstance(body, str):
        text = body
    else:
        text = json.dumps(body, ensure_ascii=False) if body is not None else ""
    signals = set()
    if RTSP_RE.search(text):
        signals.add("rtsp")
    if FILE_URL_RE.search(text):
        signals.add("fileUrl")
    if JWT_LIKE_RE.search(text):
        signals.add("token")
    for ip in INTERNAL_IP_RE.findall(text):
        try:
            if ipaddress.ip_address(ip).is_private:
                signals.add("internalIp")
                break
        except Exception:
            pass
    return sorted(signals)


def _risk(sensitive: List[str], text_signals: List[str], data_signal: Dict[str, Any], verdict: str) -> str:
    if verdict in {"auth_failed", "http_error", "business_error", "framework_not_found", "catch_all"}:
        return "LOW"
    names = set(sensitive) | set(text_signals)
    if {"token", "accessToken", "appToken", "bankCard"} & names:
        return "CRITICAL"
    if {"idCard", "phone", "rtsp", "internalIp", "fileUrl"} & names:
        return "HIGH"
    if data_signal:
        return "MEDIUM"
    return "LOW"


def classify_response(status: int, body: Any, headers: Dict[str, str] = None, catch_all_match: bool = False) -> Dict[str, Any]:
    """Classify an HTTP response without returning raw response content.

    Admission order:
      envelope auth failure -> any HTTP non-2xx -> explicit business error ->
      framework not-found -> stable catch-all -> meaningful data/credential ->
      unknown.
    """
    headers = headers or {}
    try:
        status_int = int(status or 0)
    except Exception:
        status_int = 0
    parsed = _safe_json_load(body)
    envelope_text = _envelope_message_text(parsed) if parsed is not None else ""
    code = _business_code(parsed)
    business_state = _business_state(parsed)
    reasons: List[str] = []

    auth_failed = status_int in (401, 403) or str(code).strip().lower() in AUTH_FAIL_CODES or _has_auth_phrase(envelope_text)
    if auth_failed:
        verdict, confidence = "auth_failed", 0.93
        reasons.append("envelope_auth_failure")
        data_ok, data_signal = False, {}
        sensitive, signals = [], []
    elif status_int and not (200 <= status_int < 300):
        verdict, confidence = "http_error", 0.92
        reasons.append("http_non_2xx")
        data_ok, data_signal = False, {}
        sensitive, signals = [], []
    elif _explicit_business_error(parsed):
        verdict, confidence = "business_error", 0.90
        reasons.append("business_error_state")
        data_ok, data_signal = False, {}
        sensitive, signals = [], []
    elif _framework_not_found(parsed, status_int):
        verdict, confidence = "framework_not_found", 0.88
        reasons.append("framework_not_found")
        data_ok, data_signal = False, {}
        sensitive, signals = [], []
    elif catch_all_match:
        verdict, confidence = "catch_all", 0.86
        reasons.append("stable_catch_all_match")
        data_ok, data_signal = False, {}
        sensitive, signals = [], []
    else:
        data_ok, data_signal = _nonempty_data_signal(parsed) if parsed is not None else (False, {})
        if data_ok:
            reasons.append("meaningful_data")
        if business_state == "success":
            reasons.append("success_business_state")
        sensitive = _sensitive_fields(parsed) if parsed is not None else []
        signals = _text_signals(body)
        if sensitive:
            reasons.append("meaningful_sensitive_fields")
        if signals:
            reasons.append("sensitive_value_patterns")

        content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
        if any(x in content_type for x in ("pdf", "octet-stream", "zip", "image/", "video/")):
            signals = sorted(set(signals) | {"fileOrStream"})
            reasons.append("file_or_stream_content_type")

        if data_ok:
            verdict = "success_data"
            confidence = 0.86 if (sensitive or signals) else 0.74
        elif sensitive or signals:
            verdict = "sensitive_signal"
            confidence = 0.72
        else:
            verdict = "unknown"
            confidence = 0.35

    return {
        "verdict": verdict,
        "risk": _risk(sensitive, signals, data_signal, verdict),
        "confidence": confidence,
        "reasons": sorted(set(reasons)),
        "sensitive_fields": sensitive,
        "data_signals": data_signal,
        "business_state": business_state,
    }

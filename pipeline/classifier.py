"""Safe response classifier for unauth/IDOR-style API triage.

The classifier returns compact signals only. It intentionally never returns raw
response bodies or body snippets so callers can persist summaries safely.
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
ERROR_CODES = {"404", "500", "501", "502", "503", "false", "error", "fail", "failed"}
DATA_KEYS = {"data", "records", "list", "items", "rows", "result", "payload", "page"}
COUNT_KEYS = {"total", "count", "pageTotal", "totalCount", "recordsTotal"}
SENSITIVE_FIELD_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("phone", re.compile(r"phone|mobile|tel|手机号|电话", re.I)),
    ("idCard", re.compile(r"idcard|identity|cert(?:ificate)?no|身份证", re.I)),
    ("address", re.compile(r"address|addr|location|住址|地址", re.I)),
    ("token", re.compile(r"(?:^|_)(?:token|jwt|session)(?:$|_)|accessToken|appToken|refreshToken", re.I)),
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


def _business_code(parsed: Any) -> str:
    if not isinstance(parsed, dict):
        return ""
    for key in ("code", "retCode", "statusCode"):
        if parsed.get(key) is not None:
            return str(parsed.get(key))
    status = parsed.get("status")
    if isinstance(status, dict) and status.get("code") is not None:
        return str(status.get("code"))
    if status is not None and not isinstance(status, (dict, list)):
        return str(status)
    return ""


def _message_text(parsed: Any) -> str:
    if isinstance(parsed, dict):
        parts = []
        for key, value in _iter_items(parsed):
            if key.lower() in {"msg", "message", "error", "errormsg", "errormessage", "detail", "reason"}:
                parts.append(str(value))
        return " ".join(parts)[:2000]
    return ""


def _has_auth_phrase(text: str) -> bool:
    lowered = (text or "").lower()
    return any(p.lower() in lowered for p in AUTH_FAIL_PHRASES)


def _nonempty_data_signal(obj: Any, depth: int = 0) -> Tuple[bool, Dict[str, Any]]:
    if depth > 4:
        return False, {}
    if isinstance(obj, list):
        return bool(obj), {"container": "list", "count": len(obj)} if obj else {}
    if not isinstance(obj, dict):
        return False, {}
    for key in ("records", "list", "items", "rows"):
        value = obj.get(key)
        if isinstance(value, list) and value:
            return True, {"container": key, "count": len(value)}
    for key in ("data", "result", "payload", "page"):
        if key in obj:
            value = obj.get(key)
            if isinstance(value, list) and value:
                return True, {"container": key, "count": len(value)}
            if isinstance(value, dict):
                child_ok, child = _nonempty_data_signal(value, depth + 1)
                if child_ok:
                    child.setdefault("container", key)
                    return True, child
                meaningful = set(value.keys()) - {"path", "time", "timestamp", "error", "status", "msg", "message"}
                if meaningful:
                    return True, {"container": key, "keys": sorted(map(str, list(meaningful)))[:20]}
    if any(k in obj for k in COUNT_KEYS):
        try:
            count = max(int(obj.get(k) or 0) for k in COUNT_KEYS if obj.get(k) is not None)
        except Exception:
            count = 0
        if count > 0:
            return True, {"container": "count", "count": count}
    return False, {}


def _sensitive_fields(parsed: Any) -> List[str]:
    found = set()
    for key, _value in _iter_items(parsed):
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
    for ip in INTERNAL_IP_RE.findall(text):
        try:
            if ipaddress.ip_address(ip).is_private:
                signals.add("internalIp")
                break
        except Exception:
            pass
    return sorted(signals)


def _risk(sensitive: List[str], text_signals: List[str], data_signal: Dict[str, Any], verdict: str) -> str:
    if verdict == "auth_failed":
        return "LOW"
    names = set(sensitive) | set(text_signals)
    if {"token", "accessToken", "appToken", "bankCard"} & names:
        return "CRITICAL"
    if {"idCard", "phone", "rtsp", "internalIp", "fileUrl"} & names:
        return "HIGH"
    if data_signal:
        return "MEDIUM"
    return "LOW"


def classify_response(status: int, body: Any, headers: Dict[str, str] = None) -> Dict[str, Any]:
    """Classify an HTTP response without returning raw response content."""
    headers = headers or {}
    try:
        status_int = int(status or 0)
    except Exception:
        status_int = 0
    parsed = _safe_json_load(body)
    text_for_auth = _message_text(parsed) if parsed is not None else (body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body or ""))[:4000]
    code = _business_code(parsed)
    reasons: List[str] = []

    auth_failed = status_int in (401, 403) or code in AUTH_FAIL_CODES or _has_auth_phrase(text_for_auth)
    if auth_failed:
        reasons.append("auth_failure_signal")

    data_ok, data_signal = _nonempty_data_signal(parsed) if parsed is not None else (False, {})
    if data_ok:
        reasons.append("nonempty_data_container")
    if code and code in SUCCESS_CODES:
        reasons.append("success_business_code")
    elif code and code in ERROR_CODES:
        reasons.append("error_business_code")

    sensitive = _sensitive_fields(parsed) if parsed is not None else []
    signals = _text_signals(body)
    if sensitive:
        reasons.append("sensitive_field_names")
    if signals:
        reasons.append("sensitive_value_patterns")

    content_type = str(headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if any(x in content_type for x in ("pdf", "octet-stream", "zip", "image/", "video/")):
        signals = sorted(set(signals) | {"fileOrStream"})
        reasons.append("file_or_stream_content_type")

    if auth_failed:
        verdict = "auth_failed"
        confidence = 0.9
    elif data_ok or (code in SUCCESS_CODES and (sensitive or signals)):
        verdict = "success_data"
        confidence = 0.86 if (sensitive or signals) else 0.72
    elif sensitive or signals:
        verdict = "sensitive_signal"
        confidence = 0.7
    elif status_int >= 400 or code in ERROR_CODES:
        verdict = "empty_or_error"
        confidence = 0.66
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
    }

"""Target input parsing and optional external preflight tool integration."""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile


def input_item(url, title="", score=0):
    url = str(url or "").strip()
    if not url:
        return None
    return (url, str(title or ""), score or 0)


def dedupe_targets(items):
    seen, out = set(), []
    for item in items or []:
        if not item:
            continue
        key = item[0]
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def parse_masscan_item(obj):
    if not isinstance(obj, dict):
        return []
    host = obj.get("ip") or obj.get("host") or obj.get("addr")
    ports = obj.get("ports") or []
    out = []
    if host and isinstance(ports, list):
        for port_obj in ports:
            if not isinstance(port_obj, dict):
                continue
            port = port_obj.get("port")
            proto = str(port_obj.get("proto") or port_obj.get("protocol") or "tcp").lower()
            if port and proto == "tcp":
                item = input_item(f"{host}:{port}", "masscan", 0)
                if item:
                    out.append(item)
    port = obj.get("port")
    if host and port:
        item = input_item(f"{host}:{port}", "masscan", 0)
        if item:
            out.append(item)
    return out


def load_targets(path, input_format):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    targets = []
    if input_format == "targets":
        stripped = raw.strip()
        data = None
        if stripped.startswith("[") or stripped.startswith("{"):
            data = json.loads(stripped)
            if isinstance(data, dict):
                data = data.get("targets") or data.get("items") or data.get("data") or []
        if data is not None:
            for t in data:
                if isinstance(t, str):
                    item = input_item(t)
                else:
                    item = input_item(t.get("url"), t.get("title", ""), t.get("score", 0))
                if item:
                    targets.append(item)
            return targets
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            item = input_item(parts[0])
            if item:
                targets.append(item)
    elif input_format == "hostport":
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            item = input_item(parts[0], "hostport", 0)
            if item:
                targets.append(item)
    elif input_format == "masscan":
        stripped = raw.strip()
        if stripped.startswith("["):
            for obj in json.loads(stripped):
                targets.extend(parse_masscan_item(obj))
        elif stripped.startswith("{"):
            for line in raw.splitlines():
                line = line.strip().rstrip(",")
                if not line or not line.startswith("{"):
                    continue
                try:
                    targets.extend(parse_masscan_item(json.loads(line)))
                except Exception:
                    continue
        else:
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                item = None
                if len(parts) >= 4 and parts[0].lower() == "open" and parts[1].lower() == "tcp" and parts[2].isdigit():
                    item = input_item(f"{parts[3]}:{parts[2]}", "masscan", 0)
                elif len(parts) >= 2 and parts[1].isdigit():
                    item = input_item(f"{parts[0]}:{parts[1]}", "masscan", 0)
                elif re.match(r"^[^:\s]+:\d+$", parts[0]):
                    item = input_item(parts[0], "masscan", 0)
                if item:
                    targets.append(item)
    elif input_format == "httpx-json":
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            item = input_item(
                obj.get("url") or obj.get("input") or obj.get("final_url"),
                obj.get("title", ""),
                obj.get("status_code", 0),
            )
            if item:
                targets.append(item)
    return targets


def resolve_tool(name, override=""):
    if override:
        if os.path.exists(override) or shutil.which(override):
            return override
        return ""
    candidates = [name]
    if os.name == "nt" and not name.lower().endswith(".exe"):
        candidates.append(name + ".exe")
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return ""


def require_tool(name, override=""):
    path = resolve_tool(name, override)
    if not path:
        raise RuntimeError(f"Missing external tool: {name}. Install it or pass --{name}-bin /path/to/{name}.")
    return path


def command_env(no_proxy=False):
    env = os.environ.copy()
    if no_proxy:
        for proxy_var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env.pop(proxy_var, None)
        env["NO_PROXY"] = "*"
    return env


def run_command(cmd, label, *, no_proxy=False, debug=False, log=None):
    if debug:
        print(f"  {label}: {' '.join(shlex.quote(str(c)) for c in cmd)}")
    proc = subprocess.run(cmd, text=True, capture_output=True, env=command_env(no_proxy=no_proxy))
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"{label} failed with exit {proc.returncode}: {detail[:1000]}")
    if debug and proc.stderr.strip() and log:
        log.debug(proc.stderr.strip()[:2000])
    return proc.stdout


def write_target_lines(path, targets):
    with open(path, "w", encoding="utf-8") as f:
        for target, _, _ in targets:
            if target:
                f.write(str(target).strip() + "\n")


def run_port_discovery(
    targets,
    *,
    port_scanner="none",
    masscan_bin="",
    naabu_bin="",
    scan_ports="",
    scan_rate=1000,
    no_proxy=False,
    debug=False,
    log=None,
):
    if port_scanner == "none":
        return targets
    scanner = port_scanner
    if scanner == "auto":
        if resolve_tool("masscan", masscan_bin):
            scanner = "masscan"
        elif resolve_tool("naabu", naabu_bin):
            scanner = "naabu"
        else:
            raise RuntimeError("No port scanner found in PATH. Install masscan/naabu or use --port-scanner none.")
    print(f"\n[Preflight] 端口发现: {scanner} ports={scan_ports} rate={scan_rate}")
    with tempfile.TemporaryDirectory(prefix="scanner_ports_") as tmp:
        in_path = os.path.join(tmp, "targets.txt")
        out_path = os.path.join(tmp, "ports.out")
        write_target_lines(in_path, targets)
        if scanner == "masscan":
            bin_path = require_tool("masscan", masscan_bin)
            cmd = [bin_path, "-iL", in_path, "-p", scan_ports, "--rate", str(scan_rate), "-oL", out_path]
            run_command(cmd, "masscan", no_proxy=no_proxy, debug=debug, log=log)
            discovered = load_targets(out_path, "masscan")
        elif scanner == "naabu":
            bin_path = require_tool("naabu", naabu_bin)
            cmd = [bin_path, "-list", in_path, "-p", scan_ports, "-rate", str(scan_rate), "-silent", "-o", out_path]
            run_command(cmd, "naabu", no_proxy=no_proxy, debug=debug, log=log)
            discovered = load_targets(out_path, "hostport")
        else:
            discovered = targets
    discovered = dedupe_targets(discovered)
    print(f"  端口发现结果: {len(discovered)} host:port")
    return discovered


def run_httpx_probe(
    targets,
    *,
    http_prober="internal",
    httpx_bin="",
    httpx_extra_args="",
    http_timeout=12,
    no_proxy=False,
    debug=False,
    log=None,
):
    if http_prober == "internal":
        return None
    bin_path = resolve_tool("httpx", httpx_bin)
    if http_prober == "auto" and not bin_path:
        print("\n[Preflight] HTTP探测: httpx not found, fallback to internal Phase 1")
        return None
    if not bin_path:
        raise RuntimeError("Missing external tool: httpx. Install ProjectDiscovery httpx or use --http-prober internal.")
    print(f"\n[Preflight] HTTP探测: httpx")
    with tempfile.TemporaryDirectory(prefix="scanner_httpx_") as tmp:
        in_path = os.path.join(tmp, "hostports.txt")
        out_path = os.path.join(tmp, "httpx.jsonl")
        write_target_lines(in_path, targets)
        cmd = [
            bin_path, "-l", in_path, "-json", "-silent", "-no-color",
            "-title", "-status-code", "-location", "-follow-host-redirects",
            "-timeout", str(max(1, http_timeout)), "-o", out_path,
        ]
        if httpx_extra_args:
            cmd.extend(shlex.split(httpx_extra_args))
        run_command(cmd, "httpx", no_proxy=no_proxy, debug=debug, log=log)
        discovered = load_targets(out_path, "httpx-json")
    discovered = dedupe_targets(discovered)
    print(f"  HTTP探测结果: {len(discovered)} live URLs")
    return [item[0] for item in discovered]

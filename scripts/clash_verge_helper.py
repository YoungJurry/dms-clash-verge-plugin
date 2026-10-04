#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml


APP_ID = "io.github.clash-verge-rev.clash-verge-rev"
DEFAULT_SOCKET_PATH = "/tmp/verge/verge-mihomo.sock"
MODE_VALUES = {"rule", "global", "direct"}
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
DEFAULT_DELAY_TEST_URL = "http://cp.cloudflare.com"
DEFAULT_DELAY_TIMEOUT_MS = 5000
IDENTITY_SCRIPT = """// Define main function (script entry)

function main(config, profileName) {
  return config;
}
"""


class HelperError(RuntimeError):
    pass


def data_home() -> Path:
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home)
    return Path.home() / ".local" / "share"


def detect_app_home() -> Path:
    env_home = os.environ.get("CLASH_VERGE_HOME")
    if env_home:
        return Path(env_home).expanduser()
    return data_home() / APP_ID


def yaml_mapping(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    default_value = deepcopy(default) if default is not None else {}
    if not path.exists():
        return default_value
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle)
    if loaded is None:
        return default_value
    if not isinstance(loaded, dict):
        raise HelperError(f"Expected YAML mapping in {path}")
    return loaded


def yaml_sequence_mapping(path: Path) -> dict[str, Any]:
    return yaml_mapping(path, {"prepend": [], "append": [], "delete": []})


def save_yaml(path: Path, payload: Any, header: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        if header:
            handle.write(f"{header}\n\n")
        yaml.safe_dump(payload, handle, allow_unicode=True, sort_keys=False)


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def deep_merge(base: Any, patch: Any) -> Any:
    if isinstance(base, dict) and isinstance(patch, dict):
        merged = dict(base)
        for key, value in patch.items():
            if key in merged:
                merged[key] = deep_merge(merged[key], value)
            else:
                merged[key] = deepcopy(value)
        return merged
    return deepcopy(patch)


def unique_names(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if isinstance(value, dict):
            name = value.get("name")
        else:
            name = value
        if isinstance(name, str) and name not in seen:
            seen.add(name)
            result.append(name)
    return result


def is_selector_group(group: dict[str, Any]) -> bool:
    group_type = str(group.get("type", "")).lower()
    return group_type in {"select", "selector"}


def apply_seq(seq_map: dict[str, Any], config: dict[str, Any], field: str) -> dict[str, Any]:
    prepend = list(seq_map.get("prepend") or [])
    append = list(seq_map.get("append") or [])
    delete = set(seq_map.get("delete") or [])

    existing = config.get(field) or []
    filtered_existing: list[Any] = []
    for item in existing:
        if isinstance(item, str):
            if item in delete:
                continue
        elif isinstance(item, dict):
            item_name = item.get("name")
            if isinstance(item_name, str) and item_name in delete:
                continue
        filtered_existing.append(deepcopy(item))

    merged_sequence = [deepcopy(item) for item in prepend]
    merged_sequence.extend(filtered_existing)
    merged_sequence.extend(deepcopy(item) for item in append)
    config[field] = merged_sequence

    if field != "proxies":
        return config

    added_proxy_names = unique_names(prepend + append)
    groups = config.get("proxy-groups")
    if not isinstance(groups, list):
        return config

    appended_to_selector = False
    for group in groups:
        if not isinstance(group, dict):
            continue
        proxies = group.get("proxies")
        if isinstance(proxies, list):
            group["proxies"] = [proxy for proxy in proxies if not (isinstance(proxy, str) and proxy in delete)]
        if appended_to_selector or not added_proxy_names or not is_selector_group(group):
            continue
        current_proxies = group.get("proxies") or []
        if not isinstance(current_proxies, list):
            current_proxies = []
        combined: list[str] = []
        seen: set[str] = set()
        for proxy_name in added_proxy_names + [item for item in current_proxies if isinstance(item, str)]:
            if proxy_name in seen:
                continue
            seen.add(proxy_name)
            combined.append(proxy_name)
        group["proxies"] = combined
        appended_to_selector = True

    return config


def cleanup_proxy_groups(config: dict[str, Any]) -> dict[str, Any]:
    proxies = config.get("proxies") or []
    proxy_groups = config.get("proxy-groups") or []
    proxy_providers = config.get("proxy-providers") or {}

    allowed = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
    for item in proxies:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            allowed.add(item["name"])
        elif isinstance(item, str):
            allowed.add(item)

    for item in proxy_groups:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            allowed.add(item["name"])

    if isinstance(proxy_providers, dict):
        allowed.update(name for name in proxy_providers.keys() if isinstance(name, str))

    for group in proxy_groups:
        if not isinstance(group, dict):
            continue
        use_values = group.get("use")
        has_provider = False
        if isinstance(use_values, list):
            filtered_use = []
            for provider_name in use_values:
                if isinstance(provider_name, str) and provider_name in proxy_providers:
                    filtered_use.append(provider_name)
                    has_provider = True
            group["use"] = filtered_use
        proxies_value = group.get("proxies")
        if isinstance(proxies_value, list):
            filtered_proxies = []
            for proxy_name in proxies_value:
                if not isinstance(proxy_name, str):
                    filtered_proxies.append(proxy_name)
                    continue
                if has_provider or proxy_name in allowed:
                    filtered_proxies.append(proxy_name)
            group["proxies"] = filtered_proxies

    return config


def apply_tun(config: dict[str, Any], enable_tun: bool) -> dict[str, Any]:
    tun_config = config.get("tun")
    if not isinstance(tun_config, dict):
        tun_config = {}

    if enable_tun:
        dns_config = config.get("dns")
        if not isinstance(dns_config, dict):
            dns_config = {}
        current_mode = str(dns_config.get("enhanced-mode", "fake-ip"))
        if current_mode == "fake-ip" or "enhanced-mode" not in dns_config:
            dns_config["enable"] = True
            dns_config["ipv6"] = bool(config.get("ipv6", False))
            dns_config.setdefault("enhanced-mode", "fake-ip")
            dns_config.setdefault("fake-ip-range", "198.18.0.1/16")
        config["dns"] = dns_config

    tun_config["enable"] = enable_tun
    config["tun"] = tun_config
    return config


def apply_dns_settings(ctx: dict[str, Path], config: dict[str, Any], enable_dns_settings: bool) -> dict[str, Any]:
    if not enable_dns_settings:
        return config
    dns_path = ctx["dns_path"]
    if not dns_path.exists():
        return config

    dns_yaml = yaml_mapping(dns_path, {})
    hosts_value = dns_yaml.get("hosts")
    if isinstance(hosts_value, dict):
        config["hosts"] = deepcopy(hosts_value)
    dns_value = dns_yaml.get("dns")
    if isinstance(dns_value, dict):
        config["dns"] = deepcopy(dns_value)
    elif dns_yaml:
        config["dns"] = deepcopy(dns_yaml)
    return config


def merge_default_config(config: dict[str, Any], clash_config: dict[str, Any], verge_config: dict[str, Any]) -> dict[str, Any]:
    socks_enabled = bool(verge_config.get("verge_socks_enabled", False))
    http_enabled = bool(verge_config.get("verge_http_enabled", False))
    redir_enabled = bool(verge_config.get("verge_redir_enabled", False))
    tproxy_enabled = bool(verge_config.get("verge_tproxy_enabled", False))
    enable_external_controller = bool(verge_config.get("enable_external_controller", False))

    for key, value in clash_config.items():
        if key == "tun":
            base_tun = config.get("tun")
            if not isinstance(base_tun, dict):
                base_tun = {}
            patch_tun = value if isinstance(value, dict) else {}
            base_tun.update(deepcopy(patch_tun))
            config["tun"] = base_tun
            continue

        if key == "socks-port" and not socks_enabled:
            config.pop("socks-port", None)
            continue
        if key == "port" and not http_enabled:
            config.pop("port", None)
            continue
        if key == "redir-port" and not redir_enabled:
            config.pop("redir-port", None)
            continue
        if key == "tproxy-port" and not tproxy_enabled:
            config.pop("tproxy-port", None)
            continue

        if key == "external-controller":
            config[key] = deepcopy(value) if enable_external_controller else ""
        else:
            config[key] = deepcopy(value)

    return config


def script_is_trivial(script_text: str) -> bool:
    normalized = "".join(script_text.split())
    return normalized in {
        "",
        "functionmain(config,profileName){returnconfig;}",
        "//Definemainfunction(scriptentry)functionmain(config,profileName){returnconfig;}",
    }


def run_script(script_text: str, config: dict[str, Any], profile_name: str) -> dict[str, Any]:
    if script_is_trivial(script_text):
        return config

    node_code = r"""
const fs = require('fs');
const vm = require('vm');

(async () => {
  const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
  const sandbox = {
    console: { log: () => {}, error: () => {}, warn: () => {} },
    setTimeout,
    clearTimeout,
    JSON,
    Math,
    Date
  };
  vm.createContext(sandbox);
  vm.runInContext(payload.script, sandbox, { timeout: 2000 });
  if (typeof sandbox.main !== 'function') {
    throw new Error('script does not define main(config, profileName)');
  }
  const result = await Promise.resolve(sandbox.main(payload.config, payload.profileName));
  const finalValue = result === undefined ? payload.config : result;
  process.stdout.write(JSON.stringify(finalValue));
})().catch((error) => {
  process.stderr.write(String(error && error.stack ? error.stack : error));
  process.exit(1);
});
"""

    payload = json.dumps(
        {"script": script_text, "config": config, "profileName": profile_name},
        ensure_ascii=False,
    )
    try:
        completed = subprocess.run(
            ["node", "-e", node_code],
            input=payload.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
    except FileNotFoundError as exc:
        raise HelperError("Node.js is required to run Clash Verge profile scripts") from exc

    if completed.returncode != 0:
        error_text = completed.stderr.decode("utf-8", errors="replace").strip()
        raise HelperError(f"Profile script failed: {error_text or completed.returncode}")

    try:
        result = json.loads(completed.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HelperError("Profile script returned invalid JSON") from exc

    if not isinstance(result, dict):
        raise HelperError("Profile script must return a mapping")
    return result


def unix_http_request(socket_path: Path, method: str, request_path: str, payload: Any | None = None) -> tuple[int, bytes]:
    body = b""
    headers = {
        "Host": "localhost",
        "Connection": "close",
        "Accept": "application/json",
    }
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))

    request_lines = [f"{method} {request_path} HTTP/1.1"]
    request_lines.extend(f"{key}: {value}" for key, value in headers.items())
    request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("utf-8") + body

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    try:
        client.connect(str(socket_path))
        client.sendall(request)
        response = bytearray()
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
    finally:
        client.close()

    header_bytes, _, body_bytes = bytes(response).partition(b"\r\n\r\n")
    header_lines = header_bytes.split(b"\r\n")
    if not header_lines:
        raise HelperError("Empty HTTP response from Mihomo socket")
    try:
        status_code = int(header_lines[0].decode("utf-8", errors="replace").split()[1])
    except Exception as exc:  # noqa: BLE001
        raise HelperError("Invalid HTTP status from Mihomo socket") from exc

    header_map: dict[str, str] = {}
    for raw_header in header_lines[1:]:
        if b":" not in raw_header:
            continue
        key, value = raw_header.split(b":", 1)
        header_map[key.decode("utf-8", errors="replace").strip().lower()] = value.decode(
            "utf-8",
            errors="replace",
        ).strip()

    if header_map.get("transfer-encoding", "").lower() == "chunked":
        body_bytes = decode_chunked_body(body_bytes)

    if status_code >= 400:
        body_text = body_bytes.decode("utf-8", errors="replace").strip()
        raise HelperError(f"Mihomo API error {status_code}: {body_text or request_path}")

    return status_code, body_bytes


def decode_chunked_body(body: bytes) -> bytes:
    decoded = bytearray()
    index = 0
    total = len(body)

    while index < total:
        line_end = body.find(b"\r\n", index)
        if line_end < 0:
            raise HelperError("Invalid chunked HTTP body")

        size_text = body[index:line_end].split(b";", 1)[0].strip()
        if not size_text:
            raise HelperError("Invalid chunk size in chunked HTTP body")

        try:
            chunk_size = int(size_text.decode("ascii"), 16)
        except ValueError as exc:
            raise HelperError("Failed to parse chunk size from Mihomo response") from exc

        index = line_end + 2
        if chunk_size == 0:
            break

        chunk_end = index + chunk_size
        if chunk_end > total:
            raise HelperError("Truncated chunked HTTP body")

        decoded.extend(body[index:chunk_end])
        index = chunk_end

        if body[index:index + 2] != b"\r\n":
            raise HelperError("Malformed chunk boundary in Mihomo response")
        index += 2

    return bytes(decoded)


def api_get_json(ctx: dict[str, Path], request_path: str) -> dict[str, Any]:
    _, body = unix_http_request(ctx["socket_path"], "GET", request_path)
    if not body:
        return {}
    return json.loads(body.decode("utf-8"))


def api_patch_json(ctx: dict[str, Path], request_path: str, payload: dict[str, Any]) -> None:
    unix_http_request(ctx["socket_path"], "PATCH", request_path, payload)


def api_put_json(ctx: dict[str, Path], request_path: str, payload: dict[str, Any]) -> None:
    unix_http_request(ctx["socket_path"], "PUT", request_path, payload)


def api_get_json_raw(ctx: dict[str, Path], request_path: str) -> Any:
    _, body = unix_http_request(ctx["socket_path"], "GET", request_path)
    if not body:
        return {}
    return json.loads(body.decode("utf-8"))


def profile_kind(item: dict[str, Any]) -> str:
    return str(item.get("type") or item.get("itype") or "")


def profile_items(profiles_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = profiles_data.get("items") or []
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        uid = item.get("uid")
        if isinstance(uid, str):
            result[uid] = item
    return result


def load_chain_data(ctx: dict[str, Path], items_by_uid: dict[str, dict[str, Any]], uid: str | None, chain_type: str) -> Any:
    if not uid or uid not in items_by_uid:
        if chain_type == "script":
            return IDENTITY_SCRIPT
        if chain_type in {"rules", "proxies", "groups"}:
            return {"prepend": [], "append": [], "delete": []}
        return {}

    item = items_by_uid[uid]
    file_name = item.get("file")
    if not isinstance(file_name, str) or not file_name:
        if chain_type == "script":
            return IDENTITY_SCRIPT
        if chain_type in {"rules", "proxies", "groups"}:
            return {"prepend": [], "append": [], "delete": []}
        return {}

    path = ctx["profiles_dir"] / file_name
    if chain_type == "script":
        return read_text(path, IDENTITY_SCRIPT)
    if chain_type in {"rules", "proxies", "groups"}:
        return yaml_sequence_mapping(path)
    return yaml_mapping(path, {})


def current_profile_item(profiles_data: dict[str, Any]) -> dict[str, Any] | None:
    current_uid = profiles_data.get("current")
    if not isinstance(current_uid, str):
        return None
    return profile_items(profiles_data).get(current_uid)


def read_profile_config(ctx: dict[str, Path], profile_item: dict[str, Any]) -> dict[str, Any]:
    file_name = profile_item.get("file")
    if not isinstance(file_name, str) or not file_name:
        raise HelperError("Selected profile is missing its backing file")
    return yaml_mapping(ctx["profiles_dir"] / file_name, {})


def generate_runtime(ctx: dict[str, Path], profiles_data: dict[str, Any]) -> dict[str, Any]:
    items_by_uid = profile_items(profiles_data)
    current_item = current_profile_item(profiles_data)
    if not current_item:
        raise HelperError("No active Clash Verge profile found")

    config = read_profile_config(ctx, current_item)
    profile_name = str(current_item.get("name") or "")
    option = current_item.get("option") or {}
    if not isinstance(option, dict):
        option = {}

    global_merge = load_chain_data(ctx, items_by_uid, "Merge", "merge")
    global_script = load_chain_data(ctx, items_by_uid, "Script", "script")
    rules_item = load_chain_data(ctx, items_by_uid, str(option.get("rules") or ""), "rules")
    proxies_item = load_chain_data(ctx, items_by_uid, str(option.get("proxies") or ""), "proxies")
    groups_item = load_chain_data(ctx, items_by_uid, str(option.get("groups") or ""), "groups")
    merge_item = load_chain_data(ctx, items_by_uid, str(option.get("merge") or "Merge"), "merge")
    script_item = load_chain_data(ctx, items_by_uid, str(option.get("script") or "Script"), "script")

    config = deep_merge(config, global_merge)
    config = run_script(global_script, config, profile_name)
    config = apply_seq(rules_item, config, "rules")
    config = apply_seq(proxies_item, config, "proxies")
    config = apply_seq(groups_item, config, "proxy-groups")
    config = deep_merge(config, merge_item)
    config = run_script(script_item, config, profile_name)

    clash_config = yaml_mapping(ctx["config_path"], {})
    verge_config = yaml_mapping(ctx["verge_path"], {})

    config = merge_default_config(config, clash_config, verge_config)
    config = cleanup_proxy_groups(config)
    config = apply_tun(config, bool(verge_config.get("enable_tun_mode", False)))
    config = apply_dns_settings(ctx, config, bool(verge_config.get("enable_dns_settings", False)))
    return config


def detect_running_mihomo_socket() -> Path | None:
    """Locate the live `-ext-ctl-unix` socket of a running verge-mihomo process.

    Clash Verge Rev in service mode launches the core through
    `clash-verge-service` with `-ext-ctl-unix` pointing at a socket under
    `/run/clash-verge-service/...`, which overrides whatever stale
    `external-controller-unix` value is baked into the generated config. Scanning
    the running process is the only reliable way to find the real socket.
    """
    proc_dir = Path("/proc")
    if not proc_dir.exists():
        return None

    for entry in proc_dir.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except (OSError, PermissionError):
            continue
        args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
        if not args or "verge-mihomo" not in args[0]:
            continue
        for index, arg in enumerate(args):
            if arg == "-ext-ctl-unix" and index + 1 < len(args):
                socket_path = Path(args[index + 1])
                if socket_path.is_absolute():
                    return socket_path
    return None


def service_mode_socket() -> Path | None:
    """Return the privileged service-mode socket for the current user, if present."""
    uid = os.getuid()
    candidate = Path(f"/run/clash-verge-service/users/{uid}/verge-mihomo.sock")
    return candidate if candidate.exists() else None


def detect_socket_path(app_home: Path) -> Path:
    env_socket = os.environ.get("CLASH_VERGE_SOCKET")
    if env_socket:
        return Path(env_socket)

    # Service mode (privileged clash-verge-service) is authoritative over the
    # stale value written into the generated config, so check it first.
    running_socket = detect_running_mihomo_socket()
    if running_socket and running_socket.exists():
        return running_socket

    service_socket = service_mode_socket()
    if service_socket:
        return service_socket

    for candidate in (app_home / "config.yaml", app_home / "clash-verge.yaml"):
        if not candidate.exists():
            continue
        try:
            config = yaml_mapping(candidate, {})
        except Exception:  # noqa: BLE001
            continue
        socket_path = config.get("external-controller-unix")
        if isinstance(socket_path, str) and socket_path:
            return Path(socket_path)

    return Path(DEFAULT_SOCKET_PATH)


def load_ctx() -> dict[str, Path]:
    app_home = detect_app_home()
    return {
        "app_home": app_home,
        "profiles_dir": app_home / "profiles",
        "profiles_path": app_home / "profiles.yaml",
        "verge_path": app_home / "verge.yaml",
        "config_path": app_home / "config.yaml",
        "runtime_path": app_home / "clash-verge.yaml",
        "dns_path": app_home / "dns_config.yaml",
        "socket_path": detect_socket_path(app_home),
    }


def ensure_runtime_available(ctx: dict[str, Path]) -> None:
    if not ctx["app_home"].exists():
        raise HelperError(f"Clash Verge app directory does not exist: {ctx['app_home']}")
    if not ctx["socket_path"].exists():
        raise HelperError(f"Clash Verge Mihomo socket does not exist: {ctx['socket_path']}")


def saved_profile_entries(profiles_data: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    current_uid = profiles_data.get("current")
    for item in profiles_data.get("items") or []:
        if not isinstance(item, dict):
            continue
        kind = profile_kind(item)
        if kind not in {"local", "remote"}:
            continue
        uid = item.get("uid")
        name = item.get("name")
        if not isinstance(uid, str) or not isinstance(name, str):
            continue
        result.append(
            {
                "uid": uid,
                "name": name,
                "type": kind,
                "isCurrent": uid == current_uid,
                "selected": deepcopy(item.get("selected") or []),
            }
        )
    return result


def selector_groups_from_live(live_proxies: dict[str, Any], selected_order: list[str]) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    proxies_map = live_proxies.get("proxies") if isinstance(live_proxies.get("proxies"), dict) else live_proxies
    if not isinstance(proxies_map, dict):
        return groups

    for group_name, payload in proxies_map.items():
        if group_name == "GLOBAL" or not isinstance(payload, dict):
            continue
        options = payload.get("all")
        now_value = payload.get("now")
        if not isinstance(options, list) or not isinstance(now_value, str):
            continue
        groups.append(
            {
                "name": group_name,
                "type": str(payload.get("type") or ""),
                "now": now_value,
                "all": [item for item in options if isinstance(item, str)],
            }
        )

    if not selected_order:
        return groups

    order_index = {name: index for index, name in enumerate(selected_order)}
    groups.sort(key=lambda item: (order_index.get(item["name"], len(order_index)), item["name"]))
    return groups


def can_test_node_name(node_name: str) -> bool:
    return node_name not in BUILTIN_POLICIES


def live_group(ctx: dict[str, Path], group_name: str) -> dict[str, Any]:
    live_proxies = api_get_json(ctx, "/proxies")
    groups = {item["name"]: item for item in selector_groups_from_live(live_proxies, [])}
    group = groups.get(group_name)
    if not group:
        raise HelperError(f"Unknown selector group: {group_name}")
    return group


def make_delay_result(group_name: str, node_name: str, delay_value: int | None, ok: bool, error: str = "") -> dict[str, Any]:
    return {
        "group": group_name,
        "node": node_name,
        "url": DEFAULT_DELAY_TEST_URL,
        "timeout": DEFAULT_DELAY_TIMEOUT_MS,
        "delay": delay_value,
        "ok": ok,
        "error": error,
    }


def run_delay_test(ctx: dict[str, Path], group_name: str, node_name: str, group: dict[str, Any] | None = None) -> dict[str, Any]:
    if group is None:
        group = live_group(ctx, group_name)

    if node_name not in group.get("all", []):
        raise HelperError(f"Node {node_name} is not part of selector group {group_name}")

    if not can_test_node_name(node_name):
        return make_delay_result(
            group_name,
            node_name,
            None,
            False,
            f"Latency test is not available for {node_name}",
        )

    request_path = "/proxies/{node}/delay?url={url}&timeout={timeout}".format(
        node=quote(node_name, safe=""),
        url=quote(DEFAULT_DELAY_TEST_URL, safe=""),
        timeout=DEFAULT_DELAY_TIMEOUT_MS,
    )
    payload = api_get_json_raw(ctx, request_path)
    delay_value = payload.get("delay") if isinstance(payload, dict) else None
    ok = isinstance(delay_value, int) and delay_value >= 0
    return make_delay_result(
        group_name,
        node_name,
        delay_value if ok else None,
        ok,
        "" if ok else "Latency test returned no usable delay",
    )


def upsert_profile_selection(profile_item: dict[str, Any], group_name: str, node_name: str) -> None:
    selected = profile_item.get("selected")
    if not isinstance(selected, list):
        selected = []
        profile_item["selected"] = selected

    for entry in selected:
        if isinstance(entry, dict) and entry.get("name") == group_name:
            entry["now"] = node_name
            return

    selected.append({"name": group_name, "now": node_name})


def apply_saved_selections(ctx: dict[str, Path], profile_item: dict[str, Any]) -> None:
    live_proxies = api_get_json(ctx, "/proxies")
    groups = {item["name"]: item for item in selector_groups_from_live(live_proxies, [])}
    for entry in profile_item.get("selected") or []:
        if not isinstance(entry, dict):
            continue
        group_name = entry.get("name")
        node_name = entry.get("now")
        if not isinstance(group_name, str) or not isinstance(node_name, str):
            continue
        group = groups.get(group_name)
        if not group or node_name not in group.get("all", []):
            continue
        api_put_json(ctx, f"/proxies/{quote(group_name, safe='')}", {"name": node_name})


def collect_status(ctx: dict[str, Path]) -> dict[str, Any]:
    profiles_data = yaml_mapping(ctx["profiles_path"], {"current": None, "items": []})
    current_item = current_profile_item(profiles_data)
    current_profile_name = str(current_item.get("name") or "") if current_item else ""
    current_profile_type = profile_kind(current_item) if current_item else ""
    current_selected = current_item.get("selected") if current_item else []
    selected_order = [entry.get("name") for entry in current_selected or [] if isinstance(entry, dict) and isinstance(entry.get("name"), str)]

    verge_config = yaml_mapping(ctx["verge_path"], {})
    clash_config = yaml_mapping(ctx["config_path"], {})
    data: dict[str, Any] = {
        "available": False,
        "appHome": str(ctx["app_home"]),
        "socketPath": str(ctx["socket_path"]),
        "currentProfileId": profiles_data.get("current"),
        "currentProfileName": current_profile_name,
        "currentProfileType": current_profile_type,
        "mode": str(clash_config.get("mode") or "unknown"),
        "tunEnabled": bool(verge_config.get("enable_tun_mode", False)),
        "systemProxyEnabled": bool(verge_config.get("enable_system_proxy", False)),
        "coreVersion": None,
        "selectorGroups": [],
        "profiles": saved_profile_entries(profiles_data),
        "runtimeError": "",
        "summaryGroup": "",
        "summaryNode": "",
    }

    try:
        ensure_runtime_available(ctx)
        version = api_get_json(ctx, "/version")
        configs = api_get_json(ctx, "/configs")
        proxies = api_get_json(ctx, "/proxies")
        selector_groups = selector_groups_from_live(proxies, selected_order)
        data["available"] = True
        data["mode"] = str(configs.get("mode") or data["mode"])
        data["coreVersion"] = version.get("version")
        data["selectorGroups"] = selector_groups
        if selector_groups:
            data["summaryGroup"] = selector_groups[0]["name"]
            data["summaryNode"] = selector_groups[0]["now"]
    except Exception as exc:  # noqa: BLE001
        data["runtimeError"] = str(exc)

    return data


def command_status(ctx: dict[str, Path]) -> dict[str, Any]:
    return collect_status(ctx)


def command_set_node(ctx: dict[str, Path], group_name: str, node_name: str) -> dict[str, Any]:
    ensure_runtime_available(ctx)
    api_put_json(ctx, f"/proxies/{quote(group_name, safe='')}", {"name": node_name})

    profiles_data = yaml_mapping(ctx["profiles_path"], {"current": None, "items": []})
    current_item = current_profile_item(profiles_data)
    if current_item:
        upsert_profile_selection(current_item, group_name, node_name)
        save_yaml(ctx["profiles_path"], profiles_data, "# Profiles Config for Clash Verge")

    return collect_status(ctx)


def command_set_profile(ctx: dict[str, Path], profile_uid: str) -> dict[str, Any]:
    ensure_runtime_available(ctx)

    profiles_data = yaml_mapping(ctx["profiles_path"], {"current": None, "items": []})
    items_by_uid = profile_items(profiles_data)
    target_item = items_by_uid.get(profile_uid)
    if not target_item:
        raise HelperError(f"Unknown profile id: {profile_uid}")
    if profile_kind(target_item) not in {"local", "remote"}:
        raise HelperError(f"Profile {profile_uid} is not switchable")

    next_profiles = deepcopy(profiles_data)
    next_profiles["current"] = profile_uid
    runtime_config = generate_runtime(ctx, next_profiles)
    save_yaml(ctx["runtime_path"], runtime_config, "# Generated by Clash Verge")
    api_put_json(ctx, "/configs?force=true", {"path": str(ctx["runtime_path"])})
    save_yaml(ctx["profiles_path"], next_profiles, "# Profiles Config for Clash Verge")
    apply_saved_selections(ctx, profile_items(next_profiles)[profile_uid])

    return collect_status(ctx)


def command_test_delay(ctx: dict[str, Path], group_name: str, node_name: str) -> dict[str, Any]:
    ensure_runtime_available(ctx)
    return run_delay_test(ctx, group_name, node_name)


def command_test_group(ctx: dict[str, Path], group_name: str) -> dict[str, Any]:
    ensure_runtime_available(ctx)
    group = live_group(ctx, group_name)

    results: list[dict[str, Any]] = []
    for node_name in group.get("all", []):
        if not isinstance(node_name, str):
            continue
        try:
            results.append(run_delay_test(ctx, group_name, node_name, group))
        except Exception as exc:  # noqa: BLE001
            results.append(make_delay_result(group_name, node_name, None, False, str(exc)))

    return {
        "group": group_name,
        "results": results,
    }


def dispatch(ctx: dict[str, Path], argv: list[str]) -> dict[str, Any]:
    if not argv or argv[0] == "status":
        return command_status(ctx)
    if argv[0] == "set-node":
        if len(argv) != 3:
            raise HelperError("Usage: set-node <group> <node>")
        return command_set_node(ctx, argv[1], argv[2])
    if argv[0] == "set-profile":
        if len(argv) != 2:
            raise HelperError("Usage: set-profile <profile-id>")
        return command_set_profile(ctx, argv[1])
    if argv[0] == "test-delay":
        if len(argv) != 3:
            raise HelperError("Usage: test-delay <group> <node>")
        return command_test_delay(ctx, argv[1], argv[2])
    if argv[0] == "test-group":
        if len(argv) != 2:
            raise HelperError("Usage: test-group <group>")
        return command_test_group(ctx, argv[1])
    raise HelperError(f"Unknown command: {argv[0]}")


def main() -> int:
    try:
        ctx = load_ctx()
        payload = dispatch(ctx, sys.argv[1:])
    except HelperError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"Unexpected helper failure: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"ok": True, "data": payload}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

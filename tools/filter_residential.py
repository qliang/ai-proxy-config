#!/usr/bin/env python3
"""Filter Clash proxies to residential IPs; emit Shadowrocket sub + Clash Meta config.

  python tools/filter_residential.py

Reads refer/proxy_select/*.yaml (IP-filtered) and refer/proxy_fix/*.yaml (kept as-is).
Country and residential class come from the *egress* IP (traffic through the node),
not the entry server IP or the advertised name.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("需要 PyYAML：pip install -r requirements.txt")

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "clash" / "ai.yaml"
CACHE_PATH = ROOT / ".cache" / "ip-api.json"
EGRESS_CACHE_PATH = ROOT / ".cache" / "egress.json"
IP_API_FIELDS = (
    "status,message,country,countryCode,city,isp,org,as,"
    "mobile,proxy,hosting,query"
)
IP_API_URL = "http://ip-api.com/json/{ip}?fields=" + IP_API_FIELDS
IP_API_SELF = "http://ip-api.com/json/?fields=" + IP_API_FIELDS
SKIP_NAME = re.compile(r"(剩余流量|套餐到期|expire|traffic|过期|到期)", re.I)
STRIP_EMOJI = re.compile(
    r"[\U0001F1E6-\U0001F1FF]|[\U0001F300-\U0001FAFF]|[\u2600-\u27BF]|[\uFE0F]"
)
XHTTP_TAG = re.compile(r"\[vless reality xhttp\]", re.I)
VLESS_TAG = re.compile(r"\[vless reality (?:xhttp|tcp)\]", re.I)
COST_SUFFIX = re.compile(r"(?:[-_\s|｜]*)((?:\d+(?:\.\d+)?|[xX])倍消耗)\s*$")
SELECT_DIR = ROOT / "refer" / "proxy_select"
FIX_DIR = ROOT / "refer" / "proxy_fix"
MIHOMO_CANDIDATES = (
    Path.home() / "Library/Application Support/net.fbclient.app/cores/mihomo/FbclientCore_arm64",
    Path.home()
    / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-meta",
)


def load_cache() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def save_cache(cache: dict) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def load_egress_cache() -> dict:
    if EGRESS_CACHE_PATH.exists():
        try:
            data = json.loads(EGRESS_CACHE_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def save_egress_cache(cache: dict) -> None:
    EGRESS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    EGRESS_CACHE_PATH.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def load_proxies(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    proxies = data.get("proxies") or []
    out = []
    for p in proxies:
        if isinstance(p, dict) and p.get("server") and p.get("type"):
            p = dict(p)
            p["_source"] = path.name
            p["_stem"] = path.stem
            out.append(p)
    return out


def proxy_key(p: dict) -> tuple:
    secret = p.get("uuid") or p.get("password") or p.get("psk") or ""
    return (p.get("type"), p.get("server"), p.get("port"), secret)


def egress_cache_key(p: dict) -> str:
    return "|".join("" if x is None else str(x) for x in proxy_key(p))


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def resolve_ip(host: str) -> str | None:
    if is_ip(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except OSError:
        return None


def lookup_ip(ip: str, cache: dict, sleep_s: float) -> dict:
    if ip in cache:
        return cache[ip]
    url = IP_API_URL.format(ip=urllib.parse.quote(ip))
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.7.1"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
        data = {"status": "fail", "message": str(e)}
    cache[ip] = data
    save_cache(cache)
    if data.get("status") == "fail" and "rate" in str(data.get("message", "")).lower():
        time.sleep(max(sleep_s, 5))
    else:
        time.sleep(sleep_s)
    return data


def classify(info: dict) -> str:
    if info.get("status") != "success":
        return "unknown"
    if info.get("hosting"):
        return "datacenter"
    if info.get("proxy"):
        return "proxy"
    return "residential"


def http_json(url: str, timeout: float, proxy: str | None = None, method: str = "GET", body: bytes | None = None) -> tuple[int, object]:
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "curl/8.7.1")
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = getattr(resp, "status", 200)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        status = e.code
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        return 0, {"error": str(e)}
    try:
        return status, json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return status, raw


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def default_iface() -> str | None:
    try:
        out = subprocess.check_output(
            ["route", "-n", "get", "default"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            name = line.split(":", 1)[1].strip()
            return name or None
    return None


def find_mihomo(explicit: Path | None) -> Path | None:
    if explicit:
        path = explicit.expanduser().resolve()
        return path if path.is_file() and os.access(path, os.X_OK) else None
    for name in ("mihomo", "clash-meta", "clash"):
        found = shutil.which(name)
        if found:
            return Path(found)
    env = os.environ.get("MIHOMO")
    if env:
        path = Path(env).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return path
    for path in MIHOMO_CANDIDATES:
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


class EgressProbe:
    """Temporary mihomo instance: switch node, then query ip-api through mixed-port."""

    def __init__(self, binary: Path, proxies: list[dict], timeout: float):
        self.binary = binary
        self.timeout = timeout
        self.mixed_port = free_port()
        self.api_port = free_port()
        self.workdir = ROOT / ".cache" / "mihomo-probe"
        self.proc: subprocess.Popen | None = None
        self.probe_name: dict[int, str] = {}
        self.proxies = []
        for i, p in enumerate(proxies):
            name = f"n{i:04d}"
            self.probe_name[id(p)] = name
            item = clash_proxy(p, name)
            self.proxies.append(item)

    @property
    def api(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.mixed_port}"

    def start(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        names = [p["name"] for p in self.proxies]
        cfg = {
            "mixed-port": self.mixed_port,
            "bind-address": "127.0.0.1",
            "allow-lan": False,
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            "external-controller": f"127.0.0.1:{self.api_port}",
            "dns": {
                "enable": True,
                "ipv6": False,
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "nameserver": ["8.8.8.8", "1.1.1.1"],
            },
            "proxies": self.proxies,
            "proxy-groups": [{"name": "PROBE", "type": "select", "proxies": names or ["DIRECT"]}],
            "rules": ["MATCH,PROBE"],
        }
        iface = default_iface()
        if iface:
            cfg["interface-name"] = iface
        config_path = self.workdir / "config.yaml"
        config_path.write_text(dump_yaml(cfg), encoding="utf-8")
        log_path = self.workdir / "mihomo.log"
        self.log_f = open(log_path, "w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [str(self.binary), "-f", str(config_path), "-d", str(self.workdir)],
            stdout=self.log_f,
            stderr=subprocess.STDOUT,
            cwd=str(self.workdir),
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"mihomo 启动失败（exit {self.proc.returncode}），见 {log_path}"
                )
            status, _data = http_json(f"{self.api}/version", timeout=1)
            if status == 200:
                return
            time.sleep(0.2)
        raise RuntimeError(f"mihomo API 未就绪，见 {log_path}")

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
            self.proc = None
        log_f = getattr(self, "log_f", None)
        if log_f:
            log_f.close()
            self.log_f = None

    def select(self, p: dict) -> None:
        name = self.probe_name[id(p)]
        payload = json.dumps({"name": name}).encode()
        status, data = http_json(
            f"{self.api}/proxies/PROBE",
            timeout=5,
            method="PUT",
            body=payload,
        )
        if status not in (200, 204):
            raise RuntimeError(f"切换节点失败 HTTP {status}: {data}")

    def lookup(self) -> dict:
        status, data = http_json(IP_API_SELF, timeout=self.timeout, proxy=self.proxy_url)
        if status == 200 and isinstance(data, dict) and data.get("status") == "success":
            return data
        status, raw = http_json("http://icanhazip.com", timeout=self.timeout, proxy=self.proxy_url)
        if status != 200 or not isinstance(raw, str):
            msg = data.get("error") if isinstance(data, dict) else data
            return {"status": "fail", "message": str(msg or "egress lookup failed")}
        ip = raw.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return {"status": "fail", "message": f"bad egress ip: {ip}"}
        return {"status": "pending", "query": ip}

    def probe(self, p: dict) -> dict:
        self.select(p)
        return self.lookup()


def iter_yaml_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        [p for p in directory.iterdir() if p.suffix.lower() in {".yaml", ".yml"} and p.is_file()]
    )


def is_xhttp(p: dict) -> bool:
    name = str(p.get("name") or "")
    if XHTTP_TAG.search(name):
        return True
    if str(p.get("network") or "").lower() == "xhttp":
        return True
    return bool(p.get("xhttp-opts"))


def name_snippet(name: str, limit: int = 12) -> str:
    s = VLESS_TAG.sub("", name or "")
    s = STRIP_EMOJI.sub("", s)
    s = s.replace("|", "-")
    s = re.sub(r"\s+", "", s)
    s = s.strip("-")
    parts = [part for part in s.split("-") if part]
    s = "-".join(parts[:2]) if parts else "node"
    return s[:limit] if s else "node"


def split_cost_suffix(name: str) -> tuple[str, str]:
    text = name or ""
    m = COST_SUFFIX.search(text)
    if not m:
        return text, ""
    return text[: m.start()].rstrip(), m.group(1)


def new_label(country: str, seq: int, filename: str, original: str) -> str:
    base, cost = split_cost_suffix(original)
    snippet = name_snippet(base)
    label = f"{country}{seq:02d}-{filename}-{snippet}"
    if cost:
        return f"{label}-{cost}"
    return label


# 输出节点顺序：日 / 美 / 韩 / 新 → 其它国家 → 港 / 澳
PRIORITY_COUNTRIES = ("JP", "US", "KR", "SG")
LAST_COUNTRIES = ("HK", "MO")


def country_sort_key(country: str, name: str = "") -> tuple:
    code = (country or "XX").upper()
    if code in PRIORITY_COUNTRIES:
        return (0, PRIORITY_COUNTRIES.index(code), name)
    if code in LAST_COUNTRIES:
        return (2, LAST_COUNTRIES.index(code), name)
    return (1, code, name)


def q(value) -> str:
    return urllib.parse.quote(str(value), safe="")


def clash_proxy(p: dict, name: str) -> dict:
    out = {k: v for k, v in p.items() if not str(k).startswith("_")}
    out["name"] = name
    return out


def load_clash_template(path: Path = TEMPLATE_PATH) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"找不到 Clash 模板: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Clash 模板无效: {path}")
    return data


def build_clash_config(proxies: list[dict], template_path: Path = TEMPLATE_PATH) -> dict:
    """Load clash/ai.yaml and splice filtered proxies into a standalone profile."""
    cfg = load_clash_template(template_path)
    names = [p["name"] for p in proxies]
    cfg.pop("proxies", None)
    ordered = {}
    inserted = False
    for key, value in cfg.items():
        if key == "proxy-groups" and not inserted:
            ordered["proxies"] = proxies
            inserted = True
        ordered[key] = value
    if not inserted:
        ordered["proxies"] = proxies
    cfg = ordered

    provider_keys = set((cfg.get("proxy-providers") or {}).keys())
    cfg.pop("proxy-providers", None)

    for group in cfg.get("proxy-groups") or []:
        uses = list(group.get("use") or [])
        if not uses:
            continue
        rest_use = [u for u in uses if u not in provider_keys]
        if rest_use:
            group["use"] = rest_use
        else:
            group.pop("use", None)
        existing = [p for p in (group.get("proxies") or []) if p not in names]
        if group.get("type") == "url-test":
            group["proxies"] = names or existing or ["DIRECT"]
        else:
            group["proxies"] = names + existing if names else (existing or ["DIRECT"])
    return cfg


def dump_yaml(data) -> str:
    return yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


def dump_flow_item(item: dict) -> str:
    return yaml.safe_dump(
        item,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=True,
        width=10**9,
    ).strip()


def dump_proxies_flow(proxies: list[dict]) -> str:
    lines = ["proxies:"]
    if not proxies:
        lines.append("  []")
        return "\n".join(lines) + "\n"
    for item in proxies:
        lines.append(f"  - {dump_flow_item(item)}")
    return "\n".join(lines) + "\n"


def dump_clash_config(cfg: dict) -> str:
    proxies = cfg.get("proxies") or []
    chunks = []
    wrote_proxies = False
    for key, value in cfg.items():
        if key == "proxies":
            if not wrote_proxies:
                chunks.append(dump_proxies_flow(proxies).rstrip())
                wrote_proxies = True
            continue
        if key == "proxy-groups" and not wrote_proxies:
            chunks.append(dump_proxies_flow(proxies).rstrip())
            wrote_proxies = True
        chunks.append(dump_yaml({key: value}).rstrip())
    if not wrote_proxies:
        chunks.append(dump_proxies_flow(proxies).rstrip())
    return "\n".join(chunks) + "\n"


def to_shadowrocket_uri(p: dict, remark: str) -> str | None:
    ptype = (p.get("type") or "").lower()
    server = p.get("server")
    port = p.get("port")
    if not server or not port:
        return None
    fragment = q(remark)

    if ptype == "vless":
        uuid = p.get("uuid")
        if not uuid:
            return None
        params = {
            "encryption": "none",
            "type": p.get("network") or "tcp",
        }
        if p.get("udp"):
            params["udp"] = "true"
        flow = p.get("flow")
        if flow:
            params["flow"] = flow
        fp = p.get("client-fingerprint")
        if fp:
            params["fp"] = fp
        reality = p.get("reality-opts") or {}
        if reality or p.get("tls"):
            if reality:
                params["security"] = "reality"
                if reality.get("public-key"):
                    params["pbk"] = reality["public-key"]
                if reality.get("short-id"):
                    params["sid"] = reality["short-id"]
            else:
                params["security"] = "tls"
        sni = p.get("servername") or p.get("sni")
        if sni:
            params["sni"] = sni
        if p.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        ws = p.get("ws-opts") or {}
        if params.get("type") == "ws":
            if ws.get("path"):
                params["path"] = ws["path"]
            headers = ws.get("headers") or {}
            if headers.get("Host"):
                params["host"] = headers["Host"]
        query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        return f"vless://{uuid}@{server}:{port}?{query}#{fragment}"

    if ptype == "trojan":
        password = p.get("password")
        if not password:
            return None
        params = {"type": p.get("network") or "tcp"}
        sni = p.get("sni") or p.get("servername")
        if sni:
            params["sni"] = sni
        if p.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if p.get("udp"):
            params["udp"] = "true"
        query = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        return f"trojan://{q(password)}@{server}:{port}?{query}#{fragment}"

    if ptype in ("ss", "shadowsocks"):
        method = p.get("cipher")
        password = p.get("password")
        if not method or not password:
            return None
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{fragment}"

    if ptype == "vmess":
        net = p.get("network") or "tcp"
        cfg = {
            "v": "2",
            "ps": remark,
            "add": server,
            "port": str(port),
            "id": p.get("uuid"),
            "aid": str(p.get("alterId", 0)),
            "scy": p.get("cipher") or "auto",
            "net": net,
            "type": "none",
            "tls": "tls" if p.get("tls") else "",
            "sni": p.get("servername") or p.get("sni") or "",
        }
        ws = p.get("ws-opts") or {}
        if net == "ws":
            cfg["path"] = ws.get("path") or "/"
            cfg["host"] = (ws.get("headers") or {}).get("Host") or ""
        raw = json.dumps(cfg, ensure_ascii=False, separators=(",", ":")).encode()
        return "vmess://" + base64.b64encode(raw).decode()

    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clash 节点落地 IP 住宅过滤 → 小火箭/Clash Meta（走节点探测出口）"
    )
    parser.add_argument(
        "--select-dir",
        type=Path,
        default=SELECT_DIR,
        help="需要 IP 筛选的 YAML 目录",
    )
    parser.add_argument(
        "--fix-dir",
        type=Path,
        default=FIX_DIR,
        help="不筛选、全部保留的 YAML 目录",
    )
    parser.add_argument("-o", "--out-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--sleep", type=float, default=1.5, help="ip-api 直连查询间隔（秒）")
    parser.add_argument("--keep-unknown", action="store_true", help="查询失败的节点也保留")
    parser.add_argument("--mihomo", type=Path, help="mihomo / Clash Meta 可执行文件")
    parser.add_argument(
        "--skip-probe",
        action="store_true",
        help="不走节点，退回入口 server IP（不准确，仅调试）",
    )
    parser.add_argument("--probe-timeout", type=float, default=12, help="每个节点落地探测超时（秒）")
    parser.add_argument("--refresh-egress", action="store_true", help="忽略落地探测缓存")
    parser.add_argument(
        "-toclash",
        action="store_true",
        help="把 guaguaMMDD.yaml 写到 ~/.config/clash.meta/（不加则不写）",
    )
    return parser.parse_args()


def collect_proxies(path: Path, seen: set) -> list[dict]:
    out = []
    for p in load_proxies(path):
        name = str(p.get("name") or "")
        if SKIP_NAME.search(name) or is_xhttp(p):
            continue
        key = proxy_key(p)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def entry_lookup(p: dict, host_ip: dict, cache: dict, sleep_s: float) -> dict:
    host = str(p["server"])
    if host not in host_ip:
        host_ip[host] = resolve_ip(host)
    ip = host_ip[host]
    return lookup_ip(ip, cache, sleep_s) if ip else {"status": "fail", "message": "dns"}


def egress_lookup(
    p: dict,
    probe: EgressProbe | None,
    cache: dict,
    egress_cache: dict,
    host_ip: dict,
    sleep_s: float,
    refresh: bool,
) -> tuple[dict, str]:
    key = egress_cache_key(p)
    if not refresh and key in egress_cache:
        cached = egress_cache[key]
        if isinstance(cached, dict) and cached.get("status") == "success":
            return cached, "cache"
    if probe is None:
        info = entry_lookup(p, host_ip, cache, sleep_s)
        return info, "entry-ip"
    try:
        info = probe.probe(p)
    except Exception as e:
        info = {"status": "fail", "message": str(e)}
    if info.get("status") == "pending" and info.get("query"):
        info = lookup_ip(str(info["query"]), cache, sleep_s)
    if info.get("status") == "success":
        egress_cache[key] = info
        save_egress_cache(egress_cache)
    return info, "probe"


def keep_proxy(p: dict, kind: str, keep_unknown: bool) -> bool:
    if p.get("_always_keep"):
        return True
    return kind == "residential" or (keep_unknown and kind == "unknown")


def main() -> int:
    args = parse_args()
    select_files = iter_yaml_files(args.select_dir)
    fix_files = iter_yaml_files(args.fix_dir)
    if not select_files and not fix_files:
        print(f"没有输入文件。请把 YAML 放到 {args.select_dir} 或 {args.fix_dir}")
        return 1

    seen: set = set()
    select_proxies: list[dict] = []
    for path in select_files:
        select_proxies.extend(collect_proxies(path, seen))

    fix_proxies: list[dict] = []
    for path in fix_files:
        for p in collect_proxies(path, seen):
            p["_always_keep"] = True
            fix_proxies.append(p)

    proxies = select_proxies + fix_proxies
    print(
        f"待处理 {len(proxies)} 个（筛选 {len(select_proxies)} / "
        f"固定 {len(fix_proxies)}；xhttp 与套餐信息节点已跳过）"
    )

    cache = load_cache()
    egress_cache = load_egress_cache()
    probe: EgressProbe | None = None
    if args.skip_probe:
        print("警告: --skip-probe 使用入口 server IP，中转节点的国家和住宅类型都会不准。")
    else:
        missing = [
            p
            for p in proxies
            if args.refresh_egress
            or not (
                isinstance(egress_cache.get(egress_cache_key(p)), dict)
                and egress_cache[egress_cache_key(p)].get("status") == "success"
            )
        ]
        if not missing:
            print("落地探测: 全部命中缓存（--refresh-egress 可强制重测）")
        else:
            binary = find_mihomo(args.mihomo)
            if not binary:
                print(
                    "找不到 mihomo。请安装 Clash Meta，或用 --mihomo /path/to/mihomo。\n"
                    "仅调试可用 --skip-probe（入口 IP，结果不可信）。"
                )
                return 1
            print(
                f"落地探测: {binary}（{len(missing)}/{len(proxies)} 个需实测出口 IP）"
            )
            probe = EgressProbe(binary, proxies, timeout=args.probe_timeout)
            try:
                probe.start()
            except Exception as e:
                print(f"mihomo 启动失败: {e}")
                return 1
            print(f"mihomo mixed-port={probe.mixed_port} api={probe.api_port}")

    host_ip: dict[str, str | None] = {}
    counters: dict[str, int] = defaultdict(int)
    rows = []
    kept = []

    try:
        for i, p in enumerate(proxies, 1):
            info, src = egress_lookup(
                p,
                probe,
                cache,
                egress_cache,
                host_ip,
                args.sleep,
                args.refresh_egress,
            )
            kind = classify(info)
            country = info.get("countryCode") or "XX"
            ip = info.get("query")
            tag = "fix" if p.get("_always_keep") else "select"
            print(
                f"[{i}/{len(proxies)}] {tag:6s} {kind:12s} {country:2s} "
                f"{src:8s} {ip or '-':15s} "
                f"{info.get('isp') or info.get('message') or ''}  |  {p.get('name')}"
            )
            row = {
                "source": p.get("_source"),
                "original_name": p.get("name"),
                "type": p.get("type"),
                "server": p.get("server"),
                "port": p.get("port"),
                "ip": ip,
                "class": kind,
                "country": country,
                "lookup": src,
                "city": info.get("city"),
                "isp": info.get("isp"),
                "as": info.get("as"),
                "hosting": bool(info.get("hosting")),
                "proxy": bool(info.get("proxy")),
                "mobile": bool(info.get("mobile")),
                "fixed": bool(p.get("_always_keep")),
            }
            if keep_proxy(p, kind, args.keep_unknown):
                counters[country] += 1
                label = new_label(
                    country,
                    counters[country],
                    str(p.get("_stem") or "node"),
                    str(p.get("name") or ""),
                )
                row["new_name"] = label
                uri = to_shadowrocket_uri(p, label)
                kept.append(
                    {
                        "proxy": clash_proxy(p, label),
                        "uri": uri,
                        "row": row,
                    }
                )
            rows.append(row)
    finally:
        if probe:
            probe.stop()

    kept.sort(
        key=lambda item: country_sort_key(
            item["row"].get("country") or "XX",
            item["row"].get("new_name") or "",
        )
    )

    sr_dir = args.out_dir / "shadowrocket"
    clash_dir = args.out_dir / "clash"
    sr_dir.mkdir(parents=True, exist_ok=True)
    clash_dir.mkdir(parents=True, exist_ok=True)

    uris = [item["uri"] for item in kept if item["uri"]]
    sub_txt = sr_dir / "residential.txt"
    sub_b64 = sr_dir / "residential.base64"
    report = sr_dir / "residential_report.json"
    sub_txt.write_text("\n".join(uris) + ("\n" if uris else ""), encoding="utf-8")
    payload = ("\n".join(uris) + "\n").encode()
    sub_b64.write_text(base64.b64encode(payload).decode() + "\n", encoding="utf-8")
    report.write_text(
        json.dumps(
            {
                "kept": len(kept),
                "total": len(proxies),
                "by_class": {
                    k: sum(1 for r in rows if r["class"] == k)
                    for k in sorted({r["class"] for r in rows})
                },
                "nodes": rows,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    clash_proxies = [item["proxy"] for item in kept]
    proxies_yaml = clash_dir / "proxies.yaml"
    stamp = datetime.date.today().strftime("%m%d")
    config_yaml = clash_dir / f"guagua{stamp}.yaml"
    proxies_yaml.write_text(dump_proxies_flow(clash_proxies), encoding="utf-8")
    config_text = dump_clash_config(build_clash_config(clash_proxies))
    config_yaml.write_text(config_text, encoding="utf-8")

    print(f"\n输出节点: {len(kept)} / {len(proxies)}")
    print(f"小火箭订阅: {sub_txt}")
    print(f"Clash Meta 完整配置: {config_yaml}")
    print(f"Clash 仅节点: {proxies_yaml}")
    if args.toclash:
        dest_dir = Path.home() / ".config" / "clash.meta"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / config_yaml.name
        dest.write_text(config_text, encoding="utf-8")
        print(f"已写入 Clash Meta: {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

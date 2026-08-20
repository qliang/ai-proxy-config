#!/usr/bin/env python3
"""Filter Clash proxies to residential IPs; emit Shadowrocket sub + Clash Meta config.

Classifies the **entry** server IP via ip-api.com (same hosting/proxy flags as
refer/claude_check.py). Relay/transit nodes are often datacenter even if the
name says 家宽 — that is expected.

  python tools/filter_residential.py refer/clash_simple.yaml refer/clash_full.yaml
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import socket
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
CACHE_PATH = ROOT / ".cache" / "ip-api.json"
IP_API_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,country,countryCode,city,isp,org,as,"
    "mobile,proxy,hosting,query"
)
SKIP_NAME = re.compile(r"(剩余流量|套餐到期|expire|traffic|过期|到期)", re.I)
STRIP_EMOJI = re.compile(
    r"[\U0001F1E6-\U0001F1FF]|[\U0001F300-\U0001FAFF]|[\u2600-\u27BF]|[\uFE0F]"
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
            out.append(p)
    return out


def proxy_key(p: dict) -> tuple:
    secret = p.get("uuid") or p.get("password") or p.get("psk") or ""
    return (p.get("type"), p.get("server"), p.get("port"), secret)


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


def name_snippet(name: str, limit: int = 16) -> str:
    s = STRIP_EMOJI.sub("", name or "")
    s = s.replace("|", "-").replace("/", "-")
    s = re.sub(r"\s+", "", s)
    s = re.sub(r"^-+|-+$", "", s)
    return s[:limit] if s else "node"


def new_label(country: str, seq: int, original: str) -> str:
    snippet = name_snippet(original)
    return f"{country}-{seq:02d}-{snippet}"


def q(value) -> str:
    return urllib.parse.quote(str(value), safe="")


def clash_proxy(p: dict, name: str) -> dict:
    out = {k: v for k, v in p.items() if not str(k).startswith("_")}
    out["name"] = name
    return out


def build_clash_config(proxies: list[dict]) -> dict:
    names = [p["name"] for p in proxies]
    select_list = names + ["DIRECT"] if names else ["DIRECT"]
    auto_list = names or ["DIRECT"]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "external-controller": "127.0.0.1:9090",
        "tun": {
            "enable": True,
            "stack": "mixed",
            "dns-hijack": ["any:53"],
            "auto-route": True,
            "auto-detect-interface": True,
        },
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "use-hosts": True,
            "nameserver": [
                "223.5.5.5",
                "119.29.29.29",
                "https://dns.alidns.com/dns-query",
            ],
            "fallback": ["8.8.8.8", "1.1.1.1", "https://1.1.1.1/dns-query"],
            "fallback-filter": {
                "geoip": True,
                "geoip-code": "CN",
                "ipcidr": ["240.0.0.0/4"],
            },
        },
        "proxies": proxies,
        "proxy-groups": [
            {"name": "手动选择", "type": "select", "proxies": select_list},
            {
                "name": "自动选择",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": auto_list,
            },
            {
                "name": "AI",
                "type": "select",
                "proxies": ["手动选择", "自动选择", "DIRECT"] + names,
            },
        ],
        "rule-providers": {
            "advertising": {
                "type": "http",
                "behavior": "domain",
                "format": "text",
                "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdvertisingLite/AdvertisingLite_Domain.txt",
                "path": "./ruleset/advertising.txt",
                "interval": 86400,
            },
            "ai": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "url": "https://cdn.jsdelivr.net/gh/VPSDance/ai-proxy-rules@main/rules/clash/global.yaml",
                "path": "./ruleset/ai.yaml",
                "interval": 86400,
            },
            "proxy": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Global/Global.yaml",
                "path": "./ruleset/global.yaml",
                "interval": 86400,
            },
            "lan": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Lan/Lan.yaml",
                "path": "./ruleset/lan.yaml",
                "interval": 86400,
            },
            "cn": {
                "type": "http",
                "behavior": "classical",
                "format": "yaml",
                "url": "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/China/China.yaml",
                "path": "./ruleset/china.yaml",
                "interval": 86400,
            },
        },
        "rules": [
            "RULE-SET,advertising,REJECT",
            "RULE-SET,ai,AI",
            "RULE-SET,proxy,手动选择",
            "RULE-SET,lan,DIRECT",
            "RULE-SET,cn,DIRECT",
            "GEOIP,CN,DIRECT",
            "MATCH,手动选择",
        ],
    }


def dump_yaml(data) -> str:
    return yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )


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
    parser = argparse.ArgumentParser(description="Clash 节点入口 IP 住宅过滤 → 小火箭订阅")
    parser.add_argument("inputs", nargs="*", type=Path, help="Clash YAML，默认 refer/clash_*.yaml")
    parser.add_argument("-o", "--out-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--sleep", type=float, default=1.5, help="ip-api 请求间隔（秒）")
    parser.add_argument("--keep-unknown", action="store_true", help="查询失败的节点也保留")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    inputs = args.inputs
    if not inputs:
        inputs = sorted((ROOT / "refer").glob("clash_*.yaml"))
    if not inputs:
        print("没有输入文件。用法: python tools/filter_residential.py refer/clash_simple.yaml")
        return 1

    proxies: list[dict] = []
    seen = set()
    for path in inputs:
        if not path.exists():
            print(f"跳过不存在: {path}")
            continue
        for p in load_proxies(path):
            name = str(p.get("name") or "")
            if SKIP_NAME.search(name):
                continue
            key = proxy_key(p)
            if key in seen:
                continue
            seen.add(key)
            proxies.append(p)

    print(f"去重后节点 {len(proxies)} 个（来自 {len(inputs)} 个文件）")
    print("注意: 分类的是入口 server IP，中转节点入口多为机房，不等于落地住宅。")

    cache = load_cache()
    host_ip: dict[str, str | None] = {}
    counters: dict[str, int] = defaultdict(int)
    rows = []
    kept = []

    for i, p in enumerate(proxies, 1):
        host = str(p["server"])
        if host not in host_ip:
            host_ip[host] = resolve_ip(host)
        ip = host_ip[host]
        info = lookup_ip(ip, cache, args.sleep) if ip else {"status": "fail", "message": "dns"}
        kind = classify(info)
        country = info.get("countryCode") or "XX"
        print(
            f"[{i}/{len(proxies)}] {kind:12s} {country:2s} {ip or '-':15s} "
            f"{info.get('isp') or info.get('message') or ''}  |  {p.get('name')}"
        )
        row = {
            "source": p.get("_source"),
            "original_name": p.get("name"),
            "type": p.get("type"),
            "server": host,
            "port": p.get("port"),
            "ip": ip,
            "class": kind,
            "country": country,
            "city": info.get("city"),
            "isp": info.get("isp"),
            "as": info.get("as"),
            "hosting": bool(info.get("hosting")),
            "proxy": bool(info.get("proxy")),
            "mobile": bool(info.get("mobile")),
        }
        keep = kind == "residential" or (args.keep_unknown and kind == "unknown")
        if keep:
            counters[country] += 1
            label = new_label(country, counters[country], str(p.get("name") or ""))
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
    config_yaml = clash_dir / "config.yaml"
    proxies_yaml.write_text(dump_yaml({"proxies": clash_proxies}), encoding="utf-8")
    config_yaml.write_text(dump_yaml(build_clash_config(clash_proxies)), encoding="utf-8")

    print(f"\n住宅/ISP: {len(kept)} / {len(proxies)}")
    print(f"小火箭订阅: {sub_txt}")
    print(f"Clash Meta 完整配置: {config_yaml}")
    print(f"Clash 仅节点: {proxies_yaml}")
    print("Clash Verge / Meta：Profiles → Import → 选 config.yaml")
    print("或把 proxies.yaml 拷到 clash/ 后导入仓库里的 clash/ai.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

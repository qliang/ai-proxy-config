# ai-proxy-config

**Language:** [中文](README.md) | English

Filter Clash proxies down to **residential egress IPs**, then emit a Shadowrocket subscription and a Clash Meta node file. Country and residential class come from the IP traffic actually leaves through — not the entry server IP or the advertised node name.

Clash rules live in `clash/ai.yaml` (copy it into the Clash working directory yourself). The script writes nodes to `dist/clash/myproxy.yaml`; with `-toclash` it only refreshes `~/.config/clash.meta/mine/myproxy.yaml`. Shadowrocket rules are `shadowrocket/airule.conf`; nodes come from the subscription.

## How it works

1. Read `refer/proxy_select/*.yaml` (filtered) and `refer/proxy_fix/*.yaml` (kept as-is).
2. Skip quota/expiry info nodes and xhttp nodes.
3. Switch to each node with local mihomo / Clash Meta, then query [ip-api](http://ip-api.com/) for egress country and type.
4. Keep residential IPs only (`--keep-unknown` also keeps lookup failures; `proxy_fix` is always kept).
5. Rename, sort by country, and write the subscription plus `myproxy.yaml`.

## Outputs

Written under `dist/` by default:

| File | What it is |
| --- | --- |
| `dist/clash/myproxy.yaml` | Filtered proxy list for Clash `proxy-providers` |
| `dist/shadowrocket/proxy.txt` | Shadowrocket plain-text subscription |
| `dist/shadowrocket/proxy.base64` | Shadowrocket Base64 subscription |
| `dist/shadowrocket/proxy_report.json` | Probe report (includes dropped nodes) |

With `-toclash`, only `myproxy.yaml` is written to `~/.config/clash.meta/mine/` (`ai.yaml` is yours to place).

The Clash working directory needs your copy of `ai.yaml` plus the script-written `mine/myproxy.yaml`.

## Shadowrocket rule subscription

In the app: Config → + → paste the subscribe URL → download → use the profile. Set global routing to Config. Add nodes separately via Home → Subscribe; this file has rules only.

| | URL |
| --- | --- |
| Subscribe | https://cdn.jsdelivr.net/gh/qliang/ai-proxy-config@main/shadowrocket/airule.conf |
| Purge CDN | https://purge.jsdelivr.net/gh/qliang/ai-proxy-config@main/shadowrocket/airule.conf |

After pushing `main`, if Shadowrocket still shows the old rules, open the purge URL in a browser to clear the jsDelivr cache, then update the profile in the app.

## Naming and sort order

New names look like `JP01-source-file-snippet`.

- Country code + per-country index + source YAML stem + a snippet of the original name (snippet capped at 12 characters).
- If the original name **ends with** a multiplier such as `2倍消耗` or `1.5倍消耗`, that suffix is appended in full (no length cap).
- List order: Japan → United States → South Korea → Singapore → other countries (by country code) → Hong Kong → Macau.

## Usage

Requires Python 3.10+, PyYAML, and a local **mihomo** (Clash Meta) binary. The script looks on `PATH`, in `MIHOMO`, and in common macOS client install locations.

```bash
pip install -r requirements.txt

# Place Clash YAML files in refer/proxy_select/ and/or refer/proxy_fix/
python main.py

# Write only ~/.config/clash.meta/mine/myproxy.yaml (copy ai.yaml yourself)
python main.py -toclash
```

### Flags

| Flag | Meaning |
| --- | --- |
| `-toclash` | Write `myproxy.yaml` to `~/.config/clash.meta/mine/`; omit to skip |
| `-o` / `--out-dir` | Output directory (default `dist/`) |
| `--select-dir` | YAML dir to filter (default `refer/proxy_select`) |
| `--fix-dir` | YAML dir kept as-is (default `refer/proxy_fix`) |
| `--mihomo` | Path to the mihomo binary |
| `--keep-unknown` | Also keep nodes whose lookup failed |
| `--refresh-egress` | Ignore egress cache and re-probe |
| `--skip-probe` | Use entry server IP instead of egress (inaccurate; debug only) |
| `--probe-timeout` | Per-node egress probe timeout in seconds (default 12) |
| `--sleep` | Delay between direct ip-api queries in seconds (default 1.5) |

Probe results are cached under `.cache/` (entry IP and egress IP separately). `refer/`, `dist/`, and `.cache/` are gitignored by default.

## Layout

```
main.py                    Main script
clash/ai.yaml              Clash Meta rule template (no node secrets)
shadowrocket/airule.conf   Shadowrocket rules (no nodes)
refer/proxy_select/        YAML to filter (local)
refer/proxy_fix/           YAML always kept (local)
dist/                      Generated output (local)
```

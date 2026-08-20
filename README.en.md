# ai-proxy-config

**Language:** [中文](README.md) | English

Filter Clash proxies down to **residential egress IPs**, then emit a Shadowrocket subscription and a Clash Meta profile. Country and residential class come from the IP traffic actually leaves through — not the entry server IP or the advertised node name.

## How it works

1. Read `refer/proxy_select/*.yaml` (filtered) and `refer/proxy_fix/*.yaml` (kept as-is).
2. Skip quota/expiry info nodes and xhttp nodes.
3. Switch to each node with local mihomo / Clash Meta, then query [ip-api](http://ip-api.com/) for egress country and type.
4. Keep residential IPs only (`--keep-unknown` also keeps lookup failures; `proxy_fix` is always kept).
5. Rename, sort by country, and write outputs.

## Outputs

Written under `dist/` by default:

| File | What it is |
| --- | --- |
| `dist/clash/guaguaMMDD.yaml` | Full Clash Meta config (`clash/ai.yaml` template + filtered proxies). Example: 20 Aug → `guagua0820.yaml` |
| `dist/clash/proxies.yaml` | Proxy list only |
| `dist/shadowrocket/residential.txt` | Shadowrocket plain-text subscription |
| `dist/shadowrocket/residential.base64` | Shadowrocket Base64 subscription |
| `dist/shadowrocket/residential_report.json` | Probe report (includes dropped nodes) |

With `-toclash`, the same `guaguaMMDD.yaml` is also written to `~/.config/clash.meta/`.

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
python tools/filter_residential.py

# Also write ~/.config/clash.meta/guaguaMMDD.yaml
python tools/filter_residential.py -toclash
```

### Flags

| Flag | Meaning |
| --- | --- |
| `-toclash` | Write `guaguaMMDD.yaml` to `~/.config/clash.meta/`; omit to skip |
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
clash/ai.yaml              Clash Meta rule template (no node secrets)
shadowrocket/ai.conf       Shadowrocket rule reference
tools/filter_residential.py
refer/proxy_select/        YAML to filter (local)
refer/proxy_fix/           YAML always kept (local)
dist/                      Generated output (local)
```

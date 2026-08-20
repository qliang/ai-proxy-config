# ai-proxy-config

**语言：** 中文 | [English](README.en.md)

按**落地出口 IP**筛选住宅节点，生成 Shadowrocket 订阅和 Clash Meta 配置。国家和是否住宅以流量实际走出的 IP 为准，不以入口服务器 IP 或节点广告名为准。

## 工作流程

1. 读取 `refer/proxy_select/*.yaml`（做住宅筛选）和 `refer/proxy_fix/*.yaml`（全部保留）。
2. 跳过套餐/流量信息节点，以及 xhttp 节点。
3. 用本机 mihomo / Clash Meta 切到该节点，再查 [ip-api](http://ip-api.com/) 得到出口国家与类型。
4. 只保留住宅 IP（`--keep-unknown` 时可额外保留查询失败的节点；`proxy_fix` 始终保留）。
5. 重命名、按国家排序后写出订阅与配置。

## 输出

默认写到 `dist/`：

| 文件 | 说明 |
| --- | --- |
| `dist/clash/guaguaMMDD.yaml` | 完整 Clash Meta 配置（模板 `clash/ai.yaml` + 筛选后的节点）。例如 8 月 20 日为 `guagua0820.yaml` |
| `dist/clash/proxies.yaml` | 仅节点列表 |
| `dist/shadowrocket/residential.txt` | 小火箭纯文本订阅 |
| `dist/shadowrocket/residential.base64` | 小火箭 Base64 订阅 |
| `dist/shadowrocket/residential_report.json` | 探测明细（含未保留节点） |

加上 `-toclash` 时，会把当天的 `guaguaMMDD.yaml` 再写一份到 `~/.config/clash.meta/`。

## 节点命名与排序

新名称形如：`JP01-订阅文件名-原名片段`。

- 国家码 + 同国序号 + 来源 YAML 文件名 + 原名摘要（摘要最长 12 字）。
- 原名**末尾**若带 `2倍消耗`、`1.5倍消耗` 等，会原样接到新名字后面，不截断。
- 列表顺序：日本 → 美国 → 韩国 → 新加坡 → 其它国家（国家码字母序）→ 香港 → 澳门。

## 使用

需要 Python 3.10+、PyYAML，以及本机可执行的 **mihomo**（Clash Meta）。脚本会在 `PATH`、环境变量 `MIHOMO`，以及常见 macOS 客户端目录里查找。

```bash
pip install -r requirements.txt

# 把 Clash YAML 放到 refer/proxy_select/ 和/或 refer/proxy_fix/
python tools/filter_residential.py

# 同时写入 ~/.config/clash.meta/guaguaMMDD.yaml
python tools/filter_residential.py -toclash
```

### 常用参数

| 参数 | 说明 |
| --- | --- |
| `-toclash` | 把 `guaguaMMDD.yaml` 写到 `~/.config/clash.meta/`；不加则不写 |
| `-o` / `--out-dir` | 输出目录，默认 `dist/` |
| `--select-dir` | 需要筛选的 YAML 目录，默认 `refer/proxy_select` |
| `--fix-dir` | 不筛选、全部保留的 YAML 目录，默认 `refer/proxy_fix` |
| `--mihomo` | mihomo 可执行文件路径 |
| `--keep-unknown` | 查询失败的节点也保留 |
| `--refresh-egress` | 忽略落地探测缓存，强制重测 |
| `--skip-probe` | 不走节点，改用入口 server IP（结果不可信，仅调试） |
| `--probe-timeout` | 单节点落地探测超时（秒），默认 12 |
| `--sleep` | 直连 ip-api 的间隔（秒），默认 1.5 |

探测结果缓存在 `.cache/`（入口 IP 与落地 IP 分开存）。`refer/`、`dist/`、`.cache/` 默认不进 Git。

## 目录

```
clash/ai.yaml              Clash Meta 规则模板（不含节点密钥）
shadowrocket/ai.conf       小火箭规则参考
tools/filter_residential.py
refer/proxy_select/        待筛选订阅 YAML（本地）
refer/proxy_fix/           固定保留 YAML（本地）
dist/                      生成结果（本地）
```

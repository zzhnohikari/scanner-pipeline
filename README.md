# Scanner Pipeline v13

JS/API 未授权访问扫描器 — 文件专项 + HTML/JS 静态参数画像 + URL/参数绑定 + POST body/form fuzz

> **定位**: CTF/攻防赛场景。脚本完成机械工作（JS 提取、API 发现、批量未授权测试），产出报告后由 AI（Claude/GPT）基于结果做精判：选高价值目标、构造正确参数、判断真伪、决定深挖方向。AI 层不在代码内，在操作流程中。

## 架构

脚本完成机械工作，AI（操作者）基于产出做精判：

```
┌─ 脚本层 (4 Phase, 自动) ──────────────────────┐
│ Preflight: masscan/naabu 端口发现（可选）        │
│ Phase 1: httpx 或内置 HTTP/scheme 规范化         │
│ Phase 2: JS 爬取 + API 提取                    │
│   BeautifulSoup / LinkFinder / Webpack chunk    │
│   Vue-React 路由 / 深度递归 / 200+ 库过滤       │
│   API-only 服务器自适应 / 路径拼接              │
│ Phase 3: 两阶段未授权测试                       │
│   3a: 快筛 (扁平池, TOP30 API × 2 绕过)         │
│   3b: 深度 (仅候选 × 全绕过方法)                │
│   文件专项: download/file/export/preview评分     │
│   参数画像: HTML/JS 参数名 + ID/文件名种子池      │
│ Phase 4: 报告 (JSON + Markdown, 风险分级)       │
├────────────────────────────────────────────────┤
│ → 产出: 漏洞列表 + 风险分级 + 绕过统计          │
└────────────────────────────────────────────────┘
                          ↓
┌─ AI 层 (操作者驱动) ──────────────────────────┐
│ 基于报告做精判:                                │
│   - 按比赛标准筛选高价值目标                    │
│   - 对模糊结果构造正确参数重试                  │
│   - 排除假阳性 (版本号/空响应/业务错误)         │
│   - 决定深挖方向: 摄像头接管? 公民数据? 横向?    │
│   - 证据采集: Chrome MCP 截图, curl 复现        │
└────────────────────────────────────────────────┘
```

## 快速开始

`pipeline/deep_scanner.py` 是主入口，**完全自包含**，不依赖项目中其他任何脚本。

```bash
# 1. 唯一依赖
pip3 install beautifulsoup4 --break-system-packages

# 2. 准备目标文件 (JSON 格式)
# [{"url": "https://target:port", "title": "系统名", "score": 100}]

# 3. 运行 (默认参数)
python3 pipeline/deep_scanner.py --input /tmp/my_targets.json --outdir /tmp/results

# 4. 高级用法
python3 pipeline/deep_scanner.py \
  --input targets.json \
  --outdir results/ \
  --workers 100 \
  --timeout 15 \
  --no-proxy \
  --fresh \
  --limit 50 \
  --full-bypass \
  --file-max-probes 36 \
  --param-max-probes 12 \
  --debug

# 5. 只提取 API，不测试 (dry-run)，可附带未授权/IDOR 矩阵预览
python3 pipeline/deep_scanner.py --input targets.json --dry-run --unauth-matrix

# 5b. 授权真实目标测试前建议控速但不封顶
python3 pipeline/deep_scanner.py --input targets.json --outdir results_safe \
  --max-rps-per-host 1 --min-delay-ms 1000 \
  --phase12-workers 4 --redact-raw-findings

# 6. 大批 IP/CIDR：masscan 发现端口 + httpx 确认 HTTP
python3 pipeline/deep_scanner.py \
  --input cidrs.txt \
  --input-format hostport \
  --port-scanner masscan \
  --http-prober httpx \
  --scan-ports 80,443,8080,8443,8001,9443 \
  --scan-rate 5000 \
  --outdir results_mass \
  --fresh \
  --no-proxy

# 7. 不装 httpx 时：masscan/naabu 只做端口发现，Phase 1 内置 HTTP 确认
python3 pipeline/deep_scanner.py \
  --input cidrs.txt \
  --input-format hostport \
  --port-scanner auto \
  --http-prober internal \
  --skip-port-probe \
  --outdir results_internal \
  --fresh \
  --no-proxy

# 8. 查看结果
cat results/report.json   # JSON 报告
cat results/report.md     # Markdown 报告 (含风险分级)

# 9. 运行本地复杂靶场回归测试
python3 tests/v10_realistic_lab.py
python3 tests/v11_param_bind_lab.py
python3 tests/v12_request_style_lab.py
python3 tests/v13_post_body_lab.py
```

## CLI 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--input` | `/tmp/v7_targets.json` | 目标 JSON 文件 |
| `--input-format` | `targets` | 输入格式: `targets` / `hostport` / `masscan` / `httpx-json` |
| `--port-scanner` | `none` | 外部端口发现器: `none` / `masscan` / `naabu` / `auto` |
| `--http-prober` | `internal` | HTTP确认层: `internal` / `httpx` / `auto` |
| `--expand-api-ports` | 空 | 对显式 host/URL 目标额外探测同主机的 API 后端口(如 `8080,8443,8000,8001`);空=关闭。命中前后端分离站点(前端 :443 + 裸后端 :8080) |
| `--no-expand-api-ports` | false | 强制关闭同主机 API 端口扇出 |
| `--expand-api-ports-max-targets` | 200 | 目标数超过阈值时自动跳过端口扇出,避免大批量放大请求;0=不限制 |
| `--replay-scope` | `host` | 跨 base 回放 API 清单范围: `none`=各 base 独立; `host`=同主机名不同端口共享(默认,命中前后端分离未授权); `global`=所有目标共享(跨实例) |
| `--replay-max-apis` | 0 | 每个 base 回放注入的独立精确 API 上限;0=不限制，非零值会在覆盖统计中记录被截断数量 |
| `--config-service-base-mode` | `same-host` | JS 静态配置服务基址: `off`=仅保留提取结果, `inventory`=只展示, `same-host`=对同主机声明 origin 做独立安全 GET 探测 |
| `--config-service-base-max-per-target` | 8 | 每个前端目标参与 REST 约定探测的配置服务基址上限;0=不限制,不影响全局爬虫队列 |
| `--config-rest-max-suffixes` | 8 | 每个配置服务基址最多使用的只读 REST 后缀数;0=全部 |
| `--enable-backend-baseline` | false | 启用小型裸后端高价值 API baseline,适合纯 JSON/API-only 后端二次深挖;默认关闭,避免大批量噪声 |
| `--extra-api-wordlist` | 空 | 额外 API 路径字典文件,可重复传入;每行一个 `/path` 或完整 URL,用于补齐无 JS 清单的行业/厂商接口 |
| `--scan-ports` | 常用Web端口 | masscan/naabu 使用的端口列表 |
| `--scan-rate` | 1000 | masscan/naabu 速率 |
| `--masscan-bin` | PATH | 指定 masscan/masscan.exe 路径 |
| `--naabu-bin` | PATH | 指定 naabu/naabu.exe 路径 |
| `--httpx-bin` | PATH | 指定 httpx/httpx.exe 路径 |
| `--httpx-extra-args` | 空 | 透传给 httpx 的附加参数 |
| `--outdir` | `/tmp/v13_scan_results` | 输出目录 |
| `--workers` | 50 | 并发线程数 |
| `--timeout` | 12 | HTTP 超时(秒) |
| `--phase2-timeout` | 180 | Phase 2 软超时, 超时目标用 baseline 兜底 |
| `--phase3a-timeout` | 240 | Phase 3a 快筛软超时, 超时后先进入候选/补筛流程 |
| `--exact-api-max` | 0 | 每目标独立精确来源 API 的安全首扫上限;0=不限制 |
| `--exact-sweep-timeout` | 0 | 全量精确 API 首扫软超时;0=不限制且不受 `--phase3a-timeout` 影响 |
| `--rescue-timeout` | 180 | Phase 3a baseline 补筛软超时 |
| `--disable-rescue-baseline` | false | 关闭 Phase 3a baseline 补筛 |
| `--phase3b-layer-timeout` | 300 | Phase 3b 每个分层的软超时 |
| `--limit` | 0 | 限制目标数, 0=全部 |
| `--dry-run` | false | 只提取 API, 不测试 |
| `--unauth-matrix` | false | 仅 dry-run 输出未授权/IDOR 矩阵预览，不发送额外请求 |
| `--min-delay-ms` | 0 | Phase 3 每主机请求最小间隔毫秒，0=不限制 |
| `--max-rps-per-host` | 0 | Phase 3 每主机最大请求速率，0=不限制；与最小间隔取更保守值 |
| `--max-requests-per-host` | 0 | Phase 3 每主机最大请求数硬上限，0=不限制 |
| `--redact-raw-findings` | false | 写出 checkpoint/report 前移除 finding 内 `raw` 等原始响应字段，避免敏感正文落盘 |
| `--phase12-workers` | 0 | 单独限制 Phase 1/2 线程池大小，0=沿用当前 `--workers` 派生行为；Phase 3 仍使用 `--workers` |
| `--legacy-recovery` | false | 启用小型 reviewed legacy 候选集，按 `legacy_recovery` 低置信源(0.30)标记；默认关闭 |
| `--compare-inventory OLD` | 空 | dry-run 后对比旧 apis.json/phase2_inventory.jsonl，输出默认聚合、不含具体 host/path 的 inventory_diff.json |
| `--compare-output PATH` | 空 | 指定 inventory diff 输出路径 |
| `--include-samples` | false | inventory diff 中包含少量 path 样本；默认不输出具体路径 |
| `--validate-from-report REPORT` | 空 | 从既有 report.json 提取命中端点做保守聚焦复核，自动强制 redaction 与安全限速 |
| `--validate-plan-only` | false | 仅生成 validate_plan.json，不发起复核请求 |
| `--full-bypass` | false | 启用 FULL 绕过方法, 默认仍命中断路 |
| `--collect-all-variants` | false | 命中后继续收集所有绕过/参数变体, 隐含 `--full-bypass`, 小批目标补证据用 |
| `--debug` | false | 调试日志 |
| `--no-proxy` | false | 绕过 macOS/环境系统代理 |
| `--skip-port-probe` | false | 跳过 TCP connect 端口预检，但仍保留 HTTP/scheme 确认 |
| `--allow-unverified-url` | false | 显式 URL 的 HTTP/scheme 确认失败时仍保留输入 URL |
| `--fresh` | false | 扫描前清理输出目录中的旧 JSON/Markdown 结果 |
| `--resume` | false | 报告阶段合并输出目录中的历史 checkpoint，默认只统计本轮结果 |
| `--disable-file-hunter` | false | 关闭下载/预览/导出接口专项 |
| `--enable-file-baseline` | false | 启用硬编码文件下载 baseline 路径, 大批资产默认不建议开启 |
| `--file-max-probes` | 36 | 每个疑似文件接口最多文件参数探测次数 |
| `--disable-param-harvest` | false | 关闭 HTML/JS 静态参数画像 |
| `--phase3a-param-rescue` | false | 3a 阶段对有 URL 绑定参数的高价值 API 做小流量参数补筛 |
| `--phase3a-param-rescue-max-apis` | 10 | 每个目标最多参与 3a 参数补筛的 API 数, 0=不限制 |
| `--phase3a-body-max-apis` | 4 | 每个目标在 3a body-fast 阶段最多参与 POST/JSON 参数探测的 API 数, 0=不限制 |
| `--param-max-probes` | 12 | 每个接口最多静态参数模板探测次数 |
| `--param-probe-mode` | `targeted` | 静态参数探测模式: `targeted` 仅高价值接口, `broad` 全部接口 |
| `--js-max-download` | 0 | 每个目标最多下载外链JS数, 0=全部下载 |
| `--js-max-bytes` | 2097152 | 单个 JS/module/lazy 响应的解压后硬上限；0 仍使用安全默认 2 MiB，不表示无限 |
| `--js-ast-mode` | `auto` | `auto` 在安装 esprima 时启用有界 AST 并保留正则回退；`off` 关闭；`required` 在依赖缺失时退出 |
| `--js-ast-max-bytes/nodes/depth/expressions` | `750000/20000/64/4000` | 单个脚本 AST 输入和遍历硬边界 |
| `--js-advanced-max-assets` | 64 | AST/import map/manifest/source map 每目标新增同源 JS 资产总上限, 0=不限 |
| `--advanced-inventory-max-declarations` | 64 | 每类高级 inventory 持久化声明上限；同源/data eligible 记录可替换先到的 inventory-only 记录, 0=不限 |
| `--import-map-mode` | `explicit` | 只解析 HTML 中显式 inline/external `type=importmap`；`off` 关闭 |
| `--import-map-max-count/bytes/entries` | `8/131072/128` | import map 每目标数量、单文件字节和条目边界 |
| `--asset-manifest-mode` | `explicit` | 只跟随 HTML/JS 明确引用的 manifest，不猜测常见路径；`off` 关闭 |
| `--asset-manifest-max-count/bytes/nodes/entries` | `8/262144/2048/256` | asset manifest 抓取及 JSON 遍历边界 |
| `--source-map-mode` | `off` | `explicit` 时只跟随同源 `sourceMappingURL` 或 bounded data URI；默认不抓 Source Map |
| `--source-map-max-count/bytes/sources/ratio` | `4/524288/32/8.0` | Source Map 数量、字节、`sourcesContent` 数量和解压比例边界 |

## 大批资产前置扫描

推荐分层：

```text
IP/CIDR
  -> masscan/naabu: 只发现开放端口
  -> httpx 或内置 Phase 1: 确认 HTTP/HTTPS、跳转、base_url
  -> Phase 2: HTML/JS/Swagger/参数画像
  -> Phase 3: 未授权探测
```

跨平台要求：

- Linux/macOS/Windows 都通过 PATH 查找 `masscan`、`naabu`、`httpx`；Windows 可直接使用 `.exe`。
- `httpx` 指 ProjectDiscovery 的 HTTP toolkit，不是 Python 的 httpx 库。
- 如果二进制不在 PATH，用 `--masscan-bin`、`--naabu-bin`、`--httpx-bin` 指定完整路径。
- `--port-scanner auto` 优先使用 masscan，其次 naabu。
- `--http-prober auto` 优先使用 httpx；找不到 httpx 时回退内置 Phase 1。
- `--skip-port-probe` 只跳过内置 TCP connect，不跳过 HTTP/scheme 确认，适合 masscan/naabu 已经给出 host:port 的场景。

示例：

```bash
# masscan + httpx + scanner
python3 pipeline/deep_scanner.py \
  --input cidrs.txt \
  --input-format hostport \
  --port-scanner masscan \
  --http-prober httpx \
  --scan-ports 80,443,8080,8443,9443 \
  --scan-rate 5000 \
  --outdir results \
  --fresh \
  --no-proxy

# naabu + 内置 HTTP 确认
python3 pipeline/deep_scanner.py \
  --input cidrs.txt \
  --input-format hostport \
  --port-scanner naabu \
  --http-prober internal \
  --skip-port-probe \
  --outdir results \
  --fresh \
  --no-proxy

# 已有 httpx JSONL，直接接入
python3 pipeline/deep_scanner.py \
  --input httpx.jsonl \
  --input-format httpx-json \
  --http-prober internal \
  --skip-port-probe \
  --outdir results \
  --fresh \
  --no-proxy
```

## 六种认证绕过方法

| 方法 | 说明 | 默认启用 |
|------|------|----------|
| GET_no_auth | 标准 GET 无认证头 | ✅ |
| POST_JSON_no_auth | JSON POST 无认证 | ✅ |
| GET_empty_bearer | `Authorization: Bearer ` 空 token | `--full-bypass` |
| GET_admin_token | `Authorization: Bearer admin-token` | `--full-bypass` |
| POST_FORM_no_auth | 表单 POST (x-www-form-urlencoded) | `--full-bypass` |
| POST_JWT_none | JWT `alg: none` 绕过 | `--full-bypass` |

> **注意**: 默认模式下第一个有价值命中后立即短路。开启 `--full-bypass` 会尝试更多认证绕过方法，但仍然命中断路，适合大批资产争取覆盖率。开启 `--collect-all-variants` 会隐含 `--full-bypass`，并在命中后继续收集所有绕过/参数变体，适合小批目标补证据。

普通 API 端点自动尝试 3 种查询后缀: 无参数 / `?page=1&count=10` / `?page=1&size=10`。JS/Swagger/页面里真实出现的疑似文件接口会启用文件专项参数模板。v13 会把 HTML/JS 中提取到的 URL 与参数名绑定，在候选目标的 3b 阶段生成组合参数探测；如果前端请求明确使用 POST JSON body 或表单 body，POST_JSON/POST_FORM 会把绑定参数放进真实请求体，而不是只拼到 query。

> **比赛建议**: 大批资产默认不要开启 `--enable-file-baseline`。文件下载/导出类漏洞优先走 JS 提取到的真实端点 + 静态参数画像，这样请求量更小、噪声更低。只有在小批目标二次追打时，再打开硬编码文件 baseline。

## v13 新增: URL/参数绑定与 POST Body

v13 会从真实前端请求风格中提取 URL 与参数绑定关系，并记录参数来源是 query、JSON body 还是 form body。例如:

- `axios({ url, data })`
- `axios.get/post`
- `request({ url, data })`
- `request("/api/x", { params })`
- `fetch + JSON.stringify`
- `fetch + qs.stringify`
- `fetch + URLSearchParams`
- `jQuery ajax/get/post/getJSON`
- direct trusted `axios/request/service/http.get/post` calls (`this.http` and other property receivers remain inventory-only)
- `uni.request`
- `wx.request`
- `FormData.append + axios.post`

绑定后不会把所有全局参数乱塞到所有接口，而是优先对当前 URL 使用它自己的绑定参数:

- GET/query 风格: `/api/user/list` 绑定 `pageNum/pageSize/orgId/keyword` 后生成 `?keyword=test&orgId=1&pageNum=1&pageSize=10`
- POST JSON 风格: `fetch("/api/user/search", { body: JSON.stringify({deptId,pageNum}) })` 会发送 JSON body `{"deptId":"1","pageNum":"1"}`
- POST form 风格: `$.post("/api/doc/preview", {docId,fileType})` 或 `qs.stringify(...)` 会发送 `application/x-www-form-urlencoded` body

参数 fuzz 默认只在候选目标的 3b 深测阶段开启，3a 快筛不做静态参数组合，避免大批量目标请求膨胀。

Phase 3a 默认会对未进入候选的目标再跑一轮通用 baseline 补筛。默认模式下补筛仍使用 FAST 绕过；开启 `--full-bypass` 后补筛使用 FULL 绕过。这个设计用于覆盖通用 API 文档、健康检查与管理端点，同时不让静态参数 fuzz 在全量资产上提前膨胀。

大批资产扫描时，优先使用 `--full-bypass` 但不要开启 `--collect-all-variants`。这样仍能覆盖空 Bearer、表单 POST、JWT none 等绕过方式，但同一端点拿到可用数据/文件/凭证/攻击路径情报后会停止，避免 3b 队列在慢站点上被重复变体耗尽。`--collect-all-variants` 更适合对已命中的高价值目标二次复核，用来补充报告里的多绕过方式证据。

## HTML/JS 静态参数画像

用于补足“没有 Swagger 的站点也能做参数提取和探测”的缺口。爬取首页、内联脚本、业务 JS、同站二级页面时同步提取:

- URL 查询参数: `?id=`, `&fileId=`
- 表单字段: `name=`, `v-model=`, `prop=`, `field=`
- 请求体字段: `params: { ... }`, `data: { ... }`, `body: { ... }`
- 对象字面量中的常见字段: `userId`, `deptId`, `filePath`, `objectKey`
- 数字 ID 种子: `id: 1`, `fileId=100`
- 文件名种子: `demo.pdf`, `template.xlsx`, `1.docx`

这些数据会形成站点级参数画像，Phase 3 测试接口时按优先级生成 `?参数名=种子值` 模板。默认 `targeted` 模式只对下载、导出、预览、文件、查询、详情、用户、设备、日志、告警等高价值接口启用静态参数探测，避免普通接口全部膨胀。需要彻底覆盖时再使用 `--param-probe-mode broad`，并结合 `--param-max-probes`、`--phase3a-param-rescue`、`--phase3a-param-rescue-max-apis 0`、`--phase3a-body-max-apis 0` 放开 3a 参数补筛与 POST/JSON body 参数探测。

默认请求量边界:

- 普通接口: 3 个基础 query 后缀
- 高价值普通接口: 3 个基础后缀 + 最多 12 个静态参数后缀
- JS/Swagger/页面真实发现的文件接口: 3 个基础后缀 + 最多 36 个文件专项后缀 + 最多 12 个静态参数后缀
- 硬编码文件 baseline: 默认关闭, 仅 `--enable-file-baseline` 时加入主流程

`--dry-run` 的 `apis.json` 会输出 `param_names`、`seed_values`、`file_seed_values` 供人工复核；开启 `--unauth-matrix` 时还会输出 `unauth_matrix_preview`，只描述 GET/POST query/json/form 变体思路，不进行额外主动请求。也会输出 JS 统计:

- `js_discovered`: HTML/二级页面发现的外链 JS 总数。
- `js_app_candidates`: 过滤 `chunk-vendors` 等通用库后的业务 JS 候选数。
- `js_attempted`: 实际尝试下载的业务 JS 数，受 `--js-max-download` 控制。
- `lazy_chunks_discovered` / `lazy_chunks_attempted` / `lazy_chunks_downloaded`: Webpack/Vite 懒加载 chunk 发现、尝试、下载数量。
- `js_count`: 成功下载并解析的业务 JS 数。
- `js_advanced_stats.content_truncated`: 超过 `--js-max-bytes` 的 JS 数量。读取与 gzip/deflate 解压均保持 `limit+1` 判定边界；截断前缀仍参与安全的正则/dataflow 提取，但 partial script 不进入 AST，也不计入 `ast_parse_errors`。

正常扫描模式也会增量写出 `phase2_inventory.jsonl`。这个文件每个目标一行 JSON，包含 `apis`、JS 统计、`param_names`、`seed_values` 和可序列化的 `param_profile`，便于在 Phase 3 超时、无漏洞或后续切换探测策略时复用前面的 JS/API 提取结果；只有漏洞 checkpoint 仍然按目标单独写 `*.json`。

JS graph 还会把 inline、外链和二级页面脚本中显式声明的服务基址写入 `config_service_bases`。默认 `same-host` 模式仅对同一 hostname 的声明 origin 生成独立 `config_rest_candidates`，候选固定为精确基址及 `/users`、`/profile`、`/list`、`/page`、`/all`、`/tree`、`/info`；每项只发送一次无认证 GET，要求精确服务前缀下存在稳定的 catch-all 基线，不发送 query、body、认证头或其他 HTTP 方法。跨主机基址始终只做 inventory。

现代前端补充覆盖:

- Vite/dev module 页面会递归解析 `type=module`、`import ... from`、`import(...)` 和 `new URL(..., import.meta.url)` 指向的 `/src/*.ts`、`.vue`、`.js` 模块；这些模块只参与 JS/API 提取，不再作为 API 端点误测。
- 会从 JS 字符串常量拼接中恢复 API，例如 `const base="/api/v1/"; url: base + "settings"` 或 `const p="/admin/"; url: p + "messages"`，避免只提取到前缀而漏掉真实接口。
- ThinkPHP `controller not exists` 且带 `line/file/trace` 的框架错误响应会被过滤，不再因为 `code:0` 被误判为未授权数据。

Phase 2 高级静态发现不会执行目标 JavaScript。AST 使用成熟的 `esprima` parser，安装方式：

```bash
python3 -m pip install -r requirements-ast.txt
```

默认 `--js-ast-mode auto`：依赖存在时执行有界 AST，依赖缺失或单个脚本语法不兼容时在统计中记录并继续现有正则提取。自动模式不会静默把 AST 结果伪装成成功；需要在 CI/固定环境强制验证真实 AST 路径时使用 `--js-ast-mode required`，依赖缺失会在创建输出前返回非零。AST 只把同源、JS-like 资源加入下载队列，跨源 URL 仅保留已脱敏 inventory。高级抓取使用独立 exact-origin redirect policy，scheme、hostname 或 effective port 任一变化都会拒绝，普通 crawler 的 redirect 行为不变。

语法上直接且无歧义的 `fetch`、axios/request/service/http、`window/globalThis.fetch`、jQuery 与 uni/wx request sink 会以 `js_request` provenance 单独记录，保留观测到的 HTTP method，并进入默认不限条数的 all-exact 安全首扫。普通 route/string literal 不继承该 provenance；POST/DELETE 仍受既有 method safety 规则约束。静态高置信 trust 使用统一 fail-closed 开关：整份脚本只要包含任意模板插值 `${...}`，或基础 string/comment/template span 之外存在 `/`，所有静态 request-sink method/body/provenance 都关闭；即使插值只含字符串/注释/regex，或 `/.../` 是明确控制位置 regex，也不尝试恢复。这是避免自制 regex-vs-division/parser 绕过的有意 false negative，普通路径 inventory 与通用 API-root quota 保留；结构化 AST 可独立证明其支持的真实调用，但不会继承已关闭的静态 body。无上述语法风险时，精确大小写的 axios/request/service/http 仍要求整份脚本不存在声明、参数、解构、catch/for 绑定、别名、任意赋值或 identifier Unicode escape 歧义。factory client 只允许一个兼容旧前端的窄例外：明确语句边界（含可证明的 ASI 换行）处、顶层、大小写精确且唯一的 `http/request/service = axios.create(...)`，并且相关 receiver/axios 的每个代码态出现都能证明为该绑定或直接调用；条件声明、use-before-bind、任意重赋值或大小写不一致都会降为普通 inventory。`obj.http` 和带值的 `{http: ...}` key 作为非绑定上下文忽略；`{http}` shorthand、rest/spread 和间接调用仍 fail closed。其他 factory client、XHR 标识符、属性持有和别名传播不会获得高置信 sink provenance 或方法绑定。对于没有独立精确 provenance、但已经提取的路径，首段为 `api` 或简单的 `[a-z0-9]+-api` 时获得通用 API-root 评分和最多 16 条的启发式种子配额，例如 `prod-api`、`inner-api`、`iot-api`；扫描器不会据此生成或猜测任何 `*-api` 路径。

`fetch` options 使用有界三态解析：无第二参数或可完整证明且没有 `method/type` 的普通对象为 GET；顶层直接字面量 `method/type`（包括 quoted/computed literal key、bounded literal spread，重复键按最后一次生效）可证明具体方法。Identifier-valued method options 一律不提升，即使标识符来自字面量 `const`；`const`/`let`/`var`、参数、import、遮蔽及跨作用域形式统一标为 ambiguous，不进入主动候选。这是避免维护不完整 JavaScript 作用域解释器的安全兼容取舍，不表示 AST 成功证明了方法。非普通 options、未知 spread/计算键或调用表达式方法值同样 fail closed；无关属性的嵌套值不会改变 method truth。启发式 API-root 配额先按无 query canonical path 去重，不生成额外路径；`js_request` 等 exact 路径由 all-exact 队列独立承接。

Import map 与 asset manifest 默认只跟随 HTML/JS 中明确声明的引用，不猜测 `manifest.json` 等常见路径；跨源 entries 只做 inventory。inline import map 也要求其 containing document 与根页面 exact-origin，同 hostname 不同端口或不同 scheme 的普通子页不会授权 active entry。内部 fetch URL 会保留服务端必需的 query（去掉 fragment/userinfo），持久化 identity/provenance 则始终删除 query/fragment/userinfo，query value 也会从参数种子中移除。active count 在 same-origin/data eligibility 与 target-global dedup 后计算，因此先出现的跨源声明不会消耗 active quota；声明 inventory 另受 `--advanced-inventory-max-declarations` 限制。显式 manifest 的 link 与 JS/string 引用按原文字符偏移统一执行 first occurrence；精确同 offset 才以内存 full fetch URL 作稳定次序，因此同一 sanitized identity 的 query 变体不会依赖 set/PYTHONHASHSEED。Web App Manifest 的 icons、screenshots、shortcuts、handlers 等通用资源上下文不会作为 JS build output。

AST 的 wrapper 参数恢复只接受词法绑定明确的直接小写 `.get`、对象字面量、精确恒等函数和无分支的规范对象复制 helper。形式参数重绑定/遮蔽、接收器遮蔽或不确定成员写、分支/提前返回 helper、任意 imported transform 均不会产生参数/body 事实；不会按导入名或已观察属性猜测框架语义。直接可信接收器上的 literal 小写 GET 仍独立保留 queryless `js_request`/GET inventory、Phase 3 种子及安全基线 GET，仅该不透明调用的 query 参数变体被阻止。同路径另有可信直接参数绑定时，可信事实继续保留并解除参数阻止。wrapper literal 也可使用与扫描页面（不是 CDN/asset）exact-origin 的 queryless 绝对 URL，持久化前转换为经过共享 validator 的 root-relative path；scheme/host 大小写归一，DNS hostname 使用标准库 IDNA ASCII 形式，允许至多一个 DNS root trailing dot，默认端口等价；userinfo、host percent escape/IPv6 zone、重复 root dot、内部空 label、跨源、protocol-relative 及任何 `?`/`#` delimiter 一律拒绝。源级参数名仍可用于 inventory，但只有路径局部绑定或有界接口默认值能生成 active 参数变体；所有画像映射键、template 和 `_apis_from_params` 在 merge/序列化边界再次统一校验。active profile identity 只使用一个经过校验的精确 canonical path；短路径不会向带前缀路径泄漏 method、param、body、blocked、content-type 或 replay 事实，反向亦然。部署前缀扩展仅为低置信、目标本地的 inventory heuristic：每目标最多采用 16 个经过共享 validator 校验的前缀、生成 128 条路径，且不会对已经位于任一已知前缀下的路径继续叠加。生成路径不参与跨 base 回放、body/参数救援，也不复制任何 active profile 事实；Phase 3 初始层至多保留 8 条并且只能使用默认 queryless safe GET。路径一旦具有独立的精确来源，`prefix_inventory` 标记被丢弃，精确 method/body/params 按原规则生效。

`api_meta.sources` 是有限协议，不接受插件或输入任意扩展字符串。当前允许：`swagger`、`openapi`、`js_request`、`param_binding`、`js-graph`、`js_literal`、`js`、`html`、`vue_router`、`react_route`、`extra_wordlist`、`business_pattern`、`backend_baseline`、`api_fuzz`、`baseline`、`legacy_recovery`、`legacy_baseline`、`prefix_inventory`。其中前十一项（截至 `extra_wordlist`）是独立精确来源，可覆盖同路径的 `prefix_inventory`；其余非前缀项是已知启发式来源，不会单独把混合前缀记录提升为 active profile。未知来源以及已提供但为 string/scalar/mapping/mixed/null 的畸形 source/item/root 会在 live add、merge 与 JSONL round-trip 中统一编码为 `prefix_inventory`，置信度最高 `0.25`，仅允许有界 queryless GET 初始筛选；只有 metadata 或对应 path key 真正不存在时才保持 absent。所有 inventory API、metadata key、profile path 与 replay list 在持久化和任务构造边界统一转换为经共享 validator 验证的 queryless root-relative canonical path；非法原始条目及关联状态不会消耗排序、配额或请求。

Source Map 默认关闭，显式开启后也只处理 `sourceMappingURL`，校验 v3 schema、同源、字节/数量/比例和 source path，`sourcesContent` 仅在内存中送入既有提取器，不保存 raw map 或原始源码，也不递归猜测其他 map。派生路径、参数名、method binding 和配置 provenance 可以合并，但 seed/file-seed/enum/example 等绑定值一律丢弃。Phase 2 JSONL/dry-run 会输出安全的 `js_advanced_stats`、`js_resource_inventory`、`import_map_inventory`、`asset_manifest_inventory`、`source_map_inventory` provenance。

## 未授权文件接口专项

重点探测下载、预览、导出、附件、模板、图片等接口。v12 默认只对 JS/Swagger/页面中发现的真实文件端点启用专项探测，不再对所有目标暴力枚举硬编码文件下载路径:

```text
download, file, export, preview, view, read, attachment, attach,
upload, resource, document, doc, image, template
```

自动尝试常见文件参数:

```text
id, fileId, attachId, docId, path, filePath, url, fileUrl,
name, fileName, key, objectKey, ossKey, resourceId
```

文件响应评分:

| 信号 | 分值 |
|------|------|
| `Content-Disposition` | +3 |
| 文件魔数命中 PDF/ZIP/OLE/JPEG/PNG 等 | +3 |
| 文件类 `Content-Type` | +2 |
| 响应体大于 2KB | +1 |
| URL/路径命中文件接口关键词 | +1 |
| 登录/未授权/请登录提示 | -5 |
| 普通 HTML 且无文件信号 | -3 |

验证码与普通小图片会被过滤: URL/下载头命中 `captcha`、`verifyCode`、`checkCode`、`authcode` 等验证码关键词时不记为文件泄露；无下载头的小 JPEG/PNG/GIF 也不会因为文件魔数单独入报。图片类接口只有在强下载/导出路径、下载头或较大响应体等信号同时存在时才作为文件类发现。

证书包、控件、客户端、APK/EXE 等公开下载会标记为 `public_download_intel` 并降为 LOW。它们可能是攻击路径情报, 但默认不按高价值文件泄露处理。文件类发现按路径、下载头、魔数、大小做实体去重, 避免同一公开文件被不同 query 参数重复刷屏。

评分 >= 6 记为 HIGH，评分 >= 4 记为 MEDIUM。报告会输出 `file_leak`、`file_score`、文件魔数、文件类型、下载头和响应大小。

## 报告输出

### JSON (`report.json`)
完整 finding 列表，含响应摘要(raw 截断为 500 字符)。文件类发现会额外包含 `file_leak`、`file_score`、`file_magic`、`content_type`、`content_disposition`、`body_size`。`stats` 字段输出原始发现、去重端点、数据类发现、去重数据端点、高价值发现、公开下载情报等统计口径。

### Markdown (`report.md`)
- 漏洞汇总表（风险分级: CRITICAL/HIGH/MEDIUM/LOW）
- 统计口径（raw findings / unique endpoints / unique data endpoints / high-value findings）
- 每个目标的详细发现
- 文件类发现数量、文件评分、文件类型、文件魔数、下载头
- 绕过方法命中统计

### 风险分级规则
- CRITICAL: 凭证泄露 + 大量数据 / 敏感字段(secret/password/phone/email)
- HIGH: 凭证泄露 / 大量数据(>10条) / 文件响应评分 >= 6
- MEDIUM: 有数据返回 / Swagger/Druid等API文档暴露(攻击路径情报) / 文件响应评分 >= 4
- LOW: 端点可达但无可利用数据

> Swagger/API-Docs/Druid 虽不直接算比赛分，但是攻击路径情报——暴露全部 API 端点、参数、认证方式，可据此精准打击其他接口。

## 关键技术

- **扁平线程池**: 不嵌套, 避免 GIL 争抢
- **分层深测**: 3b 按 baseline → business → file 顺序执行, 先保住 v8/baseline 产出, 再跑 JS/参数画像和文件增量
- **Checkpoint 落盘**: 3a 候选和每个 3b 分层命中都会写目标 JSON, 中断后已完成结果不丢
- **Phase 2 软截止**: JS/API 提取超过 `--phase2-timeout` 的尾部慢目标会 baseline 兜底, 不阻塞后续未授权测试
- **独立精确 API 全量首扫**: `swagger`、`openapi`、`js_request`、`extra_wordlist` 等有限 allowlist 中的独立精确来源，先进入单独的 canonical-path 去重安全队列；默认不受 Top-N、候选命中、启发式池和 `--phase3a-timeout` 影响。未知方法或已证明 GET 只获得安全 GET 机会；DELETE、未获准的 action POST 和不支持的不安全方法只计入安全跳过原因，绝不降级伪装成 GET。
- **Exact 不重复调度**: all-exact 首扫已经使用 path-local method/body/param scheduler，因此同一 exact canonical path 不再进入 config-rest、legacy fast、rescue、body-fast、param-rescue、backend、business、file 或 candidate-deep provider，也不占这些启发式池的 4/8/80 等容量。传输边界另有 run-local first-opportunity ledger，按 canonical path + method/content-type/auth mode 记录 exact 实际请求；未来 legacy provider 即使遗漏构造期过滤，也不能重发同一 mode，未由 exact 执行的不同显式 mode 不受影响。启发式路径仍保留原有 deep 流程。
- **Phase 3a 软截止**: 该截止仅约束后续启发式快筛；快筛尾部慢请求超过 `--phase3a-timeout` 后跳过, 已命中目标先进入 3b, 未命中目标由 baseline FULL 补筛兜底
- **超时 drain**: 网络任务池软超时后立即关闭新的 Phase 3 request/control slot，取消尚未启动的任务，并等待已在执行的至多一个有界 HTTP 操作退出后再生成 coverage/report。任何已经进入 worker body 并正常返回或失败返回的 invocation 都计入不可变 `TaskPoolStats.completed`，即使它在截止前尚未取得请求槽；只有被取消或从未进入 worker body 的任务计入 `skipped_timeout` 并触发 `on_timeout`。两者互斥且总和不超过 submitted；`deadline_pending` 只是允许与 completed 重叠的截止时诊断数。返回或落盘后不会再有后台 worker 发送请求或修改 finding/coverage。
- **覆盖口径**: `report.json`、`api_coverage.json` checkpoint 与 `stats.api_coverage` 只保存聚合计数和有限原因，不保存端点样本、query 或正文；无发现目标不会因此生成 finding checkpoint。`scheduled` 表示进入任务队列，`attempted` 仅在真实 API 请求取得请求槽后计数，`completed` 表示至少尝试过且任务已返回。coverage wire 只接受有限字段、有限原因和非负有界整数；畸形 JSONL record 会 fail closed 并继续读取后续记录。显式 replay cap 会产生 `replay_max_apis` 不完整原因。`report.apis` 为兼容保留，仍表示 target/base 记录数；API 清单总量使用 `api_inventory_total`。
- **Metadata/Profile 索引**: 每次顶层 exact 规划、seed/provider 规划或 replay 调用，都对每个 target/record 构建一次不可变的 canonical `api_meta`、source-state 与 confidence 调用级快照，调用内 exact/prefix/replay/priority/provider 查询均为 O(1)。快照从不存入 record，下一次顶层调用会自动观察同长度的原地 metadata 变更。跨 base replay 同样为每个 source profile 一次性 canonicalize 所有 exact path-local maps 与 blocked set，随后逐 path O(1) 查找；profile 快照也只存在于该次 replay 调用并在返回时丢弃，因此下一次调用会观察同 identity/长度的嵌套原地变更。group 内使用原始 source 快照，不递归传播刚 replay 的事实。内部索引不会进入 JSON/JSONL。
- **全阶段软截止**: baseline 补筛和 3b 各层也有独立软超时, 避免任一阶段尾部慢请求拖死整批
- **SSL 自签名**: `ssl.CERT_NONE` + 12s 超时 + 3 次重试
- **API-only 服务器**: 首页为空时自动创建轻量条目 + 基准路径
- **前缀 inventory**: 从 URL 目录结构一次性生成有界、校验后的低置信路径；不递归拼接或复制主动画像
- **BeautifulSoup**: 替代正则解析 HTML, 支持 preload/prefetch JS
- **Webpack chunk**: `{...}[n]+".js"` 模式 + publicPath 解析
- **Vue/React 路由**: `__vue_app__` / `<Route path=` 检测
- **双模式测试**: 命中断路(快速) / 全量变体收集(`--collect-all-variants`)
- **文件响应识别**: `Content-Disposition`、文件魔数、文件类 `Content-Type`、响应大小综合评分
- **文件参数模板**: 对真实发现的下载/预览/导出等接口自动尝试 ID、路径、文件名、对象 Key 等常见参数
- **文件实体去重**: 文件类按路径、下载头、魔数、大小去重, 公开下载降级为 `public_download_intel`
- **静态参数画像**: 从 HTML/JS/Form/请求体对象提取参数名、ID 种子、文件名种子, 无 Swagger 时仍能生成探测模板
- **探测限流**: 默认 targeted 模式只对高价值接口使用静态参数模板, broad 模式需显式开启

## 已知限制

1. **SSL 超时**: 极慢的 SSL 握手(>30s)仍可能被跳过
2. **参数构造**: v12 会从 HTML/JS 提取参数名、种子和 URL/参数绑定关系, 但仍不是完整语义级请求重放
3. **非 JSON 响应**: XML/SOAP/HTML 中的数据可能被跳过
4. **纯 API 服务器**: 无 JS 可提取, 仅测基准路径
5. **文件专项误差**: 无真实文件 ID/对象 Key 时仍可能漏报; 业务错误若返回附件头或文件类型可能需要人工复核
6. **报告不含截图**: 证据采集需手动用 Chrome MCP 完成
7. **broad 模式请求量**: `--param-probe-mode broad` 会显著增加请求量, 大批资产默认不建议开启
8. **硬编码文件 baseline**: `--enable-file-baseline` 会显著增加请求量和 WAF 噪声, 只适合小批目标二次验证
9. **输出目录复用**: 默认报告只统计本轮结果; 需要合并历史 checkpoint 时显式加 `--resume`; 重新跑完整扫描建议加 `--fresh`
10. **Brotli 响应**: 常见 Python Brotli binding 没有可靠的 max-output API；为保证解压内存硬边界，扫描器不主动声明 `br`，bounded 读取只解 gzip/deflate。服务端强制返回 Brotli 时正文可能无法分类。

## 本地复杂靶场

`tests/v10_realistic_lab.py` 会启动 3 个本地 HTTP 目标并调用真实扫描器:

- 前缀 SPA: `/tenant/` 部署, JS 中声明 `VUE_APP_BASE_API=/tenant/prod-api`, 文件下载接口只在 JS 中出现
- API-only Swagger: 首页近似空响应, `/v3/api-docs` 暴露摄像头 API
- 噪声站点: 暴露 `/api/profile`, 用于验证 `profile` 不会被误判为文件接口
- 验证码负例: JS 暴露 `verifyCode` PNG, 用于验证验证码不会被误判为文件泄露

期望结果:

- 不开启 `--enable-file-baseline` 也能命中 JS 派生的前缀文件下载
- Swagger 派生的摄像头数据接口会被识别为高价值发现
- `/api/profile` 不产生 `file_leak`
- `verifyCode` PNG 不产生 `file_leak`
- 默认模式不会请求 `/api/common/download` 等硬编码文件 baseline

`tests/v11_param_bind_lab.py` 覆盖 webpack、jQuery ajax、axios 三类 URL/参数绑定场景。

`tests/v12_request_style_lab.py` 覆盖 axios object、request params、uni/wx request、qs.stringify、URLSearchParams、Angular HttpClient、jQuery getJSON、FormData 等更多实战请求风格。

## 比赛算分标准

- ✅ 直接算分: 摄像头/IoT 接管, 公民信息, RCE, 可利用的攻击路径
- ⚠️ 攻击路径情报: Swagger/API-Docs/Druid（不直接算分，但暴露所有 API 可据此深挖）
- ❌ 不算: 版本号, RSA 密钥(单独), 框架类型

## 参考项目

| 项目 | 继承技术 |
|------|----------|
| JSFinder | BeautifulSoup, LinkFinder 正则, 深度递归 |
| Webpack_extract | Webpack chunk, Rules.js 敏感字段 |
| VueCrack | Vue/React 实例检测, 路由提取 |
| Packer-Fuzzer | API 收集模式, Webpack 检测 |
| extract_api.py (jjjjjsz) | 200+ 库过滤列表 |

## 文件说明

`pipeline/deep_scanner.py` 是主入口, 自包含, 不 import 其他脚本。其他文件均为早期独立工具, 互不依赖, 保留作参考。


## Legacy 恢复、Inventory Diff 与聚焦复核

`--legacy-recovery` 默认关闭。开启后只加入一个小型 reviewed 候选集，用来恢复旧版输出中较常见的 Swagger/OpenAPI/doc、`.action`、file/download/export 类结构化路径；不会恢复 dot-path 伪路径、组件路径拼 API 等历史 artifact。新增候选在 `api_sources` 标记为 `legacy_recovery`，`api_confidence` 为 `0.30`，便于后续排序与审计。

Inventory diff 推荐在 dry-run 后使用：

```bash
python3 pipeline/deep_scanner.py --input targets.json --dry-run --legacy-recovery \
  --compare-inventory old_apis.json --outdir results_compare
```

默认 `inventory_diff.json` 只输出 aggregate counts 与类别统计，例如 common/old_only/new_only、swagger_openapi_doc、file_or_action、dot_path_artifact、low_confidence 等，不输出具体 host/path。只有显式 `--include-samples` 才包含少量 path 样本。

`--validate-from-report report.json` 用于对已有 redacted report 的代表端点做保守复核。它不需要 raw body，会自动强制 `--redact-raw-findings`、`max_rps_per_host<=0.5`、`min_delay_ms>=2000`、`max_requests_per_host<=40`、`workers<=4`、`phase12_workers<=4`，输出 hash 化目标/路径和脱敏 finding 摘要。若只需人工审批计划，使用 `--validate-plan-only`。

## 安全限流与响应分类

真实授权目标测试前建议显式设置 Phase 3 速率控制：`--max-rps-per-host` 控制每主机请求速率，`--min-delay-ms` 控制每主机请求间隔。默认不设置 `--max-requests-per-host`，确保参数验证完整执行；该参数仅作为人工止损开关，默认值 `0` 表示不限制。当前实现是在 Phase 3 请求路径做进程内 per-host best-effort 限速；Phase 1/2 的存活确认与 JS 下载不受这些 Phase 3 参数限制，但可用 `--phase12-workers` 单独压低 Phase 1/2 并发。

主动验证或报告落盘前建议启用 `--redact-raw-findings`。该开关保持默认关闭以兼容旧测试/旧工作流；启用后会在写出每目标 checkpoint 与最终 report.json 前递归移除 findings 内 `raw`、`raw_body`、`raw_response` 等原始包字段，保留 classifier 的安全摘要字段。

`pipeline/classifier.py` 提供 `classify_response(status, body, headers=None)`，用于输出未授权/API 响应摘要：`verdict`、`risk`、`confidence`、`reasons`、`sensitive_fields`、`data_signals`。分类器不会返回原始响应正文或正文片段，避免把敏感证据写入摘要。

Phase 2 现在会在 `phase2_inventory.jsonl` 和 dry-run `apis.json` 中输出 `api_confidence` 与 `api_sources`，用于区分 Swagger/OpenAPI、JS graph、参数绑定、业务关键字与 baseline 兜底来源。Phase 3 种子与业务层会优先测试高置信 API，减少低置信 baseline 噪声抢占队列。

默认主动探测仍只使用低风险 FAST 方法（GET 与 POST JSON）。`--unauth-matrix` 只生成 dry-run 计划预览；不会默认对 DELETE/PUT/PATCH 做破坏性主动探测。登录态对比、HAR 导入留作后续里程碑。

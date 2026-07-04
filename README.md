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

# 5b. 授权真实目标测试前建议加 Phase 3 安全限流
python3 pipeline/deep_scanner.py --input targets.json --outdir results_safe \
  --max-rps-per-host 1 --min-delay-ms 1000 --max-requests-per-host 80 \
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
| `--phase3a-param-rescue-max-apis` | 10 | 每个目标最多参与 3a 参数补筛的 API 数 |
| `--param-max-probes` | 12 | 每个接口最多静态参数模板探测次数 |
| `--param-probe-mode` | `targeted` | 静态参数探测模式: `targeted` 仅高价值接口, `broad` 全部接口 |
| `--js-max-download` | 0 | 每个目标最多下载外链JS数, 0=全部下载 |

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
- `Angular this.http.get/post`
- `uni.request`
- `wx.request`
- `FormData.append + axios.post`

绑定后不会把所有全局参数乱塞到所有接口，而是优先对当前 URL 使用它自己的绑定参数:

- GET/query 风格: `/api/user/list` 绑定 `pageNum/pageSize/orgId/keyword` 后生成 `?keyword=test&orgId=1&pageNum=1&pageSize=10`
- POST JSON 风格: `fetch("/api/user/search", { body: JSON.stringify({deptId,pageNum}) })` 会发送 JSON body `{"deptId":"1","pageNum":"1"}`
- POST form 风格: `$.post("/api/doc/preview", {docId,fileType})` 或 `qs.stringify(...)` 会发送 `application/x-www-form-urlencoded` body

参数 fuzz 默认只在候选目标的 3b 深测阶段开启，3a 快筛不做静态参数组合，避免大批量目标请求膨胀。

Phase 3a 默认会对未进入候选的目标再跑一轮 baseline 补筛。默认模式下补筛仍使用 FAST 绕过；开启 `--full-bypass` 后补筛使用 FULL 绕过。这个设计是为了尽量救回 Swagger/Druid/OA/WVP 等标准高价值路径，同时不让静态参数 fuzz 在全量资产上提前膨胀。

大批资产扫描时，优先使用 `--full-bypass` 但不要开启 `--collect-all-variants`。这样仍能覆盖空 Bearer、表单 POST、JWT none 等绕过方式，但同一端点拿到可用数据/文件/凭证/攻击路径情报后会停止，避免 3b 队列在慢站点上被重复变体耗尽。`--collect-all-variants` 更适合对已命中的高价值目标二次复核，用来补充报告里的多绕过方式证据。

## HTML/JS 静态参数画像

用于补足“没有 Swagger 的站点也能做参数提取和探测”的缺口。爬取首页、内联脚本、业务 JS、同站二级页面时同步提取:

- URL 查询参数: `?id=`, `&fileId=`
- 表单字段: `name=`, `v-model=`, `prop=`, `field=`
- 请求体字段: `params: { ... }`, `data: { ... }`, `body: { ... }`
- 对象字面量中的常见字段: `userId`, `deptId`, `filePath`, `objectKey`
- 数字 ID 种子: `id: 1`, `fileId=100`
- 文件名种子: `demo.pdf`, `template.xlsx`, `1.docx`

这些数据会形成站点级参数画像，Phase 3 测试接口时按优先级生成 `?参数名=种子值` 模板。默认 `targeted` 模式只对下载、导出、预览、文件、查询、详情、用户、设备、日志、告警等高价值接口启用静态参数探测，避免普通接口全部膨胀。需要彻底覆盖时再使用 `--param-probe-mode broad`。

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

正常扫描模式也会增量写出 `phase2_inventory.jsonl`。这个文件每个目标一行 JSON，包含 `apis`、JS 统计、`param_names`、`seed_values` 和可序列化的 `param_profile`，便于在 Phase 3 超时、无漏洞或后续切换探测策略时复用前面的 JS/API 提取结果；只有漏洞 checkpoint 仍然按目标单独写 `*.json`。

现代前端补充覆盖:

- Vite/dev module 页面会递归解析 `type=module`、`import ... from`、`import(...)` 和 `new URL(..., import.meta.url)` 指向的 `/src/*.ts`、`.vue`、`.js` 模块；这些模块只参与 JS/API 提取，不再作为 API 端点误测。
- 会从 JS 字符串常量拼接中恢复 API，例如 `const base="/admin/system.Login/"; url: base + "setting"` 或 `const p="/large/Index/"; url: p + "message"`，避免只提取到前缀而漏掉真实接口。
- ThinkPHP `controller not exists` 且带 `line/file/trace` 的框架错误响应会被过滤，不再因为 `code:0` 被误判为未授权数据。

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
- **Phase 3a 软截止**: 快筛尾部慢请求超过 `--phase3a-timeout` 后跳过, 已命中目标先进入 3b, 未命中目标由 baseline FULL 补筛兜底
- **全阶段软截止**: baseline 补筛和 3b 各层也有独立软超时, 避免任一阶段尾部慢请求拖死整批
- **SSL 自签名**: `ssl.CERT_NONE` + 12s 超时 + 3 次重试
- **API-only 服务器**: 首页为空时自动创建轻量条目 + 基准路径
- **路径拼接**: 从 URL 目录结构构造 API 路径变体
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

真实授权目标测试前建议显式设置 Phase 3 限流：`--max-rps-per-host` 控制每主机请求速率，`--min-delay-ms` 控制每主机请求间隔，`--max-requests-per-host` 是每主机硬上限。当前实现是在 Phase 3 请求路径做进程内 per-host best-effort 限流；Phase 1/2 的存活确认与 JS 下载不受这些 Phase 3 参数限制，但可用 `--phase12-workers` 单独压低 Phase 1/2 并发。

主动验证或报告落盘前建议启用 `--redact-raw-findings`。该开关保持默认关闭以兼容旧测试/旧工作流；启用后会在写出每目标 checkpoint 与最终 report.json 前递归移除 findings 内 `raw`、`raw_body`、`raw_response` 等原始包字段，保留 classifier 的安全摘要字段。

`pipeline/classifier.py` 提供 `classify_response(status, body, headers=None)`，用于输出未授权/API 响应摘要：`verdict`、`risk`、`confidence`、`reasons`、`sensitive_fields`、`data_signals`。分类器不会返回原始响应正文或正文片段，避免把敏感证据写入摘要。

Phase 2 现在会在 `phase2_inventory.jsonl` 和 dry-run `apis.json` 中输出 `api_confidence` 与 `api_sources`，用于区分 Swagger/OpenAPI、JS graph、参数绑定、业务关键字与 baseline 兜底来源。Phase 3 种子与业务层会优先测试高置信 API，减少低置信 baseline 噪声抢占队列。

默认主动探测仍只使用低风险 FAST 方法（GET 与 POST JSON）。`--unauth-matrix` 只生成 dry-run 计划预览；不会默认对 DELETE/PUT/PATCH 做破坏性主动探测。登录态对比、HAR 导入留作后续里程碑。

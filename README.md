# Scanner Pipeline v8

JS/API 未授权访问扫描器 — 单文件、CLI参数化、双模式测试、风险分级

> **定位**: CTF/攻防赛场景。脚本完成机械工作（JS 提取、API 发现、批量未授权测试），产出报告后由 AI（Claude/GPT）基于结果做精判：选高价值目标、构造正确参数、判断真伪、决定深挖方向。AI 层不在代码内，在操作流程中。

## 架构

脚本完成机械工作，AI（操作者）基于产出做精判：

```
┌─ 脚本层 (4 Phase, 自动) ──────────────────────┐
│ Phase 1: TCP 探测 (25 端口)                     │
│ Phase 2: JS 爬取 + API 提取                    │
│   BeautifulSoup / LinkFinder / Webpack chunk    │
│   Vue-React 路由 / 深度递归 / 200+ 库过滤       │
│   API-only 服务器自适应 / 路径拼接              │
│ Phase 3: 两阶段未授权测试                       │
│   3a: 快筛 (扁平池, TOP30 API × 2 绕过)         │
│   3b: 深度 (仅候选 × 全绕过方法)                │
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

`deep_scanner.py` 是唯一需要的文件，**完全自包含**，不依赖项目中其他任何脚本。

```bash
# 1. 唯一依赖
pip3 install beautifulsoup4 --break-system-packages

# 2. 准备目标文件 (JSON 格式)
# [{"url": "https://target:port", "title": "系统名", "score": 100}]

# 3. 运行 (默认参数)
python3 deep_scanner.py --input /tmp/my_targets.json --outdir /tmp/results

# 4. 高级用法
python3 deep_scanner.py \
  --input targets.json \
  --outdir results/ \
  --workers 100 \
  --timeout 15 \
  --limit 50 \
  --full-bypass \
  --debug

# 5. 只提取 API，不测试 (dry-run)
python3 deep_scanner.py --input targets.json --dry-run

# 6. 查看结果
cat results/report.json   # JSON 报告
cat results/report.md     # Markdown 报告 (含风险分级)
```

## CLI 参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--input` | `/tmp/v7_targets.json` | 目标 JSON 文件 |
| `--outdir` | `/tmp/v8_scan_results` | 输出目录 |
| `--workers` | 50 | 并发线程数 |
| `--timeout` | 12 | HTTP 超时(秒) |
| `--limit` | 0 | 限制目标数, 0=全部 |
| `--dry-run` | false | 只提取 API, 不测试 |
| `--full-bypass` | false | 收集所有绕过方法(默认命中断路) |
| `--debug` | false | 调试日志 |

## 六种认证绕过方法

| 方法 | 说明 | 默认启用 |
|------|------|----------|
| GET_no_auth | 标准 GET 无认证头 | ✅ |
| POST_JSON_no_auth | JSON POST 无认证 | ✅ |
| GET_empty_bearer | `Authorization: Bearer ` 空 token | `--full-bypass` |
| GET_admin_token | `Authorization: Bearer admin-token` | `--full-bypass` |
| POST_FORM_no_auth | 表单 POST (x-www-form-urlencoded) | `--full-bypass` |
| POST_JWT_none | JWT `alg: none` 绕过 | `--full-bypass` |

> **注意**: 默认模式 (`--full-bypass` 未开启) 下第一个绕过方法命中后立即短路，不测试后续方法。开启 `--full-bypass` 后将收集所有绕过方法的命中结果。

每个 API 端点自动尝试 3 种查询后缀: 无参数 / `?page=1&count=10` / `?page=1&size=10`

## 报告输出

### JSON (`report.json`)
完整 finding 列表，含响应摘要(raw 截断为 500 字符)

### Markdown (`report.md`)
- 漏洞汇总表（风险分级: CRITICAL/HIGH/MEDIUM/LOW）
- 每个目标的详细发现
- 绕过方法命中统计

### 风险分级规则
- CRITICAL: 凭证泄露 + 大量数据 / 敏感字段(secret/password/phone/email)
- HIGH: 凭证泄露 / 大量数据(>10条)
- MEDIUM: 有数据返回 / Swagger/Druid等API文档暴露(攻击路径情报)
- LOW: 端点可达但无可利用数据

> Swagger/API-Docs/Druid 虽不直接算比赛分，但是攻击路径情报——暴露全部 API 端点、参数、认证方式，可据此精准打击其他接口。

## 关键技术

- **扁平线程池**: 不嵌套, 避免 GIL 争抢
- **SSL 自签名**: `ssl.CERT_NONE` + 12s 超时 + 3 次重试
- **API-only 服务器**: 首页为空时自动创建轻量条目 + 基准路径
- **路径拼接**: 从 URL 目录结构构造 API 路径变体
- **BeautifulSoup**: 替代正则解析 HTML, 支持 preload/prefetch JS
- **Webpack chunk**: `{...}[n]+".js"` 模式 + publicPath 解析
- **Vue/React 路由**: `__vue_app__` / `<Route path=` 检测
- **双模式测试**: 命中断路(快速) / 全量收集(--full-bypass)

## 已知限制

1. **SSL 超时**: 极慢的 SSL 握手(>30s)仍可能被跳过
2. **参数构造**: 使用固定模板, 未从 JS 函数签名解析真实参数
3. **非 JSON 响应**: XML/SOAP/HTML 中的数据可能被跳过
4. **纯 API 服务器**: 无 JS 可提取, 仅测基准路径
5. **误报**: `check_response()` 依赖关键词和状态码, 业务错误可能误判
6. **报告不含截图**: 证据采集需手动用 Chrome MCP 完成

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

`deep_scanner.py` 是唯一需要的文件, 自包含, 不 import 其他脚本。其他文件均为早期独立工具, 互不依赖, 保留作参考。

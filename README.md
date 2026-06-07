# Scanner Pipeline v7

JS/API 未授权访问扫描器 — 脚本批量 + AI 精判混合流水线

## 架构

```
┌─ 脚本层 (机械工作) ─────────────────────────┐
│ Phase 1: TCP 探测 (35 端口分层)               │
│ Phase 2: JS 爬取 + API 提取                  │
│   - BeautifulSoup HTML 解析 (from JSFinder)   │
│   - LinkFinder 正则 (from JSFinder)           │
│   - Webpack chunk 提取 (from Webpack_extract) │
│   - Vue/React 路由检测 (from VueCrack)        │
│   - 深度递归 JS 爬取 (from JSFinder -d)       │
│   - 200+ 库过滤 (from extract_api.py)         │
│ Phase 3a: 快速筛选 (扁平 100 workers)         │
│ Phase 3b: 深度测试 (仅候选, 6 种绕过)         │
│ Phase 4: 深度利用 (大分页拉数据)              │
│ Phase 5: 报告生成 (JSON + Markdown)           │
├──────────────────────────────────────────────┤
│ AI 层 (智能判断)                              │
│   - 按比赛标准选高价值目标                      │
│   - 构造正确参数 (?page=1&count=10)           │
│   - 判断响应真伪 (非假阳性)                    │
│   - 决定下一步: 深挖/跳过/换路径               │
└──────────────────────────────────────────────┘
```

## 快速开始

```bash
# 1. 准备目标列表 (每行一个 URL 或 IP)
cat targets.txt | sort -u > /tmp/targets_filtered.txt

# 2. 准备高价值目标 JSON
# 格式: [{"url": "https://target:port", "title": "系统名", "score": 100}]

# 3. 安装依赖
pip3 install beautifulsoup4 --break-system-packages

# 4. 运行
python3 deep_scanner_v7.py

# 5. 查看结果
cat /tmp/v7_scan_results/v7_report.json
```

## 六种认证绕过方法

| 方法 | 说明 |
|------|------|
| GET_no_auth | 标准 GET 无认证头 |
| GET_empty_bearer | `Authorization: Bearer ` 空 token |
| GET_admin_token | `Authorization: Bearer admin-token` |
| POST_JSON_no_auth | JSON POST 无认证 |
| POST_FORM_no_auth | 表单 POST (x-www-form-urlencoded) |
| POST_JWT_none | JWT `alg: none` 绕过 |

## 查询参数 Fuzzing

每个 API 端点尝试 3 种后缀: 无参数 / `?page=1&count=10` / `?page=1&size=10`

## 关键技术

- **扁平线程池**: 不嵌套, 避免 GIL 争抢
- **SSL 自签名**: `ssl.CERT_NONE` + 12s 超时 + 3 次重试
- **API-only 服务器**: 首页为空时自动轻量条目 + 基准路径
- **路径拼接**: 从 URL 目录结构构造 API 路径变体
- **BeautifulSoup**: 替代正则, 支持 preload/prefetch JS
- **Webpack**: `{...}[n]+".js"` 模式 + publicPath
- **Vue/React**: `__vue_app__`, `<Route path=` 检测

## 迭代教训 (v1→v7)

1. 嵌套线程池 (40×20=800) 是灾难 → 扁平化
2. 查询参数是关键 (`?page=1&count=10`)
3. SSL 自签名需 `ssl.CERT_NONE` + 大 timeout
4. 串行文件读取阻塞流水线 → 改并行
5. `for t in candidates:` 循环缺失导致 108→1
6. SENSITIVE 正则假阳性 → 收紧为凭证关键词
7. 15K 全量太慢 → TOP500-1000 精扫
8. 比赛算分标准: 摄像头接管/公民信息/RCE/可利用路径

## 参考项目

| 项目 | 继承技术 |
|------|----------|
| JSFinder | BeautifulSoup, LinkFinder, 深度递归 |
| Webpack_extract | Webpack chunk, Rules.js 敏感字段 |
| VueCrack | Vue/React 实例, 路由提取 |
| Packer-Fuzzer | API 收集, Webpack 检测 |
| extract_api.py | 200+ 库过滤 |

## 文件说明

| 文件 | 用途 |
|------|------|
| `pipeline/deep_scanner_v7.py` | **主扫描器 v7 (当前)** |
| `pipeline/deep_scanner.py` | 主扫描器 v6 |
| `pipeline/unauth_scanner.py` | 未授权测试器 (基于 jjjjjsz) |
| `pipeline/scanner.py` | 早期全量版本 |
| `batch_scan/` | TCP 探测 + JS 提取工具 |

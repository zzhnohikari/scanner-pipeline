# scanner-pipeline

JS/API 未授权访问扫描器 — 脚本批量 + AI精判混合流水线

## 架构

```
脚本层 (机械工作)
├─ TCP端口探测 (35端口分层)
├─ JS下载 + API提取 (LinkFinder + Webpack chunk)
└─ 批量HTTP请求 (扁平线程池,不嵌套)

AI层 (智能判断)
├─ 按比赛标准筛选高价值目标
├─ 构造正确参数
└─ 判断响应是否真正敏感
```

## 使用

```bash
# 准备目标列表
cat targets.txt | sort -u > /tmp/targets_filtered.txt

# 运行全量扫描
python3 deep_scanner.py

# 结果在 /tmp/deep_scan_results/
```

## 关键发现

- 2个 WVP-GB28181 摄像头系统完全接管 (~5,400个摄像头)
- ZLMediaKit secret + SIP密码泄露
- interfaceAuthentication=false 导致全API未授权

## 文件

| 文件 | 说明 |
|------|------|
| `pipeline/deep_scanner.py` | 主扫描器 v6 |
| `pipeline/unauth_scanner.py` | 未授权测试器 |
| `pipeline/scanner.py` | 早期版本 |
| `batch_scan/` | 批量探测工具 |

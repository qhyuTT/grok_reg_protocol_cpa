# 项目任务清单

## CustomMail（已完成）

- [x] 实现凭证池、顺序地址分配和 Gmail IMAP 验证码读取
- [x] 接入邮箱 provider 分发与地址生命周期
- [x] 增加 GUI、配置模板和凭证模板
- [x] 增加单元测试与回归检查
- [x] 更新启动文档并完成端到端静态验证

## 协议 mint / 可观测性（已完成）

- [x] device-code / token 优先 curl_cffi（与 SSO 协议路径 TLS 一致）
- [x] 结构化 `error_code` + `cpa_auth_failed.jsonl`
- [x] 跨平台 Chromium 路径（`chromium_paths.py`）
- [x] CPA 纯函数单测（`tests/test_cpa_xai_core.py`）
- [x] 刷新 `optimization_checks.py` 与仓库 MD 文档

## 后续可选

- [ ] 抽出 hotmail 模块 + 单测
- [ ] 拆分 `grok_register_ttk.py`（mail / browser / register / gui）
- [ ] 统一注册与 mint 的 BrowserSession
- [ ] backfill 按 `error_code` 过滤重试

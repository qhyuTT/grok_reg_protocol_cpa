# 项目启动说明

## 环境要求

| 项 | 要求 |
|----|------|
| 系统 | Windows / macOS / 带桌面的 Linux |
| Python | **3.13**（见 `pyproject.toml`） |
| 工具 | [`uv`](https://github.com/astral-sh/uv)；可选 [`mise`](https://mise.jdx.dev/) |
| 浏览器 | Google Chrome / Chromium / Edge（注册 + 协议失败回退时） |
| 代理 | 能访问 `accounts.x.ai` / `auth.x.ai` / `cli-chat-proxy.grok.com` |

说明：

- **协议 CPA mint**（`cpa_prefer_protocol=true` 且有 SSO）纯 HTTP，不弹浏览器。  
- **注册流程**与协议失败回退仍需要本机 Chromium；路径由 `chromium_paths.py` 自动探测（含 Windows）。

## 首次启动

在项目根目录：

```bash
# 克隆后
cd grok_reg_protocol_cpa

# 安装依赖（按 uv.lock）
uv sync

# 验证核心库
uv run python -c "from DrissionPage import Chromium; from curl_cffi import requests; print('OK')"
```

可选 mise：

```bash
mise install
mise run deps
mise run test
mise run optimize-check
```

## 配置

```bash
cp config.example.json config.json
```

至少检查：

```json
{
  "proxy": "http://127.0.0.1:7890",
  "cpa_proxy": "http://127.0.0.1:7890",
  "email_provider": "hotmail",
  "cpa_export_enabled": true,
  "cpa_prefer_protocol": true,
  "cpa_auth_dir": "./cpa_auths",
  "cpa_base_url": "https://cli-chat-proxy.grok.com/v1"
}
```

代理优先级：`cpa_proxy` > `proxy` > 环境变量 `https_proxy` / `http_proxy`。  
修改 `config.json` 后需**重启** GUI 或重新跑 CLI 才会生效。

字段详解见 `config.example.json` 内 `//` 注释键。

## 邮箱凭证（按 provider）

### Hotmail / Outlook

```bash
cp mail_credentials.example.txt mail_credentials.txt
```

每行四段：

```text
邮箱----密码----ClientID----Token
```

`Token` 为 Microsoft OAuth **refresh_token**（IMAP XOAUTH2）。  
`config.json` 中：`"email_provider": "hotmail"`。

### CustomMail（自有域名 → Gmail）

```bash
cp custom_mail_credentials.example.txt custom_mail_credentials.txt
```

每行三段：

```text
自有域名----Gmail收件箱----Gmail应用专用密码
```

`config.json` 中：`"email_provider": "custommail"`。  
完整无 GUI 说明见 [`CUSTOMMAIL_CLI.md`](CUSTOMMAIL_CLI.md)。

**不要提交**含真实凭证的文件（已在 `.gitignore`）。

## 启动 GUI

```bash
uv run python grok_register_ttk.py
# 或
mise run gui
```

关闭窗口或终端 `Ctrl+C` 停止。

## 使用 CLI 注册（推荐）

```bash
# 再注册 1 个，单线程
uv run python -u register_cli.py --extra 1 --threads 1

# 再注册 5 个，2 注册线程（mint 并发由 config / --mint-workers 决定）
uv run python -u register_cli.py --extra 5 --threads 2
```

成功时默认会：

1. 追加账本 `accounts_cli.txt`：`email----password----sso`  
2. 可选推 grok2api  
3. 协议优先 mint → `cpa_auths/xai-<email>.json`（失败回退浏览器）

常用参数：

| 参数 | 含义 |
|------|------|
| `--extra N` | 再新注册 N 个 |
| `--threads N` | 注册并发 |
| `--mint-workers N` | mint 并发；`0`=内联；`-1`=auto |
| `--fast` / `--no-fast` | 快速模式（默认开） |

## 代理连通性

把地址换成你的代理：

```bash
# Windows PowerShell 示例
curl.exe -I --proxy http://127.0.0.1:7890 https://accounts.x.ai

# Linux / macOS
curl -I --proxy http://127.0.0.1:7890 https://accounts.x.ai
```

## 测试与检查

```bash
uv run python -m unittest discover -s tests -v
uv run python optimization_checks.py
```

## 常见问题

| 问题 | 处理 |
|------|------|
| 找不到 `mail_credentials.txt` | 复制 example 并填四段 Hotmail 凭证 |
| 找不到 CustomMail 凭证 | 复制 `custom_mail_credentials.example.txt` |
| 代理失败 | 确认本地/局域网代理在听端口，config 与环境变量一致 |
| 改 config 不生效 | 完全退出 GUI / 重跑 CLI |
| 注册成功但无 CPA 文件 | 查 `cpa_export_enabled`；看 `cpa_auths/cpa_auth_failed.txt` 与 `.jsonl` 的 `error_code` |
| Windows 浏览器起不来 | 安装 Chrome 或 Edge；无需手写 `/usr/bin/chromium` |
| grok2api 远端导入失败 | 关 `grok2api_auto_add_remote`，或启动对应 Admin API 并配 app key |

更完整的链路、错误码与目录说明见 [`README.md`](README.md)。

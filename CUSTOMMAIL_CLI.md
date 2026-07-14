# CustomMail 终端启动指南（无 GUI）

本文说明如何**不打开 GUI**，只用配置文件 + 终端命令，跑通 **CustomMail** 邮箱注册链路（自有域名 catch-all → Gmail IMAP 收验证码 → 注册 xAI → 可选 CPA 导出）。

适用入口：

```bash
uv run python -u register_cli.py ...
```

不要用：

```bash
uv run python grok_register_ttk.py   # 这是 GUI
```

---

## 1. 原理（先搞清楚）

CustomMail **不需要** Cloudflare API Key。链路是：

```
xAI 发验证码
  → 自有域名邮箱（如 swcares000001@你的域名）
  → Cloudflare Email Routing Catch-all 转发
  → Gmail 收件箱
  → 本程序用 Gmail「应用专用密码」走 IMAP 拉取验证码
  → 填入 accounts.x.ai 注册页
```

程序会按顺序分配地址：

```text
{prefix}000001@域名
{prefix}000002@域名
...
```

默认前缀是 `reg`；本机当前配置可用 `swcares` 等自定义前缀。

---

## 2. 前置条件

| 项 | 要求 |
|----|------|
| 系统 | macOS 或带桌面的 Linux（注册仍要开 Chromium；协议 CPA mint 可不弹浏览器） |
| Python | 3.13 + `uv` |
| 浏览器 | Google Chrome / Chromium |
| 代理 | 能访问 `accounts.x.ai` / `auth.x.ai`（写在 `config.json`） |
| 域名 | 已在 Cloudflare 托管，并开启 **Email Routing** |
| 转发 | Catch-all（或对应规则）转发到你的 Gmail |
| Gmail | 开启两步验证，并生成**应用专用密码**（不要用登录密码） |

### 2.1 Cloudflare Email Routing（一次性）

1. Cloudflare → 域名 → **Email** → **Email Routing**
2. 启用 Routing，验证目标 Gmail
3. 配置 **Catch-all** 转发到该 Gmail（或至少覆盖你将使用的本地部分）
4. 无需把 Cloudflare API 填进本项目

### 2.2 Gmail 应用专用密码

1. Google 账号 → 安全性 → 两步验证（先打开）
2. 应用专用密码 → 生成（例如「邮件」）
3. 得到 16 位密码（可能带空格，可原样粘贴，程序会去掉空格）

---

## 3. 首次环境

```bash
cd /Users/nameqhyu/WorkSpace/grok_reg-protocol_cpa

# 安装依赖
uv sync

# 验证核心库
uv run python -c "from DrissionPage import Chromium; from curl_cffi import requests; print('OK')"
```

可选代理连通性检查（按你本机代理改 IP/端口）：

```bash
nc -vz 192.168.31.206 7890
curl -I --proxy http://192.168.31.206:7890 https://accounts.x.ai
```

---

## 4. 准备凭证文件（必做）

### 4.1 复制模板

```bash
cd /Users/nameqhyu/WorkSpace/grok_reg-protocol_cpa
cp custom_mail_credentials.example.txt custom_mail_credentials.txt
```

### 4.2 编辑 `custom_mail_credentials.txt`

**每行一条路由**，三段，`----` 分隔：

```text
自有域名----Gmail收件箱----Gmail应用专用密码
```

示例：

```text
qhyu.asia----yourname@gmail.com----xxxx xxxx xxxx xxxx
```

说明：

| 段 | 含义 |
|----|------|
| 自有域名 | 不要带 `@`；邮件地址会是 `前缀序号@该域名` |
| Gmail 收件箱 | Cloudflare 转发的目标邮箱 |
| 应用专用密码 | Gmail App Password，不是账号登录密码 |

- 支持多行：多个域名/多个 Gmail 路由池
- **勿提交 git / 勿外传**（`.gitignore` 已忽略该文件）

---

## 5. 配置 `config.json`（CLI 只读这个）

CLI **不会**在命令行里选邮箱 provider，完全看 `config.json`。

若还没有配置：

```bash
cp config.example.json config.json
```

至少保证以下字段（其余可保持默认）：

```json
{
  "email_provider": "custommail",
  "custom_mail_accounts_file": "custom_mail_credentials.txt",
  "custom_mail_address_prefix": "swcares",
  "custom_mail_max_addresses_per_account": 100,
  "custom_mail_poll_interval": 5,
  "custom_mail_recent_seconds": 900,
  "custom_mail_imap_last_n": 50,
  "custom_mail_allowed_sender_domains": "x.ai,grok.com",

  "proxy": "http://192.168.31.206:7890",
  "cpa_proxy": "http://192.168.31.206:7890",

  "cpa_export_enabled": true,
  "cpa_prefer_protocol": true,
  "cpa_auth_dir": "./cpa_auths",
  "cpa_base_url": "https://cli-chat-proxy.grok.com/v1"
}
```

### 字段速查

| 字段 | 作用 | 建议 |
|------|------|------|
| `email_provider` | 必须是 `custommail`（也认 `custom_mail`） | 必填 |
| `custom_mail_accounts_file` | 凭证文件路径（相对项目根） | 默认即可 |
| `custom_mail_address_prefix` | 地址前缀，生成 `前缀000001@域名` | 如 `swcares` / `reg` |
| `custom_mail_max_addresses_per_account` | 每条凭证最多分配多少个地址 | 按域名容量设 |

启动时程序会用 `emails_used.txt`、`emails_error.txt` 和当前内存 reservation 计算剩余容量：

- 请求数量超过剩余容量时，自动缩减到可分配数量；
- 容量为 0 时不启动浏览器；
- 运行中容量耗尽时停止派发新任务，已在执行的账号可继续收尾。

该上限必须与域名实际可承载地址数量一致；提高数值不会扩充邮箱服务本身的容量。
| `custom_mail_poll_interval` | IMAP 轮询间隔（秒） | 5 |
| `custom_mail_recent_seconds` | 只读最近 N 秒邮件，防读到旧码 | 900 |
| `custom_mail_imap_last_n` | 每轮扫 INBOX 最新 N 封 | 50 |
| `custom_mail_allowed_sender_domains` | 发件域名白名单 | `x.ai,grok.com` |
| `proxy` | 注册用 Chromium / 相关 HTTP | 本机可达代理 |
| `cpa_*` | 注册成功后 OIDC/CPA 导出 | 需要 Grok 4.5 时保持开启 |

改完 `config.json` 后，**重新运行 CLI** 才会生效（CLI 每次启动 `load_config()`）。

---

## 6. 终端启动命令

### 6.1 再注册 1 个号（最常用）

```bash
cd /Users/nameqhyu/WorkSpace/grok_reg-protocol_cpa
uv run python -u register_cli.py --extra 1 --threads 1
```

### 6.2 批量再注册 N 个

```bash
# 再注册 5 个，2 线程（有头浏览器建议线程别太高）
uv run python -u register_cli.py --extra 5 --threads 2
```

### 6.3 按「总数目标」注册

```bash
# 账本里最终要有 10 个号；已有则只补差
uv run python -u register_cli.py --count 10 --threads 1
```

### 6.4 常用 CLI 参数

| 参数 | 含义 |
|------|------|
| `--extra N` | **再新注册 N 个**（推荐） |
| `--count N` | 账号总数目标（含已有）；已达标则退出 |
| `--threads N` | 注册并发 1–10 |
| `--accounts-file PATH` | 账本路径，默认 `accounts_cli.txt` |
| `--mint-workers N` | CPA mint 并发；`-1` 跟 config/auto；`0` 内联 |
| `--browser-reuse` | 显式复用注册浏览器；默认每账号结束即关闭 |
| `--no-fast` | 关闭快速模式（多 sleep、可截图，调试用） |
| `--inline-mint` | 注册线程内直接 mint（调试） |

等价 mise：

```bash
mise run register -- --extra 1 --threads 1
```

---

## 7. 成功后产物在哪

| 产物 | 路径 | 格式 / 用途 |
|------|------|-------------|
| 账本 SSO | `accounts_cli.txt` 或你指定的 `--accounts-file` | `邮箱----密码----sso` |
| 占用记录 | `emails_used.txt`、`created_mailboxes.txt` | 已用地址，防重复分配 |
| 失败邮箱 | `emails_error.txt` | 失败标记 |
| CPA OIDC | `cpa_auths/xai-<email>.json` | 免费 Grok 4.5（需 `cpa_export_enabled`） |
| 调试截图 | `screenshots/` | 非 fast 或失败时可能有 |

日志里典型成功片段：

```text
[*] 配置加载完成，额外新注册 1 个 ...
... 注册流程 ...
[cpa] mint try protocol (SSO HTTP device flow)
[cpa] mint protocol SUCCESS
=== 完成: 注册成功 1, ... CPA成功 1 ... ===
```

---

## 8. 仅补 CPA（不重新注册）

若账本里已有 `email----password----sso`，只缺 `cpa_auths`：

```bash
uv run python -u scripts/backfill_cpa_xai_from_accounts.py \
  --accounts accounts_cli.txt \
  --limit 1 --probe --timeout 300

# 补全部缺失
uv run python -u scripts/backfill_cpa_xai_from_accounts.py \
  --limit 0 --probe --timeout 300 --sleep 3
```

---

## 9. 可选：单独测 CustomMail 单元逻辑

不发起真实注册，只跑 CustomMail 解析/分配相关单测：

```bash
uv run python -m unittest tests.test_custom_mail -v
```

---

## 10. 故障排查

| 现象 | 处理 |
|------|------|
| 找不到凭证 / 分配失败 | 检查 `custom_mail_credentials.txt` 是否存在、三段格式、域名与 Gmail 是否正确 |
| 收不到验证码 | Cloudflare catch-all 是否转发到该 Gmail；Gmail 是否收到 xAI 邮件；应用专用密码是否有效 |
| IMAP 登录失败 | 必须用**应用专用密码**；确认 Gmail 已开两步验证 |
| 读到旧码 / 错码 | 调大/确认 `custom_mail_recent_seconds`；并发时依赖收件人匹配 |
| 地址耗尽 | 提高 `custom_mail_max_addresses_per_account`，或加新凭证行 |
| 代理失败 | `proxy` / `cpa_proxy` 是否可达；改完配置后重新跑 CLI |
| 注册成功但无 `cpa_auths` | `cpa_export_enabled` 是否 true；看日志 `[cpa]` 与 `cpa_auth_failed.txt` |
| provider 不是 CustomMail | `config.json` 里 `email_provider` 必须为 `custommail` |

调试原则：

1. 先确认 Gmail 收件箱**人工**能否看到 xAI 验证码邮件  
2. 再跑 CLI；看终端是否在「等验证码」阶段超时  
3. 需要更多现场时用 `--no-fast` 并看 `screenshots/`

---

## 11. 最小检查清单（复制即用）

```bash
cd /Users/nameqhyu/WorkSpace/grok_reg-protocol_cpa

# 1) 依赖
uv sync

# 2) 凭证（若尚未创建）
cp -n custom_mail_credentials.example.txt custom_mail_credentials.txt
# 编辑 custom_mail_credentials.txt → 域名----Gmail----应用专用密码

# 3) 配置（若尚未创建）
cp -n config.example.json config.json
# 编辑 config.json：
#   "email_provider": "custommail"
#   "custom_mail_accounts_file": "custom_mail_credentials.txt"
#   "custom_mail_address_prefix": "你的前缀"
#   "proxy" / "cpa_proxy": 你的代理

# 4) 跑 1 个号
uv run python -u register_cli.py --extra 1 --threads 1

# 5) 检查产物
ls -l accounts_cli.txt cpa_auths/ 2>/dev/null
tail -n 3 accounts_cli.txt 2>/dev/null
```

---

## 12. 安全提醒

- `custom_mail_credentials.txt`、`config.json`、账本、`cpa_auths/*.json` 含密码 / SSO / refresh_token  
- 权限建议：`chmod 600 custom_mail_credentials.txt config.json cpa_auths/*.json`  
- 勿提交、勿打进分享包  

---

## 相关文件

| 文件 | 说明 |
|------|------|
| `custom_mail.py` | CustomMail 池与 IMAP 实现 |
| `register_cli.py` | 无 GUI 批量注册入口 |
| `config.example.json` | 全量配置注释 |
| `STARTUP.md` | 本机启动与代理说明 |
| `README.md` | 项目总文档（Hotmail + CPA 协议 mint 等） |

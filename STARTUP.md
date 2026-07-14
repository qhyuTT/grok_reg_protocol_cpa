# 项目启动说明

## 环境要求

- macOS 或带桌面环境的 Linux
- Python 3.13
- `uv`
- Google Chrome 或 Chromium
- 可访问 xAI 服务的代理

本机当前代理来自 `~/.zshrc`：

```text
http://192.168.31.206:7890
```

项目的 `config.json` 中，`proxy` 和 `cpa_proxy` 均应使用该地址。修改配置后，需要关闭并重新启动正在运行的 GUI。

## 首次启动

进入项目目录并安装依赖：

```bash
cd /Users/nameqhyu/WorkSpace/grok_reg-protocol_cpa
uv sync
```

验证核心依赖：

```bash
uv run python -c "from DrissionPage import Chromium; from curl_cffi import requests; print('OK')"
```

## 启动 GUI

```bash
cd /Users/nameqhyu/WorkSpace/grok_reg-protocol_cpa
uv run python grok_register_ttk.py
```

GUI 进程会持续占用当前终端。关闭窗口或在终端按 `Ctrl+C` 即可停止。

## 使用 CLI 注册

注册 1 个账号，单线程运行：

```bash
cd /Users/nameqhyu/WorkSpace/grok_reg-protocol_cpa
uv run python -u register_cli.py --extra 1 --threads 1
```

CLI 默认在每个账号结束后完整关闭注册浏览器；只有确认需要批量性能时才加 `--browser-reuse` 显式复用。

批量注册时可调整 `--extra` 和 `--threads`，但不建议一开始使用过高并发。

## 使用 CustomMail 自有域名邮箱

CustomMail 适用于“Cloudflare Email Routing Catch-all → Gmail”链路。先复制凭证模板：

```bash
cp custom_mail_credentials.example.txt custom_mail_credentials.txt
```

每行填写一个域名路由，格式如下：

```text
自有域名----Gmail收件箱----Gmail应用专用密码
```

然后在 GUI 中选择 `custommail`，或在 `config.json` 设置：

```json
{
  "email_provider": "custommail",
  "custom_mail_accounts_file": "custom_mail_credentials.txt"
}
```

Cloudflare 不需要 API key，但必须事先完成域名邮件路由和 Gmail 目标地址验证。Gmail 需要开启两步验证并使用应用专用密码；不要使用普通登录密码。程序会生成 `reg000001@你的域名` 一类顺序地址，并按原始收件地址和 xAI 发件域名匹配验证码。

## 启动前检查

### 配置文件

确认 `config.json` 存在且至少检查以下字段：

```json
{
  "proxy": "http://192.168.31.206:7890",
  "cpa_proxy": "http://192.168.31.206:7890",
  "email_provider": "hotmail"
}
```

### Hotmail 凭证

当 `email_provider` 为 `hotmail` 时，必须创建 `mail_credentials.txt`：

```bash
cp mail_credentials.example.txt mail_credentials.txt
```

然后按以下格式填写真实凭证，每个账号一行：

```text
邮箱----密码----ClientID----Token
```

不要提交包含真实凭证的文件。

### 代理连通性

检查代理端口是否可达：

```bash
nc -vz 192.168.31.206 7890
```

通过代理测试 HTTPS：

```bash
curl -I --proxy http://192.168.31.206:7890 https://accounts.x.ai
```

## 常见问题

- 提示找不到 `mail_credentials.txt`：按上文复制模板并填写真实 Hotmail OAuth 凭证。
- 代理连接失败：确认代理设备 IP 未变化、代理程序正在监听 `7890`，并允许局域网连接。
- 修改 `config.json` 后未生效：完全退出 GUI 后重新运行启动命令。
- grok2api 本地/远端自动入池默认均关闭，手动入池不受影响。显式启用 `grok2api_auto_add_remote` 时，需启动对应服务并配置有效 app key。
- 浏览器无法启动：确认 Google Chrome/Chromium 已安装，并避免已有调试端口冲突。

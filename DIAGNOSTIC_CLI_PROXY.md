# CLIProxyAPI 单凭证隔离诊断

用于判断账号停用是否与批量导入、跨凭证重试或注册/调用出口不一致有关。诊断实例不修改主 `:8317` 服务和 `~/.cli-proxy-api` 凭证池。

## 当前环境已确认的事实

- 23 个 xAI 凭证在 `16:16:35` 集中写入主凭证池。
- 随后几分钟内出现密集 `/v1/messages` 请求；`16:36:50` 附近又在数秒内出现大量管理 API 调用。
- 注册与 CPA 导出使用项目 `cpa_proxy/proxy`，主 CLIProxyAPI 的 `proxy-url` 为空，上游调用出口可能不一致。
- 主 CLIProxyAPI 配置为 `request-retry: 3` 且 `max-retry-credentials: 0`；后者表示失败时可继续尝试全部匹配凭证。
- 因此先验证“单凭证 + 同出口 + 无重试扩散”，不更换国家或轮换代理节点。

## 1. 准备目录

先生成空的隔离配置：

```bash
python3 scripts/prepare_clipproxy_diagnostic.py
```

需要测试时，只指定一个新鲜且未禁用的 CPA xAI 凭证：

```bash
python3 scripts/prepare_clipproxy_diagnostic.py \
  --source-auth ./cpa_auths/xai-user@example.com.json
```

工具会从项目 `config.json` 读取 `cpa_proxy > proxy`，并生成：

- `127.0.0.1:18317` 隔离端口
- `/tmp/cliproxyapi-xai-diagnostic/auth` 单凭证目录
- `request-retry: 0`
- `max-retry-credentials: 1`
- 与注册/CPA 一致的稳定代理出口

若 `proxy` 与 `cpa_proxy` 同时配置但值不同，工具会拒绝生成诊断环境，避免把出口差异误判成账号问题。

## 2. 启动隔离实例

必须使用 7.1.56 二进制的绝对路径，避免误用 PATH 中的旧版：

```bash
cd /tmp/cliproxyapi-xai-diagnostic
/Users/nameqhyu/Documents/CLIProxyAPI_7.1.56_darwin_amd64/cli-proxy-api \
  -config /tmp/cliproxyapi-xai-diagnostic/config.yaml \
  -local-model
```

## 3. 本地自检

```bash
test "$(find /tmp/cliproxyapi-xai-diagnostic/auth -name '*.json' | wc -l | tr -d ' ')" = "1"
lsof -nP -iTCP:18317 -sTCP:LISTEN
DIAG_API_KEY="$(tr -d '\n' </tmp/cliproxyapi-xai-diagnostic/api_key.txt)"
curl --noproxy '*' -fsS \
  -H "Authorization: Bearer $DIAG_API_KEY" \
  http://127.0.0.1:18317/v1/models | jq '.data | length'
```

`/v1/models` 仅用于确认本地服务与认证配置，不代表已执行聊天请求。

## 4. 首次上游验证

- 请求前先在官网确认账号状态。
- 只发送一次最小非流式请求，不并发，不批量切换凭证。
- 请求后再次检查官网状态和诊断实例标准输出。
- 若出现停用，立即停止，不尝试切换国家、轮换节点或扩大样本。

停止诊断实例可直接在前台按 `Ctrl-C`。

## 存活口径

- 本项目把“存活”定义为单凭证能够完成一次上游模型请求。
- `disabled=false`、存在 `refresh_token` 或本地 `/v1/models` 能列出模型，都不能单独证明上游请求可用。
- 不要在主凭证池做批量探测；主服务的跨凭证重试会污染账号级结论，并可能扩大风险面。

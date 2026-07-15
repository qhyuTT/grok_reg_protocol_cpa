# Lessons

- Cloudflare 手动排障必须使用干净浏览器：不要把自动化注册机的补丁扩展、伪造 UA 和精简启动参数带入行为录制，否则容易出现真实 Chrome 版本与 UA 不一致导致 Turnstile `failure_retry`。
- 注册健康探测应在账号账本、认证文件和 token 池写入之前完成；只有明确权限拒绝才淘汰，网络异常和无法分类结果不能自动删除。
- 获取 sso cookie 不等于 Grok 注册流程完成；必须保留注册浏览器，完成首条消息、生日保存和会话创建后才能导出 Cookie、执行 CPA 健康门并落盘。
- Grok 匿名页也允许提交首条消息，不能把“消息出现在页面”当作登录成功；注册后应保留原标签等待 accounts.x.ai 自然跳转，并以 `/api/auth/session` 和 `/rest/user-settings` 的成功响应确认登录，不能提前导航或人工克隆 Cookie。
- 从上游移植分类器时必须保持条件优先级，而不只是复制关键词；auth/quota 关键词必须先于通用 402/403，否则会把认证失效和额度耗尽误报为权限拒绝。
- 刚注册账号的权限健康门不能依赖单次即时探测；拒绝结果必须保留脱敏的 status/code/content-type/主备接口证据，避免把代理或 WAF 403 当作账号封禁。
- “连续拒绝”必须要求复验结果持续落在可淘汰分类；一次 403 后混入网络失败时不能仍按连续 403 淘汰。
- 备用接口成功只应把权限类 402/403 标记为端点不一致，不能覆盖主接口已经确认的 quota 或 reauth 分类。
- 自动化浏览器追踪不能在后台线程对注册标签循环执行 `Runtime.evaluate`；这会与主流程争用同一 CDP 通道并造成页面超时。应优先消费浏览器主动回调，只有首次挂载时安装事件脚本。
- 指纹/UA 改造前必须先确认目标代码在活跃调用链上：`enable_nsfw`/`enable_nsfw_for_token`（含其 `get_user_agent()` Windows UA、`impersonate=chrome120`、cf_clearance 复用）都没有调用点，是死代码；真实生日/TOS 在浏览器内 `activate_grok_web_account` 由真实系统 Chrome 完成，UA 天然正确。不要为“完成计划”去改不影响运行的死代码。
- 成功与 permission_denied 的注册在浏览器行为上无法区分（相同步骤/端点，注册期请求全 200）；403 是注册直后风控冷却的普遍态，健康账号约 15s 内转 200，被拒账号持续 403。差异在服务端风控（IP/指纹/节奏/冷却），不在客户端操作序列。健康探测 offset 到 120s 无意义。
- 真实指纹自曝点在活跃路径上：`--disable-gpu`/`--disable-software-rasterizer` 让有头 Chrome 的 WebGL 退化为 SwiftShader 软件渲染；`turnstilePatch` 伪造 `navigator.plugins=[1,2,3,4,5]` 使 `plugins[0].name===undefined`。二者都比不改更假，有头真实系统 Chrome 下应移除。

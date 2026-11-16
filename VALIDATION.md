# v0.2.0 验证记录

验证日期：2026-11-16。

| 检查 | 结果 | 范围 |
|---|---|---|
| Node.js 24.22.1 单元测试 | 11 项通过 | P-256、SEC1/PKCS8、CIDR、IPv6、DNS、路由、令牌排除 |
| Go 1.26.3 `go test -race` | 4 项通过 | 访问口令、来源限制、超大/多 JSON 拒绝、限流、登记载荷、错误脱敏、静态白名单 |
| Xray 26.11.9 / 676eaf6 | H2/H3 均通过 `run -test` | 完整配置和局域网路由可被真实内核加载；测试密钥未注册 |
| Linux amd64 / arm64 | 编译通过 | CGO_ENABLED=0，内嵌网页资源 |
| HTTP 冒烟检查 | 首页、JS、CSS、health 均 200 | 二进制真实启动后检查 Content-Type |
| DOM 字段引用 | 通过 | app.js 引用的 ID 均存在于 HTML |
| 浏览器视觉与交互 | 未完成 | 云端浏览器无法访问工作区 localhost，返回连接/HTTP 访问失败 |
| Docker / GHCR | 未运行 | 环境没有 Docker；工作流未推送到 GitHub |
| 真实 Cloudflare 注册 | 未验证 | 注册 API 使用模拟上游测试，未创建真实账号 |
| v2rayN GUI 与 WARP 出口 | 未验证 | 尚需在用户设备导入配置检查 warp=on/plus |

网页和 README 明确区分本地格式/密钥校验、内核加载检查、实际隧道连接，未将其中一项等同于另一项。

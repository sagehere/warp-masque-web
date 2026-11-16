# WARP MASQUE Web v0.2.0

简体中文网页工具：注册个人 WARP 设备，或导入已有 usque 配置，直接生成供 v2rayN/Xray 使用的 MASQUE 配置。支持电脑、手机浏览器操作；实际隧道由客户端建立。

## 当前功能

- 浏览器本地 WebCrypto 生成 P-256 私钥；Go 服务仅转发账号注册、公钥登记请求。
- 导入 usque JSON；支持 SEC1 / PKCS#8 Base64 或 PEM 私钥，严格解析 P-256，执行签名验签检查，拒绝 WireGuard 私钥。
- H2/TCP、H3/QUIC 分别生成；IPv4/IPv6 外层端点可选。H2 的 IPv6 端点未提供时要求手工填写，不编造端点。
- 默认导出完整 Xray JSON，另支持单出站和 usque 备份。连接 JSON 不含账号令牌或许可证。
- 本地 SOCKS 端口可配置，HTTP 为相邻端口；路由可选“全部经 WARP”或“局域网直连”。路由不依赖 geoip.dat。
- 自定义隧道 DNS、SNI、服务端公钥；保持公钥固定校验。
- 注册接口默认关闭，需至少 16 字符口令；限制一项并发、新注册至少间隔 60 秒；登记失败可在当前页面继续，不重复创建账号。
- 无数据库、无 npm 运行时依赖；一个 Go 二进制内嵌整个网页，或一个 Docker 容器。

## 快速运行

请从 [Releases](https://github.com/sagehere/warp-masque-web/releases) 下载完整包（含 `bin/`）或对应架构的程序。Git 仓库仅包含源码。完整包在 x86 VPS 的运行示例：

```bash
chmod +x bin/warp-web-linux-amd64
export REGISTRATION_TOKEN='请替换为至少32字符的随机口令'
./bin/warp-web-linux-amd64
```

默认监听 `127.0.0.1:8080`。本机访问 `http://localhost:8080`；远程部署请用 HTTPS 域名访问。`REGISTRATION_TOKEN` 不设置时，可用本地导入转换功能，在线注册关闭。

源码运行需要 Go 1.23+（本次实际用 Go 1.26.3 构建）：

```bash
go run .
```

修改网页后需重新编译 Go 二进制。

## Dockge / Docker Compose 部署

1. 把项目目录复制至 VPS，例如 `/opt/stacks/warp-masque-web`。目录内应有 `Dockerfile`、`compose.yml`、`main.go`、`go.mod` 和 `public/`。
2. 复制 `.env.example` 为 `.env`，设置 `REGISTRATION_TOKEN` 为随机长口令。可用 `openssl rand -hex 24` 生成。此口令用于保护注册接口，不是 WARP 账号口令。
3. 在 Dockge 中扫描/载入该 Stack（目录必须在 Dockge 的 stacks 路径中）。保留提供的 Compose，执行构建并启动；或命令行运行：

```bash
cp .env.example .env
# 编辑 .env 后运行
docker compose up -d --build
```

4. 同一宿主机的原生 Caddy 可反代 `127.0.0.1:8080`。Caddy 示例：

```caddyfile
warp.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

5. NPM/Caddy 若运行在另一个容器，容器内的 `127.0.0.1` 指向该容器自身。可为两个服务加入已有共享 Docker 网络，由反代连接 `warp-web:8080`；或在 `.env` 将 `BIND_IP` 改为宿主机上反代可达的地址，并用防火墙限制入口。无需让本项目管理反代。
6. 反代应保留原始 Host，HTTPS 超时设为至少 30 秒。建议 Cloudflare DNS 初次使用仅 DNS 模式排查；橙云代理只承载网页及注册 API，不承载客户端 MASQUE 隧道。
7. 打开 `https://你的域名/api/health`，确认 `registrationEnabled:true`。打开首页填写注册口令，确认服务条款后注册；注册成功先备份 usque 配置。

升级时替换源码，执行 `docker compose up -d --build`。服务没有数据库、账号文件或持久卷；当前设备凭据在网页内存中，刷新前请下载备份。

## v2rayN 导入

1. 先在 v2rayN 更新 Xray 核心。页面选择“v2rayN · 完整 Xray 配置”，建议先测试 H2。
2. 下载 JSON。在支持对应功能的 v2rayN 中添加“自定义配置服务器”，导入完整配置，内核选择 Xray。不同客户端版本的菜单可能略有区别。
3. 将 v2rayN 的本地 SOCKS 监听端口与生成器保持一致，默认 10808；HTTP 为 10809。确保端口没有被其他服务占用。
4. 设为活动服务器，开启系统代理。完整配置包含自己的路由，不应假定 GUI 的分流设置自动合入该文件。首版自定义完整配置以系统代理模式为验收目标，TUN 模式未验证。
5. Windows PowerShell 可显式走本地 HTTP 代理检查：

```powershell
curl.exe --proxy http://127.0.0.1:10809 https://www.cloudflare.com/cdn-cgi/trace
```

预期 `warp=on` 或 `warp=plus`。网页直接打开检测链接只有在浏览器已走客户端代理时才有意义。

高级用户可选择单出站格式，交给客户端的“自定义出站服务器”功能。单出站不能当完整 Xray 配置运行。当前未生成 `masque://` URI。

## 端点和密钥

H3 使用登记响应中的端点与公钥。默认 H2 `162.159.198.2` 使用已知固定的 P-256 SPKI 公钥；其 IPv6 对应地址 `2606:4700:103::2` 使用相同已知公钥。自定义端点应核实属于 Cloudflare 官方 WARP，且证书公钥相符。工具验证地址格式，不声称手工输入的每个 IP 都是官方端点。

服务端公钥可能轮换；失败时通过可信来源核对公钥再覆盖，不关闭证书校验。H2/H3 为独立配置，未实现自动回退。TLS SNI 默认 `consumer-masque.cloudflareclient.com`。

## 账号与隐私

注册适配器参考 usque 固定提交，来源见 `UPSTREAM.md`，不是启动 usque 隧道或伪造 VLESS 桥接。注册设备私钥不上传；账号令牌、公钥及设备信息需由 Go 后端转发给 Cloudflare，后端不记录或持久保存这些字段。无需 Cloudflare 管理 API Token。

只有用户勾选条款并点击注册后才访问注册 API。接口可能被上游限流、拒绝出口或改变协议；失败时可在本地用 usque 注册，然后导入生成的 config.json。不要连续重复注册。

页面刷新或关闭会丢失内存中的凭据。备份包含账号令牌和私钥；不要提交 Git、分享公开 URL。此版本未实现 WARP+ 升级、Zero Trust SSO、账号删除、公开订阅托管、自动端点测速。

## 验证

```bash
go test -race ./...
node --test tests/*.test.mjs
node --check public/app.js
XRAY_BIN=/path/to/xray node tests/xray-check.mjs
```

本次验证结果见 `VALIDATION.md`。配置加载测试使用临时未注册密钥，不能证明与 WARP 成功连接。导入模式可将 `public/` 静态托管；该目录不再包含 v0.1 的 Pages Worker，在线注册需本版 Go 服务。

## GitHub 镜像

附 `.github/workflows/docker.yml`。上传你自己的 GitHub 仓库 main 分支后，测试通过自动构建 linux/amd64、linux/arm64 镜像，仅推送 GHCR。仓库：https://github.com/sagehere/warp-masque-web 。镜像由 GitHub Actions 自动构建；以 Actions 运行结果为准。

发布后可将 Compose 的 `build: .` 换成 `image: ghcr.io/sagehere/warp-masque-web:latest`。需要公开拉取时，在 GitHub Packages 中将该包可见性设为 Public。

代码 MIT；usque 原许可保留在 `USQUE-LICENSE.md`。与 Cloudflare 无隶属关系。

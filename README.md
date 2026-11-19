# WARP MASQUE Web v0.3.0

简体中文网页工具。解锁生成后，粘贴个人 WARP+ 许可证，点击「生成配置」，即可生成供 v2rayN/Xray 使用的 MASQUE JSON。也可注册免费 WARP 设备或导入已有 usque 配置。

## 用 WARP+ 密钥生成

1. 从你有权使用的 1.1.1.1 应用账户复制许可证，格式为 `xxxxxxxx-xxxxxxxx-xxxxxxxx`。也可粘贴带标签、流量说明的文本。识别到多条时，手动选择其中一条。
2. 用部署时配置的网页访问口令解锁。HTTPS 同源会话有效期为 8 小时。随后只需填写 WARP+ 许可证。设备注册会占用许可证设备名额。
3. 点击「生成配置」。网页在浏览器生成 P-256 密钥，注册设备、绑定许可证、登记公钥，再查询同一设备的许可证与 WARP+ 权益。遇到临时错误时，保留当前页面并点击继续。刷新会丢失页面内的设备凭据。
4. 点击「下载 v2rayN 配置」保存默认 H2 文件 `warp-masque-xray.json`。H3、自定义参数与 usque 备份位于「高级导出设置与 usque 备份」。
5. 导入配置并检查实际出口。账户查询显示 WARP+ 后，仍需在本地客户端验证隧道连接。

## 当前功能

- 浏览器本地 WebCrypto 生成 P-256 私钥；Go 服务转发设备注册、许可证绑定、公钥登记和账户查询。
- 导入 usque JSON；支持 SEC1 / PKCS#8 Base64 或 PEM 私钥，严格解析 P-256，执行签名验签检查，拒绝 WireGuard 私钥。
- H2/TCP、H3/QUIC 分别生成；IPv4/IPv6 外层端点可选。H2 的 IPv6 端点未提供时要求手工填写，不编造端点。
- 默认导出完整 Xray JSON，另支持单出站和 usque 备份。连接 JSON 不含账号令牌或许可证。
- 本地 SOCKS 端口可配置，HTTP 为相邻端口；路由可选“全部经 WARP”或“局域网直连”。路由不依赖 geoip.dat。
- 自定义隧道 DNS、SNI、服务端公钥；保持公钥固定校验。
- 注册接口默认关闭，需至少 16 字符口令。上游请求限制为一项并发，新注册至少间隔 60 秒。绑定或登记失败时可在当前页面沿用已注册设备继续。
- 无数据库、无 npm 运行时依赖；一个 Go 二进制内嵌整个网页，或一个 Docker 容器。

## 快速运行

已附 Linux amd64 / arm64 二进制，位于 `bin/`。例如 x86 VPS：

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

Compose 从 GitHub Container Registry 拉取 `ghcr.io/sagehere/warp-masque-web:latest`。镜像支持 Linux amd64 和 arm64。

1. 将 `compose.yml` 和 `.env.example` 放到 VPS 的 Dockge Stack 目录，例如 `/opt/stacks/warp-masque-web`。
2. 首次部署时，把 `.env.example` 复制为 `.env`，将 `REGISTRATION_TOKEN` 设置为随机长口令。可用 `openssl rand -hex 24` 生成。宿主机默认监听 `0.0.0.0:9000`。仅供本机反代时，可将 `BIND_IP` 设置为 `127.0.0.1`。
3. 在 Dockge 扫描并启动该 Stack，或在 Stack 目录执行：

```bash
docker compose up -d
curl -fsS http://127.0.0.1:9000/api/health
```

4. 如果 Caddy 直接运行在宿主机上，反代 `127.0.0.1:9000`：

```caddyfile
warp.example.com {
    reverse_proxy 127.0.0.1:9000
}
```

5. 如果 NPM 或 Caddy 运行在 Docker 容器里，把反代与 `warp-web` 加入同一个 Docker 网络，反代地址用 `warp-web:8080`。
6. 反代保留原始 Host，HTTPS 超时设为至少 30 秒。使用 Cloudflare DNS 时，可先用仅 DNS 模式排查 HTTPS。Cloudflare 橙云代理只承载网页和 API 请求，客户端独立连接 MASQUE 端点。
7. 访问 `https://你的域名/api/health`，确认 `registrationEnabled:true`。打开首页，用 `REGISTRATION_TOKEN` 解锁，再输入 WARP+ 密钥。

从源码构建的 Stack 迁移时，将原 `build: .` 替换为新版 Compose 中的 `image` 和 `pull_policy`，并保留 `.env` 和已有的反代网络配置。如要切换到 9000，需同时将已有 `.env` 的 `PORT` 改为 `9000`。宿主机反代使用新端口，共享 Docker 网络的反代继续使用容器端口 8080。

更新镜像时，在 Dockge 重新部署，或再次执行 `docker compose up -d`，Compose 会检查并拉取最新的 `latest` 镜像。

## 通过 IP 和端口直连

1. 在已有 Stack 的 `.env` 中设置 `BIND_IP=0.0.0.0`。保留需要的 `PORT`，下例采用 `8003`。在 VPS 的云安全组和防火墙中允许访问 TCP 8003。
2. 使用主 Compose 启动后，可通过 `http://公网IP:8003/api/health` 确认端口可达。通过公网 IP 生成配置需要可信的 HTTPS 证书，因为浏览器在公共 HTTP 页面上不启用 Web Crypto 和安全会话。
3. 准备一份包含该公网 IP 的、浏览器信任的 TLS 证书。可以使用支持 IP 证书的签发服务，例如 [Let's Encrypt 与 Certbot](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)。签发时应通过服务商要求的挑战验证公网 IP。下面的目录和权限使容器内的 UID 10001 可以读取私钥。
4. 在 Stack 目录安装证书，并使用附带的 HTTPS 配置。把示例源路径替换为实际证书路径。

```bash
sudo install -d -m 0750 -o 10001 tls
sudo install -m 0644 /你的证书目录/fullchain.pem tls/fullchain.pem
sudo install -m 0600 -o 10001 /你的证书目录/privkey.pem tls/privkey.pem
docker compose -f compose.yml -f compose.ip-https.yml up -d
```

然后访问 `https://公网IP:8003`。在 Dockge 只维护一个 Compose 文件时，可将 `compose.ip-https.yml` 里的两个 TLS 环境变量和 `volumes` 项合入现有 `warp-web` 服务，再点击重新部署。续签后，重新安装证书文件并重启容器，使服务读取新证书。

## v2rayN 导入

1. 先在 v2rayN 更新 Xray 核心。页面点击「下载 v2rayN 配置」取得默认 H2 文件。
2. 下载 JSON。在支持对应功能的 v2rayN 中添加“自定义配置服务器”，导入完整配置，内核选择 Xray。不同客户端版本的菜单可能略有区别。
3. 将 v2rayN 的本地 SOCKS 监听端口与生成器保持一致，默认 10808；HTTP 为 10809。确保端口没有被其他服务占用。
4. 设为活动服务器，开启系统代理。完整配置包含自己的路由，不应假定 GUI 的分流设置自动合入该文件。首版自定义完整配置以系统代理模式为验收目标，TUN 模式未验证。
5. Windows PowerShell 可显式走本地 HTTP 代理检查：

```powershell
curl.exe --proxy http://127.0.0.1:10809 https://www.cloudflare.com/cdn-cgi/trace
```

WARP+ 配置的实机验收目标为 `warp=plus`。`warp=on` 只确认 WARP 连通，应结合网页显示的账户状态继续排查。需明确由本机代理发起检测请求。

高级用户可选择单出站格式，交给客户端的“自定义出站服务器”功能。单出站不能当完整 Xray 配置运行。当前未生成 `masque://` URI。

## 端点和密钥

H3 使用登记响应中的端点与公钥。默认 H2 `162.159.198.2` 使用已知固定的 P-256 SPKI 公钥；其 IPv6 对应地址 `2606:4700:103::2` 使用相同已知公钥。自定义端点应核实属于 Cloudflare 官方 WARP，且证书公钥相符。工具验证地址格式，不声称手工输入的每个 IP 都是官方端点。

服务端公钥可能轮换；失败时通过可信来源核对公钥再覆盖，不关闭证书校验。H2/H3 为独立配置，未实现自动回退。TLS SNI 默认 `consumer-masque.cloudflareclient.com`。

## 账号与隐私

注册及许可证适配器参考 usque 固定提交，来源见 `UPSTREAM.md`。P-256 私钥留在本机，账号令牌、许可证和设备公钥由 Go 服务转发给 Cloudflare。服务不记录或持久保存这些字段。网页访问口令只用于本工具的会话认证。部署时应避免配置反代记录访问口令、Cookie 或请求正文。

许可证在用户点击生成后才提交。Xray 连接文件仅含连接所需的设备私钥等配置。usque 原生备份也包含设备令牌和许可证，请妥善保管。上游接口可能限流、拒绝某些部署出口或变更协议。刷新网页会丢失待继续的注册状态。

本轮模拟过真实浏览器到 Go 后端的完整生成流程，并使用 Xray 核心加载实际下载的 H2、H3 文件。真实 Cloudflare 许可证绑定与 v2rayN 实机连接等待自有有效许可证验证。见 `VALIDATION.md`。

# WARP MASQUE Web v0.4.0

简体中文网页工具，用于注册或复用 WARP MASQUE 设备并下载 usque 原生 `config.json`。

## 生成配置

- **使用 WARP+ 许可证**。解锁后粘贴个人 WARP+ 许可证并点击生成。网页会注册设备、绑定许可证、登记公钥并核对 WARP+ 权益。本页可继续未完成的绑定或登记。
- **使用已有私钥**。接受 P-256 的 SEC1、PKCS#8，支持 Base64 和 PEM。也可粘贴包含 `masqueSettings.warp.privateKey` 的 MASQUE 出站 JSON。字段齐全时，网页按该出站提供的端点、地址和服务端公钥在本地转换。
- **复用原设备**。可导入旧 usque JSON，也可先校验私钥，再粘贴原设备的 usque 备份。公钥匹配时沿用备份中的设备信息和管理凭据。
- **登记新设备**。只有一把私钥时，先校验，再使用其公钥登记新设备。可选填 WARP+ 许可证。Cloudflare 实测会拒绝将已登记的公钥绑定到另一台设备。若遇到此情况，请通过原 usque 备份或字段齐全的 MASQUE 出站复用原设备。

各入口均下载 `config.json`。转换在浏览器运行，要求 HTTPS 或 localhost。服务无数据库、无 npm 运行时依赖。

## 快速运行

如已下载 Release 中的 Linux 二进制，可直接运行。例如 amd64 VPS：

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

## 在 usque 中连接

在 `config.json` 所在目录运行结果区显示的命令。默认示例使用 H3 及本机 SOCKS：

```bash
usque -c config.json socks --bind 127.0.0.1
curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

命令会按源配置补充 `--http2`、`--ipv6` 或 `--connect-port`。usque 的配置格式通过命令行设置连接端口。若迁移的端口不是 443，请一并保存结果区的连接命令。通过本机 SOCKS 检查出口时，`warp=on` 表示 WARP 连通，`warp=plus` 表示 WARP+ 出口。

## 账号与隐私

设备私钥、原备份及粘贴的出站 JSON 仅在浏览器中解析。在线登记只提交设备公钥、注册信息和可选的许可证。导出的 `config.json` 含设备私钥，若源配置有设备令牌等管理凭据，文件也会保留。由 MASQUE 出站迁移的配置只能使用源配置中已有的连接信息。

上游接口可能限流或限制部分出口。已知设备 ID 的登记失败后，可以在当前页面沿用同一设备重试。刷新会丢失临时登记状态。

见 [验证记录](VALIDATION.md)。

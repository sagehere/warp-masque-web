# 上游来源

本项目依据 https://github.com/Diniboy1123/usque 的 MIT 许可代码设计注册适配器。
固定参考提交：6aa03fc97d12848dce34eedbd187fb1077b5d1ea。

参考文件：api/cloudflare.go、internal/consts.go、cmd/register.go、models/register.go。
Go 后端不依赖 usque 的不稳定 Go 库接口，也不执行 usque 二进制；按固定版本的字段、端点和请求头实现兼容适配器，另在登记时明确发送 warp_enabled=true。
P-256 密钥生成移至浏览器 WebCrypto。私钥不会上传到 Go 服务。

Xray 配置规范：
https://xtls.github.io/config/transports/masque.html
https://xtls.github.io/config/outbounds/masque.html
https://xtls.github.io/document/level-2/warp.html

Cloudflare 注册 API 不具有稳定的公开接口承诺，后续变更可能需要更新适配器。

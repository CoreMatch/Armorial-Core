<div align="center">
  <h1>HRPAuth</h1>
  <p><strong>身份、服务与信任，尽在掌握。</strong></p>
  <p><a href="./README.md">English</a></p>
</div>

HRPAuth 是面向 HA 生态站长与服务的自托管身份认证与 OAuth2 授权中心。

它提供账号安全、客户端与令牌管理以及服务注册，但本身不充当 Yggdrasil 或皮肤服务。

## 为什么选择 HRPAuth

- **掌握登录体验。** 将用户账号与授权能力保留在自己的部署中。
- **多层守护账号。** 将邮箱验证与验证码，同 TOTP、通行密钥/WebAuthn 和邮箱二要素结合使用。
- **为找回账号做好准备。** 在常用第二因素不可用时，用户可使用恢复密钥。
- **管理生态接入。** 注册 OAuth2 客户端、签发与管理令牌，并维护服务注册表。
- **让信任留在自己手中。** 与依赖它的服务一起，自托管身份信任边界。

## 进一步了解

- [部署指南](https://wiki.mcnb.dev/deploy/hrpauth) — 运行 HRPAuth
- [Docker 镜像](https://hub.docker.com/r/limeight/ha-hrpauth) — 已发布的容器镜像
- [HA-Contract](https://github.com/CoreMatch/HA-Contract) — 生态 API 契约

## 许可证与来源

[AGPL-3.0](LICENSE)。来源：[CoreMatch/HRPAuth](https://github.com/CoreMatch/HRPAuth)。

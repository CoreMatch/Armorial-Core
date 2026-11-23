<div align="center">
  <h1>HRPAuth</h1>
  <p><strong>Your identity. Your services. Your control.</strong></p>
  <p><a href="./README.zh-CN.md">简体中文</a></p>
</div>

HRPAuth is a self-hosted identity and OAuth2 authorization center for server owners and services in the HA ecosystem.

It provides account security, client and token management, and service registration without acting as a Yggdrasil or skin service itself.

## Why HRPAuth

- **Own the login experience.** Keep user accounts and authorization inside your deployment.
- **Layer account protection.** Combine email verification and captcha with TOTP, passkeys/WebAuthn, and email 2FA.
- **Plan for recovery.** Give users recovery keys when their usual second factor is unavailable.
- **Manage ecosystem access.** Register OAuth2 clients, issue and manage tokens, and maintain service registries.
- **Keep trust self-hosted.** Run the identity boundary alongside the services that depend on it.

## Learn more

- [Deployment guide](https://wiki.mcnb.dev/deploy/hrpauth) — running HRPAuth
- [Docker image](https://hub.docker.com/r/limeight/ha-hrpauth) — published container image
- [HA-Contract](https://github.com/CoreMatch/HA-Contract) — ecosystem API contracts

## License & provenance

[AGPL-3.0](LICENSE). Source: [CoreMatch/HRPAuth](https://github.com/CoreMatch/HRPAuth).

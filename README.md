# Vault Extension

Vault 是一款用于 Microsoft Edge 和 Helium 的密码管理扩展。密码库加密保存在本机，用主密码解锁，不需要注册账号。

## 主要功能

- **登录网站**：在登录框旁选择账号，填入用户名和密码；也可以用库中的通行密钥（Passkey）登录。仅仅打开网页不会触发密码填充。
- **生成两步验证码**：扫描网页上的二维码，或手动添加验证器。支持 TOTP、HOTP 和 Steam Guard。
- **迁入已有数据**：可导入浏览器导出的 CSV、Bitwarden JSON、KeePass 数据库和 Ente Auth 备份。先看预览，确认后才写入密码库。
- **备份与同步**：将密码库导出为加密备份文件（`.vaultpack`）。需要在多台电脑间同步时，可以连接自己的 WebDAV 网盘。

## 从源码安装

目前是候选版，仓库尚未提供预编译安装包。建议用单独的浏览器配置试用，并保留原密码库。真实网站、网盘和硬件密钥的兼容性仍待验证，详见[候选版测试记录](docs/release-candidate-status.md)。

准备 Git、Node.js（项目使用 26.x 验证）、pnpm 12.19.0、Rust（通过 `rustup` 安装）和 `wasm-pack`，然后运行：

```sh
git clone https://github.com/IZRINO/vault-extension.git
cd vault-extension
rustup target add wasm32-unknown-unknown
pnpm install --frozen-lockfile
pnpm run build
```

1. 在 Edge 打开 `edge://extensions`，或在 Helium 打开 `chrome://extensions`。
2. 开启「开发者模式」，点击「加载解压缩的扩展」，选择 `apps/extension/.output/chrome-mv3`（包含 `manifest.json` 的目录）。
3. 首次打开 Vault，选择「暂不配置，创建本地密码库」；已有 `.vaultpack` 备份则选择「从本地备份恢复」。

**恢复码不是备份。** 建库时请离线保存应急恢复码。它能重设主密码，但不包含库中的条目。卸载扩展或清理浏览器数据前，请在「设置 → 备份与恢复」导出 `.vaultpack`，并保管好备份文件的密码。

## 开发与反馈

构建后可用 `pnpm run dev` 启动开发模式。`pnpm run test:rust` 和 `pnpm run test:extension` 分别运行 Rust 和扩展测试。

[技术架构](密码管理器浏览器插件-技术架构与选型文档.md) · [开发计划](分期开发与验证计划.md) · [反馈问题](https://github.com/IZRINO/vault-extension/issues) · [MIT 许可证](LICENSE)

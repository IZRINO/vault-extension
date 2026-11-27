# Vault Extension

Vault 是一款用于 Microsoft Edge 和 Helium 的密码管理扩展。密码库加密保存在本机，用主密码解锁，不需要注册账号。

## 主要功能

- **保管凭证**：本机加密保存网站登录、支付卡、身份与地址、开发者密钥。
- **登录网站**：在登录框旁选择账号填入用户名和密码，或用通行密钥（Passkey）登录。Vault 可提示保存新账号或更新密码；仅仅打开网页不会填入密码。认不出表单时，可在「密码库 → 当前网站 → 标记登录框」点选输入框。目前标记只保存在本机。
- **生成两步验证码**：扫描网页上的二维码，或手动添加验证器。支持 TOTP、HOTP 和 Steam Guard。
- **迁入或带走数据**：浏览器 CSV、Bitwarden、KeePass、Ente Auth 等可先预览，确认后才导入。也可按目标格式导出，例如 Bitwarden JSON 或通用 CSV；不是每种格式都能带走所有字段。
- **备份与同步**：可单独导出加密备份文件。也可连接自己的 WebDAV 网盘，在「设置 → 网盘连接」点「立即同步」。新建的远端库默认同步加密整包（Koofr 用 JSON 封装密文），已有增量库沿用原协议，不会自动迁移。

[v0.2.1 已正式发布](https://github.com/IZRINO/vault-extension/releases/tag/v0.2.1)。`v0.2.0` 的正式包已在 Edge、Helium 完成整包回环测试；**`v0.2.1` 同包双浏览器回归、真实 Koofr 建库和坚果云新版实测仍待签收**。实体 Windows Hello、真实网站表单和 Passkey 也需分别实测。详见[网盘验证记录](docs/agents/whole-pack-webdav.md)和[验收总览 #51](https://github.com/IZRINO/vault-extension/issues/51)。

## 安装正式版

1. 从 [GitHub Releases](https://github.com/IZRINO/vault-extension/releases/latest) 下载附件中以 `-chrome-mv3.zip` 结尾的安装包，解压到准备长期保留的目录。不要下载 GitHub 自动生成的 `Source code`。
2. 在 Edge 打开 `edge://extensions`，或在 Helium 打开 `chrome://extensions`。开启「开发者模式」，点击「加载解压缩的扩展」，选择刚解压的目录（能直接看到 `manifest.json`）。
3. 首次打开 Vault，选择「暂不配置，创建本地密码库」；已有 `.vaultpack` 备份则选择「从本地备份恢复」。

**恢复码不是备份。** 建库时请离线保存应急恢复码。它能重设主密码，但不包含库中的条目。卸载扩展或清理浏览器数据前，请在「设置 → 备份与恢复」导出 `.vaultpack`，并保管好备份文件的密码。

从旧版升级时，请先备份，不要卸载原扩展。将新包解压到原扩展目录后，在扩展管理页点击「重新加载」。使用同一 WebDAV 密码库的设备建议一起升级。

## 从源码构建

准备 Git、Node.js（项目使用 26.x 验证）、pnpm 12.19.0、Rust（通过 `rustup` 安装）和 `wasm-pack`，然后运行：

```sh
git clone https://github.com/IZRINO/vault-extension.git
cd vault-extension
rustup target add wasm32-unknown-unknown
pnpm install --frozen-lockfile
pnpm run build
```

按上面的安装步骤加载 `apps/extension/.output/chrome-mv3`。[v0.2.1 升级说明](docs/releases/v0.2.1.md) · [整包同步与网盘验证记录](docs/agents/whole-pack-webdav.md) · [v0.1.0 工单与验收记录](docs/issue-alignment-audit-2026-11-26.md)

## 开发与反馈

构建后可用 `pnpm run dev` 启动开发模式。`pnpm run test:rust` 和 `pnpm run test:extension` 分别运行 Rust 和扩展测试。

[技术架构](密码管理器浏览器插件-技术架构与选型文档.md) · [开发计划](分期开发与验证计划.md) · [反馈问题](https://github.com/IZRINO/vault-extension/issues) · [MIT 许可证](LICENSE)

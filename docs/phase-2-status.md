# 二期开发记录：首批可用功能

2026-11-14。此记录只涵盖浏览器密码 CSV 导入和手动 TOTP，二期尚未验收。

## 已实现

- 从「设置 → 导入浏览器密码」选择浏览器导出的 UTF-8 CSV，预览可添加、重复和无法读取的条目；输入主密码或 PIN 确认后，才将新增凭证一次写入加密快照。依据网站地址的主机与端口、账号去重，已存在或在回收站的凭证不覆盖。期间文件或快照变化会要求重新预览。
- 单次最多 2 MiB、5,000 条。支持带 BOM、引号、逗号和换行的字段。CSV 只在本机读取，不改原文件，不导入 CSV 内的验证码设置；预览会提示这部分跳过。只导入 HTTP(S) 登录凭证。
- 登录凭证的编辑页可手动添加、修改或移除 Base32 密钥或 `otpauth://totp/` 链接。详情页根据本机时间显示当前验证码与剩余秒数，可用既有的敏感数据复制流程。支持 SHA-1 / SHA-256 / SHA-512、6–8 位和链接指定的周期。受保护凭证仍须通过后台二次验证。
- 沿用一期快照及 `.vaultpack` 数据格式，没有新增站点权限或网页内容脚本。CSV 解析和 TOTP 验证使用独立的按需 Worker，详情页显示验证码时才加载 TOTP 模块。

## 验证

- `cargo test --workspace --offline`：18 项通过，含 RFC 6238 三算法向量和 Chromium / Firefox / Safari 风格的 CSV 样本。
- `pnpm run build`、`pnpm --filter ./apps/extension compile`、`pnpm run test:extension` 通过：主 WASM 254,723 字节，低于 250 KiB；13 项后台集成测试含去重、预览不写入、失效预览拒绝、旧凭证保留及验证码密钥从密文恢复。
- `pnpm run test:phase-2`、`pnpm run test:data-safety` 在独立 Edge 和 Helium 配置通过。验证了取消确认、验证码轮换、受保护详情解锁、复制请求及一期备份恢复；二期复制测试不改系统剪贴板。两套真实扩展页面均未记录控制台错误。

## 尚未实现

Ente Auth / Bitwarden 互通、通用 CSV 字段映射、HOTP / Steam、扫码和网页自动填充。本轮未新增网页权限；接入内容脚本前，先限制 `storage.local` 只对可信上下文可见，并将网页消息与现有密码库管理消息分开授权。实体 Windows Hello、系统锁屏和原生侧栏的人工验收仍依 [一期记录](phase-1-status.md)。

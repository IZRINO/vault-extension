# Vault 浏览器扩展

第一阶段实现及验证范围见 [开发与验收记录](../../docs/phase-1-status.md)。

在仓库根目录执行 `pnpm run build`，然后在 Edge 或 Helium 的扩展管理页面加载本目录下的 `.output/chrome-mv3`。

- `entrypoints/background.ts`：消息来源校验、会话与告警生命周期。
- `entrypoints/offscreen`：按需密钥派生 Worker 与剪贴板清理。
- `entrypoints/popup`、`entrypoints/sidepanel`：共用密码库界面。
- `src/vault-controller.ts`：串行化凭证操作与后台认证。
- `src/vault-storage.ts`：IndexedDB 密文和本机会话 / 设置存储。

运行 `pnpm run test:extension` 验证后台，`pnpm run test:smoke` 运行两个浏览器的端到端回归。

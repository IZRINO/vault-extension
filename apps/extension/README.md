# Vault 浏览器扩展

第一阶段实现及验证范围见 [开发与验收记录](../../docs/phase-1-status.md)。

在仓库根目录执行 `pnpm run build`，然后在 Edge 或 Helium 的扩展管理页面加载本目录下的 `.output/chrome-mv3`。

- `entrypoints/background.ts`：消息来源校验、会话与告警生命周期。
- `entrypoints/offscreen`：按需密钥派生 Worker 与剪贴板清理。
- `entrypoints/kdf-worker.ts`：以扩展自身地址加载的密钥派生线程，开发和生产模式共用。
- `entrypoints/popup`、`entrypoints/sidepanel`：共用密码库界面。
- `src/vault-controller.ts`：串行化凭证操作与后台认证。
- `src/vault-storage.ts`：IndexedDB 密文和本机会话 / 设置存储。

运行 `pnpm run test:extension` 验证后台，`pnpm run test:smoke` 运行两个浏览器的端到端回归。

## 开发调试

先在仓库根目录执行 `pnpm run build:wasm`。在本目录的本地文件 `web-ext.config.ts` 中指定 Edge 和独立调试目录（该文件已被 Git 忽略）：

~~~ts
import { resolve } from 'node:path';
import { defineWebExtConfig } from 'wxt';

export default defineWebExtConfig({
  binaries: { edge: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe' },
  chromiumProfile: resolve('.wxt/edge-debug-profile'),
  keepProfileChanges: true,
});
~~~

在本目录执行 `node node_modules/wxt/bin/wxt.mjs -b edge`，保持进程运行。WXT 自动启动 Edge 并加载 `.output/edge-mv3-dev`。扩展内点击“展开”后按 F12 调试界面；在 `edge://extensions` 的开发人员模式下打开扩展的 Service Worker 检查后台。修改 Rust 后需重新编译 WASM 并重新加载扩展。

密钥 Worker 必须从扩展自身地址加载。不要改回 Vite 的 `?worker` 导入：开发模式会生成 localhost Worker 地址，在 Edge 中触发 `DWH_INVALID_SCRIPT_URL_ORIGIN` 并导致扩展进程崩溃。

保持开发服务器运行，在仓库根目录执行以下 PowerShell 命令回归开发版；测试使用临时独立浏览器配置和测试密码：

~~~powershell
$env:VAULT_EXTENSION_PATH = 'apps/extension/.output/edge-mv3-dev'
node scripts/smoke-extension.cjs
Remove-Item Env:VAULT_EXTENSION_PATH
~~~

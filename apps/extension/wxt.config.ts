import { defineConfig } from 'wxt';

export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  manifest: {
    name: 'Vault · 本地密码库',
    description: '本地加密保存登录、支付卡、身份与开发者凭证。',
    permissions: ['storage', 'unlimitedStorage', 'alarms', 'idle', 'sidePanel', 'clipboardWrite', 'clipboardRead', 'offscreen'],
    optional_permissions: ['privacy'],
    optional_host_permissions: ['https://api.pwnedpasswords.com/*'],
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';",
    },
  },
});

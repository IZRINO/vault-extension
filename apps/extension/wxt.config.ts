import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'wxt';

// See https://wxt.dev/api/reference/wxt/interfaces/inlineconfig.html
export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  vite: () => ({
    plugins: [tailwindcss()],
  }),
  manifest: {
    permissions: [
      'storage',
      'unlimitedStorage',
      'activeTab',
      'tabs',
      'alarms',
      'idle',
      'contextMenus',
      'sidePanel',
      'clipboardWrite',
      'clipboardRead',
      'offscreen',
    ],
    optional_permissions: ['privacy'],
    host_permissions: ['<all_urls>'],
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';",
    },
  },
});

import { VaultController, DAV_ALARM, LOCK_ALARM, IDLE_DETECTION_SECONDS } from '../src/vault-controller';
import { loadVaultCore } from '../src/vault-core';
import { isVaultPage } from '../src/sender-policy';
import { CLIPBOARD_ALARM, clearExpiredClipboard, restoreClipboardAlarm } from '../src/clipboard';
import type { VaultMessage } from '../src/vault-messages';
import { AutofillController } from '../src/autofill-controller';
import type { AutofillMessage } from '../src/autofill-messages';
import type { SiteFlags } from '../src/autofill-settings';
import { restoreDavBadge } from '../src/sync/connection';
import { PasskeyController } from '../src/passkeys/controller';
import { PASSKEY_PORT } from '../src/passkeys/protocol';
import { connectQrScan, QR_SCAN_PORT } from '../src/qr-scan';

export default defineBackground(() => {
  performance.mark('vault:background-entry');
  const vault = new VaultController();
  const autofill = new AutofillController(vault);
  const passkeys = new PasskeyController(vault);
  const ready = Promise.all([
    browser.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
    browser.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
  ]);
  void ready.then(restoreDavBadge).catch(() => undefined);
  void ready.then(restoreClipboardAlarm).catch(() => undefined);
  const notifyAutofill = (type: 'settings-changed' | 'site-settings-changed') => {
    void browser.tabs.query({}).then(tabs => Promise.allSettled(tabs.filter(tab => tab.id != null)
      .map(tab => browser.tabs.sendMessage(tab.id!, { target: 'vault-fill', type })))).catch(() => undefined);
  };
  const siteChanged = (rule: string, flags: Partial<SiteFlags>) => {
    if (flags.passkeyDisabled === true) passkeys.stop(undefined, rule);
    autofill.siteChanged(rule, flags);
    if (flags.inlineDisabled !== undefined || flags.saveDisabled !== undefined) notifyAutofill('site-settings-changed');
  };
  browser.runtime.onConnect.addListener(port => {
    if (port.name === PASSKEY_PORT) passkeys.connect(port);
    if (port.name === QR_SCAN_PORT) {
      if (!port.sender || !isVaultPage(port.sender, browser.runtime.id)) { port.disconnect(); return; }
      connectQrScan(port, ready, (source, signal) => vault.scanOtp(source, signal));
    }
  });
  browser.idle.setDetectionInterval(IDLE_DETECTION_SECONDS);
  browser.runtime.onMessage.addListener((message, sender, respond) => {
    if (message?.target === 'vault-autofill') {
      void ready.then(() => autofill.handle(message as AutofillMessage, sender)).then(
        value => {
          if (message.type === 'site' && message.flags !== undefined) siteChanged(message.origin, message.flags);
          respond({ ok: true, value });
        },
        error => respond({ ok: false, error: error instanceof Error ? error.message : '填充失败，请重试。' }),
      );
      return true;
    }
    if (message?.target === 'vault-passkey-ui') {
      void ready.then(() => passkeys.handle(message, sender)).then(
        value => respond({ ok: true, value }), error => respond({ ok: false, error: error instanceof Error ? error.message : '请求失效。' }),
      );
      return true;
    }
    if (message?.target === 'vault-event' && message.type === 'locked' && !sender.tab &&
        (!sender.url || sender.url === browser.runtime.getURL('/background.js')) && sender.id === browser.runtime.id) passkeys.stop();
    if (message?.target !== 'vault') return;
    if (message.type === 'webdav-scheduled') {
      respond({ ok: false, error: '无效的同步消息。' });
      return;
    }
    if (!isVaultPage(sender, browser.runtime.id)) {
      respond({ ok: false, error: '消息来源不允许访问密码库。' });
      return;
    }
    if (message.type === 'lock') { autofill.clear(); passkeys.stop(); }
    // The trusted open request can start compiling the static binary while storage access
    // levels are being applied. Vault/session reads still wait for that protection.
    if (message.type === 'open') void loadVaultCore().catch(() => undefined);
    const handle = ready.then(() => vault.handle(message as VaultMessage));
    const isMigrationInput = message.type === 'preview-migration' || message.type === 'import-migration' || message.type === 'csv-headers'
      || message.type === 'preview-auth-backup' || message.type === 'import-auth-backup';
    // Chrome delivers an independent JSON copy to this listener.
    const completed = isMigrationInput ? handle.finally(() => {
      if (Array.isArray(message.bytes)) message.bytes.fill(0);
    }) : handle;
    void completed.then(
      value => {
        if (message.type === 'set-autofill-site') siteChanged(message.origin, message.flags);
        if (['unlock', 'unlock-pin', 'unlock-prf', 'recover', 'create', 'webdav-create', 'webdav-join', 'webdav-update-key', 'set-equivalent-domains'].includes(message.type)) {
          autofill.clear();
          notifyAutofill('settings-changed');
        }
        respond({ ok: true, value });
      },
      error => respond({ ok: false, error: typeof error === 'string' ? error : error.message || '操作失败。' }),
    );
    return true;
  });
  browser.idle.onStateChanged.addListener(state => { if (state === 'locked') { autofill.clear(); passkeys.stop(); void vault.lock(); } });
  browser.tabs.onRemoved.addListener(tabId => { autofill.clear(tabId); passkeys.stop(tabId); });
  browser.tabs.onUpdated.addListener((tabId, update) => { if (update.status === 'loading' || update.url != null) passkeys.stop(tabId); });
  browser.tabs.onActivated.addListener(info => passkeys.selected(info.tabId, info.windowId));
  browser.windows.onRemoved.addListener(id => passkeys.closed(id));
  browser.commands.onCommand.addListener(async (command, tab) => {
    if (command === 'fill-login') {
      const active = tab ?? (await browser.tabs.query({ active: true, currentWindow: true }))[0];
      if (active?.id != null) await browser.tabs.sendMessage(active.id, { target: 'vault-fill', type: 'open' }).catch(() => undefined);
    }
  });
  function registerMenu() {
    void browser.contextMenus.removeAll().then(() => browser.contextMenus.create({ id: 'vault-fill', title: '使用 Vault 填充', contexts: ['editable'] })).catch(() => undefined);
  }
  browser.runtime.onInstalled.addListener(({ reason }) => {
    registerMenu();
    if (reason === 'install') void browser.tabs.create({ url: browser.runtime.getURL('/sidepanel.html?view=setup') }).catch(() => undefined);
  });
  browser.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'vault-fill' && tab?.id != null) void browser.tabs.sendMessage(tab.id,
      { target: 'vault-fill', type: 'open', reason: 'context-menu' }, { frameId: info.frameId ?? 0 }).catch(() => undefined);
  });
  browser.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === DAV_ALARM) void ready.then(() => vault.handle({ type: 'webdav-scheduled' })).catch(() => undefined);
    if (alarm.name === LOCK_ALARM) void ready.then(() => vault.lockExpiredSession()).then(locked => {
      if (locked) { autofill.clear(); passkeys.stop(); }
    }).catch(() => undefined);
    if (alarm.name === CLIPBOARD_ALARM) void clearExpiredClipboard().catch(() => undefined);
  });
  browser.runtime.onStartup.addListener(() => { registerMenu(); passkeys.stop(); void vault.lock(); });
});

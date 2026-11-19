import { VaultController, LOCK_ALARM, IDLE_DETECTION_SECONDS } from '../src/vault-controller';
import { isVaultPage } from '../src/sender-policy';
import { CLIPBOARD_ALARM, clearExpiredClipboard } from '../src/clipboard';
import type { VaultMessage } from '../src/vault-messages';
import { AutofillController } from '../src/autofill-controller';
import type { AutofillMessage } from '../src/autofill-messages';

export default defineBackground(() => {
  performance.mark('vault:background-entry');
  const vault = new VaultController();
  const autofill = new AutofillController(vault);
  const ready = Promise.all([
    browser.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
    browser.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
  ]);
  browser.idle.setDetectionInterval(IDLE_DETECTION_SECONDS);
  browser.runtime.onMessage.addListener((message, sender, respond) => {
    if (message?.target === 'vault-autofill') {
      void ready.then(() => autofill.handle(message as AutofillMessage, sender)).then(
        value => respond({ ok: true, value }),
        error => respond({ ok: false, error: error instanceof Error ? error.message : '填充失败，请重试。' }),
      );
      return true;
    }
    if (message?.target !== 'vault') return;
    if (!isVaultPage(sender, browser.runtime.id)) {
      respond({ ok: false, error: '消息来源不允许访问密码库。' });
      return;
    }
    if (message.type === 'lock') autofill.clear();
    void ready.then(() => vault.handle(message as VaultMessage)).then(
      value => {
        if (['unlock', 'unlock-pin', 'unlock-prf', 'recover', 'create', 'set-equivalent-domains'].includes(message.type)) {
          autofill.clear();
          void browser.tabs.query({}).then(tabs => Promise.allSettled(tabs.filter(tab => tab.id != null)
            .map(tab => browser.tabs.sendMessage(tab.id!, { target: 'vault-fill', type: 'settings-changed' })))).catch(() => undefined);
        }
        respond({ ok: true, value });
      },
      error => respond({ ok: false, error: typeof error === 'string' ? error : error.message || '操作失败。' }),
    );
    return true;
  });
  browser.idle.onStateChanged.addListener(state => { if (state === 'locked') { autofill.clear(); void vault.lock(); } });
  browser.tabs.onRemoved.addListener(tabId => autofill.clear(tabId));
  browser.commands.onCommand.addListener(async (command, tab) => {
    if (command === 'fill-login') {
      const active = tab ?? (await browser.tabs.query({ active: true, currentWindow: true }))[0];
      if (active?.id != null) await browser.tabs.sendMessage(active.id, { target: 'vault-fill', type: 'open' }).catch(() => undefined);
    }
  });
  function registerMenu() {
    void browser.contextMenus.removeAll().then(() => browser.contextMenus.create({ id: 'vault-fill', title: '使用 Vault 填充', contexts: ['editable'] })).catch(() => undefined);
  }
  browser.runtime.onInstalled.addListener(registerMenu);
  browser.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'vault-fill' && tab?.id != null) void browser.tabs.sendMessage(tab.id,
      { target: 'vault-fill', type: 'open', reason: 'context-menu' }, { frameId: info.frameId ?? 0 }).catch(() => undefined);
  });
  browser.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === LOCK_ALARM) void vault.handle({ type: 'status' }).then(status => {
      if (!(status as { unlocked: boolean }).unlocked) autofill.clear();
    });
    if (alarm.name === CLIPBOARD_ALARM) void clearExpiredClipboard().catch(() => undefined);
  });
  browser.runtime.onStartup.addListener(() => { registerMenu(); void vault.lock(); });
});

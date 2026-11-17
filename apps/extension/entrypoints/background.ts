import { VaultController, LOCK_ALARM, CLIPBOARD_ALARM } from '../src/vault-controller';
import { isVaultPage } from '../src/sender-policy';
import { offscreen } from '../src/bridge';
import type { VaultMessage } from '../src/vault-messages';
import { AutofillController } from '../src/autofill-controller';
import type { AutofillMessage } from '../src/autofill-messages';

export default defineBackground(() => {
  const vault = new VaultController();
  const autofill = new AutofillController(vault);
  const ready = Promise.all([
    browser.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
    browser.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }),
  ]);
  browser.idle.setDetectionInterval(60);
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
  browser.contextMenus.removeAll().then(() => browser.contextMenus.create({ id: 'vault-fill', title: '使用 Vault 填充', contexts: ['editable'] })).catch(() => undefined);
  browser.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'vault-fill' && tab?.id != null) void browser.tabs.sendMessage(tab.id,
      { target: 'vault-fill', type: 'open', reason: 'context-menu' }, { frameId: info.frameId ?? 0 }).catch(() => undefined);
  });
  browser.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === LOCK_ALARM) void vault.handle({ type: 'status' }).then(status => {
      if (!(status as { unlocked: boolean }).unlocked) autofill.clear();
    });
    if (alarm.name === CLIPBOARD_ALARM) void clearClipboard();
  });
  async function clearClipboard() {
    const { clipboard } = await browser.storage.session.get<{ clipboard: { hash: string; expiresAt: number } }>('clipboard');
    if (!clipboard) return;
    if (clipboard.expiresAt > Date.now()) {
      await browser.alarms.create(CLIPBOARD_ALARM, { when: clipboard.expiresAt });
      return;
    }
    try {
      await offscreen('clear-clipboard', clipboard.hash);
      await browser.storage.session.remove('clipboard');
    } catch { await browser.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + 30000 }); }
  }
  browser.runtime.onStartup.addListener(() => { void vault.lock(); });
  // Alarms can be lost across browser restarts; the timestamp check is authoritative.
  void ready.then(() => vault.handle({ type: 'status' })).catch(() => undefined);
});

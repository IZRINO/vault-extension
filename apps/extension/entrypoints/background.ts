import { VaultController, LOCK_ALARM, CLIPBOARD_ALARM } from '../src/vault-controller';
import { isVaultPage } from '../src/sender-policy';
import { offscreen } from '../src/bridge';
import type { VaultMessage } from '../src/vault-messages';

export default defineBackground(() => {
  const vault = new VaultController();
  const ready = browser.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  browser.idle.setDetectionInterval(60);
  browser.runtime.onMessage.addListener((message, sender, respond) => {
    if (message?.target !== 'vault') return;
    if (!isVaultPage(sender, browser.runtime.id)) {
      respond({ ok: false, error: '消息来源不允许访问密码库。' });
      return;
    }
    void ready.then(() => vault.handle(message as VaultMessage)).then(
      value => respond({ ok: true, value }),
      error => respond({ ok: false, error: typeof error === 'string' ? error : error.message || '操作失败。' }),
    );
    return true;
  });
  browser.idle.onStateChanged.addListener(state => { if (state === 'locked') void vault.lock(); });
  browser.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === LOCK_ALARM) void vault.handle({ type: 'status' });
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

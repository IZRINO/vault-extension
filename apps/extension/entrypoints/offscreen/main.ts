import type { Reply } from '../../src/vault-messages';
import { clipboardDigest } from '../../src/clipboard-digest';

const preparedScanner = location.search === '?scan' ? new Worker(browser.runtime.getURL('/qr-worker.js')) : undefined;
const lockError = '密码库已锁定，请重新解锁。';
let abortAudit: (() => void) | undefined;
let documentLocked = false;

function clipboardWrite(text: string) {
  const field = document.createElement('textarea');
  // An empty selection makes execCommand report success without replacing the clipboard.
  field.value = text || ' ';
  document.body.append(field);
  field.select();
  const onCopy = (event: ClipboardEvent) => {
    event.clipboardData?.setData('text/plain', text);
    event.preventDefault();
  };
  document.addEventListener('copy', onCopy, { once: true });
  try { if (!document.execCommand('copy')) throw new Error('无法写入剪贴板'); }
  finally { document.removeEventListener('copy', onCopy); field.value = ''; field.remove(); }
}
function clipboardRead(): string | null {
  const field = document.createElement('textarea');
  document.body.append(field);
  field.focus();
  let text: string | null | undefined;
  const onPaste = (event: ClipboardEvent) => {
    event.preventDefault();
    // Read the original text/plain. Inserting it into a textarea folds CRLF and CR to LF.
    const data = event.clipboardData;
    if (data) text = data.types.includes('text/plain') ? data.getData('text/plain') : null;
  };
  document.addEventListener('paste', onPaste, { once: true });
  try {
    if (!document.execCommand('paste') || text === undefined) throw new Error('无法读取剪贴板');
    return text;
  } finally { document.removeEventListener('paste', onPaste); field.value = ''; field.remove(); }
}
browser.runtime.onMessage.addListener((message, sender, respond) => {
  const locked = message?.target === 'vault-event' && message.type === 'locked';
  if (message?.target !== 'vault-offscreen' && !locked) return;
  if (sender.id !== browser.runtime.id || sender.tab || (sender.url && sender.url !== browser.runtime.getURL('/background.js'))) return;
  if (locked) {
    // This document is short-lived and jobs are serialized. Even an audit
    // message delivered after the lock must not start until a new document.
    documentLocked = true;
    abortAudit?.();
    return;
  }
  const run = async (): Promise<unknown> => {
    if (message.operation === 'scan-otp' || message.operation === 'scan-migration-qr') {
      const migration = message.operation !== 'scan-otp';
      if (typeof message.payload !== 'string' || !/^data:image\/(?:png|jpeg|webp);base64,/.test(message.payload) || message.payload.length > (migration ? 6 : 48) * 1024 * 1024) throw new Error('图像内容无效。');
      try {
        return await new Promise((resolve, reject) => {
          const worker = preparedScanner ?? new Worker(browser.runtime.getURL('/qr-worker.js'));
          const timer = setTimeout(() => { worker.terminate(); reject(new Error('扫码超时，请缩小窗口后重试。')); }, 20000);
          const finish = () => { clearTimeout(timer); worker.terminate(); };
          worker.onmessage = ({ data }: MessageEvent<Reply>) => { finish(); data.ok ? resolve(data.value) : reject(new Error(data.error)); };
          worker.onerror = () => { finish(); reject(new Error('扫码线程无法启动。')); };
          worker.postMessage(migration ? { url: message.payload, migration: true } : message.payload);
        });
      } finally { message.payload = ''; }
    }
    if (message.operation === 'derive') {
      const { operation } = message.payload;
      const audit = operation === 'audit-snapshot';
      const wipeCopies = audit || operation === 'parse-authenticator-backup';
      if (audit && documentLocked) {
        for (const arg of message.payload.args) if (Array.isArray(arg?.bytes)) arg.bytes.fill(0);
        throw new Error(lockError);
      }
      return new Promise((resolve, reject) => {
        // Keep optional WASM out of the unlock path, including when WXT inlines worker assets.
        const entry = operation === 'parse-browser-csv' ? '/csv-worker.js'
          : operation === 'parse-ente' || operation === 'export-ente' ? '/ente-worker.js'
          : audit ? '/audit-worker.js'
          : ['csv-headers', 'parse-mapped-csv', 'export-login-csv', 'parse-authenticator-backup', 'portable-import', 'portable-export'].includes(operation) ? '/migration-worker.js'
          : ['seal-preferences', 'open-preferences', 'seal-webdav', 'open-webdav', 'sign-authorization', 'verify-authorization'].includes(operation) ? '/preferences-worker.js'
          : operation.startsWith('sync:') ? '/sync-worker.js'
          : operation.startsWith('passkey:') ? '/passkey-worker.js'
          : operation === 'validate-totp' || operation === 'generate-hotp' || operation === 'generate-otp' ? '/otp-worker.js' : '/kdf-worker.js';
        const worker = new Worker(browser.runtime.getURL(entry));
        const timer = setTimeout(() => { finish(); reject(new Error('后台任务超时，请重试。')); }, 120000);
        const finish = () => { clearTimeout(timer); worker.terminate(); if (audit) abortAudit = undefined; };
        if (audit) abortAudit = () => { finish(); reject(new Error(lockError)); };
        worker.onmessage = ({ data }: MessageEvent<Reply>) => {
          finish();
          if (data.ok) resolve(data.value); else reject(new Error(data.error));
        };
        worker.onerror = () => { finish(); reject(new Error('后台线程启动失败，请重试。')); };
        const args = message.payload.args.map((v: unknown) => {
          if (!v || typeof v !== 'object' || !('bytes' in v)) return v;
          const bytes = (v as { bytes: number[] }).bytes;
          const copy = new Uint8Array(bytes);
          if (wipeCopies) bytes.fill(0);
          return copy;
        });
        try { worker.postMessage({ operation, args }); }
        catch (error) { finish(); reject(error); }
        finally { for (const arg of args) if (arg instanceof Uint8Array) arg.fill(0); }
      });
    }
    if (message.operation === 'copy') {
      if (documentLocked) throw new Error(lockError);
      const { text, expiresAt } = message.payload;
      if (typeof text !== 'string' || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new Error('复制请求已过期，请重试。');
      clipboardWrite(text);
      return Date.now();
    }
    if (message.operation === 'clear-clipboard') {
      const current = clipboardRead();
      if (current !== null && await clipboardDigest(current) === message.payload && clipboardRead() === current) clipboardWrite('');
      return null;
    }
    throw new Error('无效的离屏操作');
  };
  void run().then(value => respond({ ok: true, value }), error => respond({ ok: false, error: error.message }));
  return true;
});

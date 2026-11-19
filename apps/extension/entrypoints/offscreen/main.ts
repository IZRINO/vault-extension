import type { Reply } from '../../src/vault-messages';

const preparedScanner = location.search === '?scan' ? new Worker(browser.runtime.getURL('/qr-worker.js')) : undefined;

async function digest(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  try { return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join(''); }
  finally { bytes.fill(0); }
}
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
function clipboardRead(): string {
  const field = document.createElement('textarea');
  document.body.append(field);
  field.focus();
  try {
    if (!document.execCommand('paste')) throw new Error('无法读取剪贴板');
    return field.value;
  } finally { field.value = ''; field.remove(); }
}
browser.runtime.onMessage.addListener((message, sender, respond) => {
  if (message?.target !== 'vault-offscreen') return;
  if (sender.id !== browser.runtime.id || sender.tab || (sender.url && sender.url !== browser.runtime.getURL('/background.js'))) return;
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
      return new Promise((resolve, reject) => {
        // Keep optional WASM out of the unlock path, including when WXT inlines worker assets.
        const operation = message.payload.operation;
        const entry = operation === 'parse-browser-csv' ? '/csv-worker.js'
          : operation === 'parse-ente' || operation === 'export-ente' ? '/ente-worker.js'
          : ['csv-headers', 'parse-mapped-csv', 'export-login-csv', 'parse-authenticator-backup', 'portable-import', 'portable-export'].includes(operation) ? '/migration-worker.js'
          : ['seal-preferences', 'open-preferences', 'seal-webdav', 'open-webdav', 'sign-authorization', 'verify-authorization'].includes(operation) ? '/preferences-worker.js'
          : operation.startsWith('sync:') ? '/sync-worker.js'
          : operation.startsWith('passkey:') ? '/passkey-worker.js'
          : operation === 'validate-totp' || operation === 'generate-hotp' || operation === 'generate-otp' ? '/otp-worker.js' : '/kdf-worker.js';
        const worker = new Worker(browser.runtime.getURL(entry));
        const timer = setTimeout(() => { worker.terminate(); reject(new Error('后台任务超时，请重试。')); }, 120000);
        const finish = () => { clearTimeout(timer); worker.terminate(); };
        worker.onmessage = ({ data }: MessageEvent<Reply>) => {
          finish();
          if (data.ok) resolve(data.value); else reject(new Error(data.error));
        };
        worker.onerror = () => { finish(); reject(new Error('后台线程启动失败，请重试。')); };
        const args = message.payload.args.map((v: unknown) =>
          v && typeof v === 'object' && 'bytes' in v ? new Uint8Array((v as { bytes: number[] }).bytes) : v);
        worker.postMessage({ operation, args });
        for (const arg of args) if (arg instanceof Uint8Array) arg.fill(0);
      });
    }
    if (message.operation === 'copy') {
      const hash = await digest(message.payload);
      clipboardWrite(message.payload);
      return hash;
    }
    if (message.operation === 'clear-clipboard') {
      const current = clipboardRead();
      if (await digest(current) === message.payload && clipboardRead() === current) clipboardWrite('');
      return null;
    }
    throw new Error('无效的离屏操作');
  };
  void run().then(value => respond({ ok: true, value }), error => respond({ ok: false, error: error.message }));
  return true;
});

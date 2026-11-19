import type { QrScan } from './vault-messages';

export const QR_SCAN_PORT = 'vault-qr-scan';
type ScanPort = ReturnType<typeof browser.runtime.connect>;
export type ScanSource = { id: number; windowId: number; url: string };
export type ScanTicket = { scan: QrScan; checkSession(): void };
export type ScanRequest = { type: 'start'; source: ScanSource } | { type: 'select'; index: number };
export type ScanEvent =
  | { type: 'preview'; labels: string[]; timings: QrScan['timings'] }
  | { type: 'selected'; setup: string }
  | { type: 'error'; message: string };

export async function checkScanSource(source: ScanSource, signal: AbortSignal) {
  signal.throwIfAborted();
  const tab = await browser.tabs.get(source.id).catch(() => undefined);
  signal.throwIfAborted();
  if (!tab?.active || tab.windowId !== source.windowId || tab.url !== source.url) {
    throw new Error('网页已改变，请重新扫描。');
  }
}

function labelFor(setup: string, index: number) {
  try { return decodeURIComponent(new URL(setup).pathname.slice(1)).trim() || `验证码 ${index + 1}`; }
  catch { return `验证码 ${index + 1}`; }
}

export function connectQrScan(port: ScanPort, ready: Promise<unknown>,
  scan: (source: ScanSource, signal: AbortSignal) => Promise<ScanTicket>) {
  const controller = new AbortController();
  const signal = controller.signal;
  let source: ScanSource | undefined;
  let ticket: ScanTicket | undefined;
  const release = () => {
    controller.abort();
    ticket = undefined;
    browser.tabs.onActivated.removeListener(activated);
    browser.tabs.onUpdated.removeListener(updated);
    browser.tabs.onRemoved.removeListener(removed);
    browser.windows.onFocusChanged.removeListener(focused);
    port.onMessage.removeListener(receive);
    port.onDisconnect.removeListener(release);
  };
  const cancel = () => {
    if (signal.aborted) return;
    release();
    port.disconnect();
  };
  const activated = ({ tabId, windowId }: { tabId: number; windowId: number }) => {
    if (!source || (windowId === source.windowId && tabId !== source.id)) cancel();
  };
  const updated = (tabId: number, change: { status?: string; url?: string }) => {
    if (source?.id === tabId && (change.status === 'loading' || change.url != null)) cancel();
  };
  const removed = (tabId: number) => { if (source?.id === tabId) cancel(); };
  const focused = (windowId: number) => {
    if (source && windowId !== browser.windows.WINDOW_ID_NONE && windowId !== source.windowId) cancel();
  };
  const send = (event: ScanEvent) => {
    if (!signal.aborted) port.postMessage(event);
  };
  const fail = (error: unknown) => {
    if (signal.aborted) return;
    try { send({ type: 'error', message: error instanceof Error ? error.message : '扫描失败，请重试。' }); }
    catch { /* The UI may have closed before onDisconnect was delivered. */ }
    finally { release(); }
  };
  const receive = (message: ScanRequest | undefined) => {
    if (message?.type === 'start') {
      const chosen = message.source;
      const senderWindow = port.sender?.tab?.windowId;
      if (source || !chosen || !Number.isInteger(chosen.id) || !Number.isInteger(chosen.windowId) ||
        typeof chosen.url !== 'string' || !chosen.url || (senderWindow != null && chosen.windowId !== senderWindow)) {
        fail(new Error('扫码页面已失效，请重试。'));
        return;
      }
      source = chosen;
      void (async () => {
        await ready;
        await checkScanSource(chosen, signal);
        const result = await scan(chosen, signal);
        signal.throwIfAborted();
        ticket = result;
        send({ type: 'preview', labels: result.scan.values.map(labelFor), timings: result.scan.timings });
      })().catch(fail);
      return;
    }
    const current = ticket;
    if (!source || !current || message?.type !== 'select' || !Number.isInteger(message.index)) return;
    const setup = current.scan.values[message.index];
    if (!setup) return;
    ticket = undefined;
    void checkScanSource(source, signal).then(() => {
      current.checkSession();
      send({ type: 'selected', setup });
      release();
    }).catch(fail);
  };
  port.onDisconnect.addListener(release);
  port.onMessage.addListener(receive);
  browser.tabs.onActivated.addListener(activated);
  browser.tabs.onUpdated.addListener(updated);
  browser.tabs.onRemoved.addListener(removed);
  browser.windows.onFocusChanged.addListener(focused);
}

import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { QR_SCAN_PORT, type ScanEvent, type ScanRequest, type ScanSource } from '../qr-scan';
import { useOps } from './Main';

type Stage = { type: 'scanning' } | { type: 'preview' | 'selecting'; labels: string[] };

export default function ScanOtp({ onChange }: { onChange(value: string): void }) {
  const { busy } = useOps();
  const [stage, setStage] = useState<Stage>();
  const [error, setError] = useState('');
  const port = useRef<ReturnType<typeof browser.runtime.connect>>(undefined);
  const stopWatching = useRef<() => void>(undefined);
  const scanButton = useRef<HTMLButtonElement>(null);
  const choices = useRef<HTMLFieldSetElement>(null);

  function disconnect() {
    stopWatching.current?.();
    stopWatching.current = undefined;
    const current = port.current;
    port.current = undefined;
    current?.disconnect();
  }
  function stop() {
    disconnect();
    setStage(undefined);
  }
  useEffect(() => disconnect, []);
  useLayoutEffect(() => {
    if (stage?.type !== 'preview') return;
    performance.mark('vault:qr-dom');
    if (document.activeElement === scanButton.current) choices.current?.querySelector('button')?.focus();
    let presented: number | undefined;
    const next = requestAnimationFrame(() => {
      presented = requestAnimationFrame(() => performance.mark('vault:qr-presented'));
    });
    return () => {
      cancelAnimationFrame(next);
      if (presented != null) cancelAnimationFrame(presented);
    };
  }, [stage]);

  function begin() {
    stop();
    setError('');
    for (const mark of ['vault:qr-start', 'vault:qr-preview', 'vault:qr-dom', 'vault:qr-presented']) performance.clearMarks(mark);
    performance.mark('vault:qr-start');
    const current = browser.runtime.connect({ name: QR_SCAN_PORT });
    port.current = current;
    setStage({ type: 'scanning' });
    let source: ScanSource | undefined;
    const changed = new Set<number>();
    const activated = ({ tabId, windowId }: { tabId: number; windowId: number }) => {
      if (!source || (source.windowId === windowId && source.id !== tabId)) stop();
    };
    const updated = (tabId: number, change: { url?: string; status?: string }) => {
      if (change.url == null && change.status !== 'loading') return;
      if (!source) changed.add(tabId);
      else if (source.id === tabId) stop();
    };
    const focused = (windowId: number) => {
      if (windowId !== browser.windows.WINDOW_ID_NONE && (!source || windowId !== source.windowId)) stop();
    };
    stopWatching.current = () => {
      browser.tabs.onActivated.removeListener(activated);
      browser.tabs.onUpdated.removeListener(updated);
      browser.windows.onFocusChanged.removeListener(focused);
    };
    browser.tabs.onActivated.addListener(activated);
    browser.tabs.onUpdated.addListener(updated);
    browser.windows.onFocusChanged.addListener(focused);
    current.onDisconnect.addListener(() => {
      if (port.current !== current) return;
      stopWatching.current?.();
      stopWatching.current = undefined;
      port.current = undefined;
      setStage(undefined);
    });
    current.onMessage.addListener((answer: ScanEvent) => {
      if (port.current !== current) return;
      if (answer.type === 'preview') {
        stopWatching.current?.();
        stopWatching.current = undefined;
        performance.mark('vault:qr-preview', { detail: answer.timings });
        setStage({ type: 'preview', labels: answer.labels });
      } else {
        stop();
        if (answer.type === 'error') setError(answer.message);
        else onChange(answer.setup);
      }
    });
    void browser.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
      if (port.current !== current) return;
      if (tab?.id == null) throw new Error('请先打开显示二维码的网站。');
      if (!tab.url) throw new Error('截图尚未授权。请先点击浏览器工具栏的 Vault 图标，再扫描当前网站的二维码。');
      if (changed.has(tab.id)) throw new Error('网页已改变，请重新扫描。');
      source = { id: tab.id, windowId: tab.windowId, url: tab.url };
      current.postMessage({ type: 'start', source } satisfies ScanRequest);
    }).catch(error => {
      if (port.current !== current) return;
      stop();
      setError(error instanceof Error ? error.message : '扫描失败，请重试。');
    });
  }

  function choose(index: number) {
    if (stage?.type !== 'preview' || !port.current || busy) return;
    setStage({ ...stage, type: 'selecting' });
    port.current.postMessage({ type: 'select', index } satisfies ScanRequest);
  }

  return <div className="form">
    <button ref={scanButton} type="button" className="btn" disabled={stage?.type !== 'scanning' && busy}
      onClick={stage?.type === 'scanning' ? stop : begin}>
      {stage?.type === 'scanning' ? '取消扫描' : '扫描当前网页二维码'}
    </button>
    {error && <p className="hint" role="alert">{error}</p>}
    {stage && stage.type !== 'scanning' && <fieldset ref={choices} className="form" aria-busy={stage.type === 'selecting'}>
      <legend>选择要添加的验证码</legend>
      {stage.labels.map((label, index) =>
        <button key={index} type="button" className="btn" disabled={busy || stage.type === 'selecting'} onClick={() => choose(index)}>
          <span style={{ overflowWrap: 'anywhere', minWidth: 0 }}>{label}</span>
        </button>)}
      <button type="button" className="btn btn-quiet" onClick={stop}>取消选择</button>
    </fieldset>}
    <p className="hint">先在二维码所在网页点击工具栏的 Vault 图标，再扫描。截图只在本机内存处理，选择后仍需保存凭证。</p>
  </div>;
}

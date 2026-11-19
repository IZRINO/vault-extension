import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { request, type ItemSummary, type VaultOpening, type VaultStatus } from '../vault-messages';
import { ErrorBanner } from './components';
import { errorText } from './lib';
import Main from './Main';
import type { EmergencyKit } from './Welcome';
const Welcome = lazy(() => import('./Welcome'));
const KitScreen = lazy(async () => ({ default: (await import('./Welcome')).KitScreen }));
const SyncConflicts = lazy(async () => ({ default: (await import('./SyncConflicts')).SyncConflicts }));

export default function App({ readOpening }: { readOpening?: () => Promise<VaultOpening | undefined> }) {
  const [status, setStatus] = useState<VaultStatus>();
  const [initialItems, setInitialItems] = useState<ItemSummary[]>();
  const [error, setError] = useState('');
  const [kit, setKit] = useState<EmergencyKit>();
  const [shutter, setShutter] = useState(0);
  const [showConflicts, setShowConflicts] = useState(() => !readOpening && new URLSearchParams(location.search).get('view') === 'conflicts');
  const wasUnlocked = useRef<boolean | undefined>(undefined);
  const lockVersion = useRef(0);
  const refresh = useCallback(async () => {
    const version = lockVersion.current;
    const current = await request<VaultStatus>({ type: 'status' });
    if (version !== lockVersion.current) return;
    if (!current.unlocked) setInitialItems(undefined);
    setStatus(current);
  }, []);

  useLayoutEffect(() => {
    let mounted = true;
    const onMessage = (message: { target?: string; type?: string }) => {
      if (message?.target === 'vault-event' && message.type === 'locked') {
        lockVersion.current++;
        setInitialItems(undefined);
        setStatus(old => old ? { ...old, unlocked: false } : old);
        void refresh().catch(() => undefined);
      }
    };
    browser.runtime.onMessage.addListener(onMessage);
    const version = lockVersion.current;
    const current = () => mounted && version === lockVersion.current;
    void (async () => {
      const opened = await readOpening?.() ?? await request<VaultOpening>({ type: 'open' });
      if (current()) {
        setInitialItems(opened.items);
        setStatus(opened.status);
      }
    })().catch(e => { if (current()) setError(errorText(e)); });
    return () => {
      mounted = false;
      browser.runtime.onMessage.removeListener(onMessage);
    };
  }, [readOpening, refresh]);
  const unlocked = status?.unlocked;
  useEffect(() => {
    if (!unlocked) return;
    const timer = setInterval(() => void refresh().catch(() => undefined), 5000);
    return () => clearInterval(timer);
  }, [unlocked, refresh]);

  // 柜门只在“这个页面里刚刚解锁”时收起一次；平常打开已解锁的密码库没有动画。
  const showMain = !!unlocked && !kit;
  useLayoutEffect(() => {
    if (!status) return;
    if (wasUnlocked.current === false && showMain) setShutter(count => count + 1);
    wasUnlocked.current = showMain;
  }, [status, showMain]);
  useEffect(() => {
    if (!shutter) return;
    const timer = setTimeout(() => setShutter(0), 700);
    return () => clearTimeout(timer);
  }, [shutter]);

  return <div className="app">
    {!status ? <div className="door">
      <div className="band-top"><span className="wordmark">Vault</span></div>
      <div className="door-head">
        <h1>{error ? '没能打开密码库' : '正在读取密码库…'}</h1>
        {error && <p>扩展的后台没有回应。可以重试一次；如果还不行，请在浏览器的扩展管理页面里重新加载 Vault。</p>}
      </div>
      {error && <div className="door-panel">
        <ErrorBanner text={error} />
        <button type="button" className="btn btn-primary btn-wide" onClick={() => { setError(''); void refresh().catch(e => setError(errorText(e))); }}>重试</button>
      </div>}
    </div>
      : status.unlocked && !kit ? showConflicts ?
        <main className="sync-review-page">
          <Suspense fallback={<p role="status">正在读取同步冲突…</p>}>
            <SyncConflicts close={() => {
              history.replaceState(null, '', location.pathname);
              setInitialItems(undefined);
              setShowConflicts(false);
            }} changed={refresh} />
          </Suspense>
        </main> : <Main status={status} refresh={refresh} initialItems={initialItems} />
        : <Suspense fallback={<div className="door" role="status">正在打开密码库…</div>}>
          {kit ? <KitScreen kit={kit} onDone={() => { setKit(undefined); void refresh().catch(e => setError(errorText(e))); }} />
            : <Welcome key={String(status.configured)} status={status} refresh={refresh} onCreated={setKit} />}
        </Suspense>}
    {shutter > 0 && <div key={shutter} className="shutter" aria-hidden="true" />}
  </div>;
}

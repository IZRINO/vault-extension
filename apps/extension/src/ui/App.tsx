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
  const [setup, setSetup] = useState<{ kit?: EmergencyKit; restoreBackup?: boolean }>();
  const [startBackupImport, setStartBackupImport] = useState(false);
  const [shutter, setShutter] = useState(0);
  const [showConflicts, setShowConflicts] = useState(() => !readOpening && new URLSearchParams(location.search).get('view') === 'conflicts');
  const wasUnlocked = useRef<boolean | undefined>(undefined);
  const statusVersion = useRef(0);
  const refresh = useCallback(async (onCurrent?: (status: VaultStatus) => void) => {
    const version = statusVersion.current;
    const current = await request<VaultStatus>({ type: 'status' });
    if (version !== statusVersion.current) return;
    if (!current.unlocked) {
      setInitialItems(undefined);
      setStartBackupImport(false);
      setSetup(undefined);
    }
    setStatus(current);
    onCurrent?.(current);
  }, []);

  useLayoutEffect(() => {
    let mounted = true;
    const onMessage = (message: { target?: string; type?: string }) => {
      if (message?.target === 'vault-event' && message.type === 'locked') {
        statusVersion.current++;
        setInitialItems(undefined);
        setStartBackupImport(false);
        setSetup(undefined);
        setStatus(old => old ? { ...old, unlocked: false } : old);
        void refresh().catch(() => undefined);
      }
    };
    browser.runtime.onMessage.addListener(onMessage);
    const version = statusVersion.current;
    const current = () => mounted && version === statusVersion.current;
    if (readOpening) performance.mark('vault:popup-opening-listener');
    void (async () => {
      const opened = await readOpening?.() ?? await request<VaultOpening>({ type: 'open' });
      if (current()) {
        if (readOpening) performance.mark('vault:popup-opening-apply');
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
  const configured = status?.configured;
  useEffect(() => {
    if (readOpening || configured !== false || new URLSearchParams(location.search).get('view') !== 'setup') return;
    const onFocus = () => void refresh().catch(() => undefined);
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [readOpening, configured, refresh]);
  useEffect(() => {
    if (!unlocked) return;
    const timer = setInterval(() => void refresh().catch(() => undefined), 5000);
    return () => clearInterval(timer);
  }, [unlocked, refresh]);

  // 柜门只在“这个页面里刚刚解锁”时收起一次；平常打开已解锁的密码库没有动画。
  const showMain = !!unlocked && !setup;
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

  const version = statusVersion.current;
  function finishSetup(restoreBackup?: boolean) {
    setSetup({ restoreBackup });
    setError('');
    void refresh(current => {
      setStartBackupImport(current.unlocked && !!restoreBackup);
      setSetup(undefined);
    }).catch(e => { if (version === statusVersion.current) setError(errorText(e)); });
  }
  const finishingSetup = setup !== undefined && !setup.kit;
  return <div className="app">
    {!status || finishingSetup ? <div className="door">
      <div className="band-top"><span className="wordmark">Vault</span></div>
      <div className="door-head" role={error ? undefined : 'status'}>
        <h1>{error ? '没能打开密码库' : '正在读取密码库…'}</h1>
        {error && <p>扩展的后台没有回应。可以重试一次；如果还不行，请在浏览器的扩展管理页面里重新加载 Vault。</p>}
      </div>
      {error && <div className="door-panel">
        <ErrorBanner text={error} />
        <button type="button" className="btn btn-primary btn-wide" onClick={() => {
          if (finishingSetup) finishSetup(setup.restoreBackup);
          else { setError(''); void refresh().catch(e => setError(errorText(e))); }
        }}>重试</button>
      </div>}
    </div>
      : status.unlocked && !setup ? showConflicts ?
        <main className="sync-review-page">
          <Suspense fallback={<p role="status">正在读取同步冲突…</p>}>
            <SyncConflicts close={() => {
              history.replaceState(null, '', location.pathname);
              setInitialItems(undefined);
              setShowConflicts(false);
            }} changed={refresh} />
          </Suspense>
        </main> : <Main status={status} refresh={refresh} initialItems={initialItems} startBackupImport={startBackupImport} />
        : <Suspense fallback={<div className="door" role="status">正在打开密码库…</div>}>
          {setup?.kit && unlocked ? <KitScreen kit={setup.kit} restoreBackup={setup.restoreBackup} onDone={() => finishSetup(setup.restoreBackup)} />
            : <Welcome key={String(status.configured)} status={status} refresh={refresh} onCreated={(kit, restoreBackup) => {
              if (version !== statusVersion.current) return;
              statusVersion.current++;
              setStatus(old => old && { ...old, configured: true, unlocked: true });
              setSetup({ kit, restoreBackup });
            }} />}
        </Suspense>}
    {shutter > 0 && <div key={shutter} className="shutter" aria-hidden="true" />}
  </div>;
}

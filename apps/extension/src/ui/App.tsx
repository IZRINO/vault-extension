import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { request, type VaultStatus } from '../vault-messages';
import { ErrorBanner } from './components';
import { errorText } from './lib';
import Main from './Main';
import Welcome, { KitScreen, type EmergencyKit } from './Welcome';

export default function App() {
  const [status, setStatus] = useState<VaultStatus>();
  const [error, setError] = useState('');
  const [kit, setKit] = useState<EmergencyKit>();
  const [shutter, setShutter] = useState(0);
  const wasUnlocked = useRef<boolean | undefined>(undefined);
  const refresh = useCallback(async () => setStatus(await request<VaultStatus>({ type: 'status' })), []);

  useEffect(() => {
    void refresh().catch(e => setError(errorText(e)));
    const onMessage = (message: { target?: string; type?: string }) => {
      if (message?.target === 'vault-event' && message.type === 'locked') {
        setStatus(old => old ? { ...old, unlocked: false } : old);
        void refresh().catch(() => undefined);
      }
    };
    browser.runtime.onMessage.addListener(onMessage);
    return () => { browser.runtime.onMessage.removeListener(onMessage); };
  }, [refresh]);
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
      : kit ? <KitScreen kit={kit} onDone={() => { setKit(undefined); void refresh().catch(e => setError(errorText(e))); }} />
        : status.unlocked ? <Main status={status} refresh={refresh} />
          : <Welcome key={String(status.configured)} status={status} refresh={refresh} onCreated={setKit} />}
    {shutter > 0 && <div key={shutter} className="shutter" aria-hidden="true" />}
  </div>;
}

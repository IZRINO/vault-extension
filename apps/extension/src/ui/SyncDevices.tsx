import { useEffect, useState } from 'react';
import { ArrowLeft, Laptop, Plus, Trash2 } from 'lucide-react';
import { request, type SyncDevice, type SyncDevices as DeviceList } from '../vault-messages';
import { ErrorBanner, Ico, SecretField, TextField } from './components';
import { errorText } from './lib';

type Operation = { action: 'register' | 'claim' | 'rename' | 'remove'; device?: SyncDevice };
const verbs: Record<Operation['action'], string> = { register: '登记新设备', claim: '认领这台设备', rename: '修改设备名称', remove: '移除设备记录' };

export function SyncDevices({ close }: { close(): void }) {
  const [devices, setDevices] = useState<DeviceList>();
  const [operation, setOperation] = useState<Operation>();
  const [name, setName] = useState('');
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let mounted = true;
    void request<DeviceList>({ type: 'webdav-devices' }).then(value => { if (mounted) setDevices(value); },
      error => { if (mounted) setError(errorText(error)); });
    return () => { mounted = false; };
  }, []);
  function choose(next?: Operation) {
    setOperation(next); setName(next?.device?.name ?? (next?.action === 'register' ? devices?.suggestedName ?? '' : '')); setSecret(''); setError('');
  }
  async function submit() {
    if (!operation || busy) return;
    setBusy(true); setError('');
    try {
      setDevices(await request<DeviceList>({ type: 'webdav-device-change', action: operation.action, id: operation.device?.id,
        name, proof: { method: 'master', secret } }));
      choose();
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); setSecret(''); }
  }
  return <div className="form sync-conflicts">
    <div className="actions">
      <button className="btn" type="button" disabled={busy} onClick={() => operation ? choose() : close()}><Ico of={ArrowLeft} />返回</button>
      <h3><Ico of={Laptop} />同步设备</h3>
    </div>
    {error && <ErrorBanner text={error} />}
    {!operation && devices && <>
      {!devices.registered && <button className="btn btn-primary" type="button" onClick={() => choose({ action: 'register' })}>
        <Ico of={Plus} />登记本机</button>}
      {devices.rows.map(device => <details className="fold" key={device.id}>
        <summary>{device.name || '未命名设备'}{device.id === devices.active ? ' · 本机' : ''}</summary>
        <div className="fold-body form">
          <p>{device.system} · {device.browser} · {device.version}</p>
          <time>最近同步：{new Date(device.lastSeen).toLocaleString()}</time>
          {device.lastEditCount != null && <p className="hint">最近变更的凭证：{device.lastEditCount} 条</p>}
          {!devices.registered && (device.system === devices.system || device.browser === devices.browser || device.browser.startsWith(`${devices.browser} `)) &&
            <p className="hint">与本机的系统或浏览器相同</p>}
          <div className="actions">
            {!devices.registered && <button className="btn" type="button" onClick={() => choose({ action: 'claim', device })}>认领</button>}
            <button className="btn" type="button" onClick={() => choose({ action: 'rename', device })}>改名</button>
            {device.id !== devices.active && <button className="btn" type="button" onClick={() => choose({ action: 'remove', device })}><Ico of={Trash2} />移除</button>}
          </div>
        </div>
      </details>)}
    </>}
    {operation && <form className="form" onSubmit={event => { event.preventDefault(); void submit(); }}>
      {operation.action === 'remove'
        ? <p>移除「{operation.device?.name}」的记录。不删除凭证，也不会撤销该设备已持有的密钥。</p>
        : <TextField label="设备名称" required value={name} onChange={setName} maxLength={80} disabled={busy} />}
      <SecretField label="主密码" value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="current-password" />
      <button className="btn btn-primary" disabled={busy}>{verbs[operation.action]}</button>
    </form>}
  </div>;
}

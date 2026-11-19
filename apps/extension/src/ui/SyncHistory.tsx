import { useEffect, useState } from 'react';
import { ArrowLeft, History, RotateCcw } from 'lucide-react';
import { request, type SyncHistoryEntry, type SyncRestorePreview } from '../vault-messages';
import { ErrorBanner, Ico, SecretField } from './components';
import { errorText } from './lib';

export function SyncHistory({ close, changed }: { close(): void; changed(): Promise<void> }) {
  const [versions, setVersions] = useState<SyncHistoryEntry[]>();
  const [preview, setPreview] = useState<SyncRestorePreview>();
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    void request<SyncHistoryEntry[]>({ type: 'webdav-history' })
      .then(result => { if (active) setVersions(result); }, error => { if (active) setError(errorText(error)); });
    return () => { active = false; };
  }, []);

  async function select(id: string) {
    setBusy(true); setPreview(undefined); setError(''); setSecret('');
    try { setPreview(await request<SyncRestorePreview>({ type: 'webdav-history-preview', id })); }
    catch (error) { setError(errorText(error)); }
    finally { setBusy(false); }
  }
  async function restore() {
    if (!preview || (preview.blocked && !preview.readOnly) || busy) return;
    setBusy(true); setError('');
    try {
      await request({ type: 'webdav-history-restore', id: preview.id, stamp: preview.stamp,
        destination: preview.readOnly ? 'local' : 'remote', proof: { method: 'master', secret } });
      await changed();
      close();
    } catch (error) { setError(errorText(error)); }
    finally { setBusy(false); setSecret(''); }
  }
  return <div className="form sync-conflicts">
    <div className="actions">
      <button className="btn" type="button" onClick={close} disabled={busy}><Ico of={ArrowLeft} />返回</button>
      <h3><Ico of={History} />网盘历史</h3>
    </div>
    {error && <ErrorBanner text={error} />}
    {!versions && !error && <p role="status">正在读取版本…</p>}
    {versions?.map(version => <button key={version.id} className="btn" type="button" disabled={busy}
      aria-pressed={preview?.id === version.id} onClick={() => void select(version.id)}>
      <time>{new Date(version.time).toLocaleString()}</time> · {version.count} 条{version.current ? ' · 当前快照' : ''}
    </button>)}
    {preview && <form className="form" onSubmit={event => { event.preventDefault(); void restore(); }}>
      <p role="status">恢复后剩余 {preview.after} 条有效凭证，移除 {preview.removed} 条。当前有 {preview.before} 条。</p>
      {preview.blocked && <p className="banner banner-warn">恢复结果为空库，不能发布到网盘。</p>}
      {preview.readOnly && <p className="banner banner-warn">只恢复本机，不更改网盘。连接保持只读。</p>}
      {preview.bulk && <p className="banner banner-warn">这会删除一批有效凭证。请确认选择的是正确的版本。</p>}
      {(!preview.blocked || preview.readOnly) && <>
        <SecretField label="主密码" value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="current-password" />
        <button className="btn btn-primary" disabled={busy}><Ico of={RotateCcw} />{preview.readOnly ? '恢复到本机' : '发布为新版本'}</button>
      </>}
    </form>}
  </div>;
}

import { useEffect, useState } from 'react';
import { RotateCw } from 'lucide-react';
import type { DavConnectionStatus } from '../sync/connection';
import { deviceProfile } from '../sync/device-profile';
import type { SyncResult } from '../sync/run';
import type { DavProbe, WebDavInput } from '../sync/webdav';
import { request, type DavJoinPreview } from '../vault-messages';
import { AreaField, ErrorBanner, Ico, SecretField, SelectField, SwitchRow, TextField } from './components';
import { errorText } from './lib';
import type { EmergencyKit } from './Welcome';
import { openConflictReview } from './shell';
import { SyncHistory } from './SyncHistory';
import { SyncDevices } from './SyncDevices';

const probeText: Record<DavProbe['kind'], string> = {
  empty: '已连接，目标目录为空。只读测试未创建任何文件。',
  existing: '找到已有密码库。连接测试没有下载或更改凭证。',
  incomplete: '目录非空，但没有找到完整的密码库。请核对目录或检查远端文件。',
  missing: '目标目录还不存在。只有完成写入验证并确认建库后，才会创建。',
};
const syncText: Record<SyncResult['kind'], string> = {
  synced: '同步完成。',
  unchanged: '没有新变更。',
  'read-only': '网盘当前只读，未上传本机变更。',
  deferred: '仍有本机草稿未上传。',
  unlinked: '尚未连接密码库。',
  locked: '先解锁密码库。',
  paused: '网盘连接已暂停。',
  empty: '本机有效凭证为零，已拦截上传。本机和网盘数据保持原状。',
  conflicts: '无争议的变更已合入，部分凭证等待裁决。',
  'key-update': '另一台设备已修改主密码，请在解锁页验证新密码。',
  'confirm-deletion': '有一批删除尚未发送到网盘。',
};

export default function WebDav({ onboarding = false, stayLocal, onCreated, refresh }: {
  onboarding?: boolean; stayLocal?(): void; onCreated?(kit: EmergencyKit): void; refresh?(): Promise<void>;
}) {
  const [provider, setProvider] = useState<WebDavInput['provider']>('nutstore');
  const [base, setBase] = useState('');
  const [folder, setFolder] = useState('my-vault');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmHttp, setConfirmHttp] = useState(false);
  const [status, setStatus] = useState<DavConnectionStatus>();
  const [result, setResult] = useState<DavProbe>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [method, setMethod] = useState<'master' | 'recovery'>('master');
  const [secret, setSecret] = useState('');
  const [confirm, setConfirm] = useState('');
  const [scratchFolder, setScratchFolder] = useState('');
  const [deviceName, setDeviceName] = useState<string>();
  const [fromSaved, setFromSaved] = useState(false);
  const [syncResult, setSyncResult] = useState<SyncResult>();
  const [verifyWrites, setVerifyWrites] = useState(false);
  const [readingHistory, setReadingHistory] = useState(false);
  const [editingDevices, setEditingDevices] = useState(false);
  const [localMaster, setLocalMaster] = useState('');
  const [joinReview, setJoinReview] = useState<DavJoinPreview>();
  const input: WebDavInput = { provider, base, folder, username, password, confirmHttp };
  useEffect(() => {
    let live = true;
    void request<DavConnectionStatus>({ type: 'webdav-status' }).then(value => {
      if (live) setStatus(value);
    }).catch(e => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, []);
  useEffect(() => {
    if (result?.kind !== 'empty' && result?.kind !== 'missing') return;
    let live = true;
    void deviceProfile().then(({ suggestedName }) => { if (live) setDeviceName(value => value ?? suggestedName); }).catch(() => undefined);
    return () => { live = false; };
  }, [result?.kind]);
  function clearResult() { setResult(undefined); setJoinReview(undefined); setLocalMaster(''); setError(''); setSecret(''); setConfirm(''); }
  async function run(action: () => Promise<void>) {
    setBusy(true); setError('');
    try { await action(); }
    catch (e) {
      setError(errorText(e));
      await request<DavConnectionStatus>({ type: 'webdav-status' }).then(setStatus).catch(() => undefined);
    } finally { setBusy(false); }
  }
  const test = (fresh: boolean) => run(async () => {
    clearResult();
    const value = await request<DavProbe>({ type: 'webdav-test', input: fresh ? input : undefined, remember: fresh && !onboarding });
    setResult(value);
    setFromSaved(!onboarding);
    if (!onboarding && fresh && value.kind !== 'incomplete' && value.kind !== 'existing') setPassword('');
    setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
  });
  const restore = () => run(async () => {
    try {
      if (onboarding) await request({ type: 'webdav-join', input, method, secret });
      else {
        const next = await request<DavJoinPreview>({ type: 'webdav-merge', input, method, secret,
          proof: { method: 'master', secret: localMaster }, stamp: joinReview?.stamp });
        if (!joinReview) { setJoinReview(next); return; }
      }
      setPassword(''); clearResult();
      await refresh?.();
      setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
    } catch (error) {
      if (error instanceof Error && error.message.includes('重新预览')) setJoinReview(undefined);
      throw error;
    } finally { setSecret(''); setLocalMaster(''); }
  });
  const create = () => run(async () => {
    if (onboarding && secret !== confirm) throw new Error('两次主密码输入不一致。');
    const kit = await request<EmergencyKit | undefined>({ type: 'webdav-create', input: fromSaved ? undefined : input,
      scratchFolder, masterPassword: secret, deviceName });
    setSecret(''); setPassword(''); setConfirm(''); setResult(undefined);
    if (kit) onCreated?.(kit);
    else await refresh?.();
    setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
  });
  const sync = (confirmed: boolean) => run(async () => {
    const stamp = syncResult?.kind === 'confirm-deletion' ? syncResult.stamp : undefined;
    try {
      const value = await request<SyncResult>({ type: 'webdav-sync',
        confirmation: confirmed && stamp ? { stamp, proof: { method: 'master', secret } } : undefined });
      setSyncResult(value);
      await refresh?.();
      setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
    } finally { setSecret(''); }
  });
  const enable = () => run(async () => {
    try {
      await request({ type: 'webdav-enable-write', scratchFolder, masterPassword: secret });
      setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
      setVerifyWrites(false); setSyncResult(undefined);
    } finally { setSecret(''); }
  });
  const offset = result?.offsetSeconds ?? status?.offsetSeconds;
  if (readingHistory) return <SyncHistory close={() => setReadingHistory(false)} changed={async () => {
    await refresh?.();
    setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
    setSyncResult(undefined);
  }} />;
  if (editingDevices) return <SyncDevices close={() => setEditingDevices(false)} />;
  return <div className="form">
    {status?.paused && <p className="banner banner-warn" role="status">网盘连接已暂停（HTTP {status.paused}）。修正设置并手动测试成功后恢复。</p>}
    {status?.localRestoreHeld && <p className="banner banner-warn" role="status">历史恢复仅保存在本机。启用网盘写入后，本机变更将参与同步。</p>}
    {!!status?.drafts && <p className="banner banner-warn" role="status">有 {status.drafts} 份草稿仍保存在本机，尚未上传。</p>}
    {status?.saved && <div className="actions"><button type="button" className="btn" disabled={busy} onClick={() => void test(false)}>
      <Ico of={RotateCw} />重测已保存的连接</button></div>}
    {status?.linked && <div className="actions">
      <button type="button" className="btn btn-primary" disabled={busy || status.paused != null} onClick={() => void sync(false)}><Ico of={RotateCw} />立即同步</button>
      <button type="button" className="btn" disabled={busy || status.paused != null} onClick={() => { setSecret(''); setVerifyWrites(!verifyWrites); setSyncResult(undefined); }}>验证写入能力</button>
      <button type="button" className="btn" disabled={busy || status.paused != null} onClick={() => setReadingHistory(true)}>查看历史版本</button>
      <button type="button" className="btn" disabled={busy} onClick={() => setEditingDevices(true)}>管理设备</button>
    </div>}
    {!!status?.conflicts && <button className="btn" type="button" disabled={busy} onClick={() => void openConflictReview().catch(e => setError(errorText(e)))}>
      处理 {status.conflicts} 项同步冲突</button>}
    {status?.linked && verifyWrites && <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void enable(); }}>
      <TextField label="独立空测试目录名" value={scratchFolder} onChange={setScratchFolder} required maxLength={100} disabled={busy} />
      <SecretField label="当前主密码" value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="current-password" />
      <button className="btn btn-primary" disabled={busy}>验证并启用网盘写入</button>
    </form>}
    {syncResult && <p className={syncResult.kind === 'synced' || syncResult.kind === 'unchanged' ? 'banner banner-ok' : 'banner banner-warn'}
      role="status">{syncText[syncResult.kind]}</p>}
    {syncResult?.kind === 'confirm-deletion' && <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void sync(true); }}>
      <p className="hint">移除 {syncResult.removed} 条有效凭证（{syncResult.before} → {syncResult.after} 条）。</p>
      <SecretField label="主密码" value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="current-password" />
      <div className="actions"><button className="btn btn-primary" disabled={busy}>确认同步这批删除</button>
        <button type="button" className="btn" disabled={busy} onClick={() => { setSyncResult(undefined); setSecret(''); }}>取消</button></div>
    </form>}
    <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void test(true); }}>
      <SelectField label="服务商" value={provider} disabled={busy} onChange={value => { setProvider(value as WebDavInput['provider']); setConfirmHttp(false); clearResult(); }}>
        <option value="nutstore">坚果云</option><option value="koofr">Koofr</option><option value="custom">自定义 WebDAV</option>
      </SelectField>
      {provider === 'custom' && <TextField label="WebDAV 根地址" type="url" required value={base} maxLength={2048} disabled={busy} placeholder="https://nas.example.com/dav/"
        onChange={value => { setBase(value); setConfirmHttp(false); clearResult(); }} />}
      <TextField label="同步目录名" value={folder} maxLength={100} required disabled={busy} onChange={value => { setFolder(value); clearResult(); }} />
      <TextField label="网盘账号" value={username} maxLength={320} required disabled={busy} onChange={value => { setUsername(value); clearResult(); }} autoComplete="off" />
      <SecretField label="应用专用密码" value={password} maxLength={1024} required disabled={busy} onChange={value => { setPassword(value); clearResult(); }} autoComplete="off" />
      {provider === 'custom' && /^http:/i.test(base) && <label className="check">
        <input type="checkbox" checked={confirmHttp} disabled={busy} onChange={event => { setConfirmHttp(event.target.checked); clearResult(); }} />
        <span>允许本机 HTTP 调试：网盘账号和密码将以未加密的方式发出。仅使用测试凭据。</span>
      </label>}
      <button className="btn btn-primary" disabled={busy}>{busy ? '正在连接…' : onboarding ? '测试连接' : '测试并保存连接'}</button>
    </form>
    {error && <ErrorBanner text={error} />}
    {result && <p role="status" className={result.kind === 'incomplete' ? 'banner banner-warn' : 'banner banner-ok'}>{probeText[result.kind]}</p>}
    {(onboarding || (status && !status.linked && !!password)) && result?.kind === 'existing' &&
      <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void restore(); }}>
      {joinReview && <section className="section" aria-label="合并预览">
        <p className="hint">本机 {joinReview.sourceCount} 条，网盘 {joinReview.targetCount} 条。合并后 {joinReview.mergedCount} 条，{joinReview.conflicts} 项待裁决。</p>
        <p className="banner banner-warn">请先保存源库的最新加密备份。确认后将切换到目标库，源库密文留存，PIN 和 Hello 需重新设置。网盘不会收到写入。</p>
      </section>}
      <SelectField label="验证已有网盘库" value={method} disabled={busy} onChange={value => { setSecret(''); setMethod(value as typeof method); }}>
        <option value="master">已有主密码</option><option value="recovery">应急恢复码</option>
      </SelectField>
      {method === 'recovery'
        ? <AreaField label="应急恢复码" rows={3} mono value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="off" spellCheck={false} />
        : <SecretField label="网盘库主密码" value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="current-password" />}
      {!onboarding && <SecretField label="本机源库主密码" value={localMaster} onChange={setLocalMaster} required maxLength={1024}
        disabled={busy} autoComplete="current-password" />}
      <div className="actions">
        <button className="btn btn-primary" disabled={busy}>{busy ? '正在验证…' : onboarding ? '恢复到本机' : joinReview ? '确认合并到目标库' : '验证并预览合并'}</button>
        {joinReview && <button type="button" className="btn" disabled={busy} onClick={() => { setJoinReview(undefined); setSecret(''); setLocalMaster(''); }}>取消合并</button>}
      </div>
    </form>}
    {!status?.linked && (result?.kind === 'empty' || result?.kind === 'missing') && <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void create(); }}>
      <TextField label="本机名称" value={deviceName ?? ''} onChange={setDeviceName} maxLength={80} disabled={busy} />
      <TextField label="独立空测试目录名" value={scratchFolder} onChange={setScratchFolder} required maxLength={100} disabled={busy}
        hint="与同步目录同级，必须已存在且为空。只在此目录读写随机测试文件。" />
      <SecretField label={onboarding ? '新主密码' : '当前主密码'} value={secret} onChange={setSecret} required
        minLength={onboarding ? 12 : undefined} maxLength={1024} disabled={busy} autoComplete={onboarding ? 'new-password' : 'current-password'} />
      {onboarding && <SecretField label="再次输入主密码" value={confirm} onChange={setConfirm} required disabled={busy}
        minLength={12} maxLength={1024} autoComplete="new-password" />}
      <button className="btn btn-primary" disabled={busy}>{busy ? '正在验证并建库…' : '验证写入并在网盘建库'}</button>
    </form>}
    {offset != null && <p className="hint">网盘时间与本机相差 {Math.abs(offset)} 秒，本机时钟{offset > 0 ? '偏慢' : '偏快'}。</p>}
    {status?.saved && <SwitchRow label="补偿时间验证码偏差" checked={status.compensation} disabled={busy || (!status.compensation && (status.paused != null || status.offsetSeconds == null))}
      onChange={enabled => void run(async () => setStatus({ ...await request<DavConnectionStatus>({ type: 'webdav-clock', enabled }),
        linked: status.linked, conflicts: status.conflicts }))} />}
    {stayLocal && <button type="button" className="btn btn-l btn-wide" disabled={busy} onClick={stayLocal}>暂不配置，创建本地密码库</button>}
  </div>;
}

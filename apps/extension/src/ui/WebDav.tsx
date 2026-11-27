import { useEffect, useId, useRef, useState } from 'react';
import { ChevronRight, RotateCw } from 'lucide-react';
import { SITE_FLAG_KEYS, type SiteFlags } from '../autofill-settings';
import type { DavConnectionStatus } from '../sync/connection';
import { deviceProfile } from '../sync/device-profile';
import type { SyncResult } from '../sync/run';
import type { DavProbe, WebDavInput } from '../sync/webdav';
import { request, type DavJoinPreview, type DavRuleConflictsPreview, type DavSiteRulesPreview } from '../vault-messages';
import { AreaField, ErrorBanner, Ico, SecretField, SelectField, SwitchRow, TextField } from './components';
import { errorText } from './lib';
import type { EmergencyKit } from './Welcome';
import { openConflictReview } from './shell';
import { SyncHistory } from './SyncHistory';
import { SyncDevices } from './SyncDevices';

type ConnectionProbe = DavProbe & { createPending?: true };
const probeText: Record<DavProbe['kind'], string> = {
  empty: '已连接，目标目录为空。只读测试未创建任何文件。',
  existing: '找到已有密码库。连接测试没有下载或更改凭证。',
  incomplete: '目录非空，但没有找到完整的密码库。请核对目录或检查远端文件。',
  missing: '目标目录还不存在。确认建库时会创建目录并在其中验证写入。',
};
const syncText: Record<SyncResult['kind'], string> = {
  synced: '同步完成。',
  unchanged: '没有新变更。',
  'read-only': '网盘当前只读，未上传本机变更。',
  deferred: '本机还有待同步的修改。',
  unlinked: '尚未连接密码库。',
  locked: '先解锁密码库。',
  paused: '网盘连接已暂停。',
  empty: '本机有效凭证为零，已拦截上传。本机和网盘数据保持原状。',
  conflicts: '无争议的变更已合入，部分凭证等待裁决。',
  'key-update': '另一台设备已修改主密码，请在解锁页验证新密码。',
  'confirm-deletion': '有一批删除尚未发送到网盘。',
};
const disabledLabels: Record<keyof SiteFlags, string> = {
  inlineDisabled: '隐藏填充图标',
  saveDisabled: '关闭密码保存提示',
  passkeyDisabled: '由浏览器处理通行密钥',
};

function DomainGroupList({ groups }: { groups: string[][] }) {
  return groups.length
    ? <ul className="fold-body site-rule-list" role="list">{groups.map((group, index) => <li key={index}>{group.join('、')}</li>)}</ul>
    : <p className="fold-body hint">这一版没有关联域名。</p>;
}

export default function WebDav({ onboarding = false, stayLocal, onCreated, refresh }: {
  onboarding?: boolean; stayLocal?(next: 'create' | 'restore'): void; onCreated?(kit: EmergencyKit): void; refresh?(): Promise<void>;
}) {
  const [provider, setProvider] = useState<WebDavInput['provider']>('nutstore');
  const [base, setBase] = useState('');
  const [folder, setFolder] = useState('my-vault');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmHttp, setConfirmHttp] = useState(false);
  const [status, setStatus] = useState<DavConnectionStatus>();
  const [result, setResult] = useState<ConnectionProbe>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [method, setMethod] = useState<'master' | 'recovery'>('master');
  const [secret, setSecret] = useState('');
  const [confirm, setConfirm] = useState('');
  const [deviceName, setDeviceName] = useState<string>();
  const [fromSaved, setFromSaved] = useState(false);
  const [syncResult, setSyncResult] = useState<SyncResult>();
  const [verifyWrites, setVerifyWrites] = useState(false);
  const [readingHistory, setReadingHistory] = useState(false);
  const [editingDevices, setEditingDevices] = useState(false);
  const [localMaster, setLocalMaster] = useState('');
  const [joinReview, setJoinReview] = useState<DavJoinPreview>();
  const [siteRules, setSiteRules] = useState<DavSiteRulesPreview>();
  const [ruleConflicts, setRuleConflicts] = useState<DavRuleConflictsPreview>();
  const rulesHeading = useRef<HTMLHeadingElement>(null);
  const rulesHeadingId = useId();
  const input: WebDavInput = { provider, base, folder, username, password, confirmHttp };
  useEffect(() => {
    let live = true;
    const update = () => void request<DavConnectionStatus>({ type: 'webdav-status' }).then(value => {
      if (live) setStatus(value);
    }).catch(e => { if (live) setError(errorText(e)); });
    const changed = (changes: Record<string, unknown>, area: string) => {
      if (area === 'local' && ('webDavClock' in changes || 'webDavPaused' in changes || 'webDavConflicts' in changes)) update();
    };
    const notified = (message?: { target?: string; type?: string }) => {
      if (message?.target === 'vault-event' && (message.type === 'sync-changed' || message.type === 'webdav-pending')) update();
    };
    update();
    browser.storage.onChanged.addListener(changed);
    browser.runtime.onMessage.addListener(notified);
    return () => {
      live = false;
      browser.storage.onChanged.removeListener(changed);
      browser.runtime.onMessage.removeListener(notified);
    };
  }, []);
  const siteRulesPending = status?.siteRulesPending === true;
  useEffect(() => {
    if (!siteRulesPending) { setSiteRules(undefined); return; }
    let live = true;
    if (onboarding) rulesHeading.current?.focus();
    void request<DavSiteRulesPreview | null>({ type: 'webdav-site-rules' }).then(value => {
      if (live) {
        setSiteRules(value ?? undefined);
        if (!value) void request<DavConnectionStatus>({ type: 'webdav-status' }).then(current => {
          if (live) setStatus(current);
        }).catch(e => { if (live) setError(errorText(e)); });
      }
    }).catch(e => { if (live) setError(errorText(e)); });
    return () => { live = false; };
  }, [onboarding, siteRulesPending]);
  const reviewingRules = !!ruleConflicts && status?.siteRulesApplied === true;
  useEffect(() => { if (reviewingRules) rulesHeading.current?.focus(); }, [reviewingRules]);
  const resumingGenesis = result?.createPending === true;
  useEffect(() => {
    const end = status?.clockExpiresAt;
    if (end === undefined) return;
    const timer = window.setTimeout(() => setStatus(current => current?.clockExpiresAt === end
      ? { ...current, clockExpiresAt: undefined, offsetSeconds: null } : current), Math.max(0, end - Date.now()));
    return () => window.clearTimeout(timer);
  }, [status?.clockExpiresAt]);
  useEffect(() => {
    if (resumingGenesis || (result?.kind !== 'empty' && result?.kind !== 'missing')) return;
    let live = true;
    void deviceProfile().then(({ suggestedName }) => { if (live) setDeviceName(value => value ?? suggestedName); }).catch(() => undefined);
    return () => { live = false; };
  }, [result?.kind, resumingGenesis]);
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
    const value = await request<ConnectionProbe>({ type: 'webdav-test', input: fresh ? input : undefined, remember: fresh && !onboarding });
    setResult(value);
    setFromSaved(!onboarding && (!fresh || value.kind !== 'incomplete'));
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
      const current = await request<DavConnectionStatus>({ type: 'webdav-status' });
      setStatus(current);
      if (!current.siteRulesPending) await refresh?.();
    } catch (error) {
      if (error instanceof Error && error.message.includes('重新预览')) setJoinReview(undefined);
      throw error;
    } finally { setSecret(''); setLocalMaster(''); }
  });
  const chooseSiteRules = (use: boolean) => run(async () => {
    if (!siteRules) return;
    try {
      await request({ type: 'webdav-site-rules-choice', use, stamp: siteRules.stamp });
    } catch (error) {
      setSiteRules(await request<DavSiteRulesPreview | null>({ type: 'webdav-site-rules' }).catch(() => null) ?? undefined);
      throw error;
    }
    setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
    await refresh?.();
  });
  const retrySiteRules = () => run(async () => {
    const next = await request<DavSiteRulesPreview | null>({ type: 'webdav-site-rules' });
    setSiteRules(next ?? undefined);
    if (!next) {
      setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
      await refresh?.();
    }
  });
  async function loadRuleConflicts() {
    const next = await request<DavRuleConflictsPreview | null>({ type: 'webdav-rule-conflicts' });
    setRuleConflicts(next ?? undefined);
    setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
  }
  const chooseRuleConflict = (index: number, choice: 'first' | 'second') => run(async () => {
    if (!ruleConflicts) return;
    try {
      await request({ type: 'webdav-rule-conflict-choice', index, choice, stamp: ruleConflicts.stamp });
    } catch (error) {
      await loadRuleConflicts().catch(() => undefined);
      throw error;
    }
    await loadRuleConflicts();
  });
  const create = () => run(async () => {
    if (onboarding && !resumingGenesis && secret !== confirm) throw new Error('两次主密码输入不一致。');
    const kit = await request<EmergencyKit | undefined>({ type: 'webdav-create', input: fromSaved ? undefined : input,
      masterPassword: secret, deviceName });
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
      await request({ type: 'webdav-enable-write', masterPassword: secret });
      setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
      setVerifyWrites(false); setSyncResult(undefined);
    } finally { setSecret(''); }
  });
  const offset = status?.saved ? status.offsetSeconds : result?.offsetSeconds;
  const latestResult = status?.pending === false && syncResult?.pending ? undefined : syncResult;
  const pending = status?.pending ?? latestResult?.pending;
  const syncDisplay = pending && (!latestResult || latestResult.kind === 'synced' || latestResult.kind === 'unchanged')
    ? 'deferred' : latestResult?.kind;
  if (siteRulesPending) return <section className="section" aria-labelledby={rulesHeadingId} aria-busy={busy}>
    <h2 id={rulesHeadingId} ref={rulesHeading} tabIndex={-1}>预览网盘库的网站规则</h2>
    <p className="lede">{onboarding && '已加入网盘密码库。'}关联域名可以共用登录凭证。采用前，请核对这些网站。</p>
    {siteRules ? <>
      {siteRules.sites.length > 0 && <details className="fold" open>
        <summary>网站开关 · {siteRules.sites.length} 项<Ico of={ChevronRight} /></summary>
        <dl className="fold-body site-rule-list">
          {siteRules.sites.map(({ rule, flags }) => <div key={rule}>
            <dt>{rule}</dt>
            <dd className="hint">{SITE_FLAG_KEYS.filter(key => flags[key]).map(key => disabledLabels[key]).join('、') || '使用默认开关'}</dd>
          </div>)}
        </dl>
      </details>}
      {siteRules.domainGroups.length > 0 && <details className="fold" open>
        <summary>关联域名 · {siteRules.domainGroups.length} 组<Ico of={ChevronRight} /></summary>
        <DomainGroupList groups={siteRules.domainGroups} />
      </details>}
      {siteRules.sites.length === 0 && siteRules.domainGroups.length === 0 && <p className="hint">网盘库还没有网站规则。</p>}
      <p className="hint">此选择只影响这台设备。</p>
      <div className="actions">
        <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void chooseSiteRules(true)}>采用网盘网站规则</button>
        <button type="button" className="btn" disabled={busy} onClick={() => void chooseSiteRules(false)}>跳过网站规则</button>
      </div>
    </> : error
      ? <button type="button" className="btn" disabled={busy} onClick={() => void retrySiteRules()}>重试预览</button>
      : <p className="hint" role="status">正在读取网站规则…</p>}
    {error && <ErrorBanner text={error} />}
  </section>;
  if (reviewingRules && ruleConflicts) return <section className="section" aria-labelledby={rulesHeadingId} aria-busy={busy}>
    <div className="actions">
      <button type="button" className="btn" disabled={busy} onClick={() => { setRuleConflicts(undefined); setError(''); }}>返回网盘设置</button>
    </div>
    <h2 id={rulesHeadingId} ref={rulesHeading} tabIndex={-1}>处理关联域名冲突</h2>
    <p className="lede">不同设备编辑了相同的关联设置。请核对哪些网站可以共用登录凭证，再选择一版。</p>
    {error && <ErrorBanner text={error} />}
    {ruleConflicts.alternatives.map(({ first, second }, index) =>
      <section key={index} className="section" aria-label={`关联域名冲突 ${index + 1}`}>
        {ruleConflicts.alternatives.length > 1 && <h3>第 {index + 1} 项</h3>}
        {([['first', '第一版', first], ['second', '第二版', second]] as const).map(([choice, label, groups]) =>
          <details key={choice} className="fold" open>
            <summary>{label}<Ico of={ChevronRight} /></summary>
            <DomainGroupList groups={groups} />
            <div className="fold-body">
              <button type="button" className="btn" disabled={busy} onClick={() => void chooseRuleConflict(index, choice)}>采用{label}</button>
            </div>
          </details>)}
      </section>)}
  </section>;
  if (readingHistory) return <SyncHistory close={() => setReadingHistory(false)} changed={async () => {
    await refresh?.();
    setStatus(await request<DavConnectionStatus>({ type: 'webdav-status' }));
    setSyncResult(undefined);
  }} />;
  if (editingDevices) return <SyncDevices close={() => setEditingDevices(false)} />;
  return <div className="form">
    {status?.paused && <p className="banner banner-warn" role="status">网盘连接已暂停（HTTP {status.paused}）。{status.saved
      ? `${status.paused === 401 ? '请修正连接设置，再测试并保存。' : '请手动测试并保存连接。'}Koofr 需更换应用专用密码。`
      : '请核对设置后手动测试。'}</p>}
    {status?.saved && status.linked && status.writeVerified === false && !status.paused && !status.localRestoreHeld &&
      <p className="banner banner-warn" role="status">网盘当前只读。上传本机变更前需验证写入。</p>}
    {status?.localRestoreHeld && <p className="banner banner-warn" role="status">历史恢复仅保存在本机。启用网盘写入后，本机变更将参与同步。</p>}
    {!!status?.drafts && <p className="banner banner-warn" role="status">有 {status.drafts} 份草稿仍保存在本机，尚未上传。</p>}
    {status?.saved && <div className="actions"><button type="button" className="btn" disabled={busy || status.paused != null} onClick={() => void test(false)}>
      <Ico of={RotateCw} />重测已保存的连接</button></div>}
    {status?.linked && <div className="actions">
      <button type="button" className="btn btn-primary" disabled={busy || status.paused != null} onClick={() => void sync(false)}><Ico of={RotateCw} />立即同步</button>
      <button type="button" className="btn" disabled={busy || status.paused != null} onClick={() => { setSecret(''); setVerifyWrites(!verifyWrites); setSyncResult(undefined); }}>验证写入能力</button>
      <button type="button" className="btn" disabled={busy || status.paused != null} onClick={() => setReadingHistory(true)}>查看历史版本</button>
      <button type="button" className="btn" disabled={busy} onClick={() => setEditingDevices(true)}>管理设备</button>
    </div>}
    {!!status?.conflicts && <button className="btn" type="button" disabled={busy} onClick={() => void openConflictReview().catch(e => setError(errorText(e)))}>
      处理 {status.conflicts} 项同步冲突</button>}
    {status?.siteRulesApplied && !!status.siteRuleConflicts && <button className="btn" type="button" disabled={busy} onClick={() => void run(loadRuleConflicts)}>
      处理 {status.siteRuleConflicts} 项关联域名冲突</button>}
    {status?.linked && verifyWrites && <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void enable(); }}>
      <SecretField label="当前主密码" value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="current-password" />
      <button className="btn btn-primary" disabled={busy}>验证并启用网盘写入</button>
    </form>}
    {status?.checkFailed && !status.paused && <p className="banner banner-warn" role="status">
      上次同步检查失败，本机修改已保留。点「立即同步」查看原因。若版本无法验证，请核对网盘历史或更新扩展。
    </p>}
    {!status?.checkFailed && syncDisplay && <p className={syncDisplay === 'synced' || syncDisplay === 'unchanged' ? 'banner banner-ok' : 'banner banner-warn'}
      role="status">{syncText[syncDisplay]}</p>}
    {latestResult?.kind === 'confirm-deletion' && <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void sync(true); }}>
      <p className="hint">移除 {latestResult.removed} 条有效凭证（{latestResult.before} → {latestResult.after} 条）。</p>
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
    {result && <p role="status" className={resumingGenesis || result.kind === 'incomplete' ? 'banner banner-warn' : 'banner banner-ok'}>
      {resumingGenesis ? '上次创建这个网盘库时中断了。' : probeText[result.kind]}</p>}
    {!resumingGenesis && (onboarding || (status && !status.linked && !!password)) && result?.kind === 'existing' &&
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
    {!status?.linked && !status?.paused && (resumingGenesis || result?.kind === 'empty' || result?.kind === 'missing') && <form className="form" onSubmit={event => { event.preventDefault(); if (!busy) void create(); }}>
      {!resumingGenesis && <TextField label="本机名称" value={deviceName ?? ''} onChange={setDeviceName} maxLength={80} disabled={busy} />}
      <SecretField label={onboarding && !resumingGenesis ? '新主密码' : '当前主密码'} value={secret} onChange={setSecret} required
        minLength={onboarding ? 12 : undefined} maxLength={1024} disabled={busy} autoComplete={onboarding && !resumingGenesis ? 'new-password' : 'current-password'} />
      {onboarding && !resumingGenesis && <SecretField label="再次输入主密码" value={confirm} onChange={setConfirm} required disabled={busy}
        minLength={12} maxLength={1024} autoComplete="new-password" />}
      <button className="btn btn-primary" disabled={busy}>{busy ? '正在验证并建库…' : resumingGenesis ? '继续创建网盘库' : '验证写入并在网盘建库'}</button>
    </form>}
    {offset != null && <p className="hint">网盘时间与本机相差 {Math.abs(offset)} 秒，本机时钟{offset > 0 ? '偏慢' : '偏快'}。</p>}
    {status?.saved && <SwitchRow label="补偿时间验证码偏差" checked={status.compensation} disabled={busy || (!status.compensation && (status.paused != null || status.offsetSeconds == null))}
      onChange={enabled => void run(async () => setStatus(await request<DavConnectionStatus>({ type: 'webdav-clock', enabled })))} />}
    {status?.compensation && <p className="hint" role="status">{status.offsetSeconds == null
      ? '当前使用本机时间，等待有效的网盘时间偏差样本。' : '当前按网盘时间校正动态码。'}</p>}
    {stayLocal && <>
      <button type="button" className="btn btn-l btn-wide" disabled={busy} onClick={() => stayLocal('create')}>暂不配置，创建本地密码库</button>
      <button type="button" className="btn btn-l btn-wide" disabled={busy} onClick={() => stayLocal('restore')}>从本地备份恢复</button>
    </>}
  </div>;
}

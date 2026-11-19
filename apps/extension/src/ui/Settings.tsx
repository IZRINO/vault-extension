import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowRightLeft, ChevronRight, Download, FileUp, Fingerprint, Globe, HardDrive, KeyRound, Lock, Upload } from 'lucide-react';
import { MAX_VAULTPACK_BYTES, request, type BackupExport, type BackupReceipt, type Proof, type VaultStatus } from '../vault-messages';
import { registerPrf } from '../webauthn';
import { Ico, SecretField, SelectField } from './components';
import { useDialogs } from './dialogs';
import { download } from './lib';
import { useOps } from './Main';
import BrowserCsv from './BrowserCsv';
import EnteAuth from './EnteAuth';
import { AreaField } from './components';
import type { AutofillSettings } from '../autofill-policy';
import Migration from './Migration';

export type SettingsPage = 'home' | 'security' | 'password' | 'backup' | 'csv' | 'ente' | 'browser' | 'domains' | 'bitwarden' | 'mapped-csv';
const titles: Record<SettingsPage, string> = { home: '设置', security: '解锁与自动锁定', password: '更改主密码', backup: '备份与恢复', csv: '导入浏览器密码', ente: 'Ente Auth 验证器迁移', browser: '浏览器设置', domains: '关联域名', bitwarden: 'Bitwarden 密码库迁移', 'mapped-csv': 'CSV 字段映射与导出' };
export default function Settings({ status, page, setPage, refresh }: {
  status: VaultStatus; page: SettingsPage; setPage(page: SettingsPage): void; refresh(): Promise<void>;
}) {
  return <div className="view">
    {page === 'home' ? <><h1 className="page-title">设置</h1><p className="lede">密码库加密保存在这台电脑上。记得另存备份，换电脑时也能带走。</p>
      <div className="nav-rows">
        {([
          ['security', Lock, '解锁与自动锁定', `主密码${status.pinEnabled ? '、PIN' : ''}${status.prf ? '、系统解锁' : ''} · ${status.autoLockMinutes} 分钟后锁定`],
          ['password', KeyRound, '更改主密码', '用当前主密码设置一个新的主密码'],
          ['backup', HardDrive, '备份与恢复', '保存加密备份，或从备份恢复凭证'],
          ['csv', FileUp, '导入浏览器密码', '预览浏览器导出的 CSV，不覆盖已有凭证'],
          ['ente', ArrowRightLeft, 'Ente Auth 验证器迁移', '导入或导出验证码，可合并到已有登录项'],
          ['bitwarden', ArrowRightLeft, 'Bitwarden 密码库迁移', '支持明文或密码保护的 JSON 导入与导出'],
          ['mapped-csv', FileUp, 'CSV 字段映射与导出', '选择对应列导入，或导出登录凭证'],
          ['domains', Globe, '关联域名', '允许指定网站共用登录凭证'],
          ['browser', Globe, '浏览器设置', '管理浏览器原生的保存密码提示'],
        ] as const).map(([id, icon, label, hint]) => <button type="button" className="nav-row" key={id} onClick={() => setPage(id)}>
          <Ico of={icon} /><span className="grow"><strong>{label}</strong><small>{hint}</small></span><Ico of={ChevronRight} /></button>)}
      </div><p className="meta">Vault · 本地密码库</p></>
      : <div className="view-head"><button type="button" className="icon-btn" aria-label="返回设置" onClick={() => setPage('home')}><Ico of={ArrowLeft} /></button><h1>{titles[page]}</h1></div>}
    {page === 'security' && <Security status={status} refresh={refresh} />}
    {page === 'password' && <ChangePassword refresh={refresh} />}
    {page === 'backup' && <Backup refresh={refresh} />}
    {page === 'csv' && <BrowserCsv refresh={refresh} />}
    {page === 'ente' && <EnteAuth refresh={refresh} />}
    {page === 'bitwarden' && <Migration key="bitwarden" format="bitwarden" refresh={refresh} />}
    {page === 'mapped-csv' && <Migration key="csv" format="csv" refresh={refresh} />}
    {page === 'domains' && <EquivalentDomains />}
    {page === 'browser' && <BrowserSettings />}
  </div>;
}

function EquivalentDomains() {
  const { busy, work, notify, fail } = useOps();
  const [value, setValue] = useState('');
  useEffect(() => {
    void request<AutofillSettings>({ type: 'autofill-settings' }).then(settings =>
      setValue(settings.equivalentDomains.map((group: string[]) => group.join(', ')).join('\n'))).catch(fail);
  }, [fail]);
  return <form className="form" onSubmit={event => { event.preventDefault(); void work(async () => {
    const groups = value.split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => line.split(/[,，\s]+/));
    await request({ type: 'set-equivalent-domains', groups }); notify('关联域名已保存。');
  }); }}>
    <p className="lede">同一账号体系的不同主域名可以共用凭证。每行一组，域名之间用逗号分隔。</p>
    <p className="banner banner-warn">只添加你信任的域名。设置后，这些网站会显示同组网站的登录凭证。</p>
    <AreaField label="自定义关联域名" value={value} onChange={setValue} rows={6} placeholder="example.com, example.net" />
    <p className="hint">已内置 Microsoft、Google 和阿里账号体系。公共后缀、内网地址与端口不会加入关联组。</p>
    <button className="btn btn-primary" disabled={busy}>保存关联域名</button>
  </form>;
}

function Security({ status, refresh }: { status: VaultStatus; refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const dialogs = useDialogs();
  const [pin, setPin] = useState('');
  async function verified(action: (proof: Proof) => Promise<void>) {
    const proof = await dialogs.proof();
    try { await action(proof); } finally { proof.secret = ''; }
  }
  return <>
    <SelectField label="自动锁定" value={status.autoLockMinutes} onChange={value => void work(async () => {
      await request({ type: 'set-autolock', minutes: Number(value) }); await refresh(); notify('自动锁定时间已更新。');
    })} disabled={busy} hint="系统锁屏会立即锁定。查看状态不会延长解锁时间。">
      {[1, 5, 15, 30, 60, 240].map(minutes => <option key={minutes} value={minutes}>{minutes} 分钟无操作后</option>)}
    </SelectField>
    <form className="section" onSubmit={event => { event.preventDefault(); void work(() => verified(async proof => {
      await request({ type: 'create-pin', pin, proof }); setPin(''); await refresh(); notify('已设置本机 PIN。');
    })); }}>
      <h2>本机 PIN <span className="state-tag">{status.pinEnabled ? '已启用' : '未设置'}</span></h2>
      <p className="hint">只在这台电脑上使用。连续输错 5 次后，需改用主密码。</p>
      <SecretField label="6–12 位数字" inputMode="numeric" autoComplete="new-password" pattern="[0-9]{6,12}" required minLength={6} maxLength={12} value={pin} onChange={setPin} />
      <div className="actions"><button className="btn btn-primary" disabled={busy}>{status.pinEnabled ? '更换 PIN' : '设置 PIN'}</button>
        {status.pinEnabled && <button type="button" className="btn" disabled={busy} onClick={() => void work(async () => {
          await request({ type: 'remove-pin' }); await refresh(); notify('已移除本机 PIN，可以继续用主密码解锁。');
        })}>移除 PIN</button>}</div>
    </form>
    <section className="section"><h2>系统解锁 <span className="state-tag">{status.prf ? '已启用' : '未设置'}</span></h2>
      <p className="hint">使用 Windows Hello 或系统认证器。启用时会验证是否支持安全解锁；不支持时可以使用本机 PIN。</p>
      <button type="button" className="btn" disabled={busy} onClick={() => void work(async () => {
        if (status.prf) { await request({ type: 'remove-prf' }); await refresh(); notify('系统解锁已移除。'); return; }
        await verified(async proof => {
          let credential: Awaited<ReturnType<typeof registerPrf>> | undefined;
          try { credential = await registerPrf(); await request({ type: 'register-prf', ...credential, proof }); }
          catch (e) { throw new Error((e instanceof Error ? e.message : '系统解锁不可用。') + ' 可以改用本机 PIN。'); }
          finally { credential?.output.fill(0); }
        });
        await refresh(); notify('系统解锁自检通过，已启用。');
      })}><Ico of={Fingerprint} />{status.prf ? '移除系统解锁' : '设置系统解锁'}</button>
    </section>
  </>;
}

function ChangePassword({ refresh }: { refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  return <form className="form" onSubmit={event => { event.preventDefault(); void work(async () => {
    if (next !== again) throw new Error('两次新主密码输入不一致。');
    await request({ type: 'change-password', currentPassword: current, newPassword: next });
    setCurrent(''); setNext(''); setAgain(''); await refresh(); notify('主密码已更新，请重新设置 PIN 和系统解锁。');
  }); }}>
    <p className="lede">凭证和应急恢复码会保留。更改后，本机 PIN 和系统解锁需要重新设置。</p>
    <SecretField label="当前主密码" autoComplete="current-password" value={current} onChange={setCurrent} required autoFocus />
    <SecretField label="新主密码" autoComplete="new-password" minLength={12} maxLength={1024} value={next} onChange={setNext} required />
    <SecretField label="再次输入新主密码" autoComplete="new-password" minLength={12} maxLength={1024} value={again} onChange={setAgain} required />
    <button className="btn btn-primary" disabled={busy}>更新主密码</button>
  </form>;
}

function Backup({ refresh }: { refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const dialogs = useDialogs();
  const [mode, setMode] = useState<'export' | 'import'>('export');
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [file, setFile] = useState<File>();
  const [inputVersion, setInputVersion] = useState(0);
  const [pendingBackup, setPendingBackup] = useState<BackupReceipt>();
  const receipt = mode === 'export' ? pendingBackup : undefined;
  const confirmHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (receipt) confirmHeading.current?.focus(); }, [receipt]);
  return <>
    <div className="chips" role="group" aria-label="备份操作">
      <button type="button" className="chip" disabled={busy} aria-pressed={mode === 'export'} onClick={() => { setMode('export'); setPassword(''); setAgain(''); }}>导出备份</button>
      <button type="button" className="chip" disabled={busy} aria-pressed={mode === 'import'} onClick={() => { setMode('import'); setPassword(''); setAgain(''); }}>导入备份</button>
    </div>
    <p className="lede">{mode === 'export' ? '备份包含整个密码库。用一个独立密码加密，再把文件存到另一台设备或 U 盘。' : '选择之前导出的 .vaultpack 文件。导入会合并凭证，相同编号保留较新版本。'}</p>
    {!receipt && <form className="form" onSubmit={event => { event.preventDefault(); void work(async () => {
      if (mode === 'export' && password !== again) throw new Error('两次备份密码输入不一致。');
      if (mode === 'import') {
        if (!file) throw new Error('请先选择备份文件。');
        if (file.size > MAX_VAULTPACK_BYTES) throw new Error('备份不能超过 16 MiB。');
        if (!await dialogs.confirm({ title: '合并备份中的凭证？', body: '当前条目会保留；相同编号的凭证按较新版本合并。建议先导出当前密码库的备份。', confirmLabel: '验证并导入' })) return;
      }
      const proof = await dialogs.proof();
      try {
        if (mode === 'export') {
          const { bytes, receipt } = await request<BackupExport>({ type: 'export', password, proof });
          download('Vault-' + new Date().toISOString().slice(0, 10) + '.vaultpack', new Uint8Array(bytes), 'application/octet-stream');
          setPendingBackup(receipt);
        } else {
          const count = await request<number>({ type: 'import', bytes: Array.from(new Uint8Array(await file!.arrayBuffer())), password, proof });
          setFile(undefined); setInputVersion(value => value + 1); notify('已合并 ' + count + ' 条凭证。');
        }
        setPassword(''); setAgain(''); await refresh();
      } finally { proof.secret = ''; }
    }); }}>
      {mode === 'import' && <label className="field">导入加密备份<input key={inputVersion} className="input" type="file" accept=".vaultpack" required onChange={event => setFile(event.target.files?.[0])} /></label>}
      <SecretField label="备份密码" autoComplete="off" required minLength={mode === 'export' ? 12 : undefined} maxLength={1024} value={password} onChange={setPassword}
        hint={mode === 'export' ? '至少 12 个字符。请单独记好，恢复备份时会用到。' : '填写导出这个文件时设置的密码。'} />
      {mode === 'export' && <SecretField label="再次输入备份密码" autoComplete="off" required minLength={12} value={again} onChange={setAgain} />}
      <button className="btn btn-primary" disabled={busy || (mode === 'import' && !file)}><Ico of={mode === 'export' ? Download : Upload} />{mode === 'export' ? '导出 .vaultpack' : '验证并导入'}</button>
    </form>}
    {receipt && <section className="section">
      <h2 ref={confirmHeading} tabIndex={-1}>确认备份已保存</h2>
      <p className="hint">请检查浏览器的下载记录，确认 .vaultpack 文件已经保存。如果取消了下载，备份提醒会保留。</p>
      <div className="actions">
        <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void work(async () => {
          await request({ type: 'backup-saved', receipt });
          setPendingBackup(undefined); await refresh(); notify('已记录这次备份。');
        })}>文件已保存</button>
        <button type="button" className="btn" disabled={busy} onClick={() => setPendingBackup(undefined)}>未保存</button>
      </div>
    </section>}
  </>;
}

const browserSettingsPermission = { permissions: ['privacy' as const] };
type NativeSavingState = 'ungranted' | 'available' | 'disabled' | 'policy' | 'other-extension' | 'unsupported';
const nativeSavingMessages: Partial<Record<NativeSavingState, string>> = {
  policy: '浏览器策略限制了原生保存提示设置。',
  'other-extension': '另一个扩展正在控制原生保存提示。',
  unsupported: '此浏览器未提供原生保存提示的设置接口。',
};

const nativePasswordSaving = () => browser.privacy?.services?.passwordSavingEnabled;
async function readNativeSaving(): Promise<NativeSavingState> {
  const preference = nativePasswordSaving();
  if (!preference) return 'unsupported';
  const { levelOfControl, value } = await preference.get({});
  if (levelOfControl === 'controlled_by_this_extension') return value ? 'available' : 'disabled';
  if (levelOfControl === 'controllable_by_this_extension') return 'available';
  if (levelOfControl === 'controlled_by_other_extensions') return 'other-extension';
  return 'policy';
}

function BrowserSettings() {
  const { busy, work, fail, notify } = useOps();
  const [state, setState] = useState<NativeSavingState>();
  useEffect(() => {
    let live = true;
    let revoked = false;
    const onRemoved: Parameters<typeof browser.permissions.onRemoved.addListener>[0] = ({ permissions }) => {
      if (permissions?.includes('privacy')) {
        revoked = true;
        setState('ungranted');
      }
    };
    browser.permissions.onRemoved.addListener(onRemoved);
    void browser.permissions.contains(browserSettingsPermission).then(async granted => {
      const latest = granted ? await readNativeSaving() : 'ungranted';
      if (live && !revoked) setState(latest);
    }).catch(error => { if (live && !revoked) fail(error); });
    return () => {
      live = false;
      browser.permissions.onRemoved.removeListener(onRemoved);
    };
  }, [fail]);
  const disable = () => void work(async () => {
    if (!await browser.permissions.request(browserSettingsPermission)) {
      setState('ungranted');
      notify('未授权，浏览器设置没有改变。');
      return;
    }
    const before = await readNativeSaving();
    if (before !== 'available') {
      setState(before);
      return;
    }
    await nativePasswordSaving()!.set({ value: false });
    const actual = await readNativeSaving();
    setState(actual);
    if (actual === 'disabled') notify('已关闭浏览器的保存密码提示。');
    if (actual === 'available') throw new Error('浏览器未应用保存提示设置。');
  });
  const revoke = () => void work(async () => {
    if (!await browser.permissions.contains(browserSettingsPermission)) {
      setState('ungranted');
      return;
    }
    // Clear our override while we still have permission to use the setting API.
    await nativePasswordSaving()?.clear({});
    const actual = await readNativeSaving();
    setState(actual);
    if (actual === 'disabled') throw new Error('浏览器未恢复保存提示设置。');
    await browser.permissions.remove(browserSettingsPermission);
    if (await browser.permissions.contains(browserSettingsPermission)) throw new Error('浏览器未撤回设置权限。');
    setState('ungranted');
    notify('已撤回浏览器设置权限。');
  });
  const message = state && nativeSavingMessages[state];
  return <section className="section">
    <h2>浏览器的保存密码提示</h2>
    {state === 'ungranted' && <p className="lede">关闭原生保存提示需要浏览器授权。</p>}
    {message && <p className="hint" role="status">{message}</p>}
    {(state === 'ungranted' || state === 'available') && <button type="button" className="btn" disabled={busy} onClick={disable}>
      <Ico of={ArrowRightLeft} />关闭原生保存提示
    </button>}
    {state && state !== 'ungranted' && <button type="button" className="btn" disabled={busy} onClick={revoke}>
      <Ico of={ArrowRightLeft} />{state === 'disabled' ? '恢复浏览器设置并撤回权限' : '撤回浏览器设置权限'}
    </button>}
  </section>;
}

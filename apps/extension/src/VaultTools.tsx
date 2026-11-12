import { useEffect, useState } from 'react';
import { request, type Proof, type VaultStatus } from './vault-messages';
import { registerPrf } from './webauthn';

export function download(name: string, data: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement('a');
  link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
type ToolsProps = { status: VaultStatus; proof(): Promise<Proof>; refresh(): Promise<void>; work(action: () => Promise<void>): Promise<void>; busy: boolean; notice(text: string): void };
export function Settings({ status, proof, refresh, work, busy, notice }: ToolsProps) {
  const [pin, setPin] = useState('');
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [backupPassword, setBackupPassword] = useState('');
  const [file, setFile] = useState<File>();
  const [nativeDisabled, setNativeDisabled] = useState(false);
  useEffect(() => {
    let mounted = true;
    void browser.permissions.contains({ permissions: ['privacy'] }).then(async granted => {
      if (!granted) return;
      const setting = await browser.privacy.services.passwordSavingEnabled.get({});
      if (mounted) setNativeDisabled(setting.levelOfControl === 'controlled_by_this_extension' && !setting.value);
    }).catch(() => undefined);
    return () => { mounted = false; };
  }, []);
  return <section className="tools"><p className="eyebrow">此设备</p><h2>安全与备份</h2>
    <label>自动锁定<select aria-label="自动锁定" value={status.autoLockMinutes} onChange={e => void work(async () => { await request({ type: 'set-autolock', minutes: Number(e.target.value) }); await refresh(); })}>
      {[1, 5, 15, 30, 60, 240].map(n => <option key={n} value={n}>{n} 分钟无操作后</option>)}</select></label>
    <p className="hint">系统锁屏会立即锁定密码库。</p>
    <form onSubmit={e => { e.preventDefault(); void work(async () => { await request({ type: 'create-pin', pin, proof: await proof() }); setPin(''); await refresh(); notice('已设置本机 PIN。'); }); }}>
      <h3>本地 PIN</h3><p className="hint">连续验证失败 5 次后移除快捷解锁。</p>
      <label>6–12 位数字<input type="password" inputMode="numeric" autoComplete="new-password" pattern="[0-9]{6,12}" required value={pin} onChange={e => setPin(e.target.value)} /></label>
      <div className="actions"><button disabled={busy}>{status.pinEnabled ? '更换 PIN' : '设置 PIN'}</button>{status.pinEnabled && <button type="button" disabled={busy} onClick={() => void work(async () => { await request({ type: 'remove-pin' }); await refresh(); })}>移除 PIN</button>}</div>
    </form>
    <div className="settings-section"><h3>Windows Hello / 系统解锁</h3><p className="hint">首次启用将注册凭据并验证两次密钥输出；不支持时可使用 PIN。</p>
      <button disabled={busy} onClick={() => void work(async () => {
        if (status.prf) { await request({ type: 'remove-prf' }); await refresh(); return; }
        const verified = await proof();
        let credential: Awaited<ReturnType<typeof registerPrf>> | undefined;
        try { credential = await registerPrf(); await request({ type: 'register-prf', ...credential, proof: verified }); }
        catch (error) { throw new Error((error instanceof Error ? error.message : '系统解锁不可用。') + ' 若浏览器不支持 PRF，请使用本地 PIN。'); }
        finally { credential?.output.fill(0); verified.secret = ''; }
        await refresh(); notice('系统解锁自检通过，已启用。');
      })}>{status.prf ? '移除系统解锁' : '设置系统解锁'}</button>
    </div>
    <form onSubmit={e => { e.preventDefault(); void work(async () => { await request({ type: 'change-password', currentPassword: current, newPassword: next }); setCurrent(''); setNext(''); await refresh(); notice('主密码已更新，请重新设置快捷解锁。'); }); }}>
      <h3>更改主密码</h3><label>当前主密码<input type="password" autoComplete="current-password" required value={current} onChange={e => setCurrent(e.target.value)} /></label>
      <label>新主密码<input type="password" autoComplete="new-password" required minLength={12} value={next} onChange={e => setNext(e.target.value)} /></label>
      <button disabled={busy}>更新主密码</button>
    </form>
    <div className="settings-section"><h3>加密备份</h3><p className="hint">备份包含整个密码库。用独立密码加密后保存到其他设备。</p>
      <label>备份密码<input type="password" autoComplete="off" minLength={12} value={backupPassword} onChange={e => setBackupPassword(e.target.value)} /></label>
      <button disabled={busy || backupPassword.length < 12} onClick={() => void work(async () => {
        const bytes = await request<number[]>({ type: 'export', password: backupPassword, proof: await proof() });
        download('Vault-' + new Date().toISOString().slice(0, 10) + '.vaultpack', new Uint8Array(bytes), 'application/octet-stream');
        setBackupPassword(''); await refresh(); notice('已生成加密备份，请确认下载文件已保存。');
      })}>导出 .vaultpack</button>
      <label>导入加密备份<input type="file" accept=".vaultpack" onChange={e => setFile(e.target.files?.[0])} /></label>
      <p className="hint">导入将合并条目；相同编号以较新版本为准。</p>
      <button disabled={busy || !file || !backupPassword} onClick={() => void work(async () => {
        if (!file) return;
        if (file.size > 16 * 1024 * 1024) throw new Error('备份不能超过 16 MiB。');
        if (!confirm('导入将合并备份中的凭证，是否继续？')) return;
        const count = await request<number>({ type: 'import', bytes: Array.from(new Uint8Array(await file.arrayBuffer())), password: backupPassword, proof: await proof() });
        setBackupPassword(''); setFile(undefined); await refresh(); notice('已合并 ' + count + ' 条凭证。');
      })}>验证并导入</button>
    </div>
    <div className="settings-section"><h3>浏览器密码提示</h3><p className="hint">可选权限，仅影响此浏览器的原生保存密码提示。</p><button disabled={busy} onClick={() => {
      void browser.permissions.request({ permissions: ['privacy'] }).then(granted => {
        if (!granted) return;
        return work(async () => {
          if (nativeDisabled) await browser.privacy.services.passwordSavingEnabled.clear({});
          else await browser.privacy.services.passwordSavingEnabled.set({ value: false });
          setNativeDisabled(!nativeDisabled); notice(nativeDisabled ? '已交还浏览器控制。' : '已关闭原生保存密码提示。');
        });
      });
    }}>{nativeDisabled ? '恢复浏览器设置' : '关闭原生保存提示'}</button></div>
    <p className="metadata">密钥版本 {status.keyEpoch} · 仅本地存储</p>
  </section>;
}
export function Generator({ copy, work, busy }: { copy(text: string): Promise<void>; work(action: () => Promise<void>): Promise<void>; busy: boolean }) {
  const [mode, setMode] = useState<'password' | 'passphrase'>('password');
  const [length, setLength] = useState(24);
  const [words, setWords] = useState(6);
  const [value, setValue] = useState('');
  const [symbols, setSymbols] = useState(true);
  return <section className="tools"><p className="eyebrow">本地随机生成</p><h2>密码生成器</h2>
    <label>类型<select aria-label="类型" value={mode} onChange={e => { setMode(e.target.value as typeof mode); setValue(''); }}><option value="password">随机字符</option><option value="passphrase">单词口令</option></select></label>
    {mode === 'password' ? <><label>字符数<input type="number" min={8} max={128} value={length} onChange={e => setLength(Number(e.target.value))} /></label><label className="check"><input type="checkbox" checked={symbols} onChange={e => setSymbols(e.target.checked)} />包含符号</label><p className="hint">包含大小写和数字，排除易混淆字符。</p></> : <><label>单词数<input type="number" min={3} max={12} value={words} onChange={e => setWords(Number(e.target.value))} /></label><p className="hint">使用 EFF 7776 词表，以连字符分隔。</p></>}
    <button className="primary" disabled={busy} onClick={() => void work(async () => setValue(await request<string>({ type: mode === 'password' ? 'generate-password' : 'generate-passphrase', optionsJson: JSON.stringify(mode === 'password' ? { length, symbols, minSymbols: symbols ? 1 : 0 } : { wordCount: words, separator: '-', includeNumber: false }) })))}>生成</button>
    {value && <><output className="generated mono">{value}</output><button onClick={() => void copy(value)}>复制 · 30 秒后清理</button></>}
  </section>;
}
export function Audit({ work, busy }: { work(action: () => Promise<void>): Promise<void>; busy: boolean }) {
  const [report, setReport] = useState<{ totalLoginItems: number; weakItems: { itemId: string; title: string; warnings: string[] }[]; reusedGroups: { titles: string[] }[] }>();
  return <section className="tools"><p className="eyebrow">离线分析</p><h2>密码体检</h2><p className="muted">检查弱密码与重复使用的密码。</p>
    <button disabled={busy} onClick={() => void work(async () => setReport(await request({ type: 'audit' })))}>开始本地检查</button>
    {report && <><p>已检查 {report.totalLoginItems} 个登录项</p><h3>弱密码 · {report.weakItems.length}</h3>{report.weakItems.map(item => <div className="finding" key={item.itemId}><strong>{item.title}</strong><p>{item.warnings.join('；')}</p></div>)}<h3>重复密码 · {report.reusedGroups.length} 组</h3>{report.reusedGroups.map((group, i) => <p className="finding" key={i}>{group.titles.join('、')}</p>)}{!report.weakItems.length && !report.reusedGroups.length && <p className="success">本次检查未发现弱密码或重复密码。</p>}</>}
  </section>;
}

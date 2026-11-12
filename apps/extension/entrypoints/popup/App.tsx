import { useEffect, useRef, useState } from 'react';
import { request, type ItemSummary, type Proof, type VaultItem, type VaultStatus } from '../../src/vault-messages';
import ItemEditor, { kinds, newItem } from '../../src/ItemEditor';
import { Settings, Generator, Audit, download } from '../../src/VaultTools';
import { readPrf } from '../../src/webauthn';
import './App.css';

function Brand() { return <span className="brand"><svg width="24" height="26" viewBox="0 0 24 26" fill="none" aria-hidden="true"><path d="M3 3h18v10c0 6-9 10-9 10S3 19 3 13V3Z" stroke="currentColor" strokeWidth="2" /><path d="m8 12 3 3 5-6" stroke="currentColor" strokeWidth="2" /></svg><span>Vault<span className="brand-sub">本地密码库</span></span></span>; }
export default function App() {
  const [status, setStatus] = useState<VaultStatus>();
  const [error, setError] = useState('');
  const refresh = async () => setStatus(await request<VaultStatus>({ type: 'status' }));
  useEffect(() => {
    void refresh().catch(e => setError(String(e.message)));
    const onMessage = (message: { target?: string; type?: string }) => {
      if (message.target === 'vault-event' && message.type === 'locked') {
        setStatus(old => old ? { ...old, unlocked: false } : old);
        void refresh().catch(() => undefined);
      }
    };
    browser.runtime.onMessage.addListener(onMessage);
    return () => { browser.runtime.onMessage.removeListener(onMessage); };
  }, []);
  useEffect(() => {
    if (!status?.unlocked) return;
    const timer = setInterval(() => void refresh().catch(() => undefined), 5000);
    return () => clearInterval(timer);
  }, [status?.unlocked]);
  return <div className="app-shell">
    <header><Brand /><div className="header-actions">{status?.unlocked && <button onClick={() => void request({ type: 'lock' }).then(refresh).catch(e => setError(e.message))}>锁定</button>}
      <button aria-label="打开浏览器侧栏" title="打开侧栏" onClick={() => void browser.windows.getCurrent().then(window => window.id === undefined ? undefined : browser.sidePanel.open({ windowId: window.id })).catch(e => setError(e.message))}>侧栏</button>
      <button aria-label="在标签页打开密码库" title="在标签页打开" onClick={() => void browser.tabs.create({ url: browser.runtime.getURL('/sidepanel.html') })}>展开</button></div></header>
    {error && <p className="error" role="alert">{error}</p>}
    {!status ? <main><p>正在读取密码库…</p>{error && <button onClick={() => { setError(''); void refresh().catch(e => setError(e.message)); }}>重试</button>}</main>
      : status.unlocked ? <Unlocked status={status} refresh={refresh} /> : <Welcome key={String(status.configured)} status={status} refresh={refresh} />}
    <footer><span className="status-dot" />本地加密保存<span>第一阶段 · 本地密码库</span></footer>
  </div>;
}

function Welcome({ status, refresh }: { status: VaultStatus; refresh(): Promise<void> }) {
  const [mode, setMode] = useState<'master' | 'pin' | 'recovery'>('master');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [recovery, setRecovery] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [calibrate, setCalibrate] = useState(true);
  const [strength, setStrength] = useState<{ score: number; warnings: string[] }>();
  const [kit, setKit] = useState<{ recoveryCode: string; vaultId: string }>();
  const [downloaded, setDownloaded] = useState(false);
  useEffect(() => {
    if (mode === 'pin' && !status.pinEnabled) { setMode('master'); setPassword(''); }
  }, [status.pinEnabled, mode]);
  useEffect(() => {
    if (status.configured && mode !== 'recovery') return;
    let live = true;
    const timer = setTimeout(() => void request<{ score: number; warnings: string[] }>({ type: 'strength', password, hints: [] }).then(value => { if (live) setStrength(value); }).catch(() => undefined), 200);
    return () => { live = false; clearTimeout(timer); };
  }, [password, mode, status.configured]);
  async function submit() {
    setBusy(true); setError('');
    try {
      if (!status.configured) {
        if (password !== confirmPassword) throw new Error('两次主密码输入不一致。');
        const output = await request<{ recoveryCode: string; vaultId: string }>({ type: 'create', masterPassword: password, calibrate });
        setPassword(''); setConfirmPassword(''); setKit(output);
      } else {
        if (mode === 'recovery') {
          if (password !== confirmPassword) throw new Error('两次新主密码输入不一致。');
          await request({ type: 'recover', recoveryCode: recovery, newPassword: password });
        } else await request(mode === 'pin' ? { type: 'unlock-pin', pin: password } : { type: 'unlock', password });
        setPassword(''); setRecovery(''); await refresh();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      if (mode === 'pin') { setPassword(''); await refresh(); }
    } finally { setBusy(false); }
  }
  if (kit) return <main className="welcome"><p className="eyebrow">保存恢复凭据</p><h1>留一条恢复路径。</h1><p className="muted">应急恢复码可以重设主密码。请离线保存，不要与密码库放在同一位置。</p><pre className="recovery-code">{kit.recoveryCode}</pre>
    <button className="primary" onClick={() => { download('Vault-Emergency-Kit.txt', 'Vault 应急恢复包\n密码库编号：' + kit.vaultId + '\n恢复码：' + kit.recoveryCode + '\n请离线保存；恢复码仅能恢复对应密码库，不能替代数据备份。\n', 'text/plain;charset=utf-8'); setDownloaded(true); }}>下载应急恢复包</button>
    <button disabled={!downloaded} onClick={() => { setKit(undefined); void refresh(); }}>我已保存，进入密码库</button></main>;
  return <main className="welcome"><p className="eyebrow">{status.configured ? '欢迎回来' : '从本机开始'}</p><h1>{!status.configured ? <>你的凭证，<br />由你保管。</> : mode === 'recovery' ? '恢复密码库' : '解锁密码库'}</h1>
    <p className="muted">{!status.configured ? '创建主密码，加密保存你的登录、卡片和重要资料。' : mode === 'recovery' ? '使用应急恢复码设置新的主密码。' : '输入凭据，继续访问本机保存的密码。'}</p>
    <form onSubmit={e => { e.preventDefault(); void submit(); }}>
      {mode === 'recovery' && <label>应急恢复码<textarea required value={recovery} onChange={e => setRecovery(e.target.value)} autoComplete="off" /></label>}
      <label>{mode === 'pin' ? '本机 PIN' : mode === 'recovery' ? '新主密码' : '主密码'}<input autoFocus type="password" autoComplete={status.configured ? 'current-password' : 'new-password'} minLength={!status.configured || mode === 'recovery' ? 12 : undefined} required value={password} onChange={e => setPassword(e.target.value)} /></label>
      {(!status.configured || mode === 'recovery') && <><label>再次输入主密码<input type="password" autoComplete="new-password" minLength={12} required value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} /></label>
        {password && strength && <div className="strength"><meter min={0} max={4} value={strength.score} /><span>{['很弱', '较弱', '一般', '较强', '很强'][strength.score]}</span><p>{strength.warnings.join('；')}</p></div>}</>}
      {!status.configured && <label className="check"><input type="checkbox" checked={calibrate} onChange={e => setCalibrate(e.target.checked)} />根据本机性能校准解锁参数</label>}
      {error && <p role="alert" className="error">{error}</p>}
      <button className="primary wide" disabled={busy}>{busy ? '正在处理…' : !status.configured ? '创建本地密码库' : mode === 'recovery' ? '重设主密码' : '解锁'}</button>
    </form>
    {status.configured && <div className="unlock-options"><button disabled={busy} onClick={() => { setMode(mode === 'recovery' ? 'master' : 'recovery'); setPassword(''); setError(''); }}>{mode === 'recovery' ? '返回解锁' : '使用应急恢复码'}</button>
      {status.pinEnabled && <button disabled={busy} onClick={() => { setMode(mode === 'pin' ? 'master' : 'pin'); setPassword(''); setError(''); }}>{mode === 'pin' ? '使用主密码' : '使用 PIN'}</button>}
      {status.prf && <button disabled={busy} onClick={() => { setBusy(true); setError(''); void readPrf(status.prf!.credentialId, status.prf!.salt).then(async output => { try { await request({ type: 'unlock-prf', output }); await refresh(); } finally { output.fill(0); } }).catch(e => setError(e.message)).finally(() => setBusy(false)); }}>系统解锁</button>}</div>}
    {!status.configured && <p className="hint">主密码至少 12 个字符。下一步将生成应急恢复包。</p>}
  </main>;
}

function Unlocked({ status, refresh }: { status: VaultStatus; refresh(): Promise<void> }) {
  const [tab, setTab] = useState('vault');
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [editor, setEditor] = useState<VaultItem>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [proofOpen, setProofOpen] = useState(false);
  const [proofMethod, setProofMethod] = useState<'master' | 'pin'>('master');
  const [secret, setSecret] = useState('');
  const resolver = useRef<{ resolve(value: Proof): void; reject(error: Error): void } | undefined>(undefined);
  const mounted = useRef(true);
  const proofInput = useRef<HTMLInputElement>(null);
  const fail = (e: unknown) => setError(e instanceof Error ? e.message : String(e));
  const reload = async () => { const list = await request<ItemSummary[]>({ type: 'list' }); if (mounted.current) setItems(list); await refresh(); };
  useEffect(() => { mounted.current = true; void reload().catch(fail); return () => { mounted.current = false; resolver.current?.reject(new Error('密码库已关闭。')); }; }, []);
  useEffect(() => { if (proofOpen) proofInput.current?.focus(); }, [proofOpen]);
  async function work(action: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('');
    try { await action(); } catch (e) { if (mounted.current) fail(e); }
    finally { if (mounted.current) setBusy(false); }
  }
  function proof(): Promise<Proof> {
    setSecret(''); setProofMethod('master'); setProofOpen(true);
    return new Promise((resolve, reject) => { resolver.current = { resolve, reject }; });
  }
  async function copy(value: string) { await work(async () => { await request({ type: 'copy-sensitive', value }); setNotice('已复制，将在约 30 秒后检查并清理。'); }); }
  async function open(item: ItemSummary) { await work(async () => { const verified = item.requireReprompt ? await proof() : undefined; try { const full = await request<VaultItem>({ type: 'get', id: item.id, proof: verified }); if (mounted.current) setEditor(full); } finally { if (verified) verified.secret = ''; } }); }
  const visible = items.filter(item => (filter === 'trash' ? item.trashed : !item.trashed) &&
    (['all', 'trash'].includes(filter) || (filter === 'pinned' ? item.pinned : item.kind === filter)) &&
    [item.title, item.subtitle, item.primaryDomain, ...item.tags].join(' ').toLocaleLowerCase().includes(query.toLocaleLowerCase()));
  const cancelProof = () => { resolver.current?.reject(new Error('已取消验证。')); resolver.current = undefined; setSecret(''); setProofOpen(false); };
  return <>
    <div inert={proofOpen || undefined}>
    <nav aria-label="主导航">{[['vault', '密码库'], ['generator', '生成器'], ['audit', '体检'], ['settings', '设置']].map(([id, label]) => <button key={id} aria-current={tab === id ? 'page' : undefined} onClick={() => { setTab(id!); setEditor(undefined); setError(''); setNotice(''); }}>{label}</button>)}</nav>
    <main>
      {error && <p className="error" role="alert">{error}</p>}{notice && <p className="success" role="status">{notice}</p>}
      {busy && <div className="busy" role="status">正在处理…</div>}
      {tab === 'vault' && (editor ? <ItemEditor key={editor.id || editor.data.kind + String(editor.data.subtype)} initial={editor} busy={busy} close={() => setEditor(undefined)} copy={copy} fail={fail} save={async item => work(async () => {
        const existing = items.find(i => i.id === item.id);
        const verified = existing?.requireReprompt ? await proof() : undefined;
        try { await request({ type: 'upsert', itemJson: JSON.stringify({ ...item, tags: item.tags.map(t => t.trim()).filter(Boolean) }), proof: verified }); setEditor(undefined); await reload(); setNotice('凭证已保存。'); }
        finally { if (verified) verified.secret = ''; }
      })} /> : <>
        <div className="section-heading"><div><p className="eyebrow">私人收藏</p><h1>密码库<span className="count">{items.filter(i => !i.trashed).length}</span></h1></div>
          <select aria-label="新建凭证" value="" disabled={busy} onChange={e => setEditor(newItem(e.target.value.startsWith('dev:') ? 'developer' : e.target.value, e.target.value.split(':')[1]))}>
            <option value="" disabled>＋ 新建</option><option value="login">登录</option><option value="payment_card">支付卡</option><option value="identity">身份与地址</option><optgroup label="更多类型"><option value="dev:api_token">API 令牌</option><option value="dev:license_key">软件许可证</option><option value="dev:ssh_key">SSH 密钥</option></optgroup>
          </select></div>
        {status.changesSinceBackup >= 10 && <div className="backup-reminder"><span>最近已有 {status.changesSinceBackup} 次变更，保存一份加密备份。</span><button onClick={() => setTab('settings')}>备份</button></div>}
        <input className="search" aria-label="搜索凭证" placeholder="搜索名称、账号、网站或标签" value={query} onChange={e => setQuery(e.target.value)} />
        <div className="filters" aria-label="分类筛选">{[['all', '全部'], ['pinned', '置顶'], ['login', '登录'], ['payment_card', '卡片'], ['identity', '身份'], ['developer', '开发'], ['trash', '回收站']].map(([id, label]) => <button key={id} aria-pressed={filter === id} onClick={() => setFilter(id!)}>{label}</button>)}</div>
        <div className="item-list">{visible.map(item => <article className="item-row" key={item.id}>
          <button className="item-open" disabled={busy} onClick={() => void open(item)}><span className={'item-mark ' + item.kind}>{item.kind === 'payment_card' ? '卡' : item.kind === 'identity' ? '身' : item.kind === 'developer' ? '码' : item.title.slice(0, 1).toUpperCase()}</span><span className="item-text"><strong>{item.pinned && <span aria-label="已置顶">· </span>}{item.title}</strong><small>{item.subtitle || kinds[item.kind]}{item.requireReprompt && ' · 需验证'}</small></span></button>
          <details className="item-menu"><summary aria-label={item.title + '的操作'}>•••</summary><div>
            <button disabled={busy} onClick={() => void open(item)}>查看 / 编辑</button>
            <button disabled={busy} onClick={() => void work(async () => { await request({ type: 'trash', id: item.id, trashed: !item.trashed }); await reload(); })}>{item.trashed ? '恢复' : '移入回收站'}</button>
            {!item.trashed && item.kind === 'login' && <button disabled={busy} onClick={() => {
              if (!confirm('可选在线检查：仅发送密码 SHA-1 的前 5 位到 Have I Been Pwned，是否继续？')) return;
              void browser.permissions.request({ origins: ['https://api.pwnedpasswords.com/*'] }).then(granted => { if (granted) return work(async () => { const count = await request<number>({ type: 'hibp', id: item.id, proof: item.requireReprompt ? await proof() : undefined }); setNotice(count ? '该密码出现在泄露数据中 ' + count + ' 次，请更换。' : '未在本次查询中发现此密码。'); }); }).catch(fail);
            }}>在线泄露检查</button>}
            {item.trashed && <button className="danger" disabled={busy} onClick={() => { if (confirm('永久删除“' + item.title + '”？此操作无法撤销。')) void work(async () => { await request({ type: 'delete', id: item.id }); await reload(); }); }}>永久删除</button>}
          </div></details>
        </article>)}</div>
        {visible.length === 0 && <div className="empty"><span className="empty-mark">＋</span><h2>{query ? '没有匹配的凭证' : filter === 'trash' ? '回收站为空' : '留好每一把钥匙。'}</h2><p>{query ? '换一个名称、账号或标签试试。' : filter === 'trash' ? '移除的凭证会先保存在这里。' : '从一个登录项开始，把重要信息放在一起。'}</p>{!query && filter !== 'trash' && <button onClick={() => setEditor(newItem())}>添加登录项</button>}</div>}
        {filter === 'trash' && visible.length > 0 && <button className="danger" disabled={busy} onClick={() => { if (confirm('永久清空整个回收站？此操作无法撤销。')) void work(async () => { await request({ type: 'empty-trash' }); await reload(); }); }}>清空回收站</button>}
      </>)}
      {tab === 'settings' && <Settings status={status} proof={proof} refresh={reload} work={work} busy={busy} notice={setNotice} />}
      {tab === 'generator' && <Generator copy={copy} work={work} busy={busy} />}
      {tab === 'audit' && <Audit work={work} busy={busy} />}
    </main></div>
    {proofOpen && <div className="modal-backdrop" onKeyDown={e => {
      if (e.key === 'Escape') cancelProof();
      if (e.key === 'Tab') {
        const controls = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('input,select,button'));
        const first = controls[0], last = controls.at(-1);
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
        if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
      }
    }}><section className="modal" role="dialog" aria-modal="true" aria-labelledby="verify-title"><h2 id="verify-title">再次验证身份</h2><p className="muted">输入主密码或本机 PIN 继续。</p><form onSubmit={e => { e.preventDefault(); resolver.current?.resolve({ method: proofMethod, secret }); resolver.current = undefined; setSecret(''); setProofOpen(false); }}>
      {status.pinEnabled && <label>验证方式<select value={proofMethod} onChange={e => { setProofMethod(e.target.value as typeof proofMethod); setSecret(''); }}><option value="master">主密码</option><option value="pin">本机 PIN</option></select></label>}
      <label>{proofMethod === 'master' ? '主密码' : 'PIN'}<input ref={proofInput} type="password" autoComplete="off" required value={secret} onChange={e => setSecret(e.target.value)} /></label>
      <div className="actions"><button className="primary">验证</button><button type="button" onClick={cancelProof}>取消</button></div>
    </form></section></div>}
  </>;
}

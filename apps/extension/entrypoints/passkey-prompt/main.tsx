import { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { KeyRound, ShieldCheck, X } from 'lucide-react';
import type { PasskeyCandidate, PasskeySelection } from '../../src/passkeys/protocol';
import type { Proof, Reply } from '../../src/vault-messages';
import '../../src/ui/styles/tokens.css';
import './prompt.css';

const inline = window.top !== window;
const ticket = location.hash.slice(1).replace(/\.inline$/, '');
type Prompt = { kind: 'register' | 'assert'; origin: string; rpId: string; uv: string; account?: string; chosen?: string; candidates: PasskeyCandidate[] };
async function request<T>(type: string, selection?: PasskeySelection): Promise<T> {
  const response: Reply<T> = await browser.runtime.sendMessage({ target: 'vault-passkey-ui', type, ticket, selection });
  if (!response?.ok) throw new Error(response?.error ?? '请求已结束，请回到网站重试。');
  return response.value;
}

function App() {
  const [prompt, setPrompt] = useState<Prompt>();
  const [choice, setChoice] = useState(-1);
  const [increment, setIncrement] = useState(false);
  const [optionalProof, setOptionalProof] = useState(false);
  const [method, setMethod] = useState<Proof['method']>('master');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    void request<Prompt>('prompt').then(value => {
      if (!live) return;
      setPrompt(value);
      if (value.chosen) setChoice(value.candidates.findIndex(item => item.id === value.chosen));
    }, reason => { if (live) setError(reason.message); });
    return () => { live = false; };
  }, []);
  const selected = prompt?.candidates[choice];
  const verify = !inline && (prompt?.uv === 'required' || selected?.verify || optionalProof);
  const detail = (record?: PasskeyCandidate) => ({ itemId: record?.itemId, credentialId: record?.id ?? undefined });
  const submit = useCallback(async (type: string, selection?: PasskeySelection) => {
    if (busy) return;
    setBusy(true);
    setError('');
    try { await request(type, selection); }
    catch (reason) { setError(reason instanceof Error ? reason.message : '请求失败。'); }
    finally { setBusy(false); setSecret(''); }
  }, [busy]);
  useEffect(() => {
    if (!prompt || busy) return;
    function escape(event: KeyboardEvent) {
      if (event.key !== 'Escape' || !event.isTrusted || event.isComposing) return;
      event.preventDefault();
      event.stopPropagation();
      void submit('cancel');
    }
    document.addEventListener('keydown', escape, true);
    return () => document.removeEventListener('keydown', escape, true);
  }, [prompt, busy, submit]);
  return (
    <main className={inline ? 'passkey-ui passkey-inline' : 'passkey-ui'} aria-busy={busy}>
      <header>
        <KeyRound size={18} aria-hidden="true" />
        <h1>{prompt?.kind === 'register' ? '保存通行密钥' : '使用通行密钥'}</h1>
        <button type="button" className="close" title="取消" aria-label="取消" disabled={busy || !prompt}
          onClick={event => { if (event.nativeEvent.isTrusted) void submit('cancel'); }}><X size={16} /></button>
      </header>
      {prompt && <div className="passkey-source"><b dir="ltr">{prompt.origin}</b>{prompt.rpId !== new URL(prompt.origin).hostname && <small>RP ID：{prompt.rpId}</small>}{prompt.account && <small>正在为 {prompt.account} 登记</small>}</div>}
      {error && <p className="passkey-error" role="alert">{error}</p>}
      {!prompt && !error && <p role="status">正在检查请求…</p>}
      {prompt && <form onSubmit={event => {
        event.preventDefault();
        if (!event.nativeEvent.isTrusted || inline) return;
        void submit('approve', { ...detail(selected), increment, proof: verify ? { method, secret } : undefined });
      }}>
        <div className="passkey-options">
          {prompt.kind === 'register' && <label className="passkey-choice"><input type="radio" name="key" checked={choice === -1} onChange={() => setChoice(-1)} /> 新建登录条目</label>}
          {prompt.candidates.map((record, index) => (!prompt.chosen || prompt.chosen === record.id) && (inline ?
            <button className="passkey-choice" type="button" key={`${record.itemId}:${record.id}`} disabled={record.suspended || busy}
              onClick={event => { if (event.nativeEvent.isTrusted) void submit('choose', detail(record)); }}>
              <KeyRound size={16} aria-hidden="true" /><span>{record.title}<small>{record.suspended ? '计数待核实' : record.account}</small></span>
            </button> :
            <label className="passkey-choice" key={`${record.itemId}:${record.id}`}>
              <input type="radio" name="key" checked={choice === index} disabled={record.suspended} onChange={() => setChoice(index)} />
              <span>{record.title}<small>{record.suspended ? '计数待核实' : record.account}</small></span>
            </label>))}
          {prompt.kind === 'assert' && !prompt.candidates.length && <p>此站点没有可用的通行密钥。</p>}
        </div>
        {!inline && <>
          {prompt.kind === 'register' && <label className="passkey-check">
            <input type="checkbox" checked={increment} onChange={event => setIncrement(event.target.checked)} />
            <span>递增签名计数 <small>仅适合单设备使用；旧备份可能需要重新登记。</small></span>
          </label>}
          {prompt.uv === 'preferred' && !selected?.verify && <label className="passkey-check">
            <input type="checkbox" checked={optionalProof} onChange={event => setOptionalProof(event.target.checked)} /> 重新验证身份
          </label>}
          {verify && <div className="passkey-proof">
            <label>验证方式 <select value={method} onChange={event => { setMethod(event.target.value as Proof['method']); setSecret(''); }}>
              <option value="master">主密码</option><option value="pin">PIN</option>
            </select></label>
            <label>{method === 'master' ? '主密码' : 'PIN'}
              <input type="password" autoComplete="off" value={secret} maxLength={1024} onChange={event => setSecret(event.target.value)} />
            </label>
          </div>}
        </>}
        <footer>
          <button type="button" disabled={busy} onClick={event => { if (event.nativeEvent.isTrusted) void submit('native'); }}>
            改用系统 / USB 密钥
          </button>
          {!inline && <button type="submit" className="primary" disabled={busy || (verify && !secret) || (prompt.kind === 'assert' && !selected)}>
            <ShieldCheck size={16} aria-hidden="true" />{prompt.kind === 'register' ? '保存' : '确认登录'}
          </button>}
        </footer>
      </form>}
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<App />);

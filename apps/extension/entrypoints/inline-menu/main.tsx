import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { autofillRequest, type FillCandidate, type MenuState } from '../../src/autofill-messages';
import type { Proof } from '../../src/vault-messages';
import '../../src/ui/styles/index.css';
import './style.css';

function Menu() {
  const [token, setToken] = useState('');
  const [state, setState] = useState<MenuState>();
  const [selected, setSelected] = useState<FillCandidate>();
  const [confirmed, setConfirmed] = useState(false);
  const [method, setMethod] = useState<Proof['method']>('master');
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [copyOtp, setCopyOtp] = useState(true);
  useEffect(() => {
    const receive = (event: MessageEvent) => {
      if (event.source !== parent || event.data?.target !== 'vault-menu' ||
        typeof event.data.token !== 'string' || !/^[a-f0-9-]{72}$/.test(event.data.token)) return;
      window.removeEventListener('message', receive);
      setToken(event.data.token);
      void autofillRequest<MenuState>({ type: 'menu', token: event.data.token }).then(setState).catch(error => setError(error.message));
    };
    window.addEventListener('message', receive);
    parent.postMessage({ target: 'vault-menu-ready' }, '*');
    return () => window.removeEventListener('message', receive);
  }, []);
  const close = () => { void autofillRequest({ type: 'close', token }).catch(() => undefined); setDone(true); };
  const act = async (candidate?: FillCandidate, proof?: Proof) => {
    if (busy) return;
    setBusy(true); setError('');
    try {
      await autofillRequest(state?.capture ? { type: 'save', token, confirmCrossOrigin: confirmed, proof }
        : { type: 'fill', token, id: candidate!.id, confirmCrossOrigin: confirmed, copyOtp: copyOtp && !!candidate?.otpKind && candidate.otpKind !== 'hotp', proof });
      setDone(true);
    } catch (error) { setError(error instanceof Error ? error.message : '操作失败，请重试。'); }
    finally { setBusy(false); setSecret(''); if (proof) proof.secret = ''; }
  };
  const risk = state?.crossOrigin || state?.insecure;
  const capture = state?.capture;
  const needsProof = selected?.requireReprompt || capture?.requireReprompt;
  return <div className="inline-shell">
    <header className="inline-head"><strong>Vault</strong><button type="button" className="inline-close" aria-label="关闭填充菜单" onClick={event => { if (event.isTrusted) close(); }}>关闭</button></header>
    <main className="inline-body">
      {done ? <p role="status">操作已完成，可以关闭此窗口。</p>
        : <>
          {error && <p className="banner banner-error" role="alert">{error}</p>}
          {!state && !error && <p role="status">正在确认网页来源…</p>}
          {state && <>
            <h1>{capture?.ambiguous ? '无法确定要更新的凭证' : capture ? capture.updating ? '更新网站密码' : '保存新凭证'
              : state.kind === 'otp' ? '选择验证码' : '选择要填入的凭证'}</h1>
            <p className="hint">填入网站：<strong>{state.site}</strong></p>
            {state.crossOrigin && <div className="banner banner-warn" role="alert"><p>当前页面是 {state.topSite}，输入框来自 {state.site}。请确认你信任这两个网站。</p></div>}
            {state.insecure && <p className="banner banner-warn" role="alert">这是未加密的 HTTP 网页，填入的内容可能被网络上的其他人看到。</p>}
            {risk && <label className="check"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />我确认网站来源，允许本次操作</label>}
            {capture && <p>账号：{capture.account || '未填写账号'}。</p>}
            {capture?.ambiguous && <p className="banner banner-warn" role="alert">有多条同账号凭证，请在密码库中手动选择更新。</p>}
            {!state.capture && state.kind === 'login' && state.candidates.some(candidate => candidate.otpKind && candidate.otpKind !== 'hotp') &&
              <label className="check"><input type="checkbox" checked={copyOtp} disabled={busy} onChange={event => setCopyOtp(event.target.checked)} />填充后复制时间验证码，30 秒后清理</label>}
            {state.kind === 'otp' && state.candidates.some(candidate => candidate.otpKind === 'hotp') && <p className="hint">选择 HOTP 会生成并推进一次计数，请仅在网站要求时使用。</p>}
            {!selected && !state.capture && <div className="inline-choices">
              {state.candidates.map(candidate => <button key={candidate.id} type="button" className="inline-choice" disabled={busy || !!risk && !confirmed}
                onClick={event => { if (!event.isTrusted) return; if (candidate.requireReprompt) setSelected(candidate); else void act(candidate); }}>
                <strong>{candidate.title}</strong><span>{candidate.account || '未填写账号'}{candidate.requireReprompt ? ' · 需要再次验证' : ''}</span>
              </button>)}
              {!state.candidates.length && <p className="hint">没有匹配的凭证。请在 Vault 中添加此网站，或检查已保存的网站匹配规则。</p>}
            </div>}
            {(selected || capture && !capture.ambiguous) && <form className="form" onSubmit={event => {
              event.preventDefault();
              if (!event.isTrusted || !!risk && !confirmed) return;
              void act(selected, needsProof ? { method, secret } : undefined);
            }}>
              {needsProof && <>
                {state.pinEnabled && <label className="field">验证方式<select className="select" value={method} onChange={event => { setMethod(event.target.value as Proof['method']); setSecret(''); }}>
                  <option value="master">主密码</option><option value="pin">本机 PIN</option>
                </select></label>}
                <label className="field">{method === 'master' ? '主密码' : '本机 PIN'}<input className="input" type="password" autoComplete="off" required value={secret} maxLength={1024} onChange={event => setSecret(event.target.value)} /></label>
              </>}
              <button className="btn btn-primary" disabled={busy || !!risk && !confirmed}>{busy ? '正在处理…' : state.capture ? state.capture.updating ? '确认更新密码' : '保存凭证' : '验证并填充'}</button>
              {selected && <button type="button" className="btn" onClick={() => { setSelected(undefined); setSecret(''); }}>返回账号列表</button>}
            </form>}
          </>}
        </>}
    </main>
  </div>;
}
createRoot(document.getElementById('root')!).render(<Menu />);

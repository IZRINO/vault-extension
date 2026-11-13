import { useEffect, useState } from 'react';
import { ChevronRight, CircleCheck, Download, Fingerprint, Hash, KeyRound, LifeBuoy, Undo2 } from 'lucide-react';
import { request, type VaultStatus } from '../vault-messages';
import { readPrf } from '../webauthn';
import { AreaField, ErrorBanner, Ico, SecretField } from './components';
import { download, errorText } from './lib';
import { ShellActions } from './shell';

export interface EmergencyKit { recoveryCode: string; vaultId: string }
interface Strength { score: number; warnings: string[] }
const strengthNames = ['很弱', '较弱', '一般', '较强', '很强'];

function StrengthMeter({ strength }: { strength: Strength }) {
  const score = Math.max(0, Math.min(4, strength.score));
  return <div className="strength" data-score={score}>
    <div className="strength-bar" aria-hidden="true"><i /><i /><i /><i /></div>
    <p>强度：<b>{strengthNames[score]}</b>{strength.warnings.length > 0 && '。' + strength.warnings.join('；')}</p>
  </div>;
}

export default function Welcome({ status, refresh, onCreated }: { status: VaultStatus; refresh(): Promise<void>; onCreated(kit: EmergencyKit): void }) {
  const [mode, setMode] = useState<'master' | 'pin' | 'recovery'>('master');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [recovery, setRecovery] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [calibrate, setCalibrate] = useState(true);
  const [strength, setStrength] = useState<Strength>();
  const creating = !status.configured;
  const choosing = creating || mode === 'recovery';

  useEffect(() => {
    if (mode === 'pin' && !status.pinEnabled) { setMode('master'); setPassword(''); }
  }, [status.pinEnabled, mode]);
  useEffect(() => {
    if (!choosing) return;
    let live = true;
    const timer = setTimeout(() => void request<Strength>({ type: 'strength', password, hints: [] })
      .then(value => { if (live) setStrength(value); }).catch(() => undefined), 200);
    return () => { live = false; clearTimeout(timer); };
  }, [password, choosing]);

  async function submit() {
    setBusy(true); setError('');
    try {
      if (creating) {
        if (password !== confirmPassword) throw new Error('两次主密码输入不一致。');
        const output = await request<EmergencyKit>({ type: 'create', masterPassword: password, calibrate });
        setPassword(''); setConfirmPassword('');
        onCreated(output);
      } else {
        if (mode === 'recovery') {
          if (password !== confirmPassword) throw new Error('两次新主密码输入不一致。');
          await request({ type: 'recover', recoveryCode: recovery, newPassword: password });
        } else await request(mode === 'pin' ? { type: 'unlock-pin', pin: password } : { type: 'unlock', password });
        setPassword(''); setConfirmPassword(''); setRecovery('');
        await refresh();
      }
    } catch (e) {
      setError(errorText(e));
      if (mode === 'pin') { setPassword(''); await refresh().catch(() => undefined); }
    } finally { setBusy(false); }
  }
  function unlockWithSystem() {
    const prf = status.prf;
    if (!prf) return;
    setBusy(true); setError('');
    void readPrf(prf.credentialId, prf.salt).then(async output => {
      try { await request({ type: 'unlock-prf', output }); await refresh(); } finally { output.fill(0); }
    }).catch(e => setError(errorText(e))).finally(() => setBusy(false));
  }
  function switchMode(next: typeof mode) {
    setMode(next); setPassword(''); setConfirmPassword(''); setError('');
  }

  const heading = creating ? '先设一个主密码' : mode === 'recovery' ? '用恢复码重设主密码' : '解锁密码库';
  const lede = creating ? '以后只用记住这一个密码，其余的账号和密码都交给 Vault 保管。'
    : mode === 'recovery' ? '输入应急恢复包里的恢复码，再设一个新的主密码。'
      : mode === 'pin' ? '输入本机 PIN。连续输错 5 次后，需要改用主密码。'
        : '输入主密码，取用保存在这台电脑上的账号和密码。';

  return <div className="door">
    <div className="band-top">
      <span className="wordmark">Vault</span>
      {!creating && <span className="lamp" data-state="locked">已锁定</span>}
      <ShellActions onError={e => setError(errorText(e))} />
    </div>
    <div className="door-head">
      {creating && <div className="steps"><span aria-current="step"><i>1</i>设置主密码</span><hr /><span><i>2</i>保存恢复包</span></div>}
      <h1>{heading}</h1>
      <p>{lede}</p>
    </div>
    <div className="door-panel">
      <form onSubmit={event => { event.preventDefault(); void submit(); }}>
        {mode === 'recovery' && <AreaField label="应急恢复码" rows={3} mono required autoFocus autoComplete="off" spellCheck={false} value={recovery} onChange={setRecovery}
          hint="在 Vault-Emergency-Kit.txt 文件里，13 组字母和数字。" />}
        {mode === 'pin'
          ? <SecretField key="pin" label="本机 PIN" autoFocus required inputMode="numeric" autoComplete="off" value={password} onChange={setPassword} />
          : <SecretField key={mode} label={mode === 'recovery' ? '新主密码' : '主密码'} autoFocus={mode !== 'recovery'} required minLength={choosing ? 12 : undefined}
            autoComplete={choosing ? 'new-password' : 'current-password'} value={password} onChange={setPassword}
            hint={choosing ? '至少 12 个字符。一句只有你知道的话，比一串乱码更好记，也更安全。' : undefined} />}
        {choosing && <SecretField label="再次输入主密码" revealName="确认密码" required minLength={12} autoComplete="new-password" value={confirmPassword} onChange={setConfirmPassword} />}
        {choosing && password && strength && <StrengthMeter strength={strength} />}
        {creating && <details className="fold fold-plain">
          <summary>高级选项<Ico of={ChevronRight} /></summary>
          <div className="fold-body">
            <label className="check"><input type="checkbox" checked={calibrate} onChange={event => setCalibrate(event.target.checked)} />
              <span>按这台电脑的性能调整加密强度<small>建议保持勾选。创建时会多等几秒。</small></span></label>
          </div>
        </details>}
        {error && <ErrorBanner text={error} />}
        <button className="btn btn-primary btn-l btn-wide" disabled={busy}>
          {busy ? (creating ? '正在创建，请稍候…' : '正在验证…') : creating ? '创建本地密码库' : mode === 'recovery' ? '重设主密码' : '解锁'}
        </button>
      </form>
    </div>
    {!creating && <div className="door-alt">
      {status.prf && mode !== 'recovery' && <button type="button" className="btn btn-door" disabled={busy} onClick={unlockWithSystem}><Ico of={Fingerprint} />系统解锁</button>}
      {status.pinEnabled && mode !== 'recovery' && <button type="button" className="btn btn-door" disabled={busy} onClick={() => switchMode(mode === 'pin' ? 'master' : 'pin')}>
        <Ico of={mode === 'pin' ? KeyRound : Hash} />{mode === 'pin' ? '使用主密码' : '使用 PIN'}</button>}
      <button type="button" className="btn btn-door" disabled={busy} onClick={() => switchMode(mode === 'recovery' ? 'master' : 'recovery')}>
        <Ico of={mode === 'recovery' ? Undo2 : LifeBuoy} />{mode === 'recovery' ? '返回解锁' : '使用应急恢复码'}</button>
    </div>}
    <p className="door-foot">{creating
      ? '密码库只保存在这台电脑上，不会上传。主密码没有“找回”功能，所以下一步会给你一份应急恢复包。'
      : '密码库只保存在这台电脑上，不会上传。'}</p>
  </div>;
}

export function KitScreen({ kit, onDone }: { kit: EmergencyKit; onDone(): void }) {
  const [downloaded, setDownloaded] = useState(false);
  const save = () => {
    download('Vault-Emergency-Kit.txt', 'Vault 应急恢复包\n密码库编号：' + kit.vaultId + '\n恢复码：' + kit.recoveryCode + '\n请离线保存；恢复码仅能恢复对应密码库，不能替代数据备份。\n', 'text/plain;charset=utf-8');
    setDownloaded(true);
  };
  return <div className="door">
    <div className="band-top"><span className="wordmark">Vault</span></div>
    <div className="door-head">
      <div className="steps"><span><i>1</i>设置主密码</span><hr /><span aria-current="step"><i>2</i>保存恢复包</span></div>
      <h1>保存应急恢复包</h1>
      <p>忘记主密码时，只有这串恢复码能帮你重设。请下载后存到 U 盘或打印出来，不要和这台电脑放在一起。</p>
    </div>
    <div className="door-panel">
      <div className="field">
        <span className="label" id="recovery-code-label">你的恢复码</span>
        <pre className="recovery-code" aria-labelledby="recovery-code-label">{kit.recoveryCode}</pre>
      </div>
      <button type="button" className="btn btn-primary btn-l btn-wide" onClick={save}><Ico of={Download} />下载应急恢复包</button>
      {downloaded && <div className="banner banner-ok" role="status"><Ico of={CircleCheck} /><span className="grow">已下载，文件名是 Vault-Emergency-Kit.txt。请确认它已经存到安全的地方。</span></div>}
      <button type="button" className="btn btn-l btn-wide" disabled={!downloaded} onClick={onDone}>我已保存，进入密码库</button>
      {!downloaded && <p className="hint">下载恢复包之后，才能进入密码库。</p>}
    </div>
    <p className="door-foot">恢复码只能重设主密码，不能代替数据备份。之后可以在“设置”里另存一份加密备份。</p>
  </div>;
}

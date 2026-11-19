import { useEffect, useState } from 'react';
import { request, type HotpCode, type TimedOtpCode } from '../vault-messages';
import { CodeCells, CopyButton } from './components';
import { useDialogs } from './dialogs';
import { useOps } from './Main';

const now = () => Math.floor(Date.now() / 1000);

export default function TotpSection({ id, handle }: { id: string; handle: string }) {
  const { busy, copy, fail } = useOps();
  const [reading, setReading] = useState<TimedOtpCode>();
  const [time, setTime] = useState(now);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    let latest: TimedOtpCode | undefined;
    let requestedAt = -1;
    let pending = false;
    setReading(undefined);
    setError('');
    const read = async (seconds: number) => {
      requestedAt = seconds;
      pending = true;
      try {
        latest = await request<TimedOtpCode>({ type: 'read-otp', id, handle });
        if (active) setReading(latest);
      } catch (error) {
        if (active) {
          setReading(undefined);
          setError(error instanceof Error ? error.message : '无法生成验证码，请重新打开凭证。');
          clearInterval(timer);
        }
      } finally { pending = false; }
    };
    const tick = () => {
      const seconds = now();
      setTime(seconds);
      const remaining = (latest?.validTo ?? 0) - seconds;
      if (!pending && seconds !== requestedAt &&
        (!latest || seconds < requestedAt || remaining <= 0 || (remaining < 5 && !latest.nextValue))) void read(seconds);
    };
    const timer = setInterval(tick, 250);
    tick();
    return () => { active = false; clearInterval(timer); };
  }, [handle, id]);

  const remaining = reading ? reading.validTo - time : 0;
  return <section className="section">
    <h2>两步验证码</h2>
    {error ? <p className="hint" role="alert">{error}</p>
      : !reading || remaining <= 0 ? <p className="hint" role="status">正在读取验证码…</p>
        : <div className="facts"><div className="fact">
          <div className="fact-text">
            <output aria-label="当前验证码" aria-live="off"><span className="sr-only">{reading.value}</span><CodeCells code={reading.value} /></output>
            <span className="fact-label">{remaining} 秒后刷新</span>
          </div>
          <CopyButton label="复制验证码" disabled={busy} onCopy={async () => {
            try {
              const code = await request<TimedOtpCode>({ type: 'read-otp', id, handle });
              return await copy(code.validTo <= now() && code.nextValue ? code.nextValue : code.value);
            } catch (error) {
              fail(error);
              return false;
            }
          }} />
        </div>
          {remaining < 5 && reading.nextValue && <div className="fact"><div className="fact-text">
            <span className="fact-label">下一期验证码 · 刷新后使用</span>
            <output aria-label="下一期验证码"><CodeCells code={reading.nextValue} /></output>
          </div></div>}
        </div>}
  </section>;
}

export function HotpSection({ id, requireReprompt, used }: { id: string; requireReprompt: boolean; used(): void }) {
  const { busy, work, copy } = useOps();
  const dialogs = useDialogs();
  const [code, setCode] = useState<HotpCode>();
  return <section className="section">
    <h2>计数验证码（HOTP）</h2>
    <p className="hint">每次生成都会保存并推进计数器。仅在网站要求时生成；复制当前码不会再次推进。</p>
    {code && <div className="facts"><div className="fact"><div className="fact-text">
      <output aria-label="当前验证码"><span className="sr-only">{code.value}</span><CodeCells code={code.value} /></output>
      <span className="fact-label">本次计数 {code.counter}</span>
    </div><CopyButton label="复制验证码" disabled={busy} onCopy={() => copy(code.value)} /></div></div>}
    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void work(async () => {
      const proof = requireReprompt ? await dialogs.proof() : undefined;
      try {
        setCode(await request<HotpCode>({ type: 'next-hotp', id, proof }));
        used();
      } finally { if (proof) proof.secret = ''; }
    })}>{code ? '生成下一个验证码' : '生成验证码'}</button>
  </section>;
}

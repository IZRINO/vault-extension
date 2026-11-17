import { useEffect, useState } from 'react';
import { loadVaultOtp } from '../vault-otp';
import { request, type OtpCode, type VaultItem } from '../vault-messages';
import { CodeCells, CopyButton } from './components';
import { useDialogs } from './dialogs';
import { useOps } from './Main';

const now = () => Math.floor(Date.now() / 1000);
type Code = OtpCode & { issued: number };

export default function TotpSection({ setupKey }: { setupKey: string }) {
  const { busy, copy, fail } = useOps();
  const [reading, setReading] = useState<{ code: Code; remaining: number }>();
  const [error, setError] = useState(false);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setInterval> | undefined;
    let last = -1;
    setReading(undefined);
    setError(false);
    const failed = () => {
      if (active) { setReading(undefined); setError(true); }
      clearInterval(timer);
    };
    void loadVaultOtp().then(otp => {
      if (!active) return;
      const tick = () => {
        const time = now();
        if (time === last) return;
        last = time;
        try {
          const code = { ...JSON.parse(otp.wasm_otp_at(setupKey, time, 0)), issued: time } as Code;
          setReading({ code, remaining: code.validTo! - time });
        } catch { failed(); return; }
      };
      timer = setInterval(tick, 250);
      tick();
    }).catch(failed);
    return () => { active = false; clearInterval(timer); };
  }, [setupKey]);

  return <section className="section">
    <h2>两步验证码</h2>
    {error ? <p className="hint" role="alert">无法生成验证码。请在编辑页检查设置密钥，并确认设备时间正确。</p>
      : !reading ? <p className="hint" role="status">正在读取验证码…</p>
        : <div className="facts"><div className="fact">
          <div className="fact-text">
            <output aria-label="当前验证码" aria-live="off"><span className="sr-only">{reading.code.value}</span><CodeCells code={reading.code.value} /></output>
            <span className="fact-label">{reading.remaining} 秒后刷新</span>
          </div>
          <CopyButton label="复制验证码" disabled={busy} onCopy={async () => {
            try {
              const otp = await loadVaultOtp();
              const time = now();
              const code = JSON.parse(otp.wasm_otp_at(setupKey, time, 0)) as OtpCode;
              return await copy(code.value);
            } catch {
              fail(new Error('无法复制当前验证码，请检查设置密钥和设备时间。'));
              return false;
            }
          }} />
        </div>
          {reading.code.nextValue && <div className="fact"><div className="fact-text">
            <span className="fact-label">下一期验证码 · 刷新后使用</span>
            <output aria-label="下一期验证码"><CodeCells code={reading.code.nextValue} /></output>
          </div></div>}
        </div>}
  </section>;
}

export function HotpSection({ item, updated }: { item: VaultItem; updated(item: VaultItem): void }) {
  const { busy, work, copy } = useOps();
  const dialogs = useDialogs();
  const [code, setCode] = useState<OtpCode>();
  return <section className="section">
    <h2>计数验证码（HOTP）</h2>
    <p className="hint">每次生成都会保存并推进计数器。仅在网站要求时生成；复制当前码不会再次推进。</p>
    {code && <div className="facts"><div className="fact"><div className="fact-text">
      <output aria-label="当前验证码"><span className="sr-only">{code.value}</span><CodeCells code={code.value} /></output>
      <span className="fact-label">本次计数 {code.counter}</span>
    </div><CopyButton label="复制验证码" disabled={busy} onCopy={() => copy(code.value)} /></div></div>}
    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void work(async () => {
      const proof = item.requireReprompt ? await dialogs.proof() : undefined;
      try {
        const result = await request<{ code: OtpCode; item: VaultItem }>({ type: 'next-hotp', id: item.id, proof });
        setCode(result.code); updated(result.item);
      } finally { if (proof) proof.secret = ''; }
    })}>{code ? '生成下一个验证码' : '生成验证码'}</button>
  </section>;
}

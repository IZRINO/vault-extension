import { useEffect, useState } from 'react';
import { loadVaultOtp } from '../vault-otp';
import { CodeCells, CopyButton } from './components';
import { useOps } from './Main';

const now = () => Math.floor(Date.now() / 1000);
type Code = { value: string; validTo: number; issued: number };

function parseCode(text: string, issued: number): Code {
  const [value, validTo] = text.split(':');
  return { value: value!, validTo: Number(validTo), issued };
}

export default function TotpSection({ setupKey }: { setupKey: string }) {
  const { busy, copy, fail } = useOps();
  const [reading, setReading] = useState<{ code: Code; remaining: number }>();
  const [error, setError] = useState(false);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setInterval> | undefined;
    let current: Code | undefined;
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
          if (!current || time >= current.validTo || time < current.issued) {
            current = parseCode(otp.wasm_totp_at(setupKey, time), time);
          }
          setReading({ code: current, remaining: current.validTo - time });
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
              const code = time < reading.code.validTo && time >= reading.code.issued
                ? reading.code : parseCode(otp.wasm_totp_at(setupKey, time), time);
              return await copy(code.value);
            } catch {
              fail(new Error('无法复制当前验证码，请检查设置密钥和设备时间。'));
              return false;
            }
          }} />
        </div></div>}
  </section>;
}

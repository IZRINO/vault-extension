import { useState } from 'react';
import { request } from '../vault-messages';
import { useOps } from './Main';

export default function ScanOtp({ onChange }: { onChange(value: string): void }) {
  const { busy, work } = useOps();
  const [codes, setCodes] = useState<string[]>([]);
  return <div className="form">
    <button type="button" className="btn" disabled={busy} onClick={() => void work(async () =>
      setCodes(await request<string[]>({ type: 'scan-otp' })))}>扫描当前网页二维码</button>
    <p className="hint">先在二维码所在网页点击工具栏的 Vault 图标，再扫描。截图只在本机内存处理，选择后仍需保存凭证。</p>
    {codes.length > 0 && <fieldset className="form">
      <legend>选择要添加的验证码</legend>
      {codes.map((code, index) => {
        const label = decodeURIComponent(new URL(code).pathname.slice(1));
        return <button key={index} type="button" className="btn" onClick={() => { onChange(code); setCodes([]); }}>{label || `验证码 ${index + 1}`}</button>;
      })}
      <button type="button" className="btn btn-quiet" onClick={() => setCodes([])}>取消选择</button>
    </fieldset>}
  </div>;
}

import { useEffect, useState } from 'react';
import { autofillRequest } from '../autofill-messages';
import { defaultFlags, type SiteFlags } from '../autofill-settings';
import { SwitchRow } from './components';
import { useOps } from './Main';

export default function SiteSettings() {
  const { busy, work } = useOps();
  const [site, setSite] = useState<{ origin: string; host: string }>();
  const [flags, setFlags] = useState<SiteFlags>();
  useEffect(() => {
    let active = true;
    void browser.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
      if (!tab?.url || !/^https?:\/\//.test(tab.url)) return;
      const url = new URL(tab.url);
      const flags = await autofillRequest<SiteFlags>({ type: 'site', origin: url.origin });
      if (active) { setSite({ origin: url.origin, host: url.host }); setFlags(flags); }
    }).catch(() => undefined);
    return () => { active = false; };
  }, []);
  if (!site || !flags) return null;
  const update = (key: keyof SiteFlags, enabled: boolean) => void work(async () => {
    const next = { ...defaultFlags(), ...flags, [key]: !enabled };
    await autofillRequest({ type: 'site', origin: site.origin, flags: next });
    setFlags(next);
  });
  return <details className="fold">
    <summary>当前网站 · {site.host}</summary>
    <div className="fold-body">
      <SwitchRow label="显示填充图标" checked={!flags.inlineDisabled} disabled={busy} onChange={value => update('inlineDisabled', value)} />
      <SwitchRow label="提示保存新密码" checked={!flags.saveDisabled} disabled={busy} onChange={value => update('saveDisabled', value)} />
      <SwitchRow label="允许接管通行密钥" hint="此偏好将在通行密钥功能启用后生效。" checked={!flags.passkeyDisabled} disabled={busy} onChange={value => update('passkeyDisabled', value)} />
    </div>
  </details>;
}

import { useEffect, useState } from 'react';
import { autofillRequest } from '../autofill-messages';
import { SITE_FLAG_KEYS, type SiteFlags, type SiteRuleState } from '../autofill-settings';
import { SelectField, SwitchRow } from './components';
import { useOps } from './Main';

const labels: Record<keyof SiteFlags, string> = {
  inlineDisabled: '显示填充图标',
  saveDisabled: '提示保存新密码',
  passkeyDisabled: '允许接管通行密钥',
};

export default function SiteSettings() {
  const { busy, work, fail } = useOps();
  const [site, setSite] = useState<{ origin: string; host: string; rules: SiteRuleState }>();
  const [scope, setScope] = useState<{ origin: string; rule: string }>();
  useEffect(() => {
    let generation = 0;
    let tabId: number | undefined;
    const load = async () => {
      const request = ++generation;
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (request !== generation) return;
      tabId = tab?.id;
      setSite(undefined);
      if (!tab?.url || !/^https?:\/\//.test(tab.url)) return;
      const url = new URL(tab.url);
      try {
        const rules = await autofillRequest<SiteRuleState>({ type: 'site-rules', origin: url.origin });
        if (request === generation) setSite({ origin: url.origin, host: url.host, rules });
      } catch (error) {
        if (request === generation) fail(error);
      }
    };
    const refresh = () => void load().catch(() => undefined);
    const onUpdated = (id: number, change: { url?: string }) => {
      if (id === tabId && change.url != null) refresh();
    };
    browser.tabs.onActivated.addListener(refresh);
    browser.tabs.onUpdated.addListener(onUpdated);
    refresh();
    return () => {
      generation++;
      browser.tabs.onActivated.removeListener(refresh);
      browser.tabs.onUpdated.removeListener(onUpdated);
    };
  }, [fail]);
  if (!site) return null;
  const wildcard = scope?.origin === site.origin
    ? site.rules.wildcardRules.find(entry => entry.rule === scope.rule)
    : undefined;
  const rule = wildcard?.rule ?? site.origin;
  const flags = wildcard?.flags ?? site.rules.exact;
  const inherited = SITE_FLAG_KEYS.filter(key => site.rules.effective[key] && !site.rules.exact[key]);
  const update = (key: keyof SiteFlags, enabled: boolean) => void work(async () => {
    await autofillRequest({ type: 'site', origin: rule, flags: { [key]: !enabled } });
    const rules = await autofillRequest<SiteRuleState>({ type: 'site-rules', origin: site.origin });
    setSite(current => current?.origin === site.origin ? { ...current, rules } : current);
  });
  return <details className="fold">
    <summary>当前网站 · {site.host}</summary>
    <div className="fold-body">
      {site.rules.wildcardRules.length > 0 && <SelectField label="设置范围" value={rule} disabled={busy}
        onChange={selected => setScope({ origin: site.origin, rule: selected })}
        hint="子域规则沿用当前协议与端口，只作用于点号后所示域名的子域，不包含域名本身。">
        <option value={site.origin}>仅 {site.host}</option>
        {site.rules.wildcardRules.map(({ rule }) => <option key={rule} value={rule}>{rule.split('://')[1]}</option>)}
      </SelectField>}
      {inherited.length > 0 && <p className="hint" role="status">当前网页受子域规则限制。已关闭「{inherited.map(key => labels[key]).join('」、「')}」。</p>}
      {SITE_FLAG_KEYS.map(key => <SwitchRow key={key} label={labels[key]} checked={!flags[key]} disabled={busy}
        hint={key === 'passkeyDisabled' && flags[key] ? '由浏览器或系统处理通行密钥。' : undefined}
        onChange={value => update(key, value)} />)}
    </div>
  </details>;
}

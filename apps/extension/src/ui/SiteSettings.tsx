import { useEffect, useState } from 'react';
import { autofillRequest } from '../autofill-messages';
import { SITE_FLAG_KEYS, type SiteFlags, type SiteRuleState } from '../autofill-settings';
import { Plus, ScanLine, Trash2 } from 'lucide-react';
import { markKey, type LoginMark } from '../login-marks';
import { Ico, SelectField, SwitchRow } from './components';
import { useDialogs } from './dialogs';
import { useOps } from './Main';

const labels: Record<keyof SiteFlags, string> = {
  inlineDisabled: '显示填充图标',
  saveDisabled: '提示保存新密码',
  passkeyDisabled: '允许接管通行密钥',
};
type SiteMark = { origin: string; marks: LoginMark[] };
const markLabels = { username: '用户名', password: '密码', otp: '两步验证码' } as const;

export default function SiteSettings() {
  const { busy, work, fail, notify } = useOps();
  const dialogs = useDialogs();
  const [site, setSite] = useState<{ origin: string; host: string; rules: SiteRuleState }>();
  const [scope, setScope] = useState<{ origin: string; rule: string }>();
  const [siteMark, setSiteMark] = useState<SiteMark>();
  const [selectedMarkId, setSelectedMarkId] = useState<string>();
  useEffect(() => {
    let generation = 0;
    let tabId: number | undefined;
    const load = async () => {
      const request = ++generation;
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (request !== generation) return;
      tabId = tab?.id;
      setSite(undefined);
      setSiteMark(undefined);
      if (!tab?.url || !/^https?:\/\//.test(tab.url)) return;
      const url = new URL(tab.url);
      try {
        const [rules, marked] = await Promise.all([
          autofillRequest<SiteRuleState>({ type: 'site-rules', origin: url.origin }),
          autofillRequest<SiteMark>({ type: 'mark-manage' }).catch(() => undefined),
        ]);
        if (request === generation) setSite({ origin: url.origin, host: url.host, rules });
        if (request === generation && marked?.origin === url.origin) setSiteMark(marked);
      } catch (error) {
        if (request === generation) fail(error);
      }
    };
    const refresh = () => void load().catch(() => undefined);
    const onUpdated = (id: number, change: { url?: string }) => {
      if (id === tabId && change.url != null) refresh();
    };
    const onChanged = (changes: Record<string, unknown>, area: string) => {
      if (area !== 'local' || !Object.hasOwn(changes, 'loginMarksSealed')) return;
      const request = generation;
      void autofillRequest<SiteMark>({ type: 'mark-manage' }).then(marked => {
        if (request === generation) setSiteMark(marked);
      }).catch(() => undefined);
    };
    browser.tabs.onActivated.addListener(refresh);
    browser.tabs.onUpdated.addListener(onUpdated);
    browser.storage.onChanged.addListener(onChanged);
    refresh();
    return () => {
      generation++;
      browser.tabs.onActivated.removeListener(refresh);
      browser.tabs.onUpdated.removeListener(onUpdated);
      browser.storage.onChanged.removeListener(onChanged);
    };
  }, [fail]);
  if (!site) return null;
  const wildcard = scope?.origin === site.origin
    ? site.rules.wildcardRules.find(entry => entry.rule === scope.rule)
    : undefined;
  const rule = wildcard?.rule ?? site.origin;
  const flags = wildcard?.flags ?? site.rules.exact;
  const marks = siteMark?.origin === site.origin ? siteMark.marks : [];
  const mark = marks.find(mark => mark.id === selectedMarkId) ?? marks[0];
  const inherited = SITE_FLAG_KEYS.filter(key => site.rules.effective[key] && !site.rules.exact[key]);
  const update = (key: keyof SiteFlags, enabled: boolean) => void work(async () => {
    await autofillRequest({ type: 'site', origin: rule, flags: { [key]: !enabled } });
    const rules = await autofillRequest<SiteRuleState>({ type: 'site-rules', origin: site.origin });
    setSite(current => current?.origin === site.origin ? { ...current, rules } : current);
  });
  const startMarking = (key?: string) => void work(async () => {
    await autofillRequest({ type: 'mark-start', key });
    notify('已在当前网页打开标记。');
  });
  const toggleMark = (enabled: boolean) => void work(async () => {
    if (mark) setSiteMark(await autofillRequest<SiteMark>({ type: 'mark-enable', key: markKey(mark), enabled }));
  });
  const deleteMark = async () => {
    if (!mark || !await dialogs.confirm({ title: '删除这条登录框标记？', body: '已保存的账号和密码不会删除。', confirmLabel: '删除标记', danger: true })) return;
    await work(async () => { setSiteMark(await autofillRequest<SiteMark>({ type: 'mark-delete', key: markKey(mark) })); });
  };
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
      {marks.length > 1 && <SelectField label="当前页的登录框标记" value={mark?.id ?? ''} onChange={setSelectedMarkId} disabled={busy}>
        {marks.map((entry, index) => <option key={entry.id} value={entry.id}>{`标记 ${index + 1} · ${(Object.keys(entry.fields) as (keyof typeof markLabels)[]).map(role => markLabels[role]).join('、')}${entry.form.id || entry.form.name ? ` (${entry.form.id || entry.form.name})` : ''}`}</option>)}
      </SelectField>}
      <button type="button" className="btn" disabled={busy} onClick={() => startMarking(mark && markKey(mark))}><Ico of={ScanLine} />{mark ? '重新标记登录框' : '标记登录框'}</button>
      {mark && <>
        <button type="button" className="btn" disabled={busy} onClick={() => startMarking()}><Ico of={Plus} />标记其他表单或步骤</button>
        <SwitchRow label="应用这条标记" checked={mark.enabled} disabled={busy} onChange={toggleMark}
          hint={'仅本机 · ' + (Object.keys(mark.fields) as (keyof typeof markLabels)[]).map(role => markLabels[role]).join('、')} />
        <button type="button" className="btn" disabled={busy} onClick={() => void deleteMark()}><Ico of={Trash2} />删除标记</button>
      </>}
    </div>
  </details>;
}

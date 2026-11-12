import { useState } from 'react';
import type { VaultItem } from './vault-messages';
import { request } from './vault-messages';

export const kinds: Record<string, string> = { login: '登录', payment_card: '支付卡', identity: '身份与地址', developer: '开发者凭证' };
const fieldSets: Record<string, [string, string, boolean?][]> = {
  login: [['username', '用户名'], ['password', '密码', true]],
  payment_card: [['cardholderName', '持卡人'], ['cardNumber', '卡号', true], ['expMonth', '到期月份'], ['expYear', '到期年份'], ['cvv', '安全码', true], ['cardPin', '卡片 PIN', true], ['billingAddress', '账单地址']],
  identity: [['fullName', '姓名'], ['phone', '电话'], ['email', '电子邮件'], ['nationalIdOrPassport', '证件号码', true], ['country', '国家或地区'], ['province', '省份'], ['city', '城市'], ['addressLine', '详细地址'], ['postalCode', '邮政编码'], ['company', '公司'], ['taxId', '税号']],
  developer: [['serviceOrProduct', '服务或产品'], ['tokenOrLicense', '令牌或许可密钥', true], ['publicKey', '公钥'], ['privateKey', '私钥', true]],
};
export function newItem(kind = 'login', subtype = 'api_token'): VaultItem {
  return { id: '', title: '', data: { kind, subtype }, note: '', tags: [], customFields: [], pinned: false, requireReprompt: false, trashed: false };
}
export default function ItemEditor({ initial, save, close, copy, busy, fail }: {
  initial: VaultItem; save(item: VaultItem): Promise<void>; close(): void; copy(value: string): Promise<void>;
  busy: boolean; fail(error: unknown): void;
}) {
  const [item, setItem] = useState(initial);
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const update = (key: string, value: unknown) => setItem(old => ({ ...old, data: { ...old.data, [key]: value } }));
  const uris = (item.data.uris ?? []) as { uri: string; matchRule?: string }[];
  const history = (item.data.passwordHistory ?? []) as { password: string; changedAtMs: number }[];
  return <form className="editor" onSubmit={event => { event.preventDefault(); void save(item); }}>
    <div className="section-heading"><div><p className="eyebrow">{kinds[item.data.kind]}</p><h2>{item.id ? '编辑凭证' : '新建凭证'}</h2></div><button type="button" onClick={close}>返回</button></div>
    <label>名称<input autoFocus required maxLength={200} value={item.title} onChange={e => setItem({ ...item, title: e.target.value })} /></label>
    {item.data.kind === 'developer' && <label>凭证类型<select value={String(item.data.subtype)} onChange={e => update('subtype', e.target.value)}><option value="api_token">API 令牌</option><option value="license_key">软件许可证</option><option value="ssh_key">SSH 密钥</option></select></label>}
    {(fieldSets[item.data.kind] ?? []).map(([key, label, secret]) => <label key={key}>{label}<div className="field-row">
      {key === 'publicKey' || key === 'privateKey' ? <textarea aria-label={label} rows={3} className={secret && !revealed[key] ? 'concealed' : 'mono'} value={String(item.data[key] ?? '')} onChange={e => update(key, e.target.value)} />
        : <input aria-label={label} autoComplete="off" type={secret && !revealed[key] ? 'password' : 'text'} value={String(item.data[key] ?? '')} onChange={e => update(key, e.target.value)} />}
      {secret && <button type="button" aria-label={revealed[key] ? '隐藏' + label : '显示' + label} onClick={() => setRevealed({ ...revealed, [key]: !revealed[key] })}>{revealed[key] ? '隐藏' : '显示'}</button>}
      {secret && !!item.data[key] && <button type="button" aria-label={'复制' + label} onClick={() => void copy(String(item.data[key]))}>复制</button>}
    </div></label>)}
    {item.data.kind === 'login' && <>
      <button type="button" onClick={() => void request<string>({ type: 'generate-password', optionsJson: '{}' }).then(value => update('password', value)).catch(fail)}>生成随机密码</button>
      <fieldset><legend>网站与匹配规则</legend>{uris.map((uri, index) => <div className="uri-row" key={index}>
        <input aria-label={'网站 ' + (index + 1)} placeholder="https://example.com" value={uri.uri} onChange={e => update('uris', uris.map((u, i) => i === index ? { ...u, uri: e.target.value } : u))} />
        <select aria-label={'匹配规则 ' + (index + 1)} value={uri.matchRule ?? 'auto'} onChange={e => update('uris', uris.map((u, i) => i === index ? { ...u, matchRule: e.target.value === 'auto' ? undefined : e.target.value } : u))}>
          <option value="auto">自动</option><option value="base_domain">主域名</option><option value="host">主机与端口</option><option value="starts_with">前缀</option><option value="exact">完全一致</option><option value="regex">正则表达式</option><option value="never">从不匹配</option>
        </select><button type="button" aria-label={'移除网站 ' + (index + 1)} onClick={() => update('uris', uris.filter((_, i) => i !== index))}>移除</button>
      </div>)}<button type="button" onClick={() => update('uris', [...uris, { uri: '' }])}>添加网站</button></fieldset>
      {history.length > 0 && <details><summary>密码历史 · {history.length} 条</summary>{history.map((entry, index) => <div className="history" key={index}><span>{new Date(entry.changedAtMs).toLocaleString()}</span><button type="button" onClick={() => void copy(entry.password)}>复制历史密码</button></div>)}</details>}
    </>}
    {item.data.kind === 'developer' && <label>到期日期<input type="date" value={item.data.expiresAtMs ? new Date(Number(item.data.expiresAtMs)).toISOString().slice(0, 10) : ''} onChange={e => update('expiresAtMs', e.target.value ? Date.parse(e.target.value) : null)} /></label>}
    <label>备注<textarea rows={3} value={item.note} onChange={e => setItem({ ...item, note: e.target.value })} /></label>
    <label>标签<span className="hint">用逗号分隔</span><input value={item.tags.join(',')} onChange={e => setItem({ ...item, tags: e.target.value.split(',') })} /></label>
    <fieldset><legend>自定义字段</legend>{item.customFields.map((field, index) => <div className="custom-field" key={index}>
      <input aria-label={'字段名称 ' + (index + 1)} placeholder="名称" value={field.name} onChange={e => setItem({ ...item, customFields: item.customFields.map((f, i) => i === index ? { ...f, name: e.target.value } : f) })} />
      <input aria-label={'字段内容 ' + (index + 1)} autoComplete="off" type={field.hidden ? 'password' : 'text'} placeholder="内容" value={field.value} onChange={e => setItem({ ...item, customFields: item.customFields.map((f, i) => i === index ? { ...f, value: e.target.value } : f) })} />
      <label className="check"><input type="checkbox" checked={field.hidden} onChange={e => setItem({ ...item, customFields: item.customFields.map((f, i) => i === index ? { ...f, hidden: e.target.checked } : f) })} />敏感</label>
      <button type="button" onClick={() => void copy(field.value)}>复制</button><button type="button" onClick={() => setItem({ ...item, customFields: item.customFields.filter((_, i) => i !== index) })}>移除</button>
    </div>)}<button type="button" onClick={() => setItem({ ...item, customFields: [...item.customFields, { name: '', value: '', hidden: true }] })}>添加字段</button></fieldset>
    <label className="check"><input type="checkbox" checked={item.pinned} onChange={e => setItem({ ...item, pinned: e.target.checked })} />置顶</label>
    <label className="check"><input type="checkbox" checked={item.requireReprompt} onChange={e => setItem({ ...item, requireReprompt: e.target.checked })} />查看或修改前再次验证</label>
    <div className="actions"><button className="primary" disabled={busy} type="submit">保存凭证</button><button type="button" onClick={close}>取消</button></div>
  </form>;
}

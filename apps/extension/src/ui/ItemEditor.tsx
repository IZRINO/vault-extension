import { useEffect, useState } from 'react';
import { ArrowLeft, ChevronRight, Dices, Eye, EyeOff, Plus, Trash2 } from 'lucide-react';
import { request, type VaultItem } from '../vault-messages';
import { AreaField, Ico, SecretField, SelectField, SwitchRow, TextField } from './components';
import { developerFieldVisible, fieldSets, kinds, matchRules, subtypeNames, text } from './lib';
import { useOps } from './Main';

export default function ItemEditor({ initial, save, close, onDirty }: {
  initial: VaultItem; save(item: VaultItem): void; close(): void; onDirty(value: boolean): void;
}) {
  const [item, setItem] = useState(() => structuredClone(initial));
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const { busy, work } = useOps();
  // Compare actual content so typing and then undoing does not trigger a false warning.
  useEffect(() => { onDirty(JSON.stringify(item) !== JSON.stringify(initial)); }, [item, initial, onDirty]);
  const update = (key: string, value: unknown) => setItem(old => ({ ...old, data: { ...old.data, [key]: value } }));
  const uris = (item.data.uris ?? []) as { uri: string; matchRule?: string }[];
  const fields = (fieldSets[item.data.kind] ?? []).filter(field => item.data.kind !== 'developer' ||
    developerFieldVisible(field.key, text(item.data.subtype), item.data[field.key]));
  return <form className="view form" onSubmit={event => { event.preventDefault(); if (!busy) save(item); }}>
    <div className="view-head">
      <button type="button" className="icon-btn" aria-label="返回" onClick={close}><Ico of={ArrowLeft} /></button>
      <h1>{item.id ? '编辑' : '新建'}{kinds[item.data.kind] ?? '凭证'}</h1>
    </div>
    <TextField label="名称" value={item.title} onChange={title => setItem({ ...item, title })} required maxLength={200} autoFocus placeholder="例如：常用邮箱" />
    {item.data.kind === 'developer' && <SelectField label="凭证类型" value={text(item.data.subtype)} onChange={value => update('subtype', value)}>
      {Object.entries(subtypeNames).map(([value, name]) => <option key={value} value={value}>{name}</option>)}
    </SelectField>}
    {fields.map(field => field.multiline ? <AreaField key={field.key} label={field.label} value={text(item.data[field.key])}
      onChange={value => update(field.key, value)} rows={3} mono autoComplete="off" spellCheck={false}
      concealed={field.secret && !revealed[field.key]} after={field.secret && <button type="button" className="icon-btn"
        aria-label={(revealed[field.key] ? '隐藏' : '显示') + field.label} onClick={() => setRevealed({ ...revealed, [field.key]: !revealed[field.key] })}>
        <Ico of={revealed[field.key] ? EyeOff : Eye} /></button>} />
      : field.secret ? <SecretField key={field.key} label={field.label} value={text(item.data[field.key])} autoComplete="off"
        inputMode={field.mode} onChange={value => update(field.key, value)} />
        : <TextField key={field.key} label={field.label} value={text(item.data[field.key])} autoComplete="off"
          inputMode={field.mode} onChange={value => update(field.key, value)} />)}
    {item.data.kind === 'login' && <>
      <button type="button" className="btn" disabled={busy} onClick={() => void work(async () => update('password', await request<string>({ type: 'generate-password', optionsJson: '{}' })))}>
        <Ico of={Dices} />生成随机密码</button>
      <fieldset><legend>网站与匹配规则</legend>
        {uris.map((uri, index) => <div className="uri-row" key={index}>
          <input className="input" aria-label={'网站 ' + (index + 1)} placeholder="https://example.com" value={uri.uri}
            onChange={event => update('uris', uris.map((entry, i) => i === index ? { ...entry, uri: event.target.value } : entry))} />
          <div><select className="select" aria-label={'匹配规则 ' + (index + 1)} value={uri.matchRule ?? 'auto'}
            onChange={event => update('uris', uris.map((entry, i) => i === index ? { ...entry, matchRule: event.target.value === 'auto' ? undefined : event.target.value } : entry))}>
            {matchRules.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select><button type="button" className="icon-btn" aria-label={'移除网站 ' + (index + 1)}
            onClick={() => update('uris', uris.filter((_, i) => i !== index))}><Ico of={Trash2} /></button></div>
        </div>)}
        <button type="button" className="btn" onClick={() => update('uris', [...uris, { uri: '' }])}><Ico of={Plus} />添加网站</button>
      </fieldset>
      <details className="fold">
        <summary>两步验证码（可选）<Ico of={ChevronRight} /></summary>
        <div className="fold-body">
          <SecretField label="验证码设置密钥" value={text(item.data.totpUri)} maxLength={4096} autoComplete="off" spellCheck={false}
            hint="从网站的两步验证设置页粘贴密钥（Base32）或 otpauth://totp 链接，不是当前的 6 位验证码。清空可移除设置。"
            onChange={value => update('totpUri', value || null)} />
          <p className="hint">请保留网站提供的恢复码。把密码和验证码放在同一个库里时，别人解锁密码库就能同时取到两者。</p>
        </div>
      </details>
    </>}
    {item.data.kind === 'developer' && <TextField label="到期日期" type="date"
      value={item.data.expiresAtMs ? new Date(Number(item.data.expiresAtMs)).toISOString().slice(0, 10) : ''}
      onChange={value => update('expiresAtMs', value ? Date.parse(value) : null)} />}
    <AreaField label="备注" rows={3} value={item.note} onChange={note => setItem({ ...item, note })} />
    <TextField label="标签" hint="多个标签用逗号分隔。" value={item.tags.join(',')} onChange={value => setItem({ ...item, tags: value.split(/[,，]/) })} />
    <SwitchRow label="置顶" hint="在列表前面显示，方便下次取用。" checked={item.pinned} onChange={pinned => setItem({ ...item, pinned })} />
    <SwitchRow label="查看或修改前再次验证" hint="取用这条凭证时，再输入主密码或本机 PIN。" checked={item.requireReprompt} onChange={requireReprompt => setItem({ ...item, requireReprompt })} />
    <details className="fold" open={item.customFields.length ? true : undefined}>
      <summary>自定义字段{item.customFields.length > 0 && ` · ${item.customFields.length}`}<Ico of={ChevronRight} /></summary>
      <div className="fold-body">{item.customFields.map((field, index) => {
        const change = (patch: Partial<typeof field>) => setItem({ ...item, customFields: item.customFields.map((entry, i) => i === index ? { ...entry, ...patch } : entry) });
        return <div className="custom-row" key={index}>
          <TextField label={'字段名称 ' + (index + 1)} value={field.name} onChange={name => change({ name })} required />
          {field.hidden ? <SecretField label={'字段内容 ' + (index + 1)} autoComplete="off" value={field.value} onChange={value => change({ value })} />
            : <TextField label={'字段内容 ' + (index + 1)} value={field.value} onChange={value => change({ value })} />}
          <div><label className="check"><input type="checkbox" checked={field.hidden} onChange={event => change({ hidden: event.target.checked })} />敏感内容</label>
            <button type="button" className="icon-btn" aria-label={'移除字段 ' + (index + 1)} onClick={() => setItem({ ...item, customFields: item.customFields.filter((_, i) => i !== index) })}><Ico of={Trash2} /></button></div>
        </div>;
      })}
        <button type="button" className="btn" onClick={() => setItem({ ...item, customFields: [...item.customFields, { name: '', value: '', hidden: true }] })}><Ico of={Plus} />添加字段</button>
      </div>
    </details>
    <div className="form-bar"><button type="button" className="btn" disabled={busy} onClick={close}>取消</button>
      <button className="btn btn-primary" disabled={busy}>{busy ? '正在保存…' : '保存凭证'}</button></div>
  </form>;
}

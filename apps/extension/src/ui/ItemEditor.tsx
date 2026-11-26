import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ChevronRight, Dices, Eye, EyeOff, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { MAX_OTP_SETUP_LENGTH, request, STALE_EDIT, type VaultItem } from '../vault-messages';
import { AreaField, Ico, SecretField, SelectField, SwitchRow, TextField } from './components';
import { developerFieldVisible, fieldSets, formatExpiryDate, kinds, matchRules, subtypeNames, text } from './lib';
import { useOps } from './Main';
import { applyDraftField, rebaseDraft, type DraftConflict } from './edit-draft';

export default function ItemEditor({ initial, save, loadLatest, close, onDirty }: {
  initial: VaultItem; save(item: VaultItem): Promise<void>; loadLatest(id: string): Promise<VaultItem>; close(): void; onDirty(value: boolean): void;
}) {
  const [item, setItem] = useState(() => structuredClone(initial));
  const [base, setBase] = useState(initial);
  const [stale, setStale] = useState(false);
  const [review, setReview] = useState<DraftConflict[]>();
  const draft = useRef(item);
  draft.current = item;
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const { busy, work } = useOps();
  // Compare actual content so typing and then undoing does not trigger a false warning.
  useEffect(() => { onDirty(!!review?.length || JSON.stringify(item) !== JSON.stringify(base)); }, [item, base, review, onDirty]);
  const recover = () => void work(async () => {
    const latest = await loadLatest(base.id);
    const result = rebaseDraft(base, draft.current, latest);
    setBase(latest); setItem(result.item); setReview(result.conflicts); setStale(false); setRevealed({});
  });
  const resolve = (conflict: DraftConflict, mine: boolean) => {
    if (mine) setItem(value => applyDraftField(value, conflict));
    setReview(current => current?.filter(field => field !== conflict));
  };
  const submit = () => void work(async () => {
    try { await save(item); }
    catch (error) {
      if (error instanceof Error && error.message === STALE_EDIT) setStale(true);
      throw error;
    }
  });
  const update = (key: string, value: unknown) => setItem(old => ({ ...old, data: { ...old.data, [key]: value } }));
  const uris = (item.data.uris ?? []) as { uri: string; matchRule?: string }[];
  const fields = (fieldSets[item.data.kind] ?? []).filter(field => item.data.kind !== 'developer' ||
    developerFieldVisible(field.key, text(item.data.subtype), item.data[field.key]));
  return <form className="view form" onSubmit={event => { event.preventDefault(); if (!busy && !stale && !review?.length) submit(); }}>
    <div className="view-head">
      <button type="button" className="icon-btn" aria-label="返回" onClick={close}><Ico of={ArrowLeft} /></button>
      <h1>{item.id ? '编辑' : '新建'}{kinds[item.data.kind] ?? '凭证'}</h1>
    </div>
    {stale && <button className="btn" type="button" disabled={busy} onClick={recover}><Ico of={RefreshCw} />载入最新版本并保留草稿</button>}
    {review && !stale && <div className="banner banner-warn" aria-live="polite">
      {review.length ? <><p>以下字段也在其他地方改过。表单先显示库中版本，请逐项确认。</p>
        {review.map(conflict => <div key={conflict.key}><strong>{conflict.label}</strong>
          {!conflict.canUseMine && <p>为保护已有数据，不会重放这个字段的旧值；保留最新版本后可重新编辑。</p>}
          <button type="button" className="btn" onClick={() => resolve(conflict, false)}>保留库中版本</button>
          {conflict.canUseMine && <button type="button" className="btn" onClick={() => resolve(conflict, true)}>采用我的修改</button>}
        </div>)}</> : '已在最新版本上保留你的修改，尚未保存。请检查表单后保存。'}
    </div>}
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
          <SecretField label="验证码设置密钥" value={text(item.data.totpUri)} maxLength={MAX_OTP_SETUP_LENGTH} autoComplete="off" spellCheck={false}
            hint="粘贴网站提供的 Base32 密钥或 otpauth:// 链接，支持 TOTP、HOTP 和 Steam。HOTP 链接需含 counter 计数器；清空可移除设置。"
            onChange={value => update('totpUri', value || null)} />
          <p className="hint">请保留网站提供的恢复码。把密码和验证码放在同一个库里时，别人解锁密码库就能同时取到两者。</p>
          <ScanOtp onChange={value => update('totpUri', value)} />
        </div>
      </details>
    </>}
    {item.data.kind === 'developer' && <TextField label="到期日期" type="date" min="1970-01-01" max="9999-12-31"
      value={formatExpiryDate(item.data.expiresAtMs)}
      hint="按 UTC 日期记录。到期前 30 天开始提醒，清空日期可以停止提醒。"
      onChange={value => {
        if (!value) update('expiresAtMs', null);
        else {
          const time = Date.parse(value + 'T00:00:00Z');
          if (formatExpiryDate(time) === value) update('expiresAtMs', time);
        }
      }} />}
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
      <button className="btn btn-primary" disabled={busy || stale || !!review?.length}>{busy ? '正在保存…' : '保存凭证'}</button></div>
  </form>;
}
import ScanOtp from './ScanOtp';

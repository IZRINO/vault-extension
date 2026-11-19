import { useEffect, useState } from 'react';
import { ArrowLeft, Eye, GitCompareArrows } from 'lucide-react';
import { request, type ConflictReview, type ConflictRule, type ConflictVersion, type VaultConflict } from '../vault-messages';
import { AreaField, ErrorBanner, Ico, SecretField, SelectField, TextField } from './components';
import { errorText } from './lib';

const label: Record<string, string> = {
  '$item': '整条凭证', '$duplicate': '同站点账号', title: '名称', note: '备注', tags: '标签', customFields: '自定义字段',
  pinned: '置顶', trashed: '回收站状态', data: '凭证类型', 'data.username': '用户名', 'data.password': '密码',
  'data.uris': '网站', 'data.totpUri': '二次验证码', 'data.cardNumber': '卡号', 'data.cvv': '安全码',
  'data.cardholderName': '持卡人', 'data.passkeys': '通行密钥', 'data.privateKey': '私钥',
};
const modeText: Record<ConflictRule['mode'], string> = {
  ours: '选版本 A', theirs: '选版本 B', both: '保留双份', fields: '逐字段选择',
};

function show(value: unknown) {
  if (value == null) return '—';
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function Diff({ base, value }: { base: string; value: string }) {
  if (base === value) return <>{value}</>;
  let start = 0, end = 0;
  while (start < base.length && start < value.length && base[start] === value[start]) start++;
  while (end < base.length - start && end < value.length - start &&
    base[base.length - end - 1] === value[value.length - end - 1]) end++;
  return <>{value.slice(0, start)}<mark>{value.slice(start, value.length - end) || '∅'}</mark>{end > 0 && value.slice(-end)}</>;
}

function versionTitle(version: ConflictVersion | null) {
  if (!version) return '不存在或已永久删除';
  return `${version.title || '未命名'}${version.trashed ? ' · 在回收站' : ''}`;
}

function modesFor(row: VaultConflict, mode: ConflictRule['mode']) {
  const extra = row.otherMatches?.length ?? 0;
  if (extra && mode === 'theirs') return `保留网盘的 ${extra + 1} 条`;
  if (extra && mode === 'both') return `保留全部 ${extra + 2} 条`;
  const chosen = mode === 'ours' ? row.ours : mode === 'theirs' ? row.theirs : undefined;
  const other = mode === 'ours' ? row.theirs : mode === 'theirs' ? row.ours : undefined;
  if (!chosen && other) return '确认永久删除';
  if (chosen?.trashed && other && !other.trashed) return '确认移入回收站';
  if (chosen && !chosen.trashed && (!other || other.trashed) && row.base) return '恢复并保留修改';
  return modeText[mode];
}

function VersionDiff({ row, compared, heading }: { row: VaultConflict; compared: ConflictVersion | null; heading: string }) {
  const columns = [
    { heading: '共同版本', version: row.base },
    { heading: '版本 A', version: row.ours },
    { heading, version: compared },
  ];
  const fields = row.fields.includes('$duplicate') ? ['data.username', 'data.uris', 'data.password', 'data.totpUri'] : row.fields;
  return <div className="sync-diff" role="table" aria-label={`冲突版本差异：${heading}`}>
    <div className="sync-diff-row" role="row">
      {columns.map(({ heading, version }) => <div role="columnheader" key={heading}>
        <b>{heading}</b><span>{version?.source || versionTitle(version)}</span>
        {version?.source && <span>{versionTitle(version)}</span>}
        {version && version.time > 0 && <time>{new Date(version.time).toLocaleString()}</time>}
      </div>)}
    </div>
    {fields.map(field => <div role="rowgroup" key={field}>
      <span className="sync-diff-field">{label[field] ?? field.replace(/^data\./, '')}</span>
      <div role="row" className="sync-diff-row">{columns.map(({ heading, version }) => <span key={heading} role="cell">
        <Diff base={show(row.base?.values[field])} value={show(version?.values[field])} />
      </span>)}</div>
    </div>)}
  </div>;
}

export function SyncConflicts({ close, changed }: { close(): void; changed(): Promise<void> }) {
  const [review, setReview] = useState<ConflictReview>();
  const [rules, setRules] = useState<Record<string, ConflictRule>>({});
  const [stage, setStage] = useState<'select' | 'preview' | 'reveal'>('select');
  const [secret, setSecret] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    void request<ConflictReview>({ type: 'webdav-conflicts' }).then(value => { if (active) setReview(value); },
      error => { if (active) setError(errorText(error)); });
    return () => { active = false; };
  }, []);
  const rows = review?.rows ?? [];
  const splittable = rows.filter(row => row.ours && row.theirs);
  const grouped = rows.some(row => row.otherMatches?.length);
  const selected = rows.map(row => rules[row.id]).filter((rule): rule is ConflictRule => !!rule);
  const ready = selected.length > 0 && selected.every(rule => rule.mode !== 'fields' ||
    rows.find(row => row.id === rule.id)?.fields.every(field => !!rule.fields?.[field]));
  function choose(id: string, mode: ConflictRule['mode'] | '') {
    setRules(old => {
      const next = { ...old };
      if (!mode) delete next[id]; else next[id] = { id, mode };
      return next;
    });
  }
  function update(id: string, change: Partial<ConflictRule>) {
    setRules(old => old[id] ? { ...old, [id]: { ...old[id], ...change } } : old);
  }
  async function submit() {
    if (!review || busy) return;
    setBusy(true); setError('');
    const proof = { method: 'master' as const, secret };
    try {
      if (stage === 'reveal') {
        const next = await request<ConflictReview>({ type: 'webdav-conflicts', reveal: proof });
        if (next.stamp !== review.stamp) setRules({});
        setReview(next); setStage('select');
      } else if (stage === 'preview' && ready) {
        const remaining = await request<number>({ type: 'webdav-resolve', stamp: review.stamp, rules: selected, proof });
        await changed();
        if (!remaining) close();
        else {
          setReview(await request<ConflictReview>({ type: 'webdav-conflicts' }));
          setRules({}); setStage('select');
        }
      }
    } catch (e) {
      const message = errorText(e);
      if (message.includes('重新预览')) {
        const next = await request<ConflictReview>({ type: 'webdav-conflicts' }).catch(() => undefined);
        if (next) { setReview(next); setRules({}); setStage('select'); }
      }
      setError(message);
    }
    finally { setBusy(false); setSecret(''); }
  }
  return <div className="form sync-conflicts">
    <div className="actions">
      <button className="btn" type="button" disabled={busy} onClick={() => stage === 'select' ? close() : (setSecret(''), setStage('select'))}>
        <Ico of={ArrowLeft} />返回
      </button>
      <h3><Ico of={GitCompareArrows} />同步冲突{rows.length > 0 ? ` · ${rows.length}` : ''}</h3>
    </div>
    {error && <ErrorBanner text={error} />}
    {review && !rows.length && <p className="hint">没有待裁决的凭证。</p>}
    {stage === 'select' && rows.length > 0 && <>
      <div className="actions">
        <button className="btn" type="button" onClick={() => setRules(Object.fromEntries(rows.map(row => [row.id, { id: row.id, mode: 'ours' }])))}>全部选版本 A</button>
        <button className="btn" type="button" onClick={() => setRules(Object.fromEntries(rows.map(row => [row.id, { id: row.id, mode: 'theirs' }])))}>{grouped ? '全部采用网盘版本' : '全部选版本 B'}</button>
        {splittable.length > 0 && <button className="btn" type="button"
          onClick={() => setRules(Object.fromEntries(splittable.map(row => [row.id, { id: row.id, mode: 'both' }])))}>
          {grouped ? `保留 ${splittable.length} 项的所有版本` : splittable.length === rows.length ? '全部保留双份' : `为 ${splittable.length} 项保留双份`}
        </button>}
        <button className="btn" type="button" onClick={() => setStage('reveal')}><Ico of={Eye} />验证后显示受保护的差异</button>
      </div>
      {rows.map(row => {
        const rule = rules[row.id];
        const extra = row.otherMatches ?? [];
        return <details className="fold" key={row.id}>
          <summary>{row.ours?.title || row.theirs?.title || row.base?.title || '已删除凭证'}{extra.length > 0 && ` · ${extra.length + 1} 个网盘版本`}{rule && ` · ${modesFor(row, rule.mode)}`}</summary>
          <div className="fold-body form">
            <VersionDiff row={row} compared={row.theirs} heading={extra.length ? '网盘版本 1' : '版本 B'} />
            {extra.map((candidate, index) => <VersionDiff key={index} row={row} compared={candidate} heading={`网盘版本 ${index + 2}`} />)}
            <SelectField label="裁决" value={rule?.mode ?? ''} onChange={value => choose(row.id, value as ConflictRule['mode'] | '')}>
              <option value="">暂不处理</option><option value="ours">{modesFor(row, 'ours')}</option><option value="theirs">{modesFor(row, 'theirs')}</option>
              {row.ours && row.theirs && <option value="both">{modesFor(row, 'both')}</option>}
              {!row.fields.some(field => field.startsWith('$')) && <option value="fields">逐字段选择</option>}
            </SelectField>
            {rule?.mode === 'fields' && row.fields.map(field => <SelectField key={field} label={label[field] ?? field} value={rule.fields?.[field] ?? ''}
              onChange={value => update(row.id, { fields: { ...rule.fields, [field]: value as 'ours' | 'theirs' } })}>
              <option value="">请选择</option><option value="ours">版本 A</option><option value="theirs">版本 B</option>
            </SelectField>)}
            {rule && rule.mode !== 'both' && !(rule.mode === 'theirs' && extra.length) && <details className="fold fold-plain">
              <summary>调整名称或备注</summary><div className="fold-body form">
                <TextField label="新名称（可选）" value={rule.title ?? ''} maxLength={1024} onChange={title => update(row.id, { title: title || undefined })} />
                <AreaField label="新备注（可选）" value={rule.note ?? ''} maxLength={16384} onChange={note => update(row.id, { note: note || undefined })} />
              </div>
            </details>}
          </div>
        </details>;
      })}
      <button className="btn btn-primary" type="button" disabled={!ready} onClick={() => setStage('preview')}>预览 {selected.length} 项裁决</button>
    </>}
    {stage !== 'select' && <form className="form" onSubmit={e => { e.preventDefault(); void submit(); }}>
      {stage === 'preview' && <ul className="sync-preview">{selected.map(rule => {
        const row = rows.find(item => item.id === rule.id);
        const keptRemote = [row?.theirs, ...(row?.otherMatches ?? [])].flatMap(version => version ? [versionTitle(version)] : []);
        return <li key={rule.id}><b>{rule.title ?? row?.ours?.title ?? row?.theirs?.title ?? '凭证'}</b> · {row ? modesFor(row, rule.mode) : modeText[rule.mode]}
          {keptRemote.length > 1 && rule.mode !== 'ours' && <span>保留：{[...(rule.mode === 'both' ? [versionTitle(row?.ours ?? null)] : []), ...keptRemote].join('、')}</span>}
          {rule.mode === 'fields' && <span>{Object.entries(rule.fields ?? {}).map(([field, side]) => `${label[field] ?? field}：${side === 'ours' ? '版本 A' : '版本 B'}`).join('、')}</span>}
        </li>;
      })}</ul>}
      <SecretField label="当前主密码" value={secret} onChange={setSecret} required maxLength={1024} disabled={busy} autoComplete="current-password" />
      <button className="btn btn-primary" disabled={busy}>{stage === 'reveal' ? '验证并显示差异' : '确认裁决'}</button>
    </form>}
  </div>;
}

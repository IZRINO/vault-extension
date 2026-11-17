import { useState } from 'react';
import { ArrowLeft, ChevronRight, ExternalLink, Eye, EyeOff, MoreHorizontal, Pencil, ShieldCheck, Trash2 } from 'lucide-react';
import { request, type VaultItem } from '../vault-messages';
import { CopyButton, Ico, MenuButton } from './components';
import { useDialogs } from './dialogs';
import { developerFieldVisible, fieldSets, formatDateTime, kinds, openableUrl, plateText, subtypeNames, text } from './lib';
import { useOps } from './Main';
import TotpSection, { HotpSection } from './TotpSection';

export function Fact({ label, value, secret = false }: { label: string; value: string; secret?: boolean }) {
  const [shown, setShown] = useState(false);
  const { busy, copy } = useOps();
  return <div className="fact">
    <div className="fact-text"><span className="fact-label">{label}</span>
      <span className={'fact-value' + (secret ? ' mono' : '')}>{secret && !shown ? '••••••••••••' : value || '未填写'}</span></div>
    {secret && value && <button type="button" className="icon-btn" aria-label={(shown ? '隐藏' : '显示') + label} onClick={() => setShown(!shown)}><Ico of={shown ? EyeOff : Eye} /></button>}
    {value && <CopyButton label={'复制' + label} onCopy={() => copy(value)} disabled={busy} />}
  </div>;
}

export default function ItemDetail({ item, back, edit, setTrashed, remove, updated }: {
  item: VaultItem; back(): void; edit(): void; setTrashed(trashed: boolean): void; remove(): void; updated(item: VaultItem): void;
}) {
  const ops = useOps();
  const dialogs = useDialogs();
  const [onlineNotice, setOnlineNotice] = useState('');
  const [onlineConfirmed, setOnlineConfirmed] = useState(false);
  const authenticatorOnly = item.data.kind === 'login' && !!item.data.totpUri && !item.data.password;
  const fields = (fieldSets[item.data.kind] ?? []).filter(field => item.data.kind !== 'developer' ||
    developerFieldVisible(field.key, text(item.data.subtype), item.data[field.key]))
    .filter(field => !authenticatorOnly || field.key !== 'password');
  const uris = (item.data.uris ?? []) as { uri: string }[];
  const history = (item.data.passwordHistory ?? []) as { password: string; changedAtMs: number }[];
  function checkOnline() {
    // Request permission directly in this click's user activation.
    void browser.permissions.request({ origins: ['https://api.pwnedpasswords.com/*'] }).then(granted => {
      if (!granted) { setOnlineNotice('没有授权联网，本次未查询。'); return; }
      return ops.work(async () => {
        const proof = item.requireReprompt ? await dialogs.proof() : undefined;
        try {
          const count = await request<number>({ type: 'hibp', id: item.id, proof });
          setOnlineNotice(count ? `这个密码出现在泄露数据中 ${count} 次，请尽快更换。` : '本次查询未发现泄露记录，仍建议每个网站使用不同密码。');
        } finally { if (proof) proof.secret = ''; }
      });
    }).catch(ops.fail);
  }
  return <div className="view">
    <div className="view-head"><button type="button" className="icon-btn" aria-label="返回" onClick={back}><Ico of={ArrowLeft} /></button><h1>凭证详情</h1>
      {!item.trashed && <button type="button" className="btn btn-s" disabled={ops.busy} onClick={edit}><Ico of={Pencil} />编辑</button>}
      <MenuButton className="icon-btn" label="更多操作" disabled={ops.busy} entries={item.trashed
        ? [{ label: '从回收站恢复', onSelect: () => setTrashed(false) }, { label: '永久删除', danger: true, onSelect: remove }]
        : [{ label: '移入回收站', icon: Trash2, danger: true, onSelect: () => setTrashed(true) }]}><Ico of={MoreHorizontal} /></MenuButton>
    </div>
    <div className="identity"><span className="plate plate-l" data-kind={item.data.kind} aria-hidden="true">{plateText(item.title)}</span>
      <div><h2>{item.title}</h2><p>{authenticatorOnly ? '两步验证码' : item.data.kind === 'developer' ? subtypeNames[text(item.data.subtype)] : kinds[item.data.kind]}{item.pinned && ' · 已置顶'}{item.requireReprompt && ' · 需要再次验证'}</p></div></div>
    {item.trashed && <div className="banner banner-warn">这条凭证在回收站里。恢复后可以继续使用。</div>}
    <div className="facts">{fields.map(field => <Fact key={field.key} label={field.label} value={text(item.data[field.key])} secret={field.secret} />)}</div>
    {item.data.kind === 'login' && !item.trashed && !!item.data.totpUri && (
      text(item.data.totpUri).trim().startsWith('otpauth://hotp/')
        ? <HotpSection item={item} updated={updated} /> : <TotpSection setupKey={text(item.data.totpUri)} />)}
    {uris.length > 0 && <section className="section"><h2>网站</h2><div className="facts">{uris.map((uri, i) => {
      const url = openableUrl(uri.uri);
      return <div className="fact" key={i}><div className="fact-text"><span className="fact-value">{uri.uri}</span></div>
        {url && <a className="icon-btn" href={url} target="_blank" rel="noreferrer noopener" aria-label={'打开网站 ' + uri.uri}><Ico of={ExternalLink} /></a>}</div>;
    })}</div></section>}
    {item.note && <section className="section"><h2>备注</h2><div className="facts"><Fact label="备注" value={item.note} /></div></section>}
    {item.customFields.length > 0 && <section className="section"><h2>自定义字段</h2><div className="facts">
      {item.customFields.map((field, i) => <Fact key={i} label={field.name} value={field.value} secret={field.hidden} />)}</div></section>}
    {item.tags.length > 0 && <div className="tags">{item.tags.map((tag, i) => <span className="tag" key={i}>{tag}</span>)}</div>}
    {history.length > 0 && <details className="fold"><summary>密码历史 · {history.length} 条<Ico of={ChevronRight} /></summary>
      <div className="fold-body">{history.map((entry, i) => <Fact key={i} label={formatDateTime(entry.changedAtMs)} value={entry.password} secret />)}</div></details>}
    {item.data.kind === 'login' && !authenticatorOnly && !item.trashed && <details className="fold"><summary>在线泄露检查<Ico of={ChevronRight} /></summary><div className="fold-body">
      <p className="hint">可选操作。向 Have I Been Pwned 发送密码指纹的前 5 位，不发送密码原文，也不发送网站和账号。</p>
      <label className="check"><input type="checkbox" checked={onlineConfirmed} onChange={event => setOnlineConfirmed(event.target.checked)} />我同意本次联网查询</label>
      <button type="button" className="btn" disabled={ops.busy || !onlineConfirmed} onClick={checkOnline}><Ico of={ShieldCheck} />在线泄露检查</button>
      {onlineNotice && <p role="status">{onlineNotice}</p>}
    </div></details>}
    {item.updatedAtMs && <p className="meta">上次更新：{formatDateTime(item.updatedAtMs)}</p>}
  </div>;
}

import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { request, type ItemSummary } from '../vault-messages';
import { Ico } from './components';
import { useOps } from './Main';

interface Report {
  totalLoginItems: number;
  weakItems: { itemId: string; title: string; warnings: string[] }[];
  reusedGroups: { itemIds: string[]; titles: string[] }[];
  missing2faItemIds: string[];
}
export default function Audit({ open, items }: { open(id: string): void; items: ItemSummary[] | undefined }) {
  const { busy, work } = useOps();
  const [report, setReport] = useState<Report>();
  const titles = report?.missing2faItemIds.length ? new Map(items?.map(item => [item.id, item.title])) : undefined;
  return <div className="view">
    <h1 className="page-title">密码体检</h1>
    <p className="lede">查找弱密码、重复密码和未关联验证器的高敏登录项。检查只在本机进行。</p>
    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void work(async () => setReport(await request<Report>({ type: 'audit' })))}><Ico of={ShieldCheck} />开始本地检查</button>
    {report && <>
      <p role="status">已检查 {report.totalLoginItems} 个登录项。</p>
      <section className="section"><h2>弱密码 · {report.weakItems.length}</h2>{report.weakItems.map(item =>
        <button type="button" className="finding" key={item.itemId} disabled={busy} onClick={() => open(item.itemId)}><strong>{item.title}</strong><span>{item.warnings.join('；')}</span></button>)}</section>
      <section className="section"><h2>重复密码 · {report.reusedGroups.length} 组</h2>{report.reusedGroups.map((group, i) =>
        <div className="finding" key={i}><strong>{group.titles.join('、')}</strong><span>这些登录项用了同一个密码，建议逐一更换。</span>
          {group.itemIds?.map((id, n) => <button type="button" className="btn btn-s" key={id} onClick={() => open(id)}>查看 {group.titles[n]}</button>)}</div>)}</section>
      <section className="section">
        <h2>高敏登录项未关联验证器 · {report.missing2faItemIds.length}</h2>
        <p className="hint">检查常见高敏网站和设为再次验证的登录项。本地检查无法判断网站是否已启用两步验证。请到网站的安全设置确认；如果已用独立验证器或安全密钥，不用重复设置。</p>
        {report.missing2faItemIds.map(id => <div className="finding" key={id}>
          <strong>{titles?.get(id) ?? '未在当前列表中找到该凭证'}</strong>
          <button type="button" className="btn btn-s" disabled={busy || !titles?.has(id)}
            aria-label={`查看凭证：${titles?.get(id) ?? '未找到'}`} onClick={() => open(id)}>查看凭证</button>
        </div>)}
      </section>
      {!report.weakItems.length && !report.reusedGroups.length && !report.missing2faItemIds.length && <div className="banner banner-ok"><Ico of={ShieldCheck} />
        {report.totalLoginItems ? '本次检查未发现上述问题。' : '还没有可检查的登录项，先到密码库添加一条。'}</div>}
    </>}
  </div>;
}

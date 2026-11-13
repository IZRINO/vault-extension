import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { request } from '../vault-messages';
import { Ico } from './components';
import { useOps } from './Main';

interface Report {
  totalLoginItems: number;
  weakItems: { itemId: string; title: string; warnings: string[] }[];
  reusedGroups: { itemIds: string[]; titles: string[] }[];
}
export default function Audit({ open }: { open(id: string): void }) {
  const { busy, work } = useOps();
  const [report, setReport] = useState<Report>();
  return <div className="view">
    <h1 className="page-title">密码体检</h1>
    <p className="lede">找出容易被猜到、或用在多个网站上的密码。检查在本机进行，不会上传你的密码。</p>
    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void work(async () => setReport(await request<Report>({ type: 'audit' })))}><Ico of={ShieldCheck} />开始本地检查</button>
    {report && <>
      <p role="status">已检查 {report.totalLoginItems} 个登录项。</p>
      <section className="section"><h2>弱密码 · {report.weakItems.length}</h2>{report.weakItems.map(item =>
        <button type="button" className="finding" key={item.itemId} disabled={busy} onClick={() => open(item.itemId)}><strong>{item.title}</strong><span>{item.warnings.join('；')}</span></button>)}</section>
      <section className="section"><h2>重复密码 · {report.reusedGroups.length} 组</h2>{report.reusedGroups.map((group, i) =>
        <div className="finding" key={i}><strong>{group.titles.join('、')}</strong><span>这些登录项用了同一个密码，建议逐一更换。</span>
          {group.itemIds?.map((id, n) => <button type="button" className="btn btn-s" key={id} onClick={() => open(id)}>查看 {group.titles[n]}</button>)}</div>)}</section>
      {!report.weakItems.length && !report.reusedGroups.length && <div className="banner banner-ok"><Ico of={ShieldCheck} />
        {report.totalLoginItems ? '本次检查未发现弱密码或重复密码。' : '还没有可检查的登录项，先到密码库添加一条。'}</div>}
    </>}
  </div>;
}

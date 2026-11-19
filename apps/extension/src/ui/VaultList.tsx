import { ArchiveRestore, Copy, CreditCard, KeyRound, LockKeyhole, PackageOpen, Pin, Plus, SearchX, Trash2, TriangleAlert, User, type LucideIcon } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { ItemSummary } from '../vault-messages';
import { CopyButton, Ico } from './components';
import { filterItems, plateText, rowSubtitle } from './lib';
import { useOps } from './Main';

const filters: { id: string; label: string }[] = [
  { id: 'all', label: '全部' },
  { id: 'pinned', label: '置顶' },
  { id: 'login', label: '登录' },
  { id: 'payment_card', label: '卡片' },
  { id: 'identity', label: '身份' },
  { id: 'developer', label: '开发' },
];
const PAGE_SIZE = 32;

interface QuickAction { key: string; label: string; icon: LucideIcon }
function quickActions(item: ItemSummary): QuickAction[] {
  if (item.kind === 'login') return [{ key: 'username', label: '用户名', icon: User }, { key: 'password', label: '密码', icon: KeyRound }];
  if (item.kind === 'payment_card') return [{ key: 'cardNumber', label: '卡号', icon: CreditCard }];
  if (item.kind === 'developer') {
    return item.devSubtype === 'ssh_key' ? [{ key: 'publicKey', label: '公钥', icon: Copy }]
      : [{ key: 'tokenOrLicense', label: item.devSubtype === 'license_key' ? '许可密钥' : '令牌', icon: Copy }];
  }
  return [];
}

export default function VaultList({ items, query, filter, changesSinceBackup, setFilter, clearQuery, open, quickCopy, create, restore, remove, emptyTrash, backup, importCsv }: {
  items: ItemSummary[] | undefined; query: string; filter: string; changesSinceBackup: number;
  setFilter(filter: string): void; clearQuery(): void; open(item: ItemSummary): void;
  quickCopy(item: ItemSummary, key: string, label: string): Promise<boolean>;
  create(): void; restore(item: ItemSummary): void; remove(item: ItemSummary): void; emptyTrash(expectedIds: string[]): void; backup(): void;
  importCsv(): void;
}) {
  const { busy } = useOps();
  const visible = useMemo(() => items ? filterItems(items, filter, query) : [], [items, filter, query]);
  const [page, setPage] = useState<{ query: string; filter: string; limit: number }>();
  const limit = page?.query === query && page.filter === filter ? page.limit : PAGE_SIZE;
  const searching = query.trim() !== '';
  const filterName = filters.find(entry => entry.id === filter)?.label;
  const trash = filter === 'trash' ? (items ?? []).filter(item => item.trashed) : [];
  return <div className="view">
    <div className="toolbar">
      <div className="chips" role="group" aria-label="分类筛选">
        {filters.map(entry => <button type="button" className="chip" key={entry.id} aria-pressed={filter === entry.id} onClick={() => setFilter(entry.id)}>{entry.label}</button>)}
      </div>
      <button type="button" className="icon-btn toolbar-toggle" aria-label="回收站" title="回收站" aria-pressed={filter === 'trash'} onClick={() => setFilter(filter === 'trash' ? 'all' : 'trash')}><Ico of={Trash2} /></button>
    </div>
    {changesSinceBackup >= 10 && filter !== 'trash' && <div className="banner banner-warn">
      <Ico of={TriangleAlert} />
      <span className="grow">已经有 {changesSinceBackup} 处改动还没备份。存一份加密备份，电脑出问题时也能找回来。</span>
      <button type="button" className="btn btn-s" onClick={backup}>去备份</button>
    </div>}
    {trash.length > 0 && <div className="trash-bar">
      <p className="hint">回收站共 {trash.length} 条凭证。{searching ? `当前搜索显示 ${visible.length} 条。` : '可以恢复，也可以永久删除。'}</p>
      <button type="button" className="btn btn-s btn-danger" disabled={busy} onClick={() => emptyTrash(trash.map(item => item.id))}>清空回收站</button>
    </div>}
    {visible.length > 0 && <ul className="rows">
      {visible.slice(0, limit).map(item => <li className="row" key={item.id}>
        <button type="button" className="row-main" disabled={busy} onClick={() => open(item)}>
          <span className="plate" data-kind={item.kind} aria-hidden="true">{plateText(item.title)}</span>
          <span className="row-text">
            <span className="row-title">
              <span>{item.title}</span>
              {item.pinned && <><Ico of={Pin} /><span className="sr-only">已置顶</span></>}
              {item.requireReprompt && <><Ico of={LockKeyhole} /><span className="sr-only">打开前需要验证</span></>}
            </span>
            <span className="row-sub">{rowSubtitle(item)}</span>
          </span>
        </button>
        <div className="row-actions">
          {item.trashed ? <>
            <button type="button" className="icon-btn" aria-label={'恢复“' + item.title + '”'} title="恢复" disabled={busy} onClick={() => restore(item)}><Ico of={ArchiveRestore} /></button>
            <button type="button" className="icon-btn icon-btn-danger" aria-label={'永久删除“' + item.title + '”'} title="永久删除" disabled={busy} onClick={() => remove(item)}><Ico of={Trash2} /></button>
          </> : quickActions(item).map(action => <CopyButton key={action.key} icon={action.icon} title={'复制' + action.label}
            label={'复制“' + item.title + '”的' + action.label} onCopy={() => quickCopy(item, action.key, action.label)} />)}
        </div>
      </li>)}
    </ul>}
    {visible.length > limit && <div className="actions">
      <button type="button" className="btn" onClick={() => setPage({ query, filter, limit: limit + PAGE_SIZE })}>
        显示更多（{limit} / {visible.length}）
      </button>
    </div>}
    {items && visible.length === 0 && (searching ? <div className="empty">
      <span className="plate" aria-hidden="true"><Ico of={SearchX} /></span>
      <h2>没有找到“{query.trim()}”</h2>
      <p>{filter === 'all' ? '换一个名称、账号或网站试试。' : '当前只在“' + (filter === 'trash' ? '回收站' : filterName) + '”里找。'}</p>
      <div className="actions">
        <button type="button" className="btn" onClick={clearQuery}>清除搜索</button>
        {filter !== 'all' && <button type="button" className="btn" onClick={() => setFilter('all')}>在全部凭证里找</button>}
      </div>
    </div> : filter === 'trash' ? <div className="empty">
      <span className="plate" aria-hidden="true"><Ico of={Trash2} /></span>
      <h2>回收站是空的</h2>
      <p>移入回收站的凭证会留在这里，直到你永久删除。</p>
    </div> : filter !== 'all' ? <div className="empty">
      <span className="plate" aria-hidden="true"><Ico of={PackageOpen} /></span>
      <h2>“{filterName}”里还没有凭证</h2>
      <p>{filter === 'pinned' ? '编辑一条凭证时打开“置顶”，它就会出现在这里。' : '点右上角的“新建”可以添加。'}</p>
      <button type="button" className="btn" onClick={() => setFilter('all')}>查看全部</button>
    </div> : <div className="empty">
      <span className="plate" aria-hidden="true"><Ico of={PackageOpen} /></span>
      <h2>还没有保存任何凭证</h2>
      <p>先存一个常用网站的账号和密码，以后在这里点一下就能复制。</p>
      <div className="actions">
        <button type="button" className="btn btn-primary" onClick={create}><Ico of={Plus} />添加登录项</button>
        <button type="button" className="btn" onClick={importCsv}>从浏览器导入</button>
      </div>
    </div>)}
  </div>;
}

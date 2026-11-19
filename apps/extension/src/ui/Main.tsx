import { createContext, lazy, Suspense, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Check, Dices, LayoutGrid, Plus, Search, Settings as SettingsIcon, ShieldCheck, X, type LucideIcon } from 'lucide-react';
import { request, type ItemDetailData, type ItemSummary, type VaultItem, type VaultStatus } from '../vault-messages';
import { ErrorBanner, Ico, MenuButton, type MenuEntry } from './components';
import { DialogHost, useDialogs } from './dialogs';
import { Cancelled, errorText, newItem, text } from './lib';
import { openConflictReview, ShellActions } from './shell';
import VaultList from './VaultList';
import type { SettingsPage } from './Settings';
import SiteSettings from './SiteSettings';

const ItemDetail = lazy(() => import('./ItemDetail'));
const ItemEditor = lazy(() => import('./ItemEditor'));
const Generator = lazy(() => import('./Generator'));
const Audit = lazy(() => import('./Audit'));
const Settings = lazy(() => import('./Settings'));

export interface Ops {
  busy: boolean;
  /** 运行一个操作：期间显示进度，出错时显示提示。成功返回 true。 */
  work(action: () => Promise<void>): Promise<boolean>;
  /** 复制到剪贴板（约 30 秒后自动清理）。成功返回 true。 */
  copy(value: string): Promise<boolean>;
  notify(text: string): void;
  fail(error: unknown): void;
}
const OpsContext = createContext<Ops | undefined>(undefined);
export function useOps(): Ops {
  const ops = useContext(OpsContext);
  if (!ops) throw new Error('Ops provider is missing');
  return ops;
}

type Tab = 'vault' | 'generator' | 'audit' | 'settings';
type Screen = { name: 'list' } | { name: 'detail'; item: ItemDetailData } | { name: 'edit'; item: VaultItem; back?: ItemDetailData };
const tabs: { id: Tab; label: string; icon: LucideIcon }[] = [
  { id: 'vault', label: '密码库', icon: LayoutGrid },
  { id: 'generator', label: '生成器', icon: Dices },
  { id: 'audit', label: '体检', icon: ShieldCheck },
  { id: 'settings', label: '设置', icon: SettingsIcon },
];
const COPIED = '已复制，将在约 30 秒后检查并清理。';

interface WorkspaceProps { status: VaultStatus; refresh(): Promise<void>; initialItems?: ItemSummary[] }
export default function Main(props: WorkspaceProps) {
  return <DialogHost pinEnabled={props.status.pinEnabled}><Workspace {...props} /></DialogHost>;
}

function Workspace({ status, refresh, initialItems }: WorkspaceProps) {
  const dialogs = useDialogs();
  const [tab, setTab] = useState<Tab>('vault');
  const [screen, setScreen] = useState<Screen>({ name: 'list' });
  const [settingsPage, setSettingsPage] = useState<SettingsPage>('home');
  const [items, setItems] = useState(initialItems);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [conflicts, setConflicts] = useState(0);
  const mounted = useRef(true);
  const running = useRef(0);
  const dirty = useRef(false);
  const content = useRef<HTMLElement>(null);
  const initialListReady = useRef(false);
  const initialListPresented = useRef(false);

  useLayoutEffect(() => {
    if (!items || initialListPresented.current || tab !== 'vault' || screen.name !== 'list') return;
    if (!initialListReady.current) {
      initialListReady.current = true;
      performance.mark('vault:list-ready');
    }
    // The second animation frame is after the first opportunity to paint the usable list.
    let afterPaint: number | undefined;
    const beforePaint = requestAnimationFrame(() => {
      afterPaint = requestAnimationFrame(() => {
        initialListPresented.current = true;
        performance.mark('vault:list-presented');
      });
    });
    return () => {
      cancelAnimationFrame(beforePaint);
      if (afterPaint != null) cancelAnimationFrame(afterPaint);
    };
  }, [items, tab, screen.name]);
  const fail = useCallback((e: unknown) => {
    if (mounted.current && !(e instanceof Cancelled)) setError(errorText(e));
  }, []);
  const reload = useCallback(async () => {
    const list = await request<ItemSummary[]>({ type: 'list' });
    if (mounted.current) setItems(list);
    await refresh();
  }, [refresh]);
  const work = useCallback(async (action: () => Promise<void>) => {
    running.current++;
    setBusy(true); setError(''); setNotice('');
    try { await action(); return true; }
    catch (e) { fail(e); return false; }
    finally { if (--running.current === 0 && mounted.current) setBusy(false); }
  }, [fail]);
  const copyValue = useCallback(async (value: string) => {
    await request({ type: 'copy-sensitive', value });
    if (mounted.current) setNotice(COPIED);
  }, []);
  const copy = useCallback((value: string) => work(() => copyValue(value)), [work, copyValue]);
  const ops = useMemo<Ops>(() => ({ busy, work, copy, notify: setNotice, fail }), [busy, work, copy, fail]);

  useEffect(() => {
    mounted.current = true;
    if (!initialItems) void reload().catch(fail);
    return () => { mounted.current = false; };
  }, [reload, fail, initialItems]);
  useEffect(() => {
    const syncChanged = (message: { target?: string; type?: string }) => {
      if (message?.target === 'vault-event' && message.type === 'sync-changed') void reload().catch(fail);
    };
    browser.runtime.onMessage.addListener(syncChanged);
    return () => browser.runtime.onMessage.removeListener(syncChanged);
  }, [reload, fail]);
  useEffect(() => {
    let current = true;
    let changed = false;
    const update = (value: unknown) => {
      if (current) setConflicts(typeof value === 'number' ? value : 0);
    };
    const onChanged = (changes: Record<string, { newValue?: unknown }>, area: string) => {
      if (area === 'local' && changes.webDavConflicts) {
        changed = true;
        update(changes.webDavConflicts.newValue);
      }
    };
    browser.storage.onChanged.addListener(onChanged);
    void browser.storage.local.get<{ webDavConflicts?: number }>('webDavConflicts').then(value => {
      if (!changed) update(value.webDavConflicts);
    }).catch(() => undefined);
    return () => { current = false; browser.storage.onChanged.removeListener(onChanged); };
  }, []);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(''), 4200);
    return () => clearTimeout(timer);
  }, [notice]);
  const screenKey = tab + ':' + (tab === 'vault' ? screen.name : tab === 'settings' ? settingsPage : '');
  useEffect(() => { content.current?.scrollTo(0, 0); }, [screenKey]);

  /** 编辑到一半要离开时先确认，避免误点丢掉内容。 */
  async function leave(): Promise<boolean> {
    if (!dirty.current) return true;
    const ok = await dialogs.confirm({ title: '放弃没保存的修改？', body: '离开后，这次填写的内容不会保留。', confirmLabel: '放弃修改', cancelLabel: '继续编辑', danger: true });
    if (ok) dirty.current = false;
    return ok;
  }
  async function go(next: Tab, page: SettingsPage = 'home') {
    if (!await leave()) return;
    setTab(next); setScreen({ name: 'list' }); setSettingsPage(page); setError(''); setNotice('');
  }
  async function fetchItem<T extends VaultItem>(summary: Pick<ItemSummary, 'id' | 'requireReprompt'>, type: 'get' | 'get-edit' = 'get') {
    const verified = summary.requireReprompt ? await dialogs.proof() : undefined;
    try { return await request<T>({ type, id: summary.id, proof: verified }); }
    finally { if (verified) verified.secret = ''; }
  }
  const open = (summary: ItemSummary) => work(async () => {
    const full = await fetchItem<ItemDetailData>(summary);
    if (mounted.current) { setTab('vault'); setScreen({ name: 'detail', item: full }); }
  });
  const edit = (detail: ItemDetailData) => work(async () => {
    const item = await fetchItem<VaultItem>(detail, 'get-edit');
    if (mounted.current) setScreen({ name: 'edit', item, back: detail });
  });
  const openById = (id: string) => {
    const summary = items?.find(item => item.id === id);
    if (summary) void open(summary);
    else fail(new Error('这条凭证已经不在密码库里了。'));
  };
  const quickCopy = (summary: ItemSummary, key: string, label: string) => work(async () => {
    const full = await fetchItem(summary);
    const value = text(full.data[key]);
    if (!value) throw new Error('“' + summary.title + '”还没有填写' + label + '。');
    await copyValue(value);
  });
  const save = (item: VaultItem) => work(async () => {
    const existing = items?.find(entry => entry.id === item.id);
    const verified = existing?.requireReprompt ? await dialogs.proof() : undefined;
    try {
      await request({ type: 'upsert', itemJson: JSON.stringify({ ...item, tags: item.tags.map(tag => tag.trim()).filter(Boolean) }), proof: verified });
      dirty.current = false;
      if (mounted.current) setScreen({ name: 'list' });
      await reload();
      if (mounted.current) setNotice('凭证已保存。');
    } finally { if (verified) verified.secret = ''; }
  });
  const setTrashed = (item: Pick<ItemSummary, 'id'>, trashed: boolean) => work(async () => {
    await request({ type: 'trash', id: item.id, trashed });
    if (mounted.current) setScreen({ name: 'list' });
    await reload();
    if (mounted.current) setNotice(trashed ? '已移入回收站。' : '已从回收站恢复。');
  });
  const remove = async (item: Pick<ItemSummary, 'id' | 'title'>) => {
    if (!await dialogs.confirm({ title: '永久删除“' + item.title + '”？', body: '删除后无法恢复。', confirmLabel: '永久删除', danger: true })) return;
    await work(async () => {
      await request({ type: 'delete', id: item.id });
      if (mounted.current) setScreen({ name: 'list' });
      await reload();
      if (mounted.current) setNotice('已永久删除。');
    });
  };
  const emptyTrash = async (expectedIds: string[]) => {
    const body = `将永久删除回收站里的全部 ${expectedIds.length} 条凭证，无法恢复。` +
      (query.trim() ? '也会删除未出现在当前搜索结果里的条目。' : '');
    if (!await dialogs.confirm({ title: '清空整个回收站？', body, confirmLabel: '清空回收站', danger: true })) return;
    await work(async () => {
      try { await request({ type: 'empty-trash', expectedIds }); }
      catch (error) { await reload().catch(() => undefined); throw error; }
      await reload();
      if (mounted.current) setNotice('回收站已清空。');
    });
  };
  const create = (kind: string, subtype?: string) => { setQuery(''); setFilter('all'); setScreen({ name: 'edit', item: newItem(kind, subtype) }); };
  const createMenu: MenuEntry[] = [
    { label: '登录', onSelect: () => create('login') },
    { label: '支付卡', onSelect: () => create('payment_card') },
    { label: '身份与地址', onSelect: () => create('identity') },
    { heading: '更多类型' },
    { label: 'API 令牌', onSelect: () => create('developer', 'api_token') },
    { label: '软件许可证', onSelect: () => create('developer', 'license_key') },
    { label: 'SSH 密钥', onSelect: () => create('developer', 'ssh_key') },
  ];
  const onList = tab === 'vault' && screen.name === 'list';

  return <OpsContext.Provider value={ops}>
    <div className="main">
      <header className="band">
        <div className="band-top">
          <span className="wordmark">Vault</span>
          <span className="lamp">已解锁</span>
          <ShellActions onError={fail} onLock={() => void request({ type: 'lock' }).then(refresh).catch(fail)} />
        </div>
        {onList && <div className="band-search">
          <div className="search">
            <Ico of={Search} />
            <input className="input" type="search" autoFocus aria-label="搜索凭证" placeholder="搜索名称、账号、网站或标签" value={query} onChange={event => setQuery(event.target.value)} />
            {query && <button type="button" className="icon-btn search-clear" aria-label="清除搜索" onClick={() => setQuery('')}><Ico of={X} /></button>}
          </div>
          <MenuButton className="btn btn-on-door" entries={createMenu} disabled={busy} title="新建一条凭证"><Ico of={Plus} />新建</MenuButton>
        </div>}
      </header>
      <div className="stage">
        {busy && <div className="busy-bar" />}
        {error && <div className="stage-alert"><ErrorBanner text={error} onClose={() => setError('')} /></div>}
        <main className="content" ref={content}>
          {onList && conflicts > 0 && <div className="banner banner-warn">
            <button type="button" className="btn" onClick={() => void openConflictReview().catch(fail)}>处理 {conflicts} 项同步冲突</button>
          </div>}
          {tab === 'vault' && screen.name === 'list' && <SiteSettings />}
          {tab === 'vault' && screen.name === 'list' && <VaultList items={items} query={query} filter={filter} changesSinceBackup={status.changesSinceBackup}
            setFilter={setFilter} clearQuery={() => setQuery('')} open={summary => void open(summary)} quickCopy={quickCopy}
            create={() => create('login')} restore={item => void setTrashed(item, false)} remove={item => void remove(item)}
            emptyTrash={ids => void emptyTrash(ids)} backup={() => void go('settings', 'backup')} importCsv={() => void go('settings', 'csv')} />}
          <Suspense fallback={<p className="hint" role="status">正在加载…</p>}>
          {tab === 'vault' && screen.name === 'detail' && <ItemDetail key={screen.item.id} item={screen.item}
            back={() => setScreen({ name: 'list' })} edit={() => void edit(screen.item)}
            otpUsed={() => void reload().catch(fail)}
            setTrashed={trashed => void setTrashed(screen.item, trashed)} remove={() => void remove(screen.item)} />}
          {tab === 'vault' && screen.name === 'edit' && <ItemEditor key={screen.item.id || screen.item.data.kind + String(screen.item.data.subtype)} initial={screen.item}
            save={item => void save(item)} onDirty={value => { dirty.current = value; }}
            close={() => void leave().then(ok => { if (ok) setScreen(screen.back ? { name: 'detail', item: screen.back } : { name: 'list' }); })} />}
          {tab === 'generator' && <Generator />}
          {tab === 'audit' && <Audit open={openById} />}
          {tab === 'settings' && <Settings status={status} page={settingsPage} setPage={setSettingsPage} refresh={reload} />}
          </Suspense>
        </main>
        <div className="toast-region" role="status" aria-live="polite">
          {notice && <div className="toast"><Ico of={Check} /><span>{notice}</span></div>}
        </div>
      </div>
      <nav className="nav" aria-label="主导航">
        {tabs.map(entry => <button type="button" key={entry.id} aria-current={tab === entry.id ? 'page' : undefined} onClick={() => void go(entry.id)}>
          <Ico of={entry.icon} />{entry.label}
        </button>)}
      </nav>
    </div>
  </OpsContext.Provider>;
}

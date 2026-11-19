import { useEffect, useRef } from 'react';
import { Lock, Maximize2, PanelRight } from 'lucide-react';
import { Ico } from './components';
import { isPopup } from './lib';

export function openConflictReview() {
  return browser.tabs.create({ url: browser.runtime.getURL('/sidepanel.html') + '?view=conflicts' });
}

/** 顶栏右侧的三个动作：侧栏、整页、锁定。 */
export function ShellActions({ onLock, onError }: { onLock?(): void; onError(error: unknown): void }) {
  const windowId = useRef<number | undefined>(undefined);
  useEffect(() => {
    // 预先取好窗口编号，点击时可以在用户手势内直接打开侧栏。
    void browser.windows.getCurrent().then(current => { windowId.current = current.id; }).catch(() => undefined);
  }, []);
  const openPanel = () => {
    const opening = windowId.current !== undefined
      ? browser.sidePanel.open({ windowId: windowId.current })
      : browser.windows.getCurrent().then(current => current.id === undefined ? undefined : browser.sidePanel.open({ windowId: current.id }));
    void opening.then(() => { if (isPopup()) window.close(); }).catch(onError);
  };
  const openTab = () => void browser.tabs.create({ url: browser.runtime.getURL('/sidepanel.html') }).catch(onError);
  return <div className="band-actions">
    <button type="button" className="icon-btn" aria-label="打开浏览器侧栏" title="在浏览器侧栏打开" onClick={openPanel}><Ico of={PanelRight} /></button>
    <button type="button" className="icon-btn" aria-label="在标签页打开密码库" title="在新标签页打开" onClick={openTab}><Ico of={Maximize2} /></button>
    {onLock && <button type="button" className="icon-btn" aria-label="锁定密码库" title="立即锁定" onClick={onLock}><Ico of={Lock} /></button>}
  </div>;
}

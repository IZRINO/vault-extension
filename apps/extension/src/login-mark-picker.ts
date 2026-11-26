import { canSaveMark, draftMark } from './login-mark-dom';
import { markRoles, type MarkDraft, type MarkRole } from './login-marks';
import { visible } from './autofill-dom';

const label: Record<MarkRole, string> = { username: '用户名', password: '密码', otp: '两步验证码' };
export function openMarkPicker(token: string, persist: (draft: MarkDraft) => Promise<void>, cancel: () => void) {
  const events = new AbortController();
  const options = { capture: true, signal: events.signal };
  const host = document.createElement('div');
  host.dataset.vaultMarkPicker = '';
  host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;left:16px;bottom:16px;display:block;max-width:calc(100vw - 32px)';
  const shadow = host.attachShadow({ mode: 'closed' });
  const css = document.createElement('style');
  css.textContent = `
    :host{color-scheme:light dark}
    section{color:#222a25;background:#fff;font:14px/1.45 system-ui;padding:12px;width:320px;max-width:100%;box-sizing:border-box;border-radius:8px;box-shadow:0 6px 22px #101c1670}
    .title{font-size:15px;font-weight:650;margin:0 0 8px}
    .row{display:flex;gap:6px;flex-wrap:wrap}
    p{margin:8px 0;min-height:40px;overflow-wrap:anywhere}
    button{font:inherit;color:inherit;padding:5px 8px;min-height:32px;border:1px solid #acb5ad;background:transparent;border-radius:5px;cursor:pointer}
    button[aria-pressed=true]{border-color:#2b7550;background:#e4f2e9;color:#19422d}
    button.primary{background:#286342;border-color:#286342;color:#fff}
    button:focus-visible{outline:2px solid #268353;outline-offset:2px}
    button:disabled{opacity:.5;cursor:default}
    @media(prefers-color-scheme:dark){
      section{background:#1c2922;color:#e5eee7}
      button{border-color:#7b9182}
      button[aria-pressed=true]{background:#283f32;color:#ddf4e4;border-color:#7db393}
    }`;
  const panel = document.createElement('section');
  panel.setAttribute('aria-label', 'Vault 标记登录框');
  const title = document.createElement('h2');
  title.className = 'title';
  title.textContent = '标记登录框';
  const roles = document.createElement('div');
  roles.className = 'row';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  const actions = document.createElement('div');
  actions.className = 'row';
  panel.append(title, roles, status, actions);
  shadow.append(css, panel);
  const ringHost = document.createElement('div');
  ringHost.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483646;pointer-events:none';
  const ringRoot = ringHost.attachShadow({ mode: 'closed' });
  const hover = document.createElement('div');
  const rings = Object.fromEntries(markRoles.map(role => [role, document.createElement('div')])) as Record<MarkRole, HTMLDivElement>;
  ringRoot.append(hover, ...Object.values(rings));
  const selected: { draft: MarkDraft; role: MarkRole; input: HTMLInputElement }[] = [];
  let role: MarkRole = 'username', busy = false, hovered: HTMLInputElement | undefined;
  const drawRing = (node: HTMLDivElement, element: HTMLInputElement | undefined, preview: boolean) => {
    if (!element || !visible(element)) { node.style.display = 'none'; return; }
    const { left, top, width, height } = element.getBoundingClientRect();
    node.style.cssText = `display:block;position:fixed;pointer-events:none;box-sizing:border-box;left:${left - 3}px;top:${top - 3}px;width:${width + 6}px;height:${height + 6}px;border:2px ${preview ? 'solid' : 'dashed'} #2a8555;outline:1px solid #fff;border-radius:4px`;
  };
  const redraw = () => {
    for (const key of markRoles) drawRing(rings[key], selected.findLast(item => item.role === key)?.input, true);
    drawRing(hover, hovered, false);
  };
  const button = (parent: HTMLElement, text: string, action: () => void) => {
    const value = document.createElement('button');
    value.type = 'button'; value.textContent = text;
    value.addEventListener('click', event => { if (event.isTrusted) action(); }, { signal: events.signal });
    parent.append(value); return value;
  };
  const choices = markRoles.map(key => button(roles, label[key], () => { if (!busy) { role = key; update(); } }));
  const save = button(actions, '保存标记', () => {
    const latest = selected.at(-1)?.draft;
    if (busy || !latest) return;
    if (!canSaveMark(latest)) { update('有输入框已变化，请重新点选。'); return; }
    busy = true; update();
    void persist(latest).catch(error => { busy = false; update(error instanceof Error ? error.message : '未能保存标记。'); });
  });
  save.className = 'primary';
  const undo = button(actions, '撤销上一步', () => { selected.pop(); update(); });
  button(actions, '取消', cancel);
  function update(error?: string) {
    choices.forEach((choice, index) => {
      const key = markRoles[index]!;
      choice.setAttribute('aria-pressed', String(role === key));
      choice.disabled = busy;
      choice.textContent = `${label[key]}${selected.some(item => item.role === key) ? ' · 已选' : ''}`;
    });
    save.disabled = busy || !selected.length;
    undo.disabled = busy || !selected.length;
    status.setAttribute('role', error ? 'alert' : 'status');
    status.textContent = error ?? (busy ? '正在保存标记…' : `点选${label[role]}输入框。`);
    redraw();
  }
  const from = (event: Event) => {
    const field = event.composedPath()[0];
    return field instanceof HTMLInputElement && field.getRootNode() === document ? field : undefined;
  };
  const pick = (event: Event, input: HTMLInputElement) => {
    event.preventDefault(); event.stopImmediatePropagation();
    if (busy) return;
    try { selected.push({ draft: draftMark(input, role, selected.at(-1)?.draft), input, role }); update(); }
    catch (error) { update(error instanceof Error ? error.message : '此输入框不能标记。'); }
  };
  window.addEventListener('pointermove', event => { if (event.isTrusted) { hovered = from(event); redraw(); } }, options);
  window.addEventListener('click', event => { const input = from(event); if (event.isTrusted && input) pick(event, input); }, options);
  window.addEventListener('keydown', event => {
    if (!event.isTrusted) return;
    if (event.key === 'Escape') { event.preventDefault(); event.stopImmediatePropagation(); cancel(); return; }
    const input = from(event);
    if (input && event.key === 'Enter') pick(event, input);
  }, options);
  window.addEventListener('scroll', redraw, options);
  window.addEventListener('resize', redraw, options);
  document.documentElement.append(ringHost, host);
  update();
  choices[0]!.focus({ preventScroll: true });
  return { token, close() { events.abort(); host.remove(); ringHost.remove(); } };
}

import {
  useCallback, useEffect, useId, useLayoutEffect, useRef, useState,
  type InputHTMLAttributes, type ReactNode, type RefObject, type SelectHTMLAttributes, type TextareaHTMLAttributes,
} from 'react';
import { createPortal } from 'react-dom';
import { Check, CircleAlert, Copy, Eye, EyeOff, X, type LucideIcon } from 'lucide-react';

export function Ico({ of: Glyph }: { of: LucideIcon }) {
  return <Glyph className="icon" aria-hidden="true" />;
}

/** 短暂亮起的“已取到”状态，用于复制按钮。 */
function useFlash(ms = 1800): [boolean, () => void] {
  const [on, setOn] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const flash = useCallback(() => {
    clearTimeout(timer.current);
    setOn(true);
    timer.current = setTimeout(() => setOn(false), ms);
  }, [ms]);
  return [on, flash];
}

function useCopyAction(onCopy: () => Promise<boolean>): [boolean, () => void] {
  const [got, flash] = useFlash();
  const running = useRef(false);
  const run = () => {
    if (running.current) return;
    running.current = true;
    void onCopy().then(ok => { if (ok) flash(); }).finally(() => { running.current = false; });
  };
  return [got, run];
}

/** 图标复制按钮：复制成功后原地变绿。 */
export function CopyButton({ label, title, onCopy, icon, disabled }: { label: string; title?: string; onCopy(): Promise<boolean>; icon?: LucideIcon; disabled?: boolean }) {
  const [got, run] = useCopyAction(onCopy);
  return <button type="button" className="icon-btn" data-got={got || undefined} aria-label={label} title={got ? '已复制' : title ?? label} disabled={disabled} onClick={run}>
    <Ico of={got ? Check : icon ?? Copy} />
  </button>;
}

/** 带文字的复制按钮：复制成功后原地换成“已复制”。 */
export function CopyAction({ children, onCopy, className, disabled }: { children: ReactNode; onCopy(): Promise<boolean>; className?: string; disabled?: boolean }) {
  const [got, run] = useCopyAction(onCopy);
  return <button type="button" className={'btn ' + (className ?? '')} data-got={got || undefined} disabled={disabled} onClick={run}>
    <Ico of={got ? Check : Copy} />{got ? '已复制' : children}
  </button>;
}

export function ErrorBanner({ text, onClose }: { text: string; onClose?(): void }) {
  return <div className="banner banner-error" role="alert">
    <Ico of={CircleAlert} />
    <span className="grow">{text}</span>
    {onClose && <button type="button" className="icon-btn" aria-label="关闭提示" onClick={onClose}><Ico of={X} /></button>}
  </div>;
}

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange' | 'className'>;
interface FieldBase { label: string; hint?: ReactNode }

function FieldShell({ label, hint, children }: FieldBase & { children(id: string, hintId: string | undefined): ReactNode }) {
  const id = useId();
  const hintId = hint ? id + 'h' : undefined;
  return <div className="field">
    <label htmlFor={id}>{label}</label>
    {children(id, hintId)}
    {hint && <p className="hint" id={hintId}>{hint}</p>}
  </div>;
}

export function TextField({ label, hint, value, onChange, mono, ...rest }: FieldBase & InputProps & { value: string; onChange(value: string): void; mono?: boolean }) {
  return <FieldShell label={label} hint={hint}>{(id, hintId) =>
    <input {...rest} id={id} aria-describedby={hintId} className={mono ? 'input mono' : 'input'} value={value} onChange={event => onChange(event.target.value)} />}
  </FieldShell>;
}

/** 可显示 / 隐藏的密码输入框。revealName 用于按钮的读屏名称，例如“显示主密码”。 */
export function SecretInput({ value, onChange, revealName, after, ...rest }: InputProps & { value: string; onChange(value: string): void; revealName: string; after?: ReactNode }) {
  const [shown, setShown] = useState(false);
  return <div className="input-wrap">
    <input {...rest} className={shown ? 'input mono' : 'input'} type={shown ? 'text' : 'password'} value={value} onChange={event => onChange(event.target.value)} />
    <button type="button" className="icon-btn" aria-label={(shown ? '隐藏' : '显示') + revealName} title={shown ? '隐藏' : '显示'} onClick={() => setShown(!shown)}>
      <Ico of={shown ? EyeOff : Eye} />
    </button>
    {after}
  </div>;
}

export function SecretField({ label, hint, revealName, ...rest }: FieldBase & InputProps & { value: string; onChange(value: string): void; revealName?: string; after?: ReactNode }) {
  return <FieldShell label={label} hint={hint}>{(id, hintId) =>
    <SecretInput {...rest} id={id} aria-describedby={hintId} revealName={revealName ?? label} />}
  </FieldShell>;
}

export function AreaField({ label, hint, value, onChange, mono, concealed, after, ...rest }: FieldBase & Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, 'value' | 'onChange' | 'className'> & {
  value: string; onChange(value: string): void; mono?: boolean; concealed?: boolean; after?: ReactNode;
}) {
  const className = 'textarea' + (mono ? ' mono' : '') + (concealed ? ' concealed' : '');
  return <FieldShell label={label} hint={hint}>{(id, hintId) => after
    ? <div className="input-wrap"><textarea {...rest} id={id} aria-describedby={hintId} className={className} value={value} onChange={event => onChange(event.target.value)} />{after}</div>
    : <textarea {...rest} id={id} aria-describedby={hintId} className={className} value={value} onChange={event => onChange(event.target.value)} />}
  </FieldShell>;
}

export function SelectField({ label, hint, value, onChange, children, ...rest }: FieldBase & Omit<SelectHTMLAttributes<HTMLSelectElement>, 'value' | 'onChange' | 'className'> & {
  value: string | number; onChange(value: string): void; children: ReactNode;
}) {
  return <FieldShell label={label} hint={hint}>{(id, hintId) =>
    <select {...rest} id={id} aria-describedby={hintId} className="select" value={value} onChange={event => onChange(event.target.value)}>{children}</select>}
  </FieldShell>;
}

/** 开关行：左侧文字说明，右侧开关。 */
export function SwitchRow({ label, hint, checked, onChange, disabled }: FieldBase & { checked: boolean; onChange(checked: boolean): void; disabled?: boolean }) {
  const id = useId();
  const hintId = hint ? id + 'h' : undefined;
  return <div className="switch-row">
    <div className="grow"><label htmlFor={id}>{label}</label>{hint && <p className="hint" id={hintId}>{hint}</p>}</div>
    <input id={id} type="checkbox" role="switch" className="switch" aria-describedby={hintId} checked={checked} disabled={disabled} onChange={event => onChange(event.target.checked)} />
  </div>;
}

export interface MenuItem { label: string; icon?: LucideIcon; danger?: boolean; disabled?: boolean; onSelect(): void }
export type MenuEntry = MenuItem | { heading: string } | 'separator';

/** 弹出菜单：用 fixed 定位挂到 body 上，不会被滚动容器裁掉。 */
export function MenuButton({ entries, label, title, className, disabled, align = 'end', children }: {
  entries: MenuEntry[]; label?: string; title?: string; className: string; disabled?: boolean; align?: 'start' | 'end'; children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const close = useCallback((refocus: boolean) => {
    setOpen(false);
    if (refocus) trigger.current?.focus();
  }, []);
  return <>
    <button ref={trigger} type="button" className={className} aria-haspopup="menu" aria-expanded={open} aria-label={label} title={title} disabled={disabled} onClick={() => setOpen(value => !value)}>{children}</button>
    {open && <MenuPopup anchor={trigger} entries={entries} align={align} close={close} />}
  </>;
}

function MenuPopup({ anchor, entries, align, close }: { anchor: RefObject<HTMLButtonElement | null>; entries: MenuEntry[]; align: 'start' | 'end'; close(refocus: boolean): void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ top: number; left: number }>();
  useLayoutEffect(() => {
    const box = anchor.current?.getBoundingClientRect();
    const menu = ref.current;
    if (!box || !menu) return;
    const width = menu.offsetWidth;
    const height = menu.offsetHeight;
    const left = Math.max(8, Math.min(align === 'end' ? box.right - width : box.left, window.innerWidth - width - 8));
    const below = box.bottom + 6;
    const top = below + height > window.innerHeight - 8 ? Math.max(8, box.top - height - 6) : below;
    setPosition({ top, left });
    menu.querySelector<HTMLElement>('button:not(:disabled)')?.focus();
  }, [anchor, align]);
  useEffect(() => {
    const outside = (target: EventTarget | null) => !(target instanceof Node) || (!ref.current?.contains(target) && !anchor.current?.contains(target));
    const onPointer = (event: PointerEvent) => { if (outside(event.target)) close(false); };
    const onScroll = (event: Event) => { if (outside(event.target)) close(false); };
    const dismiss = () => close(false);
    document.addEventListener('pointerdown', onPointer, true);
    document.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', dismiss);
    window.addEventListener('blur', dismiss);
    return () => {
      document.removeEventListener('pointerdown', onPointer, true);
      document.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', dismiss);
      window.removeEventListener('blur', dismiss);
    };
  }, [anchor, close]);
  const move = (step: number | 'first' | 'last') => {
    const buttons = Array.from(ref.current?.querySelectorAll<HTMLElement>('button:not(:disabled)') ?? []);
    if (!buttons.length) return;
    const current = buttons.indexOf(document.activeElement as HTMLElement);
    const next = step === 'first' ? 0 : step === 'last' ? buttons.length - 1 : (current + step + buttons.length) % buttons.length;
    buttons[next]?.focus();
  };
  return createPortal(<div ref={ref} className="menu" role="menu" style={position ?? { top: 0, left: 0, visibility: 'hidden' }} onKeyDown={event => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(true); }
    else if (event.key === 'ArrowDown') { event.preventDefault(); move(1); }
    else if (event.key === 'ArrowUp') { event.preventDefault(); move(-1); }
    else if (event.key === 'Home') { event.preventDefault(); move('first'); }
    else if (event.key === 'End') { event.preventDefault(); move('last'); }
    else if (event.key === 'Tab') close(false);
  }}>
    {entries.map((entry, index) => entry === 'separator' ? <div className="menu-sep" role="separator" key={index} />
      : 'heading' in entry ? <div className="menu-label" key={index}>{entry.heading}</div>
        : <button type="button" role="menuitem" key={index} className={entry.danger ? 'danger' : undefined} disabled={entry.disabled} onClick={() => { close(true); entry.onSelect(); }}>
          {entry.icon && <Ico of={entry.icon} />}{entry.label}
        </button>)}
  </div>, document.body);
}

/** 用固定格口显示的码（验证码、恢复码）：数字变化时原位更新，不引起布局跳动。 */
export function CodeCells({ code, groupSize = 3 }: { code: string; groupSize?: number }) {
  const cells = Array.from(code);
  return <span className="cells" aria-hidden="true">
    {cells.map((char, index) => <span key={index} data-gap={index > 0 && index % groupSize === 0 ? 'true' : undefined}>{char}</span>)}
  </span>;
}

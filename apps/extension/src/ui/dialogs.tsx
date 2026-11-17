import { createContext, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react';
import type { Proof } from '../vault-messages';
import { Cancelled } from './lib';
import { SecretField, SelectField } from './components';

export interface ConfirmOptions {
  title: string;
  body?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  danger?: boolean;
}

export interface DialogApi {
  /** 请用户再输入一次主密码或 PIN；用户取消时以 Cancelled 拒绝。 */
  proof(options?: { masterOnly?: boolean }): Promise<Proof>;
  confirm(options: ConfirmOptions): Promise<boolean>;
}

type Pending =
  | { kind: 'proof'; masterOnly?: boolean; resolve(proof: Proof): void; reject(error: Error): void }
  | { kind: 'confirm'; options: ConfirmOptions; resolve(value: boolean): void };

const DialogContext = createContext<DialogApi | undefined>(undefined);

export function useDialogs(): DialogApi {
  const api = useContext(DialogContext);
  if (!api) throw new Error('DialogHost is missing');
  return api;
}

function settle(pending: Pending | undefined, reason: string) {
  if (!pending) return;
  if (pending.kind === 'proof') pending.reject(new Cancelled(reason));
  else pending.resolve(false);
}

export function DialogHost({ pinEnabled, children }: { pinEnabled: boolean; children: ReactNode }) {
  const [pending, setPending] = useState<Pending>();
  const current = useRef<Pending | undefined>(undefined);
  const api = useMemo<DialogApi>(() => {
    const show = (next: Pending) => {
      settle(current.current, '已取消验证。');
      current.current = next;
      setPending(next);
    };
    return {
      proof: options => new Promise<Proof>((resolve, reject) => show({ kind: 'proof', masterOnly: options?.masterOnly, resolve, reject })),
      confirm: options => new Promise<boolean>(resolve => show({ kind: 'confirm', options, resolve })),
    };
  }, []);
  useEffect(() => () => {
    settle(current.current, '密码库已关闭。');
    current.current = undefined;
  }, []);
  const finish = () => {
    current.current = undefined;
    setPending(undefined);
  };
  return <DialogContext.Provider value={api}>
    {children}
    {pending?.kind === 'proof' && <ProofDialog pinEnabled={pinEnabled && !pending.masterOnly}
      onSubmit={proof => { finish(); pending.resolve(proof); }}
      onCancel={() => { finish(); pending.reject(new Cancelled('已取消验证。')); }} />}
    {pending?.kind === 'confirm' && <ConfirmDialog options={pending.options} onResult={value => { finish(); pending.resolve(value); }} />}
  </DialogContext.Provider>;
}

function Modal({ titleId, onCancel, children }: { titleId: string; onCancel(): void; children: ReactNode }) {
  const ref = useRef<HTMLDialogElement>(null);
  const pressedBackdrop = useRef(false);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (!dialog.open) dialog.showModal();
    dialog.querySelector<HTMLElement>('[data-autofocus]')?.focus();
    return () => { if (dialog.open) dialog.close(); };
  }, []);
  return <dialog ref={ref} className="dialog" aria-labelledby={titleId}
    onCancel={event => { event.preventDefault(); onCancel(); }}
    onPointerDown={event => { pressedBackdrop.current = event.target === event.currentTarget; }}
    onClick={event => { if (pressedBackdrop.current && event.target === event.currentTarget) onCancel(); }}>
    {children}
  </dialog>;
}

function ProofDialog({ pinEnabled, onSubmit, onCancel }: { pinEnabled: boolean; onSubmit(proof: Proof): void; onCancel(): void }) {
  const titleId = useId();
  const [method, setMethod] = useState<Proof['method']>(pinEnabled ? 'pin' : 'master');
  const [secret, setSecret] = useState('');
  return <Modal titleId={titleId} onCancel={onCancel}>
    <form className="dialog-body" onSubmit={event => { event.preventDefault(); onSubmit({ method, secret }); }}>
      <h2 id={titleId}>再次验证身份</h2>
      <p>{pinEnabled ? '这一步需要确认是你本人。请输入本机 PIN，或改用主密码。' : '这一步需要确认是你本人。请输入主密码。'}</p>
      {pinEnabled && <SelectField label="验证方式" value={method} onChange={value => { setMethod(value === 'pin' ? 'pin' : 'master'); setSecret(''); }}>
        <option value="pin">本机 PIN</option>
        <option value="master">主密码</option>
      </SelectField>}
      <SecretField key={method} label={method === 'master' ? '主密码' : '本机 PIN'} value={secret} onChange={setSecret} required autoComplete="off"
        inputMode={method === 'pin' ? 'numeric' : undefined} data-autofocus />
      <div className="dialog-actions">
        <button type="button" className="btn" onClick={onCancel}>取消</button>
        <button className="btn btn-primary">验证</button>
      </div>
    </form>
  </Modal>;
}

function ConfirmDialog({ options, onResult }: { options: ConfirmOptions; onResult(value: boolean): void }) {
  const titleId = useId();
  return <Modal titleId={titleId} onCancel={() => onResult(false)}>
    <div className="dialog-body">
      <h2 id={titleId}>{options.title}</h2>
      {options.body && <p>{options.body}</p>}
      <div className="dialog-actions">
        <button type="button" className="btn" data-autofocus={options.danger ? '' : undefined} onClick={() => onResult(false)}>{options.cancelLabel ?? '取消'}</button>
        <button type="button" className={options.danger ? 'btn btn-danger-solid' : 'btn btn-primary'} data-autofocus={options.danger ? undefined : ''} onClick={() => onResult(true)}>{options.confirmLabel}</button>
      </div>
    </div>
  </Modal>;
}

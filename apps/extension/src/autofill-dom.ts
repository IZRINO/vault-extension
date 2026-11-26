import type { FillKind, FillPayload } from './autofill-messages';

export type Control = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
export function controls(root: Document | ShadowRoot | Element = document): Control[] {
  const result = Array.from(root.querySelectorAll<Control>('input,textarea,select'));
  for (const element of Array.from(root.querySelectorAll('*')).slice(0, 5000)) {
    if (element.shadowRoot) result.push(...controls(element.shadowRoot));
  }
  return result.slice(0, 500);
}
export function visible(field: Control): boolean {
  if (!field.isConnected || field.disabled || ('readOnly' in field && field.readOnly) ||
    field instanceof HTMLInputElement && ['hidden', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(field.type)) return false;
  if (!field.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false;
  const rect = field.getBoundingClientRect();
  const x = rect.left + rect.width / 2, y = rect.top + rect.height / 2;
  if (rect.width < 8 || rect.height < 8 || x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return false;
  const root = field.getRootNode() as Document | ShadowRoot;
  const hit = root.elementFromPoint(x, y);
  return hit === field || !!hit && field.contains(hit);
}
const identityKeys = new Set(['name', 'given-name', 'family-name', 'tel', 'email', 'address-line1', 'street-address',
  'address-level1', 'address-level2', 'postal-code', 'country', 'organization']);
export function fieldKey(field: Control): string | undefined {
  const autocomplete = field.autocomplete.toLowerCase().split(/\s+/).filter(Boolean);
  const auto = autocomplete.find(value => value !== 'webauthn' && !value.startsWith('section-') && !['shipping', 'billing'].includes(value));
  if (auto === 'new-password') return;
  if (auto === 'current-password') return 'password';
  if (auto === 'one-time-code') return 'otp';
  if (auto === 'username') return 'username';
  if (auto === 'email') return 'email';
  if (auto?.startsWith('cc-') || auto && identityKeys.has(auto) && auto !== 'email') return auto;
  const hint = [field.id, field.name, field.getAttribute('aria-label'), field.getAttribute('placeholder'),
    ...(field.labels ? Array.from(field.labels).map(label => label.textContent) : [])].filter(Boolean).join(' ').toLowerCase();
  if (field instanceof HTMLInputElement && field.type === 'password') {
    return /new|confirm|repeat|新密码|确认|重复/.test(hint) ? undefined : 'password';
  }
  if (/otp|one.?time|verification.?code|验证码|动态码|安全代码/.test(hint)) return 'otp';
  if (field instanceof HTMLInputElement && field.maxLength === 1 && (field.inputMode === 'numeric' || field.type === 'tel')) return 'otp';
  if (/user.?name|e.?mail|account|login|用户名|账号|邮箱/.test(hint) || field instanceof HTMLInputElement && field.type === 'email') return 'username';
  if (/card.?number|卡号/.test(hint)) return 'cc-number';
  if (/cvv|cvc/.test(hint)) return 'cc-csc';
  return;
}
export function fillKind(field: Control): FillKind | undefined {
  const key = fieldKey(field);
  if (!key) return;
  if (key === 'password') return 'login';
  if (key === 'username' || key === 'email') {
    if (key === 'email' && controls(field.form ?? field.getRootNode() as Document | ShadowRoot)
      .some(other => other !== field && identityKeys.has(other.autocomplete) && other.autocomplete !== 'email')) return 'identity';
    return 'username';
  }
  if (key === 'otp') return 'otp';
  if (key.startsWith('cc-')) return 'card';
  return 'identity';
}
export function safeAction(target: Control): boolean {
  if (!target.form?.action) return true;
  try { return new URL(target.form.action, location.href).origin === location.origin; }
  catch { return false; }
}
export function setValue(field: Control, value: string, stillValid?: () => boolean): boolean {
  const prototype = field instanceof HTMLInputElement ? HTMLInputElement.prototype
    : field instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLSelectElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(prototype, 'value')!.set!;
  field.focus({ preventScroll: true });
  if (stillValid && !stillValid()) return false;
  setter.call(field, value);
  field.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertReplacementText', data: null }));
  field.dispatchEvent(new Event('change', { bubbles: true }));
  field.blur();
  return true;
}
export function fillControls(target: Control, kind: FillKind, payload: FillPayload): boolean {
  if (!visible(target) || !safeAction(target) || fillKind(target) !== kind) return false;
  const candidates = controls(target.form ?? target.getRootNode() as Document | ShadowRoot)
    .filter(field => visible(field) && field.form === target.form && safeAction(field));
  const values = payload.values;
  if (kind === 'otp') {
    const code = values.otp;
    if (!code || !/^[A-Z0-9]{5,8}$/.test(code)) return false;
    const parts = candidates.filter(field => fieldKey(field) === 'otp' && field instanceof HTMLInputElement && field.maxLength === 1);
    if (target instanceof HTMLInputElement && target.maxLength === 1) {
      if (parts.length !== code.length) return false;
      // Resolve every target before the first write.
      parts.forEach((field, index) => setValue(field, code[index]!));
    } else { setValue(target, code); }
    return true;
  }
  if (kind === 'username') { if (!values.username) return false; setValue(target, values.username); return true; }
  let count = 0;
  for (const field of candidates) {
    const key = fieldKey(field);
    if (!key) {
      const customKey = [field.name, field.id].find(name => payload.custom && Object.hasOwn(payload.custom, name));
      if (customKey && payload.custom?.[customKey] && visible(field)) { setValue(field, payload.custom[customKey]!); count++; }
      continue;
    }
    if (kind === 'login' && !['username', 'password', 'email'].includes(key)) continue;
    if (kind === 'login' && key === 'password' && field !== target) continue;
    const value = kind === 'login' && key === 'email' ? values.username : values[key];
    if (value && visible(field)) { setValue(field, value); count++; }
  }
  return count > 0;
}

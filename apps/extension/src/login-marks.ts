export const markRoles = ['username', 'password', 'otp'] as const;
export type MarkRole = typeof markRoles[number];
export type MarkAnchor = { id?: string; name?: string };
export type FieldMark = MarkAnchor & { type: string };
export type MarkDraft = { form: MarkAnchor; fields: Partial<Record<MarkRole, FieldMark>> };
export type LoginMark = MarkDraft & { version: 1; id: string; revision: number; origin: string; route: string; enabled: boolean };
export type MarkChange = { action: 'replace'; key?: string; draft: MarkDraft } | { action: 'enable'; key: string; enabled: boolean } | { action: 'delete'; key: string };
export const markKey = (mark: LoginMark) => `${mark.id}:${mark.revision}`;
export const markSetKey = (enabled: LoginMark[]) => enabled.length ? enabled.map(markKey).join(',') : undefined;

const textTypes = new Set(['text', 'email', 'tel', 'search', 'url']);
export function compatibleMark(role: MarkRole, type: string): boolean {
  if (role === 'password') return type === 'password';
  if (role === 'otp') return type === 'text' || type === 'tel' || type === 'number';
  return textTypes.has(type);
}

export function markAttribute(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.:[\]-]{0,63}$/.test(value);
}

function anchor(value: unknown, extra: readonly string[] = []): value is MarkAnchor {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const data = value as Record<string, unknown>;
  return Object.keys(data).every(key => extra.includes(key) || (key === 'id' || key === 'name') && markAttribute(data[key]));
}

export function sameFieldMark(a: FieldMark, b: FieldMark): boolean {
  return a.type === b.type && a.id === b.id && a.name === b.name;
}

export function sameMarkDraft(a: MarkDraft, b: MarkDraft): boolean {
  return a.form.id === b.form.id && a.form.name === b.form.name && markRoles.every(role => {
    const left = a.fields[role], right = b.fields[role];
    return left && right ? sameFieldMark(left, right) : left === right;
  });
}

export function validMarkDraft(value: unknown): value is MarkDraft {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const data = value as MarkDraft;
  if (Object.keys(data).sort().join(',') !== 'fields,form' || !anchor(data.form) ||
      !data.fields || typeof data.fields !== 'object' || Array.isArray(data.fields)) return false;
  const fields = Object.entries(data.fields);
  return fields.length > 0 && fields.every(([key, field], index) => markRoles.includes(key as MarkRole) &&
    anchor(field, ['type']) && !!(field.id || field.name) && compatibleMark(key as MarkRole, field.type) &&
    !fields.slice(0, index).some(([, previous]) => sameFieldMark(previous, field)));
}

export async function markScope(url: URL) {
  // Use only stable route-shaped segments; never retain query, fragment, or the path itself.
  if (!/^(?:\/[A-Za-z][A-Za-z_-]{0,23}){0,6}\/?$/.test(url.pathname)) return null;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url.pathname)));
  return { origin: url.origin, route: Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('') };
}

export function validLoginMark(value: unknown): value is LoginMark {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const { version, id, revision, origin, route, enabled, ...draft } = value as LoginMark;
  if (version !== 1 || typeof id !== 'string' || !/^[a-f0-9-]{36}$/.test(id) ||
      !Number.isInteger(revision) || revision < 1 || revision > 0xffff_ffff ||
      typeof origin !== 'string' || typeof route !== 'string' || !/^[a-f0-9]{64}$/.test(route) ||
      typeof enabled !== 'boolean' || !validMarkDraft(draft)) return false;
  try { const url = new URL(origin); return ['https:', 'http:'].includes(url.protocol) && url.origin === origin; }
  catch { return false; }
}

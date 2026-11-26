import { safeAction, setValue, visible, type Control } from './autofill-dom';
import type { FillKind, FillPayload } from './autofill-messages';
import { compatibleMark, markAttribute, markRoles, sameFieldMark, type FieldMark, type LoginMark, type MarkAnchor, type MarkDraft, type MarkRole } from './login-marks';

const anchor = (element: HTMLInputElement | HTMLFormElement): MarkAnchor => ({
  ...(markAttribute(element.id) ? { id: element.id } : {}),
  ...(markAttribute(element.getAttribute('name')) ? { name: element.getAttribute('name')! } : {}),
});
const matching = (value: MarkAnchor, expected: MarkAnchor) => value.id === expected.id && value.name === expected.name;
const describe = (input: HTMLInputElement): FieldMark => ({ ...anchor(input), type: input.type });
const editable = (input: HTMLInputElement, role: MarkRole) => compatibleMark(role, input.type) &&
  (role !== 'otp' || input.maxLength < 0 || input.maxLength >= 5) &&
  !input.matches(':disabled') && !input.closest('[inert]') && safeAction(input) && visible(input);

function matchesFor(form: HTMLFormElement, field: FieldMark) {
  if (form.elements.length > 500) return [];
  return Array.from(form.elements).filter((el): el is HTMLInputElement =>
    el instanceof HTMLInputElement && el.form === form && el.getRootNode() === form.ownerDocument &&
    sameFieldMark(describe(el), field));
}

function resolve(mark: MarkDraft): Partial<Record<MarkRole, HTMLInputElement>> {
  if (document.forms.length > 100) return {};
  const forms = Array.from(document.forms).filter(form => matching(anchor(form), mark.form) &&
    markRoles.some(role => mark.fields[role] && matchesFor(form, mark.fields[role]).length > 0));
  if (forms.length !== 1) return {};
  const fields: Partial<Record<MarkRole, HTMLInputElement>> = {};
  for (const role of markRoles) {
    const locator = mark.fields[role];
    if (!locator) continue;
    const [field, duplicate] = matchesFor(forms[0]!, locator);
    if (field && !duplicate && editable(field, role)) fields[role] = field;
  }
  return fields;
}

export function draftMark(input: HTMLInputElement, role: MarkRole, previous?: MarkDraft): MarkDraft {
  const form = input.form;
  const field = describe(input);
  if (!form || form.getRootNode() !== document || input.getRootNode() !== document || !editable(input, role) ||
      !(field.id || field.name)) throw new Error('请选择同一表单中可编辑、有稳定名称的输入框。');
  const formAnchor = anchor(form);
  if (previous && !matching(previous.form, formAnchor)) throw new Error('请在同一个表单中点选输入框。');
  if (previous && markRoles.some(other => other !== role && previous.fields[other] && sameFieldMark(field, previous.fields[other]))) {
    throw new Error('一个输入框只能标记为一种用途。');
  }
  const result: MarkDraft = { form: formAnchor, fields: { ...previous?.fields, [role]: field } };
  const resolved = resolve(result);
  if (resolved[role] !== input || markRoles.some(key => result.fields[key] && !resolved[key])) {
    throw new Error('这个表单或输入框无法唯一定位，请换一个输入框。');
  }
  return result;
}

export function canSaveMark(draft: MarkDraft): boolean {
  const fields = resolve(draft);
  return markRoles.every(role => !draft.fields[role] || !!fields[role]);
}

const kindByRole: Record<MarkRole, FillKind> = { username: 'username', password: 'login', otp: 'otp' };
function markedKind(mark: MarkDraft, target: Control): FillKind | undefined {
  if (!(target instanceof HTMLInputElement) || !target.form || !matching(anchor(target.form), mark.form)) return;
  const locator = describe(target);
  const role = markRoles.find(role => mark.fields[role] && sameFieldMark(mark.fields[role], locator));
  if (role && resolve(mark)[role] === target) return kindByRole[role];
}

export function markForTarget(marks: LoginMark[], target: Control) {
  let match: { mark: LoginMark; kind: FillKind } | undefined;
  for (const mark of marks) {
    const kind = markedKind(mark, target);
    if (!kind) continue;
    if (match) return; // Two independently valid rules can overlap after the page changes.
    match = { mark, kind };
  }
  return match;
}

export function markedForm(marks: LoginMark[], target: Control): boolean {
  const form = target.form && anchor(target.form);
  return !!form && marks.some(mark => matching(form, mark.form));
}

export function fillMarked(marks: LoginMark[], mark: LoginMark, target: Control, kind: FillKind, payload: FillPayload) {
  const match = markForTarget(marks, target);
  if (match?.mark !== mark || match.kind !== kind) return { filled: false, needsRemark: true };
  const url = location.href;
  const fields = resolve(mark);
  let filled = false;
  let needsRemark = markRoles.some(role => mark.fields[role] && !fields[role]);
  const roles: MarkRole[] = kind === 'login' ? ['username', 'password'] : kind === 'username' ? ['username'] : ['otp'];
  for (const role of roles) {
    const field = fields[role], value = payload.values[role];
    if (!field || !value || role === 'otp' && !/^[A-Z0-9]{5,8}$/.test(value)) continue;
    const valid = () => {
      const current = markForTarget(marks, field);
      return location.href === url && current?.mark === mark && current.kind === kindByRole[role];
    };
    if (valid() && setValue(field, value, valid)) filled = true;
    else needsRemark = true;
  }
  return { filled, needsRemark };
}

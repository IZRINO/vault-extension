import type { ItemSummary, VaultItem } from '../vault-messages';

export const kinds: Record<string, string> = {
  login: '登录',
  payment_card: '支付卡',
  identity: '身份与地址',
  developer: '开发者凭证',
};

export const subtypeNames: Record<string, string> = {
  api_token: 'API 令牌',
  license_key: '软件许可证',
  ssh_key: 'SSH 密钥',
};

export const matchRules: [value: string, label: string][] = [
  ['auto', '自动（推荐）'],
  ['base_domain', '主域名'],
  ['host', '主机与端口'],
  ['starts_with', '前缀'],
  ['exact', '完全一致'],
  ['regex', '正则表达式'],
  ['never', '从不匹配'],
];

export interface FieldSpec {
  key: string;
  label: string;
  secret?: boolean;
  multiline?: boolean;
  mode?: 'numeric' | 'tel' | 'email';
  /** 和下一个字段并排显示 */
  half?: boolean;
}

export const fieldSets: Record<string, FieldSpec[]> = {
  login: [
    { key: 'username', label: '用户名' },
    { key: 'password', label: '密码', secret: true },
  ],
  payment_card: [
    { key: 'cardholderName', label: '持卡人' },
    { key: 'cardNumber', label: '卡号', secret: true, mode: 'numeric' },
    { key: 'expMonth', label: '到期月份', mode: 'numeric', half: true },
    { key: 'expYear', label: '到期年份', mode: 'numeric', half: true },
    { key: 'cvv', label: '安全码', secret: true, mode: 'numeric', half: true },
    { key: 'cardPin', label: '卡片 PIN', secret: true, mode: 'numeric', half: true },
    { key: 'billingAddress', label: '账单地址' },
  ],
  identity: [
    { key: 'fullName', label: '姓名' },
    { key: 'phone', label: '电话', mode: 'tel', half: true },
    { key: 'email', label: '电子邮件', mode: 'email', half: true },
    { key: 'nationalIdOrPassport', label: '证件号码', secret: true },
    { key: 'country', label: '国家或地区', half: true },
    { key: 'province', label: '省份', half: true },
    { key: 'city', label: '城市', half: true },
    { key: 'postalCode', label: '邮政编码', half: true },
    { key: 'addressLine', label: '详细地址' },
    { key: 'company', label: '公司', half: true },
    { key: 'taxId', label: '税号', half: true },
  ],
  developer: [
    { key: 'serviceOrProduct', label: '服务或产品' },
    { key: 'tokenOrLicense', label: '令牌或许可密钥', secret: true },
    { key: 'publicKey', label: '公钥', multiline: true },
    { key: 'privateKey', label: '私钥', secret: true, multiline: true },
  ],
};

/** 开发者凭证按子类型显示的字段；已经填了内容的字段总是显示。 */
export function developerFieldVisible(key: string, subtype: string, value: unknown): boolean {
  if (key === 'serviceOrProduct' || value) return true;
  if (key === 'tokenOrLicense') return subtype !== 'ssh_key';
  return subtype === 'ssh_key';
}

export function newItem(kind = 'login', subtype = 'api_token'): VaultItem {
  return { id: '', title: '', data: { kind, subtype }, note: '', tags: [], customFields: [], pinned: false, requireReprompt: false, trashed: false };
}

export function download(name: string, data: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** 用户自己取消的操作：不当作错误提示。 */
export class Cancelled extends Error {}

export function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function plateText(title: string): string {
  const first = Array.from(title.trim())[0];
  return first ? first.toLocaleUpperCase() : '';
}

export function text(value: unknown): string {
  return typeof value === 'string' ? value : value == null ? '' : String(value);
}

export function kindLabel(item: { kind: string; devSubtype?: string | null }): string {
  if (item.kind === 'developer' && item.devSubtype) return subtypeNames[item.devSubtype] ?? kinds.developer!;
  return kinds[item.kind] ?? '凭证';
}

export function formatDateTime(ms: number | undefined): string {
  if (!ms) return '';
  return new Date(ms).toLocaleString('zh-CN', { year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export const isPopup = () => document.body.classList.contains('popup');

/** 列表筛选：回收站只看已移除的，其余只看未移除的；再按分类和搜索词过滤。 */
export function filterItems(items: ItemSummary[], filter: string, query: string): ItemSummary[] {
  const needle = query.trim().toLocaleLowerCase();
  return items.filter(item => (filter === 'trash' ? item.trashed : !item.trashed) &&
    (['all', 'trash'].includes(filter) || (filter === 'pinned' ? item.pinned : item.kind === filter)) &&
    (!needle || [item.title, item.subtitle, item.primaryDomain, ...item.tags].join(' ').toLocaleLowerCase().includes(needle)));
}

/** 后端在没有填写服务名时给出的英文占位副标题，界面上改用中文类型名。 */
const developerFallbacks = ['API Token', 'Software License', 'SSH Keypair'];

export function rowSubtitle(item: ItemSummary): string {
  if (item.kind === 'login') {
    const domain = item.primaryDomain && item.primaryDomain !== item.subtitle ? item.primaryDomain : '';
    return [item.subtitle, domain].filter(Boolean).join(' · ') || '登录';
  }
  const detail = item.kind === 'developer' && developerFallbacks.includes(item.subtitle) ? '' : item.subtitle;
  return [kindLabel(item), detail].filter(Boolean).join(' · ');
}

/** 把用户填的网址变成可以打开的地址；不是网页地址时返回 undefined。 */
export function openableUrl(uri: string): string | undefined {
  const raw = uri.trim();
  if (!raw) return undefined;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : 'https://' + raw);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : undefined;
  } catch { return undefined; }
}

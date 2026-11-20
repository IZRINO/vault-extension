import { getDomain } from 'tldts';
import { RE2JS } from 're2js';

export { defaultFlags, type AutofillSettings, type SiteFlags } from './autofill-settings';
const builtInGroups = [
  ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'],
  ['google.com', 'youtube.com'], ['taobao.com', 'tmall.com', 'alipay.com'],
  ['jd.com', '3.cn'], ['apple.com', 'icloud.com'],
];

export function webUrl(raw: unknown): URL {
  if (typeof raw !== 'string' || raw.length > 8192) throw new Error('网页地址无效。');
  const url = new URL(raw);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname) throw new Error('仅支持 HTTP(S) 网页。');
  return url;
}
export function localHost(host: string): boolean {
  return host === 'localhost' || !host.includes('.') || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.lan') ||
    host === '[::1]' || host.startsWith('[fc') || host.startsWith('[fd') || host.startsWith('[fe80:') ||
    /^\d+\.\d+\.\d+\.\d+$/.test(host);
}
function domain(url: URL) {
  return getDomain(url.hostname, { allowPrivateDomains: true }) ?? url.hostname;
}
export function sameSite(a: URL, b: URL, custom: string[][] = []): boolean {
  if (localHost(a.hostname) || localHost(b.hostname)) return a.origin === b.origin;
  if (a.protocol !== b.protocol || a.port !== b.port) return false;
  const da = domain(a), db = domain(b);
  return da === db || [...builtInGroups, ...custom].some(group => group.includes(da) && group.includes(db));
}
export function uriMatches(saved: { uri: string; matchRule?: string }, target: URL, custom: string[][] = []): boolean {
  try {
    if (saved.matchRule === 'never') return false;
    if (saved.matchRule === 'regex') {
      return !localHost(target.hostname) && saved.uri.length <= 2048 && RE2JS.compile(saved.uri).matches(target.href);
    }
    const url = webUrl(saved.uri);
    if (url.protocol !== target.protocol) return false;
    // No override can turn a loopback/private service into a wildcard.
    const local = localHost(url.hostname) || localHost(target.hostname);
    if (local && url.origin !== target.origin) return false;
    switch (saved.matchRule) {
      case 'exact': return url.href === target.href;
      case 'starts_with': return url.origin === target.origin && target.href.startsWith(url.href);
      case 'host': return url.host === target.host;
      default: return local ? url.origin === target.origin : sameSite(url, target, custom);
    }
  } catch { return false; }
}
export function loginUrisMatch(uris: readonly { uri: string; matchRule?: string }[], target: URL, custom: string[][]): boolean {
  // A page-level exclusion takes precedence over another URI's domain rule.
  if (uris.some(entry => {
    if (entry.matchRule !== 'never') return false;
    try {
      const blocked = webUrl(entry.uri);
      return blocked.origin === target.origin && blocked.pathname === target.pathname;
    } catch { return false; }
  })) return false;
  return uris.some(uri => uriMatches(uri, target, custom));
}
export function validateGroups(groups: unknown): string[][] {
  if (!Array.isArray(groups) || groups.length > 32) throw new Error('最多设置 32 组关联域名。');
  return groups.map(group => {
    if (!Array.isArray(group) || group.length < 2 || group.length > 16) throw new Error('每组需要 2–16 个主域名。');
    const result = group.map(value => {
      if (typeof value !== 'string' || value.length > 253 || !/^[a-z0-9.-]+$/i.test(value)) throw new Error('请填写主域名，不含协议、端口或路径。');
      const host = value.toLowerCase();
      const url = webUrl('https://' + host);
      if (localHost(host) || domain(url) !== host || !getDomain(host, { allowPrivateDomains: true })) throw new Error('关联组仅支持可注册的公网主域名。');
      return host;
    });
    if (new Set(result).size !== result.length) throw new Error('同组域名不能重复。');
    return result;
  });
}

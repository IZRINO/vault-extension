import { derive } from '../bridge';
import type { SessionState } from '../vault-storage';
import { probeWebDav, webDavConfig, type DavContext, type DavProbe, type DavStopStatus, type WebDavConfig, type WebDavInput } from './webdav';

interface Seal { vaultId: string; bytes: number[] }
interface ClockSample { offset: number | null; observedAt: number; enabled: boolean }
interface LocalData { webDavSealed?: Seal; webDavPaused?: DavStopStatus; webDavClock?: ClockSample; webDavConflicts?: number }
export interface DavConnectionStatus { saved: boolean; paused?: DavStopStatus; offsetSeconds: number | null; compensation: boolean; linked?: boolean; conflicts?: number; drafts?: number; localRestoreHeld?: boolean }
const keys: (keyof LocalData)[] = ['webDavSealed', 'webDavPaused', 'webDavClock', 'webDavConflicts'];
const maxClockAge = 30 * 60 * 1000;
const read = () => browser.storage.local.get<LocalData>(keys);

function clockOffset(sample: ClockSample | undefined, now = Date.now()): number | null {
  if (!sample || sample.offset === null || !Number.isInteger(sample.offset) ||
      Math.abs(sample.offset) < 15 || Math.abs(sample.offset) > 86400 ||
      !Number.isSafeInteger(sample.observedAt) || now < sample.observedAt || now - sample.observedAt > maxClockAge) return null;
  return sample.offset;
}

function pauseStatus(state: LocalData) {
  return state.webDavPaused && [401, 403, 429].includes(state.webDavPaused) ? state.webDavPaused : undefined;
}

async function showBadge(paused: boolean, conflicts = 0) {
  if (!browser.action) return;
  if (paused || conflicts) await browser.action.setBadgeBackgroundColor({ color: paused ? '#a52c24' : '#945800' });
  await browser.action.setBadgeText({ text: paused ? '!' : conflicts > 99 ? '99+' : conflicts ? String(conflicts) : '' });
}

export async function showConflictBadge(count: number) {
  await browser.storage.local.set({ webDavConflicts: count });
  await restoreDavBadge();
}

export async function pauseDav(status: DavStopStatus) {
  await browser.storage.local.set({ webDavPaused: status });
  await showBadge(true).catch(() => undefined);
}

export async function requireDavHealthy() {
  const status = pauseStatus(await read());
  if (status) throw new Error(`网盘连接已暂停（HTTP ${status}）。请手动测试连接后再试。`);
}

export async function restoreDavBadge() {
  const state = await read();
  await showBadge(!!pauseStatus(state), state.webDavConflicts ?? 0);
}

export async function saveDavConnection(config: WebDavConfig, session: SessionState, vaultId: string, offset: number | null | undefined, check: () => void) {
  const existing = await read();
  check();
  const bytes = await derive<number[]>('seal-webdav', [session.key, session.wrap, JSON.stringify(config)]);
  const sameVault = existing.webDavSealed?.vaultId === vaultId;
  const clock: ClockSample = offset === undefined && sameVault && existing.webDavClock ? existing.webDavClock :
    { offset: offset ?? null, observedAt: Date.now(), enabled: sameVault && existing.webDavClock?.enabled === true };
  check();
  await browser.storage.local.set({ webDavClock: clock, webDavSealed: { vaultId, bytes } } satisfies LocalData);
  check();
}

export async function davStatus(vaultId?: string): Promise<DavConnectionStatus> {
  const state = await read();
  const saved = !!state.webDavSealed && state.webDavSealed.vaultId === vaultId;
  return { saved, paused: pauseStatus(state), offsetSeconds: saved ? clockOffset(state.webDavClock) : null,
    compensation: saved && state.webDavClock?.enabled === true };
}

export async function openSavedDav(state: SessionState, vaultId: string): Promise<WebDavConfig> {
  const { webDavSealed } = await read();
  if (!webDavSealed || webDavSealed.vaultId !== vaultId) throw new Error('尚未保存这个密码库的网盘设置。');
  if (!Array.isArray(webDavSealed.bytes) || webDavSealed.bytes.length > 9216 ||
      !webDavSealed.bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new Error('加密的网盘配置已损坏。');
  const config = JSON.parse(await derive<string>('open-webdav', [state.key, state.wrap, new Uint8Array(webDavSealed.bytes)])) as WebDavConfig;
  const target = new URL(config.url);
  const parts = target.pathname.slice(1, -1).split('/');
  const folder = decodeURIComponent(parts.pop() ?? '');
  const base = `${target.origin}/${parts.join('/')}`;
  const valid = webDavConfig({ provider: 'custom', base, folder, username: config.username, password: config.password, confirmHttp: true });
  if (valid.url !== config.url) throw new Error('加密的网盘地址无效。');
  return { ...valid, writeVerified: config.writeVerified === true };
}

export async function testDav(input: WebDavInput | undefined, remember: boolean, session: SessionState | undefined, vaultId: string | undefined,
  context: DavContext): Promise<DavProbe> {
  if ((!input || remember) && (!session || !vaultId)) throw new Error('请先创建或解锁密码库，才能保存网盘设置。');
  const config = input ? webDavConfig(input) : await openSavedDav(session!, vaultId!);
  try {
    const result = await probeWebDav(config, { ...context, stop: pauseDav });
    context.check?.();
    if (result.kind !== 'empty' && result.kind !== 'existing' && !(input && result.kind === 'missing')) return result;
    const stored = await read();
    if (remember || !input) {
      if (remember) {
        await saveDavConnection(config, session!, vaultId!, result.offsetSeconds, () => context.check?.());
      } else {
        const clock: ClockSample = { offset: result.offsetSeconds, observedAt: Date.now(), enabled: stored.webDavClock?.enabled === true };
        context.check?.();
        await browser.storage.local.set({ webDavClock: clock });
      }
      context.check?.();
      await browser.storage.local.remove('webDavPaused');
      await restoreDavBadge().catch(() => undefined);
    } else if (!stored.webDavSealed) {
      await browser.storage.local.remove('webDavPaused');
      await restoreDavBadge().catch(() => undefined);
    }
    return result;
  } finally { config.password = ''; config.username = ''; }
}

export async function setDavCompensation(vaultId: string, enabled: boolean, check: () => void) {
  const state = await read();
  if (state.webDavSealed?.vaultId !== vaultId || typeof enabled !== 'boolean') throw new Error('请先保存网盘连接。');
  if (enabled && (pauseStatus(state) || clockOffset(state.webDavClock) === null)) throw new Error('没有有效的时间偏差样本，请重新测试 HTTPS 连接。');
  check();
  await browser.storage.local.set({ webDavClock: { ...(state.webDavClock ?? { offset: null, observedAt: 0 }), enabled } satisfies ClockSample });
}

export async function readDavClock(vaultId: string): Promise<ClockSample | undefined> {
  const state = await read();
  if (state.webDavSealed?.vaultId === vaultId && !pauseStatus(state) && state.webDavClock?.enabled === true) return state.webDavClock;
}

export function davClockOffset(sample: ClockSample | undefined) { return clockOffset(sample) ?? 0; }

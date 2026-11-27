import { derive } from '../bridge';
import type { SessionState } from '../vault-storage';
import { endpointFingerprint } from './bootstrap';
import { davPresets, probeWebDav, webDavConfig, WebDavStop, type DavContext, type DavProbe, type DavStopStatus, type WebDavConfig, type WebDavInput } from './webdav';

interface Seal { vaultId: string; bytes: number[] }
const readOnlySeals = new WeakMap<WebDavConfig, Seal>();
const sessionFallbacks = new WeakMap<SessionState, { source: number[]; seal: Seal }>();
interface ClockSample { offset: number | null; observedAt: number; enabled: boolean }
interface LocalData { webDavSealed?: Seal; webDavPaused?: DavStopStatus | null; webDavClock?: ClockSample; webDavConflicts?: number }
export interface DavConnectionStatus {
  saved: boolean; paused?: DavStopStatus; offsetSeconds: number | null; clockExpiresAt?: number; compensation: boolean;
  linked?: boolean; writeVerified?: boolean; conflicts?: number; drafts?: number; localRestoreHeld?: boolean; format?: 'pack'; pending?: boolean;
  siteRulesPending?: boolean; siteRulesApplied?: boolean; siteRuleConflicts?: number; checkFailed?: boolean;
}
const keys: (keyof LocalData)[] = ['webDavSealed', 'webDavPaused', 'webDavClock', 'webDavConflicts'];
const maxClockAge = 30 * 60 * 1000;
const read = () => browser.storage.local.get<LocalData>(keys);
const correctedSettingsNeeded = '网盘连接已暂停。请修正连接设置，再测试并保存连接。';
const koofrOrigin = new URL(davPresets.koofr).origin;

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

async function pauseDav(status: DavStopStatus) {
  await browser.storage.local.set({ webDavPaused: status });
  await showBadge(true).catch(() => undefined);
}

// Share a stop immediately, before storage or badge updates yield. Replacing a
// connection retires its request contexts, including replies already in flight.
export class DavRequestGate {
  private readonly endpoints = new Map<string, { stopped?: WebDavStop; readOnly?: boolean }>();
  constructor(private readonly onPause: () => void) {}

  reset() { this.endpoints.clear(); }
  stopped(url: string) { return !!this.endpoints.get(url)?.stopped; }

  context(config: WebDavConfig, operation: DavContext, retry = false, persist = true) {
    const url = config.url;
    let shared = this.endpoints.get(url);
    if (!shared || (retry && shared.stopped)) {
      shared = {};
      this.endpoints.set(url, shared);
    }
    const endpoint = shared;
    const startedReadOnly = endpoint.readOnly;
    if (endpoint.readOnly) config.writeVerified = false;
    const current = () => {
      if (operation.signal?.aborted) throw new Error('密码库已锁定，已停止 WebDAV 请求。');
      if (this.endpoints.get(url) !== endpoint) throw new Error('网盘连接已变更，请重新检查。');
      if (endpoint.stopped) throw endpoint.stopped;
    };
    return { ...operation, check: () => {
      current();
      if (startedReadOnly !== endpoint.readOnly) throw new Error('网盘已恢复只读，请重新检查。');
      operation.check?.();
    },
      revokeWriting: () => {
        current();
        const seal = readOnlySeals.get(config);
        if (!seal) throw new Error('无法恢复只读连接，请重新测试并保存网盘设置。');
        endpoint.readOnly = true;
        return browser.storage.local.set({ webDavSealed: seal });
      },
      stop: (status: DavStopStatus) => {
        current();
        endpoint.stopped = new WebDavStop(status);
        if (persist) {
          this.onPause();
          return pauseDav(status);
        }
      } };
  }
}

export async function requireDavHealthy() {
  const status = pauseStatus(await read());
  if (status) throw new Error(`网盘连接已暂停（HTTP ${status}）。请手动测试连接后再试。`);
}

export async function restoreDavBadge() {
  const state = await read();
  await showBadge(!!pauseStatus(state), state.webDavConflicts ?? 0);
}

async function sealDavSettings(config: WebDavConfig, session: SessionState, vaultId: string,
  offset: number | null | undefined, existing: LocalData) {
  const bytes = await derive<number[]>('seal-webdav', [session.key, session.wrap, JSON.stringify(config)]);
  const sameVault = existing.webDavSealed?.vaultId === vaultId;
  const clock: ClockSample = offset === undefined && sameVault && existing.webDavClock ? existing.webDavClock :
    { offset: offset ?? null, observedAt: Date.now(), enabled: sameVault && existing.webDavClock?.enabled === true };
  return { webDavClock: clock, webDavSealed: { vaultId, bytes } };
}

export async function saveDavConnection(config: WebDavConfig, session: SessionState, vaultId: string, offset: number | null | undefined,
  check: () => void) {
  const existing = await read();
  check();
  const update = await sealDavSettings(config, session, vaultId, offset, existing);
  check();
  await browser.storage.local.set(update);
  check();
}

export async function davStatus(vaultId?: string): Promise<DavConnectionStatus> {
  const state = await read();
  const saved = !!state.webDavSealed && state.webDavSealed.vaultId === vaultId;
  const paused = pauseStatus(state);
  const offsetSeconds = saved && !paused ? clockOffset(state.webDavClock) : null;
  return { saved, paused, offsetSeconds,
    ...(offsetSeconds !== null ? { clockExpiresAt: state.webDavClock!.observedAt + maxClockAge + 1 } : {}),
    compensation: saved && state.webDavClock?.enabled === true };
}

export async function observeDavClock(vaultId: string, offset: number | null, observedAt: number, check: () => void) {
  const state = await read();
  check();
  if (state.webDavSealed?.vaultId !== vaultId || pauseStatus(state) ||
      (offset === null && state.webDavClock?.offset == null)) return;
  await browser.storage.local.set({ webDavClock: { offset, observedAt, enabled: state.webDavClock?.enabled === true } });
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
  const saved = { ...valid, writeVerified: config.writeVerified === true };
  if (saved.writeVerified) {
    // Keep the sealed fallback ready before any network request. A lock may
    // erase the session key immediately after an integrity failure is observed.
    const source = webDavSealed.bytes;
    let cached = sessionFallbacks.get(state);
    if (!cached || cached.seal.vaultId !== vaultId || cached.source.length !== source.length ||
        !cached.source.every((byte, index) => byte === source[index])) {
      const bytes = await derive<number[]>('seal-webdav', [state.key, state.wrap, JSON.stringify({ ...saved, writeVerified: false })]);
      cached = { source, seal: { vaultId, bytes } };
      sessionFallbacks.set(state, cached);
    }
    readOnlySeals.set(saved, cached.seal);
  }
  return saved;
}

export async function testDav(input: WebDavInput | undefined, remember: boolean, session: SessionState | undefined, vaultId: string | undefined,
  operation: DavContext, gate: DavRequestGate, linkedEndpoint?: string): Promise<{ probe: DavProbe; resumed: boolean }> {
  if ((!input || remember) && (!session || !vaultId)) throw new Error('请先创建或解锁密码库，才能保存网盘设置。');
  const stored = await read();
  operation.check?.();
  const paused = pauseStatus(stored);
  const hasSaved = !!stored.webDavSealed && stored.webDavSealed.vaultId === vaultId;
  const correctSaved = !!paused && hasSaved;
  if (correctSaved && (!input || !remember)) throw new Error(correctedSettingsNeeded);
  const config = input ? webDavConfig(input) : await openSavedDav(session!, vaultId!);
  try {
    if (paused && linkedEndpoint && await endpointFingerprint(config.url) !== linkedEndpoint)
      throw new Error('连接地址与已验证的库不同。请在原同步目录修正连接设置。');
    let sameTarget = !input || !hasSaved;
    let previousUrl: string | undefined;
    if (input && hasSaved) {
      const saved = await openSavedDav(session!, vaultId!);
      try {
        previousUrl = saved.url;
        sameTarget = config.url === saved.url;
        if (correctSaved && config.password === saved.password) {
          if (new URL(config.url).origin === koofrOrigin && new URL(saved.url).origin === koofrOrigin)
            throw new Error('Koofr 连接已暂停。请更换应用专用密码，再测试并保存连接。');
          // Outside Koofr, fixing permissions or waiting out a throttle need not change the login.
          if (paused === 401 && config.url === saved.url && config.username === saved.username)
            throw new Error(correctedSettingsNeeded);
        }
      } finally { saved.password = ''; saved.username = ''; }
    }
    operation.check?.();
    const context = gate.context(config, operation, !!paused || !sameTarget, sameTarget);
    const probe = await probeWebDav(config, context);
    context.check();
    // A 404 does not establish that the server accepted the application credentials.
    if (probe.kind !== 'empty' && probe.kind !== 'existing' && !(input && probe.kind === 'missing' && !paused))
      return { probe, resumed: false };
    if (remember) {
      const update = await sealDavSettings(config, session!, vaultId!, probe.offsetSeconds, stored);
      context.check();
      if (probe.kind === 'missing' && previousUrl && gate.stopped(previousUrl)) return { probe, resumed: false };
      gate.reset();
      // Make the corrected, read-only connection and clearing the pause visible together.
      const resetPause = !!paused || !sameTarget;
      await browser.storage.local.set({ ...update, ...(resetPause ? { webDavPaused: null } : {}) });
      if (resetPause) await restoreDavBadge().catch(() => undefined);
    } else if (!input) {
      const clock: ClockSample = { offset: probe.offsetSeconds, observedAt: Date.now(), enabled: stored.webDavClock?.enabled === true };
      await browser.storage.local.set({ webDavClock: clock });
    } else if (paused && !stored.webDavSealed) {
      await browser.storage.local.remove('webDavPaused');
      await restoreDavBadge().catch(() => undefined);
    }
    return { probe, resumed: remember && !!paused };
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

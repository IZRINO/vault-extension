import { loadVaultCore, randomBytes } from './vault-core';
import { derive, offscreen } from './bridge';
import { copyWithExpiry } from './clipboard';
import * as store from './vault-storage';
import { capacityErrorText, MAX_BROWSER_CSV_BYTES, MAX_ENTE_BYTES, MAX_OTP_SETUP_LENGTH, MAX_VAULTPACK_BYTES, type BackupExport, type BackupReceipt, type BrowserCsvPreview, type EntePreview, type HotpCode, type ItemDetailData, type ItemSummary, type OtpWorkerCode, type Proof, type TimedOtpCode, type VaultItem, type VaultMessage, type VaultOpening, type VaultPackPreview, type VaultStatus } from './vault-messages';
import { planEnteImport, type EnteBatch } from './ente-auth';
import { loginUrisMatch, validateGroups, webUrl, type AutofillSettings } from './autofill-policy';
import type { FillCandidate, FillKind, FillPayload } from './autofill-messages';
import { planMigration, type MigrationBatch } from './migration';
import { AUTH_BACKUP_FORMATS, MAX_AUTH_BACKUP_BYTES, MAX_MIGRATION_BYTES, PORTABLE_FORMATS, type AuthBackupPreview, type MigrationExport, type MigrationPreview } from './vault-messages';
import type { QrScan } from './vault-messages';
import { davClockOffset, davStatus, openSavedDav, pauseDav, readDavClock, requireDavHealthy, saveDavConnection, setDavCompensation, showConflictBadge, testDav } from './sync/connection';
import { adoptDevice, nextJournalVersion, type JournalClock } from './sync/journal-device';
import { createRemoteVault, endpointFingerprint, HEAD_LIMIT, packSyncFrames, readRemoteVault, type RemoteHeadInfo, type ReplayOutput } from './sync/bootstrap';
import { proveConditionalWrites, WebDavClient, webDavConfig } from './sync/webdav';
import { runDavSync, type SyncResult } from './sync/run';
import { deviceProfile } from './sync/device-profile';
import { listHistory, prepareRestore, restoreHistory, restoreHistoryLocally } from './sync/history';
import type { PasskeyCandidate, PasskeyReply, PasskeySelection, TrustedRequest } from './passkeys/protocol';
import { checkScanSource, type ScanSource, type ScanTicket } from './qr-scan';

export const LOCK_ALARM = 'vault-lock';
export const DAV_ALARM = 'vault-webdav';
export const IDLE_DETECTION_SECONDS = 60;
type Core = Awaited<ReturnType<typeof loadVaultCore>>;
type Engine = InstanceType<Core['WasmVaultEngine']>;
type Created = { head: number[]; snap: number[]; wrap: number[]; vaultId: string; keyEpoch: number; recoveryCode: string };
type Rotation = { head: number[]; wrap: number[]; keyEpoch: number };
type Mutation = { head_bytes: Uint8Array; snap_bytes: Uint8Array; count: number; free(): void };

async function digestHex(bytes: Uint8Array<ArrayBuffer>) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

const internalFields = new Set(['Bitwarden 保留字段', 'Bitwarden 未识别的验证码设置', 'CSV 未识别的验证码设置', 'CSV 源自定义字段', 'CSV 源归档状态', 'Vault 迁移来源']);
type AuthorizationScope = 'vaultpack:receipt:v1' | 'otp:read:v1';
async function authorize(key: Uint8Array, scope: AuthorizationScope, payload: Uint8Array) {
  try {
    const mac = await derive<number[]>('sign-authorization', [key, scope, payload]);
    return btoa(String.fromCharCode(...mac));
  } finally { payload.fill(0); }
}

function validAuthorization(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(value);
}

async function verifyAuthorization(key: Uint8Array, scope: AuthorizationScope, authorization: string, payload: Uint8Array) {
  try {
    return await derive<boolean>('verify-authorization', [key, scope, payload, Uint8Array.from(atob(authorization), c => c.charCodeAt(0))]);
  } finally { payload.fill(0); }
}

function receiptPayload(vaultId: string, keyEpoch: number, changeCount: number) {
  return new TextEncoder().encode(JSON.stringify([vaultId, keyEpoch, changeCount]));
}

function otpSetup(item: VaultItem) {
  return item.data.kind === 'login' && typeof item.data.totpUri === 'string' ? item.data.totpUri.trim() : '';
}

function otpPayload(item: VaultItem, setup: string) {
  return new TextEncoder().encode(JSON.stringify([item.id, item.revision, item.updatedAtMs, item.requireReprompt, setup]));
}

function sessionExpired(session: store.SessionState, settings: store.LocalSettings): boolean {
  const now = Date.now();
  return session.lastActivityMs > now || now - session.lastActivityMs >= settings.autoLockMinutes * 60000;
}

export class VaultController {
  private core?: Core;
  private engine?: Engine;
  private files?: store.VaultFiles;
  private session?: store.SessionState;
  private settings?: store.LocalSettings;
  private tail: Promise<unknown> = Promise.resolve();
  private locking?: Promise<void>;
  private generation = 0;
  private lastCaptureMs = -Infinity;
  private autofill?: AutofillSettings;
  private auditAbort = new AbortController();
  private davAbort = new AbortController();
  private davClock?: Promise<Awaited<ReturnType<typeof readDavClock>>>;
  private davTimer?: ReturnType<typeof setTimeout>;

  handle(message: VaultMessage): Promise<unknown> {
    if (message.type === 'lock') return this.lock();
    return this.enqueue(check => this.dispatch(message, check));
  }

  private enqueue<T>(operation: (check: () => void) => Promise<T>): Promise<T> {
    const generation = this.generation;
    const run = this.tail.then(async () => {
      const check = () => { if (generation !== this.generation) throw new Error('密码库已锁定，请重新解锁。'); };
      if (this.locking) await this.locking;
      check();
      await this.prepare();
      check();
      const value = await operation(check);
      check();
      return value;
    });
    this.tail = run.catch(() => undefined);
    return run;
  }

  scanOtp(source: ScanSource, signal: AbortSignal): Promise<ScanTicket> {
    return this.enqueue(async check => {
      signal.throwIfAborted();
      if (!this.files || !this.session || !this.engine?.is_unlocked()) throw new Error('请先解锁密码库。');
      const session = this.session;
      const vaultId = this.files.vaultId;
      const checkSession = () => {
        check();
        if (this.session !== session || this.files?.vaultId !== vaultId) throw new Error('密码库会话已改变，请重新扫描。');
      };
      webUrl(source.url);
      await this.touch();
      const wait = 600 - (performance.now() - this.lastCaptureMs);
      if (wait > 0 && !signal.aborted) await new Promise<void>(resolve => {
        const finish = () => {
          clearTimeout(timer);
          signal.removeEventListener('abort', finish);
          resolve();
        };
        const timer = setTimeout(finish, wait);
        signal.addEventListener('abort', finish, { once: true });
      });
      signal.throwIfAborted();
      checkSession();
      let captureMs = 0;
      const scanned = await offscreen<Omit<QrScan, 'timings'> & { timings: Omit<QrScan['timings'], 'captureMs'> }>('scan-otp', async () => {
        await checkScanSource(source, signal);
        checkSession();
        this.lastCaptureMs = performance.now();
        let data: string;
        try {
          data = await browser.tabs.captureVisibleTab(source.windowId, { format: 'jpeg', quality: 95 });
        } catch (error) {
          if (/activeTab|all_urls|permission/i.test(error instanceof Error ? error.message : String(error))) {
            throw new Error('截图尚未授权。请先点击浏览器工具栏的 Vault 图标，再扫描当前网站的二维码。');
          }
          throw new Error('浏览器暂时无法截图，请稍后重试。');
        }
        captureMs = performance.now() - this.lastCaptureMs;
        signal.throwIfAborted();
        checkSession();
        return data;
      });
      await checkScanSource(source, signal);
      checkSession();
      if (!scanned.values.length) throw new Error('没有找到验证码二维码。请把完整二维码显示在当前页面，或手动粘贴密钥。');
      return { scan: { values: scanned.values, timings: { ...scanned.timings, captureMs } }, checkSession };
    });
  }

  passkeyAvailable(origin: string): Promise<boolean> {
    return this.enqueue(async check => !!this.session && !(await this.readAutofillSettings(check)).sites[origin]?.passkeyDisabled);
  }

  passkeyCandidates(request: TrustedRequest): Promise<PasskeyCandidate[]> {
    return this.enqueue(async check => {
      if (!this.session || (await this.readAutofillSettings(check)).sites[request.origin]?.passkeyDisabled) throw new Error('Passkey 已停用或密码库已锁定。');
      const { key, wrap } = this.session;
      const { head, snap } = this.files!;
      const json = await derive<string>('passkey:candidates', [key, wrap, head, snap, JSON.stringify(request)]);
      check();
      return JSON.parse(json) as PasskeyCandidate[];
    });
  }

  passkeyAnswer(request: TrustedRequest, selection: PasskeySelection, current: () => void): Promise<PasskeyReply> {
    return this.enqueue(async generationCheck => {
      const check = () => { generationCheck(); current(); };
      check();
      if (!this.session || (await this.readAutofillSettings(check)).sites[request.origin]?.passkeyDisabled) throw new Error('Passkey 已停用或密码库已锁定。');
      if (selection.proof) await this.verify(selection.proof, check);
      check();
      const { key, wrap } = this.session;
      const active = this.files!;
      const anchor = await store.loadRemoteAnchor(active.vaultId);
      check();
      const result = await derive<{ reply: string; head: number[]; snap: number[] }>('passkey:perform', [
        key, wrap, active.head, active.snap, JSON.stringify(request), JSON.stringify({
          itemId: selection.itemId, credentialId: selection.credentialId, verified: !!selection.proof,
          increment: selection.increment === true && request.kind === 'register', now: Date.now(),
        }),
        anchor?.appliedHead ?? new Uint8Array(), anchor?.appliedSnap ?? new Uint8Array(),
      ]);
      check();
      if (result.snap.length) {
        const files = { ...active, head: new Uint8Array(result.head), snap: new Uint8Array(result.snap),
          updatedAtMs: Date.now(), everHadRecords: true, changesSinceBackup: active.changesSinceBackup + 1 };
        await this.persistMutation(files, check);
        this.engine!.restore_from_session(key, wrap, files.head, files.snap);
      }
      check();
      return JSON.parse(result.reply) as PasskeyReply;
    });
  }

  lock(invalidatePending = true): Promise<void> {
    if (invalidatePending) this.generation++;
    this.engine?.lock_and_zeroize();
    this.session?.key.fill(0);
    this.session?.wrap.fill(0);
    this.session = undefined;
    this.autofill = undefined;
    this.auditAbort.abort(new Error('密码库已锁定，请重新解锁。'));
    this.auditAbort = new AbortController();
    this.davAbort.abort();
    this.davAbort = new AbortController();
    clearTimeout(this.davTimer);
    this.davTimer = undefined;
    this.davClock = undefined;
    const locking = store.clearSessionState().then(async () => {
      await browser.alarms.clear(LOCK_ALARM);
      await browser.alarms.clear(DAV_ALARM);
    });
    // Requests arriving after lock began must not read the session being erased.
    this.locking = locking;
    void browser.runtime.sendMessage({ target: 'vault-event', type: 'locked' }).catch(() => undefined);
    void locking.then(() => {
      if (this.locking === locking) this.locking = undefined;
    }, () => undefined);
    return locking;
  }

  async lockExpiredSession(): Promise<boolean> {
    const { session, settings } = this;
    if (!session || !settings) {
      return !(await this.handle({ type: 'status' }) as VaultStatus).unlocked;
    }
    // Don't queue an expired in-memory session behind a slow derivation.
    if (!sessionExpired(session, settings)) return false;
    await this.lock();
    return true;
  }

  private needsRemoteKey(files: store.VaultFiles) {
    return files.remoteKeyUpdate ?? store.loadRemoteAnchor(files.vaultId).then(anchor => !!anchor?.observedHead);
  }

  private async prepare() {
    const generation = this.generation;
    if (!this.core) performance.mark('vault:prepare');
    const memorySession = this.session;
    const readSession = memorySession ? undefined : store.loadSessionState();
    try {
      const [core, settings, files, saved, idle] = await Promise.all([
        this.core ?? loadVaultCore(),
        store.loadSettings(),
        store.loadVaultFiles(),
        memorySession ?? readSession,
        readSession ? browser.idle.queryState(IDLE_DETECTION_SECONDS) : undefined,
      ]);
      if (generation !== this.generation) return;
      this.core = core;
      this.engine ??= new core.WasmVaultEngine();
      this.settings = settings;
      this.files = files;
      if (!saved) return;
      if (!files || idle === 'locked' || sessionExpired(saved, settings)) {
        await this.lock(false);
        return;
      }
      // An interrupted sync can persist a new remote wrap before clearing storage.session.
      let needsRemoteKey = files.remoteKeyUpdate;
      if (!memorySession && needsRemoteKey === undefined) {
        needsRemoteKey = await this.needsRemoteKey(files);
        if (generation !== this.generation) return;
        this.files = { ...files, remoteKeyUpdate: needsRemoteKey };
      }
      if (needsRemoteKey) {
        await this.lock(false);
        return;
      }
      try {
        if (memorySession) return;
        performance.mark('vault:restore-compute-start');
        this.engine.restore_from_session(saved.key, saved.wrap, files.head, files.snap);
        this.session = saved;
        performance.mark('vault:session-restored');
      } catch { await this.lock(false); }
    } finally {
      // A lock or failed parallel read can abandon a copy read from session storage.
      void readSession?.then(saved => {
        if (saved && saved !== this.session) {
          saved.key.fill(0);
          saved.wrap.fill(0);
        }
      }, () => undefined);
    }
  }

  private status(): VaultStatus {
    return { configured: !!this.files, unlocked: !!this.engine?.is_unlocked(), pinEnabled: !!this.settings?.pinWrap,
      prf: this.settings?.prf ? { credentialId: this.settings.prf.credentialId, salt: this.settings.prf.salt } : undefined,
      vaultId: this.files?.vaultId, keyEpoch: this.files?.keyEpoch,
      autoLockMinutes: this.settings!.autoLockMinutes, changesSinceBackup: this.files?.changesSinceBackup ?? 0 };
  }

  private async activate(key: Uint8Array, wrap: number[], check: () => void) {
    check();
    this.engine!.restore_from_session(key, new Uint8Array(wrap), this.files!.head, this.files!.snap);
    this.session?.key.fill(0);
    this.session = { key: new Uint8Array(key), wrap: new Uint8Array(wrap), unlockedAtMs: Date.now(), lastActivityMs: Date.now() };
    try {
      await this.touch();
      check();
      this.scheduleDav();
    } catch (error) { await this.lock(); throw error; }
  }

  private async touch() {
    if (!this.session) throw new Error('请先解锁密码库。');
    this.session.lastActivityMs = Date.now();
    await store.saveSessionState(this.session);
    if (this.session) await browser.alarms.create(LOCK_ALARM, { when: this.session.lastActivityMs + this.settings!.autoLockMinutes * 60000 });
  }

  private async verify(proof: Proof | undefined, check: () => void) {
    if (!proof || !['master', 'pin'].includes(proof.method) || typeof proof.secret !== 'string') throw new Error('需要再次验证主密码或 PIN。');
    if (proof.method === 'pin') {
      await this.withPinAttempt(proof.secret, check, true);
    } else await this.verifyMaster(proof, check);
  }

  private async verifyMaster(proof: Proof | undefined, check: () => void) {
    if (proof?.method !== 'master' || typeof proof.secret !== 'string') throw new Error('需要再次验证主密码。');
    if (proof.secret.length > 1024) throw new Error('主密码验证失败。');
    const valid = await derive<boolean>('wasm_verify_master_password', [this.files!.head, proof.secret]);
    check();
    if (!valid) throw new Error('主密码验证失败。');
  }

  private async withPinAttempt(pin: string, check: () => void, verifyOnly = false): Promise<number[] | boolean> {
    const settings = this.settings!;
    if (!settings.pinWrap || settings.pinFailures >= 5) throw new Error('PIN 已禁用，请使用主密码解锁。');
    const wrap = new Uint8Array(settings.pinWrap);
    // Count before expensive work, so terminating the worker cannot reset the attempt budget.
    settings.pinFailures++;
    if (settings.pinFailures >= 5) delete settings.pinWrap;
    await store.saveSettings(settings);
    const key = randomBytes(32);
    try {
      const result = verifyOnly
        ? await derive<boolean>('wasm_verify_pin_wrap', [wrap, pin])
        : await derive<number[]>('wasm_unlock_with_pin_wrap', [this.files!.head, wrap, pin, key]);
      check();
      if (result === false) throw new Error('PIN 验证失败');
      settings.pinWrap = new Uint8Array(wrap);
      settings.pinFailures = 0;
      await store.saveSettings(settings);
      check();
      if (!verifyOnly) await this.activate(key, result as number[], check);
      return result;
    } catch (error) {
      if (settings.pinFailures >= 5) throw new Error('PIN 连续验证失败，快捷解锁已移除，请使用主密码。');
      throw error;
    } finally { key.fill(0); wrap.fill(0); }
  }

  private async requireItemProof(id: string, proof: Proof | undefined, check: () => void) {
    const summary = (JSON.parse(this.engine!.list_summaries_json()) as ItemSummary[]).find(item => item.id === id);
    if (!summary) throw new Error('条目不存在。');
    if (summary.requireReprompt) await this.verify(proof, check);
  }

  private async generateOtp(setup: string, check: () => void) {
    this.davClock ??= readDavClock(this.files!.vaultId).catch(() => undefined);
    const offset = davClockOffset(await this.davClock);
    check();
    const code = JSON.parse(await derive<string>('generate-otp', [setup, Math.floor(Date.now() / 1000), offset])) as OtpWorkerCode;
    check();
    if (code.validTo !== null) code.validTo -= offset;
    return code;
  }

  private async persistMutation(files: store.VaultFiles, check: () => void, resolvedAnchor?: store.RemoteAnchor, replacementClock?: JournalClock) {
    const current = this.files!;
    const { key, wrap } = this.session!;
    const { clock, legacy } = await store.loadJournal(current.vaultId);
    const version = nextJournalVersion(replacementClock ?? clock, Date.now());
    check();
    if (!resolvedAnchor) {
      const staged = (await store.loadRemoteAnchor(files.vaultId))?.conflicts;
      check();
      if (staged?.length) await derive<void>('sync:guard-staged', [key, wrap, current.head, current.snap, files.head, files.snap, staged]);
    }
    const bytes = await derive<number[]>('sync:local-wal', [key, wrap, version.id, version.state.deviceId,
      current.head, current.snap, files.head, files.snap, legacy]);
    check();
    await store.saveVaultFiles(files, { ...version, bytes: new Uint8Array(bytes), replaceLegacy: legacy }, resolvedAnchor);
    this.files = files;
    this.scheduleDav(2500);
    check();
  }

  private async saveMutation(mutate: () => Mutation, check: () => void) {
    let result: Mutation | undefined;
    try {
      check();
      result = mutate();
      const snap = result.snap_bytes;
      if (!snap.length) return 0; // An explicit no-op has no new encrypted snapshot.
      const files = { ...this.files!, head: result.head_bytes, snap, updatedAtMs: Date.now(),
        changesSinceBackup: (this.files!.changesSinceBackup ?? 0) + result.count };
      await this.persistMutation(files, check);
      return result.count;
    } catch (error) {
      // A rejected WASM mutation may have changed in-memory items before encoding failed.
      // Restore the committed snapshot before serving any further reads or writes.
      if (this.session) {
        try { this.engine!.restore_from_session(this.session.key, this.session.wrap, this.files!.head, this.files!.snap); }
        catch { await this.lock(); }
      }
      const text = capacityErrorText(error);
      if (text) throw new Error(text);
      throw error;
    } finally { result?.free(); }
  }

  private async createLinkedVault(message: Extract<VaultMessage, { type: 'webdav-create' }>, check: () => void) {
    if (message.deviceName != null && (typeof message.deviceName !== 'string' || new TextEncoder().encode(message.deviceName).length > 240))
      throw new Error('请填写有效的设备名称。');
    if (this.files) {
      if (!this.session || !this.engine?.is_unlocked()) throw new Error('请先解锁本机密码库。');
      await this.verifyMaster({ method: 'master', secret: message.masterPassword }, check);
      if (await store.loadRemoteAnchor(this.files.vaultId)) throw new Error('此密码库已连接网盘。未创建新库。');
    } else this.validatePassword(message.masterPassword);
    if (!message.input && !this.session) throw new Error('请填写网盘连接信息。');
    await requireDavHealthy();
    check();
    const key = this.session?.key ?? randomBytes(32);
    const existing = this.files;
    const config = message.input ? webDavConfig(message.input) : await openSavedDav(this.session!, existing!.vaultId);
    try {
      const context = { check, signal: this.davAbort.signal, stop: pauseDav };
      const profile = await deviceProfile();
      check();
      const initialized = await createRemoteVault(config, message.scratchFolder, context, async () => {
        check();
        const output = existing ? undefined : await derive<Created>('wasm_create_new_vault', [message.masterPassword, 65536, 3, 4, key, Date.now()]);
        check();
        const wrap = this.session?.wrap ?? new Uint8Array(output!.wrap);
        const vaultId = existing?.vaultId ?? output!.vaultId;
        const clock = (await store.loadJournal(vaultId)).clock;
        check();
        const version = nextJournalVersion(clock, Date.now());
        const localHead = existing?.head ?? new Uint8Array(output!.head);
        const localSnap = existing?.snap ?? new Uint8Array(output!.snap);
        const count = await derive<number>('sync:verify-snapshot', [key, wrap, localHead, localSnap]);
        if (count === 0 && existing && (existing.everHadRecords || (existing.backedUpChangeCount ?? 0) + existing.changesSinceBackup > 0))
          throw new Error('曾包含凭证的库目前为空，未向网盘发布。请先恢复本地数据。');
        const tracked = await derive<ReplayOutput>('sync:device-change', [key, wrap, localHead, localSnap, JSON.stringify({
          action: 'track', id: version.state.deviceId, tag: version.state.tag, name: message.deviceName?.trim() || profile.suggestedName,
          system: profile.system, browser: profile.browserLabel, version: browser.runtime.getManifest().version, time: Date.now(),
        })]);
        check();
        const genesis = await derive<{ head: number[]; snap: number[] }>('sync:genesis', [key, wrap, new Uint8Array(tracked.head),
          new Uint8Array(tracked.snap), version.id, version.state.deviceId]);
        check();
        return { head: new Uint8Array(genesis.head), snap: new Uint8Array(genesis.snap), snapshotId: `snap_${version.id}`, output, wrap, version, count };
      });
      const { genesis } = initialized;
      const { wrap, output, version } = genesis;
      const remote = await derive<RemoteHeadInfo>('sync:authenticate-head', [initialized.head.bytes, key, wrap]);
      const endpoint = await endpointFingerprint(config.url);
      check();
      const files: store.VaultFiles = { ...existing, vaultId: remote.vaultId, keyEpoch: remote.keyEpoch, head: new Uint8Array(remote.localHead),
        snap: genesis.snap, updatedAtMs: Date.now(), changesSinceBackup: existing?.changesSinceBackup ?? 0 };
      await store.saveRemoteAnchor({ vaultId: files.vaultId, endpoint, head: initialized.head.bytes, snap: genesis.snap,
        etag: initialized.head.etag, objects: [], appliedHead: files.head, appliedSnap: files.snap,
        hasRecords: genesis.count > 0, checkedAt: Date.now() }, files, version.state, !existing);
      this.files = files;
      if (!existing) await this.activate(key, Array.from(wrap), check);
      else {
        check();
        this.engine!.restore_from_session(key, wrap, files.head, files.snap);
      }
      await saveDavConnection({ ...config, writeVerified: true }, this.session!, files.vaultId, initialized.offsetSeconds, check);
      this.scheduleDav();
      return output ? { recoveryCode: output.recoveryCode, vaultId: files.vaultId } : undefined;
    } finally {
      config.password = ''; config.username = '';
      if (!existing) key.fill(0);
    }
  }

  private async joinRemoteVault(message: Extract<VaultMessage, { type: 'webdav-join' | 'webdav-merge' }>, check: () => void) {
    const source = this.files, sourceSession = this.session;
    if (message.type === 'webdav-merge') {
      if (!source || !sourceSession || !this.engine?.is_unlocked()) throw new Error('请先解锁本机源库。');
      if (await store.loadRemoteAnchor(source.vaultId)) throw new Error('此库已连接网盘。请使用加密备份迁移到另一密码库。');
      await this.verifyMaster(message.proof, check);
    } else if (source) throw new Error('本机已有密码库，请预览合并，不能直接覆盖。');
    if (!['master', 'recovery'].includes(message.method) || typeof message.secret !== 'string' || !message.secret || message.secret.length > 1024)
      throw new Error('请输入远端库自己的主密码或应急恢复码。');
    await requireDavHealthy();
    check();
    const config = webDavConfig(message.input);
    const key = randomBytes(32);
    let wrap: Uint8Array | undefined;
    try {
      const client = new WebDavClient(config, { check, signal: this.davAbort.signal, stop: pauseDav });
      const restored = await readRemoteVault(client, async head => {
        const result = await derive<RemoteHeadInfo>('sync:unlock-head', [head.bytes, key, message.secret, message.method === 'recovery']);
        check();
        wrap = new Uint8Array(result.wrap);
        result.wrap.fill(0);
        return result;
      }, async (head, snap, wal, history) => {
        const replay = await derive<ReplayOutput>('sync:replay', [key, wrap!, new Uint8Array(head.localHead), snap,
          packSyncFrames(wal), packSyncFrames(history)]);
        check();
        return replay;
      });
      const { authenticated, head, snap, objects, result } = restored;
      const files: store.VaultFiles = { vaultId: authenticated.vaultId, keyEpoch: authenticated.keyEpoch, head: new Uint8Array(result.head),
        snap: new Uint8Array(result.snap), updatedAtMs: Date.now(), changesSinceBackup: 0, remoteKeyUpdate: false };
      const anchor: store.RemoteAnchor = { vaultId: files.vaultId, endpoint: await endpointFingerprint(config.url), head: head.bytes, snap: snap.bytes,
        etag: head.etag, objects, appliedHead: files.head, appliedSnap: files.snap, hasRecords: result.count > 0, checkedAt: Date.now(),
        conflicts: new Uint8Array(result.conflicts), conflictCount: result.conflictCount, draftCount: result.draftCount };
      check();
      if (message.type === 'webdav-merge') {
        if (source!.vaultId === files.vaultId) throw new Error('两个库的身份相同。请使用新浏览器配置加入远端，或验证并导入 .vaultpack。');
        const stamp = [anchor.endpoint, ...(await Promise.all([source!.head, source!.snap, head.bytes, snap.bytes, packSyncFrames(objects)]
          .map(bytes => digestHex(new Uint8Array(bytes)))))].join(':');
        check();
        if (message.stamp !== undefined && message.stamp !== stamp) throw new Error('本机库或远端库已改动，请重新预览。');
        const sourceCount = await derive<number>('sync:verify-snapshot', [sourceSession!.key, sourceSession!.wrap, source!.head, source!.snap]);
        const merged = await derive<ReplayOutput>('sync:adopt', [sourceSession!.key, sourceSession!.wrap, source!.head, source!.snap,
          key, wrap!, files.head, files.snap, anchor.conflicts!]);
        check();
        if (message.stamp === undefined) {
          return { stamp, sourceCount, targetCount: result.count, mergedCount: merged.count,
            conflicts: merged.conflictCount } satisfies import('./vault-messages').DavJoinPreview;
        }
        if (source!.changesSinceBackup > 0) throw new Error('请先为本机源库下载最新的 .vaultpack 加密备份，再重新预览。');
        const next = { ...files, head: new Uint8Array(merged.head), snap: new Uint8Array(merged.snap),
          changesSinceBackup: sourceCount, everHadRecords: result.count > 0 || merged.count > 0 };
        const version = nextJournalVersion(undefined, Date.now(), Math.max(merged.hlc, result.hlc));
        const bytes = await derive<number[]>('sync:local-wal', [key, wrap!, version.id, version.state.deviceId,
          files.head, files.snap, next.head, next.snap, false]);
        check();
        const settings = { autoLockMinutes: this.settings!.autoLockMinutes, pinFailures: 0 };
        await store.saveSettings(settings);
        this.settings = settings;
        check();
        await store.adoptRemoteVault(source!, { ...anchor, conflicts: new Uint8Array(merged.conflicts),
          conflictCount: merged.conflictCount, draftCount: merged.draftCount }, next, { ...version, bytes: new Uint8Array(bytes), replaceLegacy: false });
        this.files = next;
        await this.lock(false);
        await this.activate(key, Array.from(wrap!), check);
        await saveDavConnection(config, this.session!, next.vaultId, restored.offsetSeconds, check);
        await showConflictBadge(merged.conflictCount).catch(() => undefined);
        return this.status();
      }
      await store.saveRemoteAnchor(anchor, files, undefined, true);
      this.files = files;
      await this.activate(key, Array.from(wrap!), check);
      await saveDavConnection(config, this.session!, files.vaultId, restored.offsetSeconds, check);
      await showConflictBadge(result.conflictCount).catch(() => undefined);
      return this.status();
    } finally { key.fill(0); wrap?.fill(0); config.password = ''; config.username = ''; }
  }

  private scheduleDav(wait = 1200) {
    if (!this.session || this.davTimer && wait < 2500) return;
    clearTimeout(this.davTimer);
    this.davTimer = setTimeout(() => {
      this.davTimer = undefined;
      void this.handle({ type: 'webdav-scheduled' }).catch(() => undefined);
    }, wait);
  }

  private async davConnectionStatus(check: () => void) {
    const { files, session } = this;
    const state = await davStatus(files?.vaultId);
    if (!files) return state;
    const anchor = await store.loadRemoteAnchor(files.vaultId);
    if (!anchor) return state;
    let writeVerified = false;
    if (session && state.saved && !state.paused && !anchor.localRestoreHeld) {
      check();
      const config = await openSavedDav(session, files.vaultId);
      try { writeVerified = config.writeVerified === true && anchor.endpoint === await endpointFingerprint(config.url); }
      finally { config.password = ''; config.username = ''; }
    }
    return { ...state, linked: true, writeVerified, conflicts: anchor.conflictCount ?? 0, drafts: anchor.draftCount ?? 0,
      localRestoreHeld: !!anchor.localRestoreHeld };
  }

  private async remoteKeyUpdate(password: string, check: () => void) {
    const files = this.files;
    if (!files || typeof password !== 'string' || !password || password.length > 1024) throw new Error('请输入远端库的新主密码。');
    const anchor = await store.loadRemoteAnchor(files.vaultId);
    if (!anchor?.observedHead || !anchor.observedKeyEpoch) throw new Error('没有待验证的远端主密码更新。');
    check();
    const key = randomBytes(32);
    let wrap: Uint8Array | undefined;
    try {
      const remote = await derive<RemoteHeadInfo>('sync:unlock-head', [anchor.observedHead, key, password, false]);
      wrap = new Uint8Array(remote.wrap);
      remote.wrap.fill(0);
      if (remote.vaultId !== files.vaultId || remote.keyEpoch !== anchor.observedKeyEpoch || remote.keyEpoch < files.keyEpoch)
        throw new Error('不能使用旧版本的主密码包装。');
      check();
      const nextHead = new Uint8Array(await derive<number[]>('sync:rebase-wrap', [key, wrap, new Uint8Array(remote.localHead), files.head, files.snap]));
      check();
      const settings = this.settings!;
      delete settings.pinWrap; delete settings.prf; settings.pinFailures = 0;
      await store.saveSettings(settings);
      check();
      const nextFiles = { ...files, head: nextHead, keyEpoch: remote.keyEpoch, remoteKeyUpdate: false };
      await store.saveRemoteAnchor({ ...anchor, observedHead: undefined, observedKeyEpoch: undefined, rotationFrom: undefined, checkedAt: undefined },
        nextFiles, undefined, false, false);
      this.files = nextFiles;
      await this.activate(key, Array.from(wrap), check);
      return this.status();
    } finally { key.fill(0); wrap?.fill(0); }
  }

  private async syncWebDav(message: Extract<VaultMessage, { type: 'webdav-sync' | 'webdav-scheduled' }>, check: () => void): Promise<SyncResult> {
    if (!this.session || !this.files || !this.engine?.is_unlocked()) return { kind: 'locked', pending: false };
    const { files, session } = this;
    const anchor = await store.loadRemoteAnchor(files.vaultId);
    check();
    if (!anchor) return { kind: 'unlinked', pending: false };
    const state = await davStatus(files.vaultId);
    if (!state.saved) return { kind: 'unlinked', pending: false };
    if (state.paused) return { kind: 'paused', pending: !!anchor.draftCount || await store.hasPendingWal(files.vaultId) };
    check();
    const config = await openSavedDav(session, files.vaultId);
    const signal = this.davAbort.signal;
    try {
      check();
      await browser.alarms.create(DAV_ALARM, { periodInMinutes: 2 });
      check();
      const result = await runDavSync(config, {
        files, session, anchor, clock: (await store.loadJournal(files.vaultId)).clock,
        pending: await store.hasPendingWal(files.vaultId),
        compactWhenIdle: message.type === 'webdav-scheduled',
        forceHead: message.type === 'webdav-sync', context: { check, signal, stop: status => { this.davClock = undefined; return pauseDav(status); } },
        commit: async (next, current, consume, clock) => {
          check();
          await store.saveRemoteAnchor(next, current, clock, false, consume);
          check();
          if (current !== files) {
            this.files = current;
            this.engine!.restore_from_session(session.key, session.wrap, current.head, current.snap);
            void browser.runtime.sendMessage({ target: 'vault-event', type: 'sync-changed' }).catch(() => undefined);
          }
          if (next.conflictCount !== anchor.conflictCount) await showConflictBadge(next.conflictCount ?? 0).catch(() => undefined);
        },
        authorize: async stamp => {
          if (message.type !== 'webdav-sync' || !message.confirmation || message.confirmation.stamp !== stamp) return false;
          await this.verifyMaster(message.confirmation.proof, check);
          return true;
        },
      });
      if (result.kind === 'key-update') await this.lock(false);
      return result;
    } finally { config.password = ''; config.username = ''; }
  }

  private async reviewConflicts(message: Extract<VaultMessage, { type: 'webdav-conflicts' | 'webdav-resolve' }>, check: () => void) {
    const files = this.files!, session = this.session!;
    const anchor = await store.loadRemoteAnchor(files.vaultId);
    check();
    const staged = anchor?.conflicts;
    const stamp = staged?.length ? await derive<string>('sync:conflict-stamp', [session.key, session.wrap, staged]) : '';
    check();
    if (message.type === 'webdav-conflicts') {
      if (message.reveal) await this.verifyMaster(message.reveal, check);
      const rows = staged?.length ? JSON.parse(await derive<string>('sync:conflicts', [session.key, session.wrap, staged, !!message.reveal])) : [];
      check();
      return { stamp, rows };
    }
    if (!anchor || !staged?.length || !stamp || stamp !== message.stamp) throw new Error('待裁决项已变更，请重新预览。');
    if (!Array.isArray(message.rules) || !message.rules.length || message.rules.length > (anchor.conflictCount ?? 0))
      throw new Error('请选择要处理的冲突。');
    const rules = JSON.stringify(message.rules);
    if (rules.length > 1024 * 1024) throw new Error('裁决内容过长。');
    await this.verifyMaster(message.proof, check);
    const output = await derive<ReplayOutput>('sync:resolve', [session.key, session.wrap, files.head, files.snap, staged, rules, Date.now()]);
    check();
    const updated = { ...files, head: new Uint8Array(output.head), snap: new Uint8Array(output.snap), updatedAtMs: Date.now(),
      changesSinceBackup: files.changesSinceBackup + message.rules.length, everHadRecords: files.everHadRecords || output.count > 0 };
    const pendingResolutions = new Uint8Array((anchor.pendingResolutions?.length ?? 0) + output.receipts.length);
    if (anchor.pendingResolutions) pendingResolutions.set(anchor.pendingResolutions);
    pendingResolutions.set(output.receipts, anchor.pendingResolutions?.length ?? 0);
    await this.persistMutation(updated, check, { ...anchor, conflicts: new Uint8Array(output.conflicts), conflictCount: output.conflictCount, draftCount: output.draftCount, pendingResolutions });
    this.engine!.restore_from_session(session.key, session.wrap, updated.head, updated.snap);
    await showConflictBadge(output.conflictCount).catch(() => undefined);
    void browser.runtime.sendMessage({ target: 'vault-event', type: 'sync-changed' }).catch(() => undefined);
    return output.conflictCount;
  }

  private async syncHistory(message: Extract<VaultMessage, { type: 'webdav-history' | 'webdav-history-preview' | 'webdav-history-restore' }>, check: () => void) {
    const files = this.files!, session = this.session!;
    const anchor = await store.loadRemoteAnchor(files.vaultId);
    if (!anchor) throw new Error('请先连接远端密码库。');
    await requireDavHealthy();
    check();
    const config = await openSavedDav(session, files.vaultId);
    try {
      if (anchor.endpoint !== await endpointFingerprint(config.url)) throw new Error('连接地址与已验证的库不同。');
      const client = new WebDavClient(config, { check, signal: this.davAbort.signal, stop: pauseDav });
      // Keep the connection credentials until the last request in the operation finishes.
      if (message.type === 'webdav-history') return await listHistory(client, anchor, session, files);
      if (await store.hasPendingWal(files.vaultId)) throw new Error('本机仍有待上传的编辑，请先同步再恢复历史。');
      const prepared = await prepareRestore(client, anchor, session, files, message.id);
      check();
      if (message.type === 'webdav-history-preview') return prepared.preview;
      if (message.destination !== (prepared.preview.readOnly ? 'local' : 'remote') || message.stamp !== prepared.preview.stamp)
        throw new Error('网盘或本机状态已变化。请重新预览。');
      await this.verifyMaster(message.proof, check);
      const reload = (committed: store.VaultFiles) => {
        this.files = committed;
        this.engine!.restore_from_session(session.key, session.wrap, committed.head, committed.snap);
        void browser.runtime.sendMessage({ target: 'vault-event', type: 'sync-changed' }).catch(() => undefined);
      };
      if (message.destination === 'local') {
        return await restoreHistoryLocally(client, anchor, files, prepared, message.stamp, check, async (next, committed) => {
          await this.persistMutation(committed, check, next);
          reload(committed);
        });
      }
      const { clock } = await store.loadJournal(files.vaultId);
      return await restoreHistory(client, anchor, session, files, prepared, clock, message.stamp, check,
        (version, pendingCompaction) => store.saveRemoteAnchor({ ...anchor, pendingCompaction }, files, version, false, false), async (next, committed) => {
          check();
          await store.saveRemoteAnchor(next, committed, undefined, false, false);
          check();
          reload(committed);
        });
    } finally { config.password = ''; config.username = ''; }
  }

  private async syncDevices(message: Extract<VaultMessage, { type: 'webdav-devices' | 'webdav-device-change' }>, check: () => void): Promise<import('./vault-messages').SyncDevices> {
    const files = this.files!, session = this.session!;
    const anchor = await store.loadRemoteAnchor(files.vaultId);
    if (!anchor) throw new Error('请先连接远端密码库。');
    const { clock } = await store.loadJournal(files.vaultId);
    check();
    const profile = await deviceProfile();
    const args = [session.key, session.wrap, files.head, files.snap] as const;
    const rows = JSON.parse(await derive<string>('sync:devices', [...args])) as import('./vault-messages').SyncDevice[];
    check();
    const registered = rows.some(device => device.id === clock?.deviceId);
    if (message.type === 'webdav-devices') return { active: clock?.deviceId, rows, system: profile.system,
      browser: profile.browser, suggestedName: profile.suggestedName, registered };
    if (!['register', 'claim', 'rename', 'remove'].includes(message.action) ||
        (message.action !== 'remove' && (typeof message.name !== 'string' || !message.name.trim() || new TextEncoder().encode(message.name).length > 240)))
      throw new Error('请填写有效的设备名称。');
    if (message.action === 'remove' && (message.id === clock?.deviceId || !rows.some(device => device.id === message.id))) throw new Error('不能移除当前设备或已经不存在的记录。');
    if (message.action === 'claim' && (registered || !message.id || !rows.some(device => device.id === message.id))) throw new Error('请选择一条已有设备记录；本机已经登记时不能再次认领。');
    if (message.action === 'register' && registered) throw new Error('此设备已登记。');
    await this.verifyMaster(message.proof, check);
    const now = Date.now();
    const next = message.action === 'claim' ? adoptDevice(message.id!, clock, now) : clock ?? nextJournalVersion(undefined, now).state;
    const id = message.action === 'rename' || message.action === 'remove' ? message.id : next.deviceId;
    const action = message.action === 'register' ? 'track' : message.action;
    const output = await derive<ReplayOutput>('sync:device-change', [...args, JSON.stringify({ id, action, tag: next.tag,
      name: message.name?.trim(), time: now, system: profile.system, browser: profile.browserLabel, version: browser.runtime.getManifest().version })]);
    check();
    const updated = { ...files, head: new Uint8Array(output.head), snap: new Uint8Array(output.snap), updatedAtMs: now };
    await this.persistMutation(updated, check, anchor, next);
    this.engine!.restore_from_session(session.key, session.wrap, updated.head, updated.snap);
    return this.syncDevices({ type: 'webdav-devices' }, check);
  }

  private async enableDavWriting(message: Extract<VaultMessage, { type: 'webdav-enable-write' }>, check: () => void) {
    const { session, files } = this;
    if (!files || !session || !this.engine?.is_unlocked()) throw new Error('请先解锁密码库。');
    const anchor = await store.loadRemoteAnchor(files.vaultId);
    if (!anchor) throw new Error('先验证并连接远端密码库。');
    await this.verifyMaster({ method: 'master', secret: message.masterPassword }, check);
    await requireDavHealthy();
    check();
    const config = await openSavedDav(session, files.vaultId);
    try {
      if (anchor.endpoint !== await endpointFingerprint(config.url)) throw new Error('连接地址与已验证的库不同。');
      const context = { check, signal: this.davAbort.signal, stop: pauseDav };
      if (config.writeVerified) await saveDavConnection({ ...config, writeVerified: false }, session, files.vaultId, undefined, check);
      const head = await new WebDavClient(config, context).get('head.bin', HEAD_LIMIT);
      if (!head || head === 'unchanged' || !head.etag) throw new Error('网盘未提供可验证的版本。密码库仍只读。');
      const checked = await derive<RemoteHeadInfo>('sync:authenticate-head', [head.bytes, session.key, session.wrap]);
      if (checked.keyEpoch !== files.keyEpoch) throw new Error('请先用新主密码验证远端库。');
      await proveConditionalWrites(config, message.scratchFolder, context);
      check();
      await saveDavConnection({ ...config, writeVerified: true }, session, files.vaultId, undefined, check);
      if (anchor.localRestoreHeld) {
        check();
        await store.saveRemoteAnchor({ ...anchor, localRestoreHeld: undefined }, files, undefined, false, false);
      }
      this.scheduleDav(2500);
    } finally { config.password = ''; config.username = ''; }
  }

  private async dispatch(message: VaultMessage, check: () => void): Promise<unknown> {
    const core = this.core!;
    const engine = this.engine!;
    const settings = this.settings!;
    if (message.type === 'status') {
      const status = this.status();
      if (!status.unlocked && this.files && await this.needsRemoteKey(this.files))
        return { ...status, remoteKeyUpdate: true };
      return status;
    }
    if (message.type === 'webdav-update-key') return this.remoteKeyUpdate(message.password, check);
    if (message.type === 'webdav-status') return this.davConnectionStatus(check);
    if (message.type === 'webdav-create') return this.createLinkedVault(message, check);
    if (message.type === 'webdav-join' || message.type === 'webdav-merge') return this.joinRemoteVault(message, check);
    if (message.type === 'webdav-sync' || message.type === 'webdav-scheduled') return this.syncWebDav(message, check);
    if (message.type === 'webdav-enable-write') return this.enableDavWriting(message, check);
    if (message.type === 'webdav-test') {
      if (this.files && (!engine.is_unlocked() || !this.session)) throw new Error('请先解锁密码库，再测试网盘连接。');
      const operation = this.davAbort.signal;
      try {
        const anchor = message.remember === true && this.files && await store.loadRemoteAnchor(this.files.vaultId);
        check();
        const { probe, resumed } = await testDav(message.input, message.remember === true, this.session, this.files?.vaultId,
          { check, signal: operation }, anchor ? anchor.endpoint : undefined);
        if (resumed && anchor) this.scheduleDav();
        return probe;
      } finally { this.davClock = undefined; }
    }
    if (message.type === 'open') {
      const opening: VaultOpening = { status: this.status() };
      if (!opening.status.unlocked && this.files && await this.needsRemoteKey(this.files))
        opening.status.remoteKeyUpdate = true;
      if (opening.status.unlocked) {
        const touch = this.touch();
        try {
          opening.items = JSON.parse(engine.list_summaries_json()) as ItemSummary[];
        } finally { await touch; }
        check();
        this.scheduleDav();
        performance.clearMarks('vault:open-response-ready');
        performance.mark('vault:open-response-ready');
      }
      return opening;
    }
    if (message.type === 'autofill-settings') {
      if (!engine.is_unlocked() || !this.session) return { sites: {}, equivalentDomains: [] };
      return this.readAutofillSettings(check);
    }
    if (message.type === 'strength') return JSON.parse(core.wasm_evaluate_password_strength(message.password, JSON.stringify(message.hints)));
    if (message.type === 'create') {
      if (this.files) throw new Error('本机已有密码库，不能覆盖。');
      this.validatePassword(message.masterPassword);
      let params = { mCostKib: 65536, tCost: 3, pCost: 4 };
      if (message.calibrate) params = JSON.parse(await derive<string>('wasm_calibrate_argon2id', []));
      check();
      const key = randomBytes(32);
      try {
        const output = await derive<Created>('wasm_create_new_vault', [message.masterPassword, params.mCostKib, params.tCost, params.pCost, key, Date.now()]);
        check();
        this.files = { head: new Uint8Array(output.head), snap: new Uint8Array(output.snap), vaultId: output.vaultId,
          keyEpoch: output.keyEpoch, updatedAtMs: Date.now(), changesSinceBackup: 0, remoteKeyUpdate: false };
        await store.saveVaultFiles(this.files);
        await this.activate(key, output.wrap, check);
        return { recoveryCode: output.recoveryCode, vaultId: output.vaultId };
      } catch (error) { await this.lock(); throw error; } finally { key.fill(0); }
    }
    if (!this.files) throw new Error('请先创建密码库。');
    if (['unlock', 'unlock-pin', 'unlock-prf', 'recover', 'change-password'].includes(message.type) &&
        await this.needsRemoteKey(this.files)) throw new Error('请先用远端库的新主密码验证。');
    if (message.type === 'unlock-pin') { await this.withPinAttempt(message.pin, check); return this.status(); }
    if (message.type === 'unlock' || message.type === 'unlock-prf') {
      const key = randomBytes(32);
      try {
        if (message.type === 'unlock-prf' && (!settings.prf || message.output.length !== 32)) throw new Error('未设置系统解锁。');
        const wrap = message.type === 'unlock'
          ? await derive<number[]>('wasm_unlock_head_with_password', [this.files.head, message.password, key])
          : Array.from(core.wasm_unlock_with_prf_wrap(this.files.head, new Uint8Array(settings.prf!.wrap), new Uint8Array(message.output), key));
        check();
        await this.activate(key, wrap, check);
        return this.status();
      } finally { key.fill(0); }
    }
    if (message.type === 'recover' || message.type === 'change-password') {
      this.validatePassword(message.newPassword);
      const anchor = await store.loadRemoteAnchor(this.files.vaultId);
      if (anchor?.rotationFrom != null) throw new Error('上次主密码修改尚未同步。请先完成网盘同步。');
      const key = randomBytes(32);
      try {
        const output = await derive<Rotation>(message.type === 'recover' ? 'wasm_recover_and_reset_master_password' : 'wasm_change_master_password',
          [this.files.head, message.type === 'recover' ? message.recoveryCode : message.currentPassword, message.newPassword, key, Date.now()]);
        check();
        const nextFiles = { ...this.files, head: new Uint8Array(output.head), keyEpoch: output.keyEpoch, updatedAtMs: Date.now() };
        if (anchor) await store.saveRemoteAnchor({ ...anchor, rotationFrom: this.files.keyEpoch }, nextFiles, undefined, false, false);
        else await store.saveVaultFiles(nextFiles);
        this.files = nextFiles;
        delete settings.pinWrap; delete settings.prf; settings.pinFailures = 0;
        await store.saveSettings(settings);
        await this.activate(key, output.wrap, check);
        return this.status();
      } catch (error) { await this.lock(); throw error; } finally { key.fill(0); }
    }
    if (!engine.is_unlocked() || !this.session) throw new Error('请先解锁密码库。');
    // An open detail page may refresh codes without a user's active interaction.
    if (message.type === 'read-otp') {
      const invalid = () => new Error('验证码授权已失效，请重新打开凭证。');
      if (!validAuthorization(message.handle)) throw invalid();
      let item: VaultItem;
      try { item = JSON.parse(engine.get_item_json(message.id, true)) as VaultItem; }
      catch { throw invalid(); }
      const setup = otpSetup(item);
      if (!setup || item.trashed || setup.startsWith('otpauth://hotp/') ||
          !await verifyAuthorization(this.session.key, 'otp:read:v1', message.handle, otpPayload(item, setup))) throw invalid();
      check();
      const code = await this.generateOtp(setup, check);
      if (code.kind === 'hotp' || code.validTo === null) throw invalid();
      return { kind: code.kind, value: code.value, validTo: code.validTo, nextValue: code.nextValue } satisfies TimedOtpCode;
    }
    await this.touch();
    check();
    const session = this.session;
    switch (message.type) {
      case 'webdav-conflicts':
      case 'webdav-resolve':
        return this.reviewConflicts(message, check);
      case 'webdav-history':
      case 'webdav-history-preview':
      case 'webdav-history-restore':
        return this.syncHistory(message, check);
      case 'webdav-devices':
      case 'webdav-device-change':
        return this.syncDevices(message, check);
      case 'webdav-clock':
        await setDavCompensation(this.files.vaultId, message.enabled, check);
        this.davClock = undefined;
        return this.davConnectionStatus(check);
      case 'preview-auth-backup':
      case 'import-auth-backup': {
        const { format, images, bytes: raw, password } = message;
        if (!AUTH_BACKUP_FORMATS.includes(format) ||
            (password != null && (typeof password !== 'string' || password.length > 4096)) ||
            (images != null && (format !== 'google' || raw != null || !Array.isArray(images) || !images.length || images.length > 64 ||
              !images.every(image => typeof image === 'string' && /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(image)) ||
              images.reduce((total, image) => total + image.length, 0) > Math.ceil(MAX_AUTH_BACKUP_BYTES * 4 / 3) + 8192)) ||
            (images == null && (!Array.isArray(raw) || !raw.length || raw.length > MAX_AUTH_BACKUP_BYTES ||
              !raw.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)))) throw new Error('请选择支持的格式、最多 4 MiB 的备份。');
        const protection = new TextEncoder().encode(format);
        const source = images ? new TextEncoder().encode(JSON.stringify(images)) : new Uint8Array(raw!);
        let bytes = source;
        try {
          const stamp = (await Promise.all([digestHex(source), digestHex(new Uint8Array(this.files.snap)), digestHex(protection)])).join(':');
          check();
          if (message.type === 'import-auth-backup') {
            if (message.stamp !== stamp) throw new Error('备份或密码库已变更，请重新预览。');
            await this.verify(message.proof, check);
          }
          if (images) {
            const codes: string[] = [];
            for (const image of images) {
              const result = await offscreen<{ values: string[] }>('scan-migration-qr', image);
              check();
              if (!result.values.length) throw new Error('有图片没有可读的 Google Authenticator 迁移二维码。');
              codes.push(...result.values);
            }
            bytes = new TextEncoder().encode(codes.join('\n'));
            codes.fill('');
          }
          const result = await derive<string>('parse-authenticator-backup', [format, bytes, password ?? '']);
          check();
          const batch = JSON.parse(result) as MigrationBatch & Pick<AuthBackupPreview, 'missingParts' | 'repeatedParts'>;
          const existing = (JSON.parse(engine.list_summaries_json()) as ItemSummary[]).map(row => JSON.parse(engine.get_item_json(row.id, true)) as VaultItem);
          const plan = planMigration(batch, existing);
          if (message.type === 'preview-auth-backup') {
            return { ...plan.preview, stamp, missingParts: batch.missingParts, repeatedParts: batch.repeatedParts } satisfies AuthBackupPreview;
          }
          if (batch.missingParts) throw new Error(`这批二维码缺少 ${batch.missingParts} 张；未导入任何条目。`);
          if (format === 'google' && batch.invalid) throw new Error('这批二维码有损坏的条目，未导入任何条目。请从原验证器重新导出。');
          return this.saveMutation(() => engine.import_records_json(JSON.stringify({ prepared: true, rows: plan.items }), Date.now(), true), check);
        } finally { source.fill(0); bytes.fill(0); }
      }
      case 'csv-headers':
      case 'preview-migration':
      case 'import-migration': {
        const isCsv = message.type === 'csv-headers' || message.format === 'csv';
        const retained = message.type !== 'csv-headers' && message.format === 'bitwarden-retained';
        const limit = isCsv ? MAX_BROWSER_CSV_BYTES : MAX_MIGRATION_BYTES;
        if (!Array.isArray(message.bytes) || (retained ? !!message.bytes.length : !message.bytes.length) || message.bytes.length > limit ||
          !message.bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new Error(isCsv ? '请选择不超过 2 MiB 的 UTF-8 CSV 文件。' : '请选择不超过 16 MiB 的迁移文件。');
        const bytes = new Uint8Array(message.bytes);
        try {
          if (message.type === 'csv-headers') return JSON.parse(await derive<string>('csv-headers', [bytes]));
          if (!isCsv && !(PORTABLE_FORMATS as readonly string[]).includes(message.format)) throw new Error('不支持的迁移格式。');
          if (message.password != null && (typeof message.password !== 'string' || message.password.length > 4096)) throw new Error('文件密码过长。');
          const mapping = JSON.stringify(message.mapping ?? {});
          const options = new TextEncoder().encode(message.format + ':' + mapping);
          const stamp = (await Promise.all([digestHex(bytes), digestHex(new Uint8Array(this.files.snap)), digestHex(options)])).join(':');
          check();
          if (message.type === 'import-migration') {
            if (message.stamp !== stamp) throw new Error('文件、字段映射或密码库已变更，请重新预览。');
            if (message.format === 'keepass') await this.verifyMaster(message.proof, check);
            else await this.verify(message.proof, check);
          }
          if (!isCsv) {
            const output = await derive<{ report: string; head: number[]; snap: number[]; count: number }>('portable-import', [
              message.format, session.key, session.wrap, this.files.head, this.files.snap, bytes, message.password ?? '',
              Date.now(), message.type === 'import-migration',
            ]);
            check();
            if (message.type === 'preview-migration') return { ...(JSON.parse(output.report) as Omit<MigrationPreview, 'stamp'>), stamp };
            if (!output.count) return 0;
            const head = new Uint8Array(output.head), snap = new Uint8Array(output.snap);
            await this.persistMutation({ ...this.files, head, snap, updatedAtMs: Date.now(),
              everHadRecords: true, changesSinceBackup: this.files.changesSinceBackup + output.count }, check);
            engine.restore_from_session(session.key, session.wrap, head, snap);
            return output.count;
          }
          const batch = JSON.parse(await derive<string>('parse-mapped-csv', [bytes, mapping])) as MigrationBatch;
          check();
          batch.rows = batch.rows.filter(item => {
            if (item.data.kind !== 'login') return true;
            try {
              if (!Array.isArray(item.data.uris)) throw new Error();
              for (const { uri } of item.data.uris) webUrl(uri);
              return true;
            } catch { batch.invalid++; return false; }
          });
          const existing = (JSON.parse(engine.list_summaries_json()) as ItemSummary[]).map(row => JSON.parse(engine.get_item_json(row.id, true)) as VaultItem);
          const plan = planMigration(batch, existing);
          if (message.type === 'preview-migration') return { ...plan.preview, stamp };
          return this.saveMutation(() => engine.import_records_json(JSON.stringify({ prepared: true, rows: plan.items }), Date.now(), true), check);
        } finally { bytes.fill(0); }
      }
      case 'export-migration': {
        if (!['csv', 'bitwarden', 'cxf'].includes(message.format)) throw new Error('不支持的迁移格式。');
        if (message.encrypted && message.format === 'csv') throw new Error('CSV 不支持加密，请选择 Bitwarden JSON 或 CXF。');
        if (!message.encrypted && message.confirmPlaintext !== true) throw new Error('请先确认明文文件的风险。');
        if (message.encrypted) this.validatePassword(message.password ?? '');
        await this.verifyMaster(message.proof, check);
        if (message.format === 'csv') {
          const items = (JSON.parse(engine.list_summaries_json()) as ItemSummary[]).map(row => JSON.parse(engine.get_item_json(row.id, true)) as VaultItem);
          const result = JSON.parse(await derive<string>('export-login-csv', [JSON.stringify(items)])) as MigrationExport;
          check();
          return result;
        }
        const result = await derive<string>('portable-export', [
          message.format, session.key, session.wrap, this.files.head, this.files.snap, message.encrypted ? message.password! : '', Date.now(),
        ]);
        check();
        return JSON.parse(result) as MigrationExport;
      }
      case 'set-equivalent-domains': {
        const groups = validateGroups(message.groups);
        const settings = await this.readAutofillSettings(check);
        await this.saveAutofillSettings({ ...settings, equivalentDomains: groups }, check);
        return null;
      }
      case 'set-autofill-site': {
        const origin = webUrl(message.origin).origin;
        const settings = await this.readAutofillSettings(check);
        settings.sites[origin] = message.flags;
        await this.saveAutofillSettings(settings, check);
        return null;
      }
      case 'autofill-current': {
        const url = webUrl(message.url);
        return (JSON.parse(engine.list_summaries_json()) as ItemSummary[])
          .filter(item => item.kind === 'login' && !item.trashed).some(summary => {
            const item = JSON.parse(engine.get_item_json(summary.id, true)) as VaultItem;
            return item.data.username === message.username && item.data.password === message.password && this.autofillMatches(item, 'login', url, message.groups);
          });
      }
      case 'autofill-candidates': {
        const url = webUrl(message.url);
        const results: FillCandidate[] = [];
        for (const summary of JSON.parse(engine.list_summaries_json()) as ItemSummary[]) {
          if (summary.trashed || !this.autofillKind(summary.kind, message.kind)) continue;
          const item = JSON.parse(engine.get_item_json(summary.id, true)) as VaultItem;
          if (!this.autofillMatches(item, message.kind, url, message.groups)) continue;
          results.push({ id: item.id, title: item.title, account: item.data.kind === 'login' ? String(item.data.username ?? '') : summary.subtitle,
            requireReprompt: item.requireReprompt, otpKind: typeof item.data.totpUri === 'string'
              ? item.data.totpUri.startsWith('otpauth://hotp/') ? 'hotp' : 'totp' : undefined });
          if (results.length >= 30) break;
        }
        return results;
      }
      case 'autofill-read': {
        await this.requireItemProof(message.id, message.proof, check);
        const item = JSON.parse(engine.get_item_json(message.id, true)) as VaultItem;
        if (!this.autofillMatches(item, message.kind, webUrl(message.url), message.groups)) throw new Error('凭证不匹配当前网页。');
        const text = (key: string) => typeof item.data[key] === 'string' ? item.data[key] as string : '';
        let values: Record<string, string>;
        if (message.kind === 'otp') {
          const code = await this.generateOtp(text('totpUri'), check);
          if (code.kind === 'hotp') {
            if (!code.nextSetupKey) throw new Error('计数验证码设置无效。');
            item.data.totpUri = code.nextSetupKey;
            await this.saveMutation(() => engine.upsert_item_json(JSON.stringify(item), Date.now(), '本机'), check);
          }
          values = { otp: code.validTo != null && code.validTo - Math.floor(Date.now() / 1000) < 2 && code.nextValue ? code.nextValue : code.value };
        } else if (message.kind === 'card') {
          values = { 'cc-name': text('cardholderName'), 'cc-number': text('cardNumber'), 'cc-csc': text('cvv'),
            'cc-exp-month': text('expMonth'), 'cc-exp-year': text('expYear'), 'cc-exp': `${text('expMonth')}/${text('expYear')}` };
        } else if (message.kind === 'identity') {
          values = { name: text('fullName'), 'given-name': text('fullName').split(' ')[0] ?? '', 'family-name': text('fullName').split(' ').slice(1).join(' '),
            tel: text('phone'), email: text('email'), 'address-line1': text('addressLine'), 'street-address': text('addressLine'),
            'address-level1': text('province'), 'address-level2': text('city'), 'postal-code': text('postalCode'), country: text('country'), organization: text('company') };
        } else {
          values = message.kind === 'username' ? { username: text('username') } : { username: text('username'), password: text('password') };
        }
        const requested = new Set(Array.isArray(message.fields) ? message.fields.filter(field => typeof field === 'string' && field.length <= 256).slice(0, 64) : []);
        const custom = Object.fromEntries(item.customFields.filter(field => !['username', 'otp'].includes(message.kind) && requested.has(field.name) && !internalFields.has(field.name))
          .map(field => [field.name, field.value]));
        return { values, ...(Object.keys(custom).length ? { custom } : {}) } satisfies FillPayload;
      }
      case 'autofill-copy-otp': {
        await this.requireItemProof(message.id, message.proof, check);
        const item = JSON.parse(engine.get_item_json(message.id, true)) as VaultItem;
        if (!this.autofillMatches(item, 'otp', webUrl(message.url), message.groups)) throw new Error('验证码不匹配此网页。');
        const setup = otpSetup(item);
        if (setup.startsWith('otpauth://hotp/')) return null; // Login filling must never advance a HOTP counter.
        const code = await this.generateOtp(setup, check);
        if (code.kind === 'hotp') return null;
        const value = code.validTo != null && code.validTo - Math.floor(Date.now() / 1000) < 2 && code.nextValue ? code.nextValue : code.value;
        await copyWithExpiry(value, check);
        return true;
      }
      case 'list': return JSON.parse(engine.list_summaries_json());
      case 'get':
      case 'get-edit': {
        await this.requireItemProof(message.id, message.proof, check);
        const item = JSON.parse(engine.get_item_json(message.id, true)) as ItemDetailData;
        if (message.type === 'get-edit') return item;
        const setup = otpSetup(item);
        if (setup) {
          item.otp = setup.startsWith('otpauth://hotp/') ? { kind: 'hotp' } :
            { kind: 'time', handle: item.trashed ? undefined : await authorize(session.key, 'otp:read:v1', otpPayload(item, setup)) };
        }
        delete item.data.totpUri;
        item.customFields = item.customFields.filter(field => !internalFields.has(field.name));
        return item;
      }
      case 'upsert': {
        const item = JSON.parse(message.itemJson) as VaultItem;
        if (!item.title?.trim()) throw new Error('请输入名称。');
        let previousTotp: unknown;
        if (item.id) {
          await this.requireItemProof(item.id, message.proof, check);
          const existing = JSON.parse(engine.get_item_json(item.id, true)) as VaultItem;
          if (existing.revision !== item.revision) throw new Error('条目已在其他窗口更新，请重新打开后编辑。');
          previousTotp = existing.data.totpUri;
        }
        const setupKey = item.data.totpUri;
        if (item.data.kind === 'login' && setupKey != null && setupKey !== previousTotp) {
          if (typeof setupKey !== 'string' || setupKey.length > MAX_OTP_SETUP_LENGTH) throw new Error('验证码设置密钥无效。');
          await derive('validate-totp', [setupKey]);
        }
        return this.saveMutation(() => engine.upsert_item_json(message.itemJson, Date.now(), '本机'), check);
      }
      case 'trash': return this.saveMutation(() => engine.set_trashed(message.id, message.trashed, Date.now()), check);
      case 'delete': {
        const item = (JSON.parse(engine.list_summaries_json()) as ItemSummary[]).find(i => i.id === message.id);
        if (!item?.trashed) throw new Error('请先将条目移入回收站。');
        return this.saveMutation(() => engine.delete_permanently(message.id, Date.now()), check);
      }
      case 'empty-trash': {
        const expected = new Set(message.expectedIds);
        const trashed = (JSON.parse(engine.list_summaries_json()) as ItemSummary[]).filter(item => item.trashed);
        if (!trashed.length || expected.size !== trashed.length || !trashed.every(item => expected.has(item.id))) {
          throw new Error('回收站内容已变化，请重新核对后再清空。');
        }
        return this.saveMutation(() => engine.empty_trash(Date.now()), check);
      }
      case 'audit': {
        const report = await derive<string>('audit-snapshot', [session.key, session.wrap, this.files.head, this.files.snap], this.auditAbort.signal);
        check();
        return JSON.parse(report);
      }
      case 'generate-password': return core.wasm_generate_password(message.optionsJson);
      case 'generate-passphrase': return core.wasm_generate_passphrase(message.optionsJson);
      case 'create-pin':
        if (!/^\d{6,12}$/.test(message.pin)) throw new Error('PIN 需要 6–12 位数字。');
        await this.verify(message.proof, check);
        settings.pinWrap = new Uint8Array(await derive<number[]>('wasm_create_pin_wrap', [session.key, session.wrap, message.pin]));
        check(); settings.pinFailures = 0;
        await store.saveSettings(settings); return this.status();
      case 'remove-pin': delete settings.pinWrap; settings.pinFailures = 0; await store.saveSettings(settings); return this.status();
      case 'remove-prf': delete settings.prf; await store.saveSettings(settings); return this.status();
      case 'register-prf': {
        await this.verify(message.proof, check);
        if (message.output.length !== 32 || message.salt.length !== 32 || !message.credentialId.length) throw new Error('系统未返回有效的 PRF 输出，请改用 PIN。');
        const wrap = core.wasm_create_prf_wrap(session.key, session.wrap, new Uint8Array(message.output), new Uint8Array(message.salt));
        // Persist only after an independent unwrap succeeds.
        core.wasm_unlock_with_prf_wrap(this.files.head, wrap, new Uint8Array(message.output), session.key);
        settings.prf = { credentialId: message.credentialId, salt: message.salt, wrap: Array.from(wrap) };
        await store.saveSettings(settings); return this.status();
      }
      case 'set-autolock':
        if (!Number.isInteger(message.minutes) || message.minutes < 1 || message.minutes > 240) throw new Error('锁定时间需为 1–240 分钟。');
        settings.autoLockMinutes = message.minutes; await store.saveSettings(settings); await this.touch(); return this.status();
      case 'copy-sensitive': {
        await copyWithExpiry(message.value, check);
        return null;
      }
      case 'export': {
        await this.verifyMaster(message.proof, check);
        this.validatePassword(message.password);
        const bytes = await derive<number[]>('wasm_export_vaultpack', [session.key, session.wrap, this.files.head, this.files.snap, message.password, Date.now()]);
        check();
        const { vaultId, keyEpoch } = this.files;
        const changeCount = (this.files.backedUpChangeCount ?? 0) + this.files.changesSinceBackup;
        const authorization = await authorize(session.key, 'vaultpack:receipt:v1', receiptPayload(vaultId, keyEpoch, changeCount));
        check();
        const receipt: BackupReceipt = { vaultId, changeCount, authorization };
        return { bytes, receipt } satisfies BackupExport;
      }
      case 'backup-saved': {
        const { vaultId, changeCount, authorization } = message.receipt ?? {};
        const backedUp = this.files.backedUpChangeCount ?? 0;
        const total = backedUp + this.files.changesSinceBackup;
        if (vaultId !== this.files.vaultId || !Number.isSafeInteger(changeCount) || changeCount < 0 || changeCount > total ||
            !validAuthorization(authorization) || !await verifyAuthorization(session.key, 'vaultpack:receipt:v1',
              authorization, receiptPayload(vaultId, this.files.keyEpoch, changeCount))) {
          throw new Error('无法确认这份备份，请重新导出。');
        }
        check();
        if (changeCount > backedUp) {
          const files = { ...this.files, backedUpChangeCount: changeCount, changesSinceBackup: total - changeCount };
          await store.saveVaultFiles(files);
          this.files = files;
        }
        return null;
      }
      case 'preview-vaultpack':
      case 'import': {
        if (typeof message.password !== 'string' || !message.password || message.password.length > 1024 ||
            !Array.isArray(message.bytes) || !message.bytes.length || message.bytes.length > MAX_VAULTPACK_BYTES ||
            !message.bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255))
          throw new Error('请选择不超过 16 MiB 的备份，并输入文件密码。');
        const files = this.files;
        if (message.proof?.method === 'recovery') {
          const anchor = await store.loadRemoteAnchor(files.vaultId);
          check();
          if (anchor?.vaultId !== files.vaultId) throw new Error('只有已验证的网盘目标库支持用恢复码合入备份。');
          const code = message.proof.secret;
          if (typeof code !== 'string' || !code || code.length > 1024 ||
              !await derive<boolean>('sync:verify-recovery', [files.head, session.key, session.wrap, code]))
            throw new Error('目标库恢复码验证失败。');
          check();
        } else await this.verifyMaster(message.proof, check);
        const bytes = new Uint8Array(message.bytes), now = Date.now();
        try {
          const stamp = (await Promise.all([digestHex(bytes), digestHex(new Uint8Array(files.head)), digestHex(new Uint8Array(files.snap))])).join(':');
          const confirm = message.type === 'import';
          if (confirm && message.stamp !== stamp) throw new Error('备份文件或目标库已变化，请重新预览。');
          check();
          const { added, updated, skipped, head: nextHead, snap: nextSnap } =
            await derive<Omit<VaultPackPreview, 'stamp'> & { head: number[]; snap: number[] }>('sync:import-pack',
              [session.key, session.wrap, files.head, files.snap, bytes, message.password, now, confirm]);
          check();
          if (!confirm) return { added, updated, skipped, stamp } satisfies VaultPackPreview;
          const count = added + updated;
          if (!count) return 0;
          const head = new Uint8Array(nextHead), snap = new Uint8Array(nextSnap);
          await this.persistMutation({ ...files, head, snap, updatedAtMs: now,
            changesSinceBackup: files.changesSinceBackup + count, everHadRecords: files.everHadRecords || added > 0 }, check);
          engine.restore_from_session(session.key, session.wrap, head, snap);
          return count;
        } finally { bytes.fill(0); }
      }
      case 'preview-browser-csv':
      case 'import-browser-csv': {
        if (!Array.isArray(message.bytes) || !message.bytes.length || message.bytes.length > MAX_BROWSER_CSV_BYTES) {
          throw new Error('请选择不超过 2 MiB 的 CSV 文件。');
        }
        const bytes = new Uint8Array(message.bytes);
        try {
          // Bind the preview to both the selected file and the vault version. Never persist the preview.
          const stamp = (await Promise.all([digestHex(bytes), digestHex(new Uint8Array(this.files.snap))])).join(':');
          check();
          if (message.type === 'import-browser-csv') {
            if (message.stamp !== stamp) throw new Error('文件或密码库已变更，请重新预览再导入。');
            await this.verify(message.proof, check);
          }
          const rows = await derive<string>('parse-browser-csv', [bytes]);
          check();
          if (message.type === 'preview-browser-csv') {
            const preview = engine.import_records_json(rows, Date.now(), false);
            try { return { ...JSON.parse(preview.item_json), stamp } as BrowserCsvPreview; }
            finally { preview.free(); }
          }
          return this.saveMutation(() => engine.import_records_json(rows, Date.now(), true), check);
        } finally { bytes.fill(0); }
      }
      case 'next-hotp': {
        await this.requireItemProof(message.id, message.proof, check);
        const item = JSON.parse(engine.get_item_json(message.id, true)) as VaultItem;
        if (item.trashed || item.data.kind !== 'login' || typeof item.data.totpUri !== 'string') throw new Error('这条凭证没有可用的计数验证码。');
        const code = JSON.parse(await derive<string>('generate-hotp', [item.data.totpUri])) as OtpWorkerCode;
        check();
        if (code.kind !== 'hotp' || !code.nextSetupKey || code.counter == null) throw new Error('这条凭证使用时间验证码，无需推进计数器。');
        item.data.totpUri = code.nextSetupKey;
        // The queue serializes callers; never expose a code before its counter is durable.
        await this.saveMutation(() => engine.upsert_item_json(JSON.stringify(item), Date.now(), '本机'), check);
        return { kind: 'hotp', value: code.value, counter: code.counter } satisfies HotpCode;
      }
      case 'preview-ente':
      case 'import-ente': {
        if (!Array.isArray(message.bytes) || !message.bytes.length || message.bytes.length > MAX_ENTE_BYTES ||
            !message.bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
          throw new Error('Ente Auth 文本不能超过 2 MiB，加密 JSON 不能超过 3 MiB。');
        }
        if (message.password !== undefined && (typeof message.password !== 'string' || message.password.length > 4096)) {
          throw new Error('Ente Auth 文件密码格式无效。');
        }
        const bytes = new Uint8Array(message.bytes);
        try {
          const stamp = (await Promise.all([digestHex(bytes), digestHex(new Uint8Array(this.files.snap))])).join(':');
          check();
          if (message.type === 'import-ente') {
            if (message.stamp !== stamp) throw new Error('文件或密码库已变更，请重新预览再导入。');
            await this.verify(message.proof, check);
          }
          const existing = (JSON.parse(engine.list_summaries_json()) as ItemSummary[])
            .filter(item => item.kind === 'login').map(item => JSON.parse(engine.get_item_json(item.id, true)) as VaultItem);
          const setups = existing.filter(item => typeof item.data.totpUri === 'string')
            .map(item => ({ setupKey: item.data.totpUri, title: item.title, account: item.data.username }));
          const batch = JSON.parse(await derive<string>('parse-ente', [bytes, JSON.stringify(setups), message.password])) as EnteBatch;
          check();
          const plan = planEnteImport(batch, existing, message.type === 'import-ente' ? message.merges : []);
          if (message.type === 'preview-ente') return { ...plan.preview, stamp } satisfies EntePreview;
          return this.saveMutation(() => engine.import_records_json(JSON.stringify({ prepared: true, rows: plan.items }), Date.now(), true), check);
        } finally { bytes.fill(0); }
      }
      case 'export-ente': {
        if (message.confirmPlaintext !== true) throw new Error('导出未加密验证码需要确认风险。');
        await this.verifyMaster(message.proof, check);
        const items = (JSON.parse(engine.list_summaries_json()) as ItemSummary[])
          .filter(item => item.kind === 'login' && item.hasTotp)
          .map(summary => {
            const item = JSON.parse(engine.get_item_json(summary.id, true)) as VaultItem;
            return { title: item.title, data: { username: item.data.username, totpUri: item.data.totpUri },
              note: item.note, tags: item.tags, pinned: item.pinned, trashed: item.trashed };
          });
        if (!items.length) throw new Error('密码库里还没有两步验证码。');
        const text = await derive<string>('export-ente', [JSON.stringify(items)]);
        check();
        return text;
      }
      case 'hibp': {
        if (message.confirmOnline !== true) throw new Error('请先同意本次联网查询。');
        await this.requireItemProof(message.id, message.proof, check);
        if (!await browser.permissions.contains({ origins: ['https://api.pwnedpasswords.com/*'] })) throw new Error('请先授权泄露检查。');
        const item = JSON.parse(engine.get_item_json(message.id, true)) as VaultItem;
        if (item.data.kind !== 'login' || typeof item.data.password !== 'string') throw new Error('仅登录密码可检查。');
        const prefix = core.wasm_hibp_prefix(item.data.password);
        const response = await fetch('https://api.pwnedpasswords.com/range/' + prefix, {
          headers: { 'Add-Padding': 'true' }, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15000),
        });
        if (!response.ok) throw new Error('泄露查询服务暂不可用。');
        const range = await response.text();
        check();
        return Number(core.wasm_hibp_match_range(item.data.password, range));
      }
      default: throw new Error('不支持的操作。');
    }
  }
  private validateAutofillSettings(value: unknown): AutofillSettings {
    if (!value || typeof value !== 'object') throw new Error('网站偏好格式无效。');
    const settings = value as AutofillSettings;
    if (!settings.sites || typeof settings.sites !== 'object' || Array.isArray(settings.sites) ||
      Object.keys(settings.sites).length > 1000) throw new Error('网站偏好最多保存 1,000 个网站。');
    for (const [origin, flags] of Object.entries(settings.sites)) {
      if (webUrl(origin).origin !== origin || !flags || typeof flags !== 'object' || Object.keys(flags).length !== 3 ||
        !['inlineDisabled', 'saveDisabled', 'passkeyDisabled'].every(key => typeof flags[key as keyof typeof flags] === 'boolean')) throw new Error('网站偏好格式无效。');
    }
    return { sites: structuredClone(settings.sites), equivalentDomains: validateGroups(settings.equivalentDomains) };
  }
  private async readAutofillSettings(check: () => void): Promise<AutofillSettings> {
    if (this.autofill) return structuredClone(this.autofill);
    const stored = await browser.storage.local.get<{
      autofillSealed?: { vaultId: string; bytes: number[] }; autofill?: AutofillSettings;
    }>(['autofillSealed', 'autofill']);
    check();
    if (stored.autofillSealed) {
      const { vaultId, bytes } = stored.autofillSealed;
      if (vaultId !== this.files!.vaultId || !Array.isArray(bytes) || bytes.length > 256 * 1024 + 1024 ||
        !bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new Error('网站偏好与当前密码库不一致或已损坏。');
      const json = await derive<string>('open-preferences', [this.session!.key, this.session!.wrap, new Uint8Array(bytes)]);
      check();
      this.autofill = this.validateAutofillSettings(JSON.parse(json));
      if (stored.autofill) {
        await browser.storage.local.remove('autofill');
        check();
      }
    } else if (stored.autofill) {
      // Migrate preferences from development builds only after a successful encrypted write.
      await this.saveAutofillSettings(this.validateAutofillSettings(stored.autofill), check);
    } else {
      this.autofill = { sites: {}, equivalentDomains: [] };
    }
    return structuredClone(this.autofill!);
  }
  private async saveAutofillSettings(settings: AutofillSettings, check: () => void) {
    const valid = this.validateAutofillSettings(settings);
    const json = JSON.stringify(valid);
    if (new TextEncoder().encode(json).length > 256 * 1024) throw new Error('网站偏好超过 256 KiB。');
    const bytes = await derive<number[]>('seal-preferences', [this.session!.key, this.session!.wrap, json]);
    check();
    await browser.storage.local.set({ autofillSealed: { vaultId: this.files!.vaultId, bytes } });
    check();
    this.autofill = valid;
    await browser.storage.local.remove('autofill');
    check();
  }
  private autofillKind(kind: string, fill: FillKind) {
    return kind === (fill === 'card' ? 'payment_card' : fill === 'identity' ? 'identity' : 'login');
  }
  private autofillMatches(item: VaultItem, fill: FillKind, url: URL, groups: string[][]): boolean {
    if (item.trashed || !this.autofillKind(item.data.kind, fill)) return false;
    if (fill === 'card' || fill === 'identity') return true;
    const uris = item.data.uris as { uri: string; matchRule?: string }[] | undefined;
    return !!uris && loginUrisMatch(uris, url, groups) && (fill !== 'otp' || !!item.data.totpUri);
  }
  private validatePassword(password: string) {
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) throw new Error('密码需要 12–1024 个字符。');
  }
}

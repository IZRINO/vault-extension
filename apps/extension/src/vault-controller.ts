import { loadVaultCore, randomBytes } from './vault-core';
import { derive, offscreen } from './bridge';
import * as store from './vault-storage';
import { capacityErrorText, MAX_BROWSER_CSV_BYTES, MAX_VAULTPACK_BYTES, type BackupExport, type BrowserCsvPreview, type ItemSummary, type Proof, type VaultItem, type VaultMessage, type VaultStatus } from './vault-messages';

export const LOCK_ALARM = 'vault-lock';
export const CLIPBOARD_ALARM = 'vault-clipboard';
type Core = Awaited<ReturnType<typeof loadVaultCore>>;
type Engine = InstanceType<Core['WasmVaultEngine']>;
type Created = { head: number[]; snap: number[]; wrap: number[]; vaultId: string; keyEpoch: number; recoveryCode: string };
type Rotation = { head: number[]; wrap: number[]; keyEpoch: number };
type Mutation = { head_bytes: Uint8Array; snap_bytes: Uint8Array; count: number; free(): void };

async function digestHex(bytes: Uint8Array<ArrayBuffer>) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

export class VaultController {
  private core?: Core;
  private engine?: Engine;
  private files?: store.VaultFiles;
  private session?: store.SessionState;
  private settings?: store.LocalSettings;
  private tail: Promise<unknown> = Promise.resolve();
  private generation = 0;

  handle(message: VaultMessage): Promise<unknown> {
    if (message.type === 'lock') return this.lock();
    const generation = this.generation;
    const run = this.tail.then(async () => {
      const check = () => { if (generation !== this.generation) throw new Error('密码库已锁定，请重新解锁。'); };
      check();
      await this.prepare();
      check();
      const value = await this.dispatch(message, check);
      check();
      return value;
    });
    this.tail = run.catch(() => undefined);
    return run;
  }

  async lock(invalidatePending = true): Promise<void> {
    if (invalidatePending) this.generation++;
    this.engine?.lock_and_zeroize();
    this.session?.key.fill(0);
    this.session?.wrap.fill(0);
    this.session = undefined;
    await store.clearSessionState();
    await browser.alarms.clear(LOCK_ALARM);
    void browser.runtime.sendMessage({ target: 'vault-event', type: 'locked' }).catch(() => undefined);
  }

  private async prepare() {
    const generation = this.generation;
    this.core ??= await loadVaultCore();
    this.engine ??= new this.core.WasmVaultEngine();
    this.settings = await store.loadSettings();
    this.files = await store.loadVaultFiles();
    const saved = this.session ?? await store.loadSessionState();
    if (!saved || generation !== this.generation) return;
    if (!this.files || saved.lastActivityMs > Date.now() || Date.now() - saved.lastActivityMs >= this.settings.autoLockMinutes * 60000) {
      saved.key.fill(0);
      await this.lock(false);
      return;
    }
    try {
      if (!this.engine.is_unlocked()) this.engine.restore_from_session(saved.key, saved.wrap, this.files.head, this.files.snap);
      this.session = saved;
    } catch { await this.lock(false); }
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
    } catch (error) { await this.lock(); throw error; }
  }

  private async touch() {
    if (!this.session) throw new Error('请先解锁密码库。');
    this.session.lastActivityMs = Date.now();
    await store.saveSessionState(this.session);
    await browser.alarms.create(LOCK_ALARM, { when: this.session.lastActivityMs + this.settings!.autoLockMinutes * 60000 });
  }

  private async verify(proof: Proof | undefined, check: () => void) {
    if (!proof || !['master', 'pin'].includes(proof.method) || typeof proof.secret !== 'string') throw new Error('需要再次验证主密码或 PIN。');
    if (proof.method === 'pin') {
      await this.withPinAttempt(proof.secret, check, true);
    } else {
      const valid = await derive<boolean>('wasm_verify_master_password', [this.files!.head, proof.secret]);
      check();
      if (!valid) throw new Error('主密码验证失败。');
    }
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

  private async saveMutation(mutate: () => Mutation, check: () => void) {
    let result: Mutation | undefined;
    try {
      check();
      result = mutate();
      const snap = result.snap_bytes;
      if (!snap.length) return 0; // An explicit no-op has no new encrypted snapshot.
      const files = { ...this.files!, head: result.head_bytes, snap, updatedAtMs: Date.now(),
        changesSinceBackup: (this.files!.changesSinceBackup ?? 0) + result.count };
      await store.saveVaultFiles(files);
      this.files = files;
      check();
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

  private async dispatch(message: VaultMessage, check: () => void): Promise<unknown> {
    const core = this.core!;
    const engine = this.engine!;
    const settings = this.settings!;
    if (message.type === 'status') return this.status();
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
          keyEpoch: output.keyEpoch, updatedAtMs: Date.now(), changesSinceBackup: 0 };
        await store.saveVaultFiles(this.files);
        await this.activate(key, output.wrap, check);
        return { recoveryCode: output.recoveryCode, vaultId: output.vaultId };
      } catch (error) { await this.lock(); throw error; } finally { key.fill(0); }
    }
    if (!this.files) throw new Error('请先创建密码库。');
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
      const key = randomBytes(32);
      try {
        const output = await derive<Rotation>(message.type === 'recover' ? 'wasm_recover_and_reset_master_password' : 'wasm_change_master_password',
          [this.files.head, message.type === 'recover' ? message.recoveryCode : message.currentPassword, message.newPassword, key, Date.now()]);
        check();
        this.files = { ...this.files, head: new Uint8Array(output.head), keyEpoch: output.keyEpoch, updatedAtMs: Date.now() };
        await store.saveVaultFiles(this.files);
        delete settings.pinWrap; delete settings.prf; settings.pinFailures = 0;
        await store.saveSettings(settings);
        await this.activate(key, output.wrap, check);
        return this.status();
      } catch (error) { await this.lock(); throw error; } finally { key.fill(0); }
    }
    if (!engine.is_unlocked() || !this.session) throw new Error('请先解锁密码库。');
    await this.touch();
    check();
    const session = this.session;
    switch (message.type) {
      case 'list': return JSON.parse(engine.list_summaries_json());
      case 'get':
        await this.requireItemProof(message.id, message.proof, check);
        return JSON.parse(engine.get_item_json(message.id, true));
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
          if (typeof setupKey !== 'string' || setupKey.length > 4096) throw new Error('验证码设置密钥无效。');
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
      case 'audit': return JSON.parse(engine.run_security_audit_json());
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
        // Install the alarm before copying; a worker restart retains the cleanup deadline.
        await browser.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + 30000 });
        const hash = await offscreen<string>('copy', message.value);
        await browser.storage.session.set({ clipboard: { hash, expiresAt: Date.now() + 30000 } });
        await browser.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + 30000 });
        return null;
      }
      case 'export': {
        await this.verify(message.proof, check);
        this.validatePassword(message.password);
        const bytes = await derive<number[]>('wasm_export_vaultpack', [session.key, session.wrap, this.files.head, this.files.snap, message.password, Date.now()]);
        check();
        return { bytes, receipt: { vaultId: this.files.vaultId, changeCount: (this.files.backedUpChangeCount ?? 0) + this.files.changesSinceBackup } } satisfies BackupExport;
      }
      case 'backup-saved': {
        const { vaultId, changeCount } = message.receipt;
        const backedUp = this.files.backedUpChangeCount ?? 0;
        const total = backedUp + this.files.changesSinceBackup;
        if (vaultId !== this.files.vaultId || !Number.isSafeInteger(changeCount) || changeCount < 0 || changeCount > total) {
          throw new Error('无法确认这份备份，请重新导出。');
        }
        if (changeCount > backedUp) {
          const files = { ...this.files, backedUpChangeCount: changeCount, changesSinceBackup: total - changeCount };
          await store.saveVaultFiles(files);
          this.files = files;
        }
        return null;
      }
      case 'import': {
        await this.verify(message.proof, check);
        if (!Array.isArray(message.bytes) || message.bytes.length > MAX_VAULTPACK_BYTES) throw new Error('备份不能超过 16 MiB。');
        const output = await derive<{ head: number[]; snap: number[]; count: number }>('wasm_import_vaultpack_into_vault',
          [session.key, session.wrap, this.files.head, this.files.snap, new Uint8Array(message.bytes), message.password, Date.now()]);
        check();
        const head = new Uint8Array(output.head), snap = new Uint8Array(output.snap);
        await store.saveVaultFiles({ ...this.files, head, snap, updatedAtMs: Date.now(), changesSinceBackup: (this.files.changesSinceBackup ?? 0) + output.count });
        this.files = (await store.loadVaultFiles())!;
        check();
        engine.restore_from_session(session.key, session.wrap, head, snap);
        return output.count;
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
            const preview = engine.browser_csv_json(rows, Date.now(), false);
            try { return { ...JSON.parse(preview.item_json), stamp } as BrowserCsvPreview; }
            finally { preview.free(); }
          }
          return this.saveMutation(() => engine.browser_csv_json(rows, Date.now(), true), check);
        } finally { bytes.fill(0); }
      }
      case 'hibp': {
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
  private validatePassword(password: string) {
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) throw new Error('密码需要 12–1024 个字符。');
  }
}

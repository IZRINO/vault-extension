import { loadVaultCore, randomBytes } from './vault-core';
import { derive, offscreen } from './bridge';
import * as store from './vault-storage';
import { capacityErrorText, MAX_BROWSER_CSV_BYTES, MAX_ENTE_BYTES, MAX_OTP_SETUP_LENGTH, MAX_VAULTPACK_BYTES, type BackupExport, type BrowserCsvPreview, type EntePreview, type ItemSummary, type OtpCode, type Proof, type VaultItem, type VaultMessage, type VaultStatus } from './vault-messages';
import { planEnteImport, type EnteBatch } from './ente-auth';
import { uriMatches, validateGroups, webUrl, type AutofillSettings } from './autofill-policy';
import type { FillCandidate, FillKind, FillPayload } from './autofill-messages';
import { planMigration, type MigrationBatch } from './migration';
import { MAX_MIGRATION_BYTES, type MigrationExport } from './vault-messages';

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
  private lastCaptureMs = -Infinity;
  private autofill?: AutofillSettings;

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
    this.autofill = undefined;
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

  private async saveMutation(mutate: () => Mutation, check: () => void, queueHotpChange = false) {
    let result: Mutation | undefined;
    try {
      check();
      result = mutate();
      const snap = result.snap_bytes;
      if (!snap.length) return 0; // An explicit no-op has no new encrypted snapshot.
      const files = { ...this.files!, head: result.head_bytes, snap, updatedAtMs: Date.now(),
        changesSinceBackup: (this.files!.changesSinceBackup ?? 0) + result.count };
      await store.saveVaultFiles(files, queueHotpChange);
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
      case 'csv-headers':
      case 'preview-migration':
      case 'import-migration': {
        const isCsv = message.type === 'csv-headers' || message.format === 'csv';
        const limit = isCsv ? MAX_BROWSER_CSV_BYTES : MAX_MIGRATION_BYTES;
        if (!Array.isArray(message.bytes) || !message.bytes.length || message.bytes.length > limit ||
          !message.bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) throw new Error(isCsv ? '请选择不超过 2 MiB 的 UTF-8 CSV 文件。' : '请选择不超过 16 MiB 的 Bitwarden JSON 文件。');
        const bytes = new Uint8Array(message.bytes);
        try {
          if (message.type === 'csv-headers') return JSON.parse(await derive<string>('csv-headers', [bytes]));
          if (!['csv', 'bitwarden'].includes(message.format)) throw new Error('不支持的迁移格式。');
          if (message.password != null && (typeof message.password !== 'string' || message.password.length > 4096)) throw new Error('文件密码过长。');
          const mapping = JSON.stringify(message.mapping ?? {});
          const options = new TextEncoder().encode(message.format + ':' + mapping);
          const stamp = (await Promise.all([digestHex(bytes), digestHex(new Uint8Array(this.files.snap)), digestHex(options)])).join(':');
          check();
          if (message.type === 'import-migration') {
            if (message.stamp !== stamp) throw new Error('文件、字段映射或密码库已变更，请重新预览。');
            await this.verify(message.proof, check);
          }
          const batch = JSON.parse(await derive<string>(isCsv ? 'parse-mapped-csv' : 'parse-bitwarden', [bytes, isCsv ? mapping : message.password ?? ''])) as MigrationBatch;
          check();
          if (isCsv) {
            batch.rows = batch.rows.filter(item => {
              try {
                const uri = (item.data.uris as { uri: string }[])[0]!.uri;
                webUrl(uri); return true;
              } catch { batch.invalid++; return false; }
            });
          }
          const existing = (JSON.parse(engine.list_summaries_json()) as ItemSummary[]).map(row => JSON.parse(engine.get_item_json(row.id, true)) as VaultItem);
          const plan = planMigration(batch, existing);
          if (message.type === 'preview-migration') return { ...plan.preview, stamp };
          return this.saveMutation(() => engine.import_records_json(JSON.stringify({ prepared: true, rows: plan.items }), Date.now(), true), check);
        } finally { bytes.fill(0); }
      }
      case 'export-migration': {
        if (!['csv', 'bitwarden'].includes(message.format) || message.proof?.method !== 'master') throw new Error('迁移导出需要再次验证主密码。');
        if (message.encrypted && message.format !== 'bitwarden') throw new Error('CSV 不支持加密，请选择 Bitwarden JSON。');
        if (!message.encrypted && message.confirmPlaintext !== true) throw new Error('请先确认明文文件的风险。');
        if (message.encrypted) this.validatePassword(message.password ?? '');
        await this.verify(message.proof, check);
        const items = (JSON.parse(engine.list_summaries_json()) as ItemSummary[]).map(row => JSON.parse(engine.get_item_json(row.id, true)) as VaultItem);
        const json = JSON.stringify(items);
        if (message.format === 'csv') {
          const result = JSON.parse(await derive<string>('export-login-csv', [json])) as MigrationExport;
          check();
          return result;
        }
        const entropy = randomBytes(64);
        try {
          const text = await derive<string>('export-bitwarden', [json, message.encrypted ? message.password! : '', entropy]);
          check();
          return { text, count: items.length, skipped: 0 } satisfies MigrationExport;
        } finally { entropy.fill(0); }
      }
      case 'scan-otp': {
        const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
        if (tab?.id == null || !tab.url) throw new Error('请先打开显示二维码的网站。');
        webUrl(tab.url);
        const wait = 600 - (performance.now() - this.lastCaptureMs);
        if (wait > 0) { await new Promise(resolve => setTimeout(resolve, wait)); check(); }
        const current = await browser.tabs.get(tab.id);
        if (!current.active || current.url !== tab.url) throw new Error('网页已改变，请重新扫描。');
        const values = await offscreen<string[]>('scan-otp', async () => {
          check();
          const active = await browser.tabs.get(tab.id!);
          if (!active.active || active.url !== tab.url) throw new Error('网页已改变，请重新扫描。');
          this.lastCaptureMs = performance.now();
          try { return await browser.tabs.captureVisibleTab(tab.windowId, { format: 'jpeg', quality: 95 }); }
          catch (error) {
            if (/activeTab|all_urls|permission/i.test(error instanceof Error ? error.message : String(error))) {
              throw new Error('截图尚未授权。请先点击浏览器工具栏的 Vault 图标，再扫描当前网站的二维码。');
            }
            throw new Error('浏览器暂时无法截图，请稍后重试。');
          }
        });
        check();
        const after = await browser.tabs.get(tab.id);
        if (!after.active || after.url !== tab.url) throw new Error('网页已改变，请重新扫描。');
        if (!values.length) throw new Error('没有找到验证码二维码。请把完整二维码显示在当前页面，或手动粘贴密钥。');
        return values;
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
          const code = JSON.parse(await derive<string>('generate-otp', [text('totpUri'), Math.floor(Date.now() / 1000)])) as OtpCode;
          check();
          if (code.kind === 'hotp') {
            if (!code.nextSetupKey) throw new Error('计数验证码设置无效。');
            item.data.totpUri = code.nextSetupKey;
            await this.saveMutation(() => engine.upsert_item_json(JSON.stringify(item), Date.now(), '本机'), check, true);
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
        const reserved = new Set(['Bitwarden 保留字段', 'Bitwarden 未识别的验证码设置', 'CSV 未识别的验证码设置']);
        const custom = Object.fromEntries(item.customFields.filter(field => !['username', 'otp'].includes(message.kind) && requested.has(field.name) && !reserved.has(field.name))
          .map(field => [field.name, field.value]));
        return { values, ...(Object.keys(custom).length ? { custom } : {}) } satisfies FillPayload;
      }
      case 'autofill-copy-otp': {
        await this.requireItemProof(message.id, message.proof, check);
        const item = JSON.parse(engine.get_item_json(message.id, true)) as VaultItem;
        if (!this.autofillMatches(item, 'otp', webUrl(message.url), message.groups)) throw new Error('验证码不匹配此网页。');
        const setup = String(item.data.totpUri);
        if (setup.startsWith('otpauth://hotp/')) return null; // Login filling must never advance a HOTP counter.
        const code = JSON.parse(await derive<string>('generate-otp', [setup, Math.floor(Date.now() / 1000)])) as OtpCode;
        check();
        if (code.kind === 'hotp') return null;
        const value = code.validTo != null && code.validTo - Math.floor(Date.now() / 1000) < 2 && code.nextValue ? code.nextValue : code.value;
        const hash = await offscreen<string>('copy', value);
        check();
        await browser.storage.session.set({ clipboard: { hash, expiresAt: Date.now() + 30000 } });
        await browser.alarms.create(CLIPBOARD_ALARM, { when: Date.now() + 30000 });
        return true;
      }
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
        const code = JSON.parse(await derive<string>('generate-hotp', [item.data.totpUri])) as OtpCode;
        check();
        if (code.kind !== 'hotp' || !code.nextSetupKey) throw new Error('这条凭证使用时间验证码，无需推进计数器。');
        item.data.totpUri = code.nextSetupKey;
        // The queue serializes callers; never expose a code before its counter is durable.
        await this.saveMutation(() => engine.upsert_item_json(JSON.stringify(item), Date.now(), '本机'), check, true);
        return { code: { ...code, nextSetupKey: null }, item: JSON.parse(engine.get_item_json(item.id, true)) as VaultItem };
      }
      case 'preview-ente':
      case 'import-ente': {
        if (!Array.isArray(message.bytes) || !message.bytes.length || message.bytes.length > MAX_ENTE_BYTES ||
            !message.bytes.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
          throw new Error('请选择不超过 2 MiB 的 Ente Auth 文本文件。');
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
          const batch = JSON.parse(await derive<string>('parse-ente', [bytes, JSON.stringify(setups)])) as EnteBatch;
          check();
          const plan = planEnteImport(batch, existing, message.type === 'import-ente' ? message.merges : []);
          if (message.type === 'preview-ente') return { ...plan.preview, stamp } satisfies EntePreview;
          return this.saveMutation(() => engine.import_records_json(JSON.stringify({ prepared: true, rows: plan.items }), Date.now(), true), check);
        } finally { bytes.fill(0); }
      }
      case 'export-ente': {
        if (message.confirmPlaintext !== true || message.proof?.method !== 'master') {
          throw new Error('导出未加密验证码需要确认风险，并再次验证主密码。');
        }
        await this.verify(message.proof, check);
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
    return !!uris?.some(uri => uriMatches(uri, url, groups)) && (fill !== 'otp' || !!item.data.totpUri);
  }
  private validatePassword(password: string) {
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) throw new Error('密码需要 12–1024 个字符。');
  }
}

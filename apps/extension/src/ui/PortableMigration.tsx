import { useRef, useState } from 'react';
import { MAX_MIGRATION_BYTES, request, type MigrationExport, type MigrationPreview } from '../vault-messages';
import { SecretField, SelectField } from './components';
import { useDialogs } from './dialogs';
import { download, kinds } from './lib';
import { useOps } from './Main';

const descriptions = {
  cxf: { label: 'FIDO CXF 1.0', accept: '.cxf,.json,.jwe', password: true },
  keepass: { label: 'KeePass KDBX / XML / CSV', accept: '.kdbx,.xml,.csv', password: true },
  onepassword: { label: '1Password 1PUX', accept: '.1pux', password: false },
  proton: { label: 'Proton Pass', accept: '.json,.zip', password: false },
};
type Format = keyof typeof descriptions;
export default function PortableMigration({ refresh }: { refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const dialogs = useDialogs();
  const input = useRef<HTMLInputElement>(null);
  const [format, setFormat] = useState<Format>('cxf');
  const [mode, setMode] = useState<'import' | 'export'>('import');
  const [source, setSource] = useState<File>();
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [encrypted, setEncrypted] = useState(true);
  const [preview, setPreview] = useState<MigrationPreview>();
  const reset = () => { setSource(undefined); setPassword(''); setConfirmation(''); setPreview(undefined); if (input.current) input.current.value = ''; };
  const withFile = async <T,>(consume: (bytes: number[]) => Promise<T>) => {
    if (!source?.size || source.size > MAX_MIGRATION_BYTES) throw new Error('请选择不超过 16 MiB 的迁移文件。');
    const raw = new Uint8Array(await source.arrayBuffer()), bytes = Array.from(raw);
    try { return await consume(bytes); } finally { raw.fill(0); bytes.fill(0); }
  };
  return <>
    <div className="chips" role="group" aria-label="迁移方向">
      <button type="button" className="chip" aria-pressed={mode === 'import'} disabled={busy} onClick={() => { reset(); setMode('import'); }}>导入凭证</button>
      <button type="button" className="chip" aria-pressed={mode === 'export'} disabled={busy} onClick={() => { reset(); setFormat('cxf'); setMode('export'); }}>导出 CXF</button>
    </div>
    {mode === 'import' ? <>
      <form className="form" onSubmit={event => { event.preventDefault(); void work(async () => {
        setPreview(undefined);
        setPreview(await withFile(bytes => request<MigrationPreview>({ type: 'preview-migration', format, bytes, password })));
      }); }}>
        <SelectField label="来源格式" value={format} disabled={busy} onChange={value => { reset(); setFormat(value as Format); }}>
          {Object.entries(descriptions).map(([key, format]) => <option key={key} value={key}>{format.label}</option>)}
        </SelectField>
        <label className="field">迁移文件<input ref={input} className="input" type="file" accept={descriptions[format].accept} disabled={busy} required
          onChange={event => { setSource(event.target.files?.[0]); setPreview(undefined); setPassword(''); }} /></label>
        {descriptions[format].password && <SecretField label={format === 'keepass' ? 'KeePass 文件密码' : 'CXF JWE 文件密码（明文留空）'} value={password}
          hint={format === 'keepass' ? '加密 KDBX 需要文件密码；明文 XML 或 CSV 请留空。' : undefined}
          maxLength={4096} autoComplete="off" onChange={value => { setPassword(value); setPreview(undefined); }} />}
        {!preview && <button className="btn btn-primary" disabled={busy || !source}>预览迁移内容</button>}
      </form>
      {preview && <section className="section">
        <h2>可导入 {preview.ready} 条凭证</h2>
        <p className="hint">可用通行密钥 {preview.passkeys ?? 0} 枚，重复 {preview.skipped} 条，无效 {preview.invalid} 条，不支持的字段或附件 {preview.unsupported} 项。</p>
        {!!preview.suspendedPasskeys && <p className="banner banner-warn">{preview.suspendedPasskeys} 枚通行密钥的签名计数待核实，暂不能登录。</p>}
        {!!preview.ignoredOtp && <p className="banner banner-warn">{preview.ignoredOtp} 个验证码设置未导入。</p>}
        {!!preview.ignoredPasskeys && <p className="banner banner-warn">{preview.ignoredPasskeys} 枚通行密钥未导入，原因可能是条目已存在、私钥缺失、无效或格式不兼容。请保留原认证器。</p>}
        {!!preview.unsupportedPasskeyVersions && <p className="banner banner-warn">其中 {preview.unsupportedPasskeyVersions} 枚使用了暂不支持的 Proton Pass 通行密钥载荷版本。</p>}
        {format === 'onepassword' && preview.ready > 0 && !preview.passkeys && !preview.suspendedPasskeys && !preview.ignoredPasskeys &&
          <p className="hint">本次没有新增通行密钥。1Password 桌面版的常规 1PUX 导出会把通行密钥留在原库。</p>}
        <ul className="facts">{preview.sample.map((row, index) => <li key={index} className="fact"><div className="fact-text">
          <span className="fact-value">{row.title}</span><span className="fact-label">{row.account || kinds[row.kind] || row.kind}</span>
        </div></li>)}</ul>
        <button type="button" className="btn btn-primary" disabled={busy || !preview.ready} onClick={() => void work(async () => {
          const proof = await dialogs.proof({ masterOnly: format === 'keepass' });
          try {
            const count = await withFile(bytes => request<number>({ type: 'import-migration', format, bytes, password, stamp: preview.stamp, proof }));
            reset(); await refresh(); notify(`已导入 ${count} 条凭证。`);
          } catch (error) { if (error instanceof Error && error.message.includes('重新预览')) setPreview(undefined); throw error; }
          finally { proof.secret = ''; }
        })}>确认导入</button>
      </section>}
    </> : <form className="form" onSubmit={event => { event.preventDefault(); if (busy) return; void work(async () => {
      if (encrypted && password !== confirmation) throw new Error('两次文件密码不一致。');
      const risk = !encrypted && await dialogs.confirm({ title: '导出未加密的 CXF？', body: '文件包含密码、通行密钥私钥和验证码种子。请只交给可信的接收应用。', confirmLabel: '验证主密码并导出', danger: true });
      if (!encrypted && !risk) return;
      const proof = await dialogs.proof({ masterOnly: true });
      try {
        const result = await request<MigrationExport>({ type: 'export-migration', format: 'cxf', encrypted, password, proof, confirmPlaintext: risk });
        download(`Vault-${new Date().toISOString().slice(0, 10)}.${encrypted ? 'cxf.jwe' : 'cxf'}`, result.text, encrypted ? 'application/jose' : 'application/json');
        setPassword(''); setConfirmation('');
        notify(`已请求下载 ${result.count} 条凭证，跳过 ${result.skipped} 条条目和 ${result.skippedPasskeys ?? 0} 枚通行密钥。`);
      } finally { proof.secret = ''; }
    }); }}>
      <SelectField label="文件保护" disabled={busy} value={encrypted ? 'jwe' : 'cxf'} onChange={value => {
        setEncrypted(value === 'jwe'); setPassword(''); setConfirmation('');
      }}>
        <option value="jwe">CXF 内容 + JWE 文件密码保护</option><option value="cxf">FIDO CXF 1.0 明文</option>
      </SelectField>
      {encrypted && <>
        <p className="hint">接收端需支持 JWE（PBES2-HS512+A256KW / A256GCM）解包，或使用本扩展导入。</p>
        <SecretField label="文件密码" value={password} onChange={setPassword} autoComplete="new-password" minLength={12} maxLength={1024} required />
        <SecretField label="确认文件密码" value={confirmation} onChange={setConfirmation} autoComplete="new-password" minLength={12} maxLength={1024} required />
      </>}
      <p className="hint">不导出递增计数、硬件绑定的通行密钥或回收站；完整备份使用 .vaultpack。</p>
      <button className="btn btn-primary" disabled={busy}>验证并导出</button>
    </form>}
  </>;
}

import { useRef, useState } from 'react';
import { MAX_BROWSER_CSV_BYTES, MAX_MIGRATION_BYTES, request, type CsvMapping, type MigrationExport, type MigrationFormat, type MigrationPreview } from '../vault-messages';
import { SecretField, SelectField } from './components';
import { useDialogs } from './dialogs';
import { download, kinds } from './lib';
import { useOps } from './Main';

async function withFile<T>(file: File, limit: number, consume: (bytes: number[]) => Promise<T>) {
  if (!file.size || file.size > limit) throw new Error(`请选择不超过 ${limit / 1024 / 1024} MiB 的文件。`);
  const raw = new Uint8Array(await file.arrayBuffer()), bytes = Array.from(raw);
  try { return await consume(bytes); } finally { raw.fill(0); bytes.fill(0); }
}
const columns: { key: keyof CsvMapping; label: string; aliases: string[]; required?: boolean }[] = [
  { key: 'url', label: '网站', aliases: ['url', 'website', '网站', '网址'], required: true },
  { key: 'password', label: '密码', aliases: ['password', '密码', '口令'], required: true },
  { key: 'username', label: '用户名', aliases: ['username', 'account', 'user', '用户名', '账号'] },
  { key: 'title', label: '名称', aliases: ['name', 'title', '名称', '标题'] },
  { key: 'note', label: '备注', aliases: ['note', 'notes', '备注'] },
  { key: 'totp', label: '验证码设置密钥', aliases: ['totp', 'otp', 'otpauth', '密钥'] },
  { key: 'tags', label: '标签', aliases: ['tags', '标签'] },
  { key: 'trashed', label: '回收站状态', aliases: ['trashed', '回收站'] },
];

export default function Migration({ format, refresh }: { format: MigrationFormat; refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const dialogs = useDialogs();
  const csv = format === 'csv';
  const limit = csv ? MAX_BROWSER_CSV_BYTES : MAX_MIGRATION_BYTES;
  const [mode, setMode] = useState<'import' | 'export'>('import');
  const [file, setFile] = useState<File>();
  const [filePassword, setFilePassword] = useState('');
  const [headers, setHeaders] = useState<string[]>();
  const [mapping, setMapping] = useState<CsvMapping>({});
  const [preview, setPreview] = useState<MigrationPreview>();
  const [encrypted, setEncrypted] = useState(!csv);
  const [exportPassword, setExportPassword] = useState('');
  const [again, setAgain] = useState('');
  const [risk, setRisk] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const clear = () => { setFile(undefined); setPreview(undefined); setHeaders(undefined); setMapping({}); setFilePassword(''); if (input.current) input.current.value = ''; };

  return <>
    <div className="chips" role="group" aria-label="密码迁移操作">
      <button type="button" className="chip" disabled={busy} aria-pressed={mode === 'import'} onClick={() => { setMode('import'); setRisk(false); }}>导入凭证</button>
      <button type="button" className="chip" disabled={busy} aria-pressed={mode === 'export'} onClick={() => { setMode('export'); setPreview(undefined); setFilePassword(''); }}>导出凭证</button>
    </div>
    {mode === 'import' ? <>
      <p className="lede">{csv ? '选择 UTF-8 CSV，为每个字段指定源列。预览后再导入，已有凭证不会被覆盖。' : '从 Bitwarden 或 Vaultwarden 导出的 JSON 导入登录项、验证码、支付卡、身份和安全备注。已有凭证不会被覆盖。'}</p>
      {!csv && <p className="hint">加密文件请选择「密码保护」导出，填写文件密码。账号绑定导出需要回到 Bitwarden 重新导出。未支持的源字段会加密保留在条目内；Passkey 暂不能使用。</p>}
      <form className="form" onSubmit={event => {
        event.preventDefault();
        if (!file || busy) return;
        void work(async () => {
          setPreview(undefined);
          if (csv && !headers) {
            const parsed = await withFile(file, limit, bytes => request<{ headers: string[] }>({ type: 'csv-headers', bytes }));
            setHeaders(parsed.headers);
            setMapping(Object.fromEntries(columns.flatMap(column => {
              const index = parsed.headers.findIndex(header => column.aliases.includes(header.trim().toLowerCase()));
              return index < 0 ? [] : [[column.key, index]];
            })));
          } else {
            setPreview(await withFile(file, limit, bytes => request<MigrationPreview>({ type: 'preview-migration', format, bytes, password: filePassword, mapping })));
          }
        });
      }}>
        <label className="field">{csv ? 'CSV 文件' : 'Bitwarden JSON 文件'}<input ref={input} className="input" type="file" required disabled={busy}
          accept={csv ? '.csv,text/csv' : '.json,application/json'}
          onChange={event => { setFile(event.target.files?.[0]); setPreview(undefined); setHeaders(undefined); setMapping({}); setFilePassword(''); }} /></label>
        <p className="hint">每次最多 {limit / 1024 / 1024} MiB、5,000 条。原文件保持不变。</p>
        {!csv && <SecretField label="文件密码（加密 JSON 才需填写）" autoComplete="off" value={filePassword} maxLength={4096} onChange={value => { setFilePassword(value); setPreview(undefined); }} />}
        {csv && headers && <fieldset className="form">
          <legend>对应源列</legend>
          {columns.map(column => <SelectField key={column.key} label={column.label + (column.required ? '（必选）' : '')} value={mapping[column.key] ?? ''} required={column.required} disabled={busy}
            onChange={value => { setMapping(old => { const next = { ...old }; if (value === '') delete next[column.key]; else next[column.key] = Number(value); return next; }); setPreview(undefined); }}>
            <option value="">{column.required ? '请选择源列' : '不导入此字段'}</option>
            {headers.map((header, index) => <option key={index} value={index}>{index + 1}. {header || '无列名'}</option>)}
          </SelectField>)}
          <p className="hint">标签支持 JSON 数组或分号分隔。回收站值为 true、1 或 yes 时保留在回收站。</p>
        </fieldset>}
        {!preview && <button className="btn btn-primary" disabled={busy || !file}>{csv && !headers ? '读取列名' : '预览迁移内容'}</button>}
      </form>
      {preview && <section className="section">
        <h2>可导入 {preview.ready} 条凭证</h2>
        <p className="hint">重复跳过 {preview.skipped} 条，无法读取 {preview.invalid} 条，不支持的类型 {preview.unsupported} 条。</p>
        {preview.ignoredOtp > 0 && <p className="banner banner-warn">有 {preview.ignoredOtp} 个验证码设置未启用，原值已保留为隐藏字段。请继续保留原验证器并检查这些记录。</p>}
        {preview.unsupported > 0 && <p className="banner banner-warn">请保留原密码库，检查未导入的条目。此向导暂不导入独立 SSH 类型或附件内容。</p>}
        <ul className="facts">{preview.sample.map((row, index) => <li className="fact" key={index}><div className="fact-text">
          <span className="fact-value">{row.title}</span><span className="fact-label">{row.account || kinds[row.kind] || row.kind}</span>
        </div></li>)}</ul>
        <div className="actions">
          <button type="button" className="btn btn-primary" disabled={busy || !preview.ready} onClick={() => void work(async () => {
            if (!file) return;
            const proof = await dialogs.proof();
            try {
              const count = await withFile(file, limit, bytes => request<number>({ type: 'import-migration', format, bytes, password: filePassword, mapping, stamp: preview.stamp, proof }));
              clear(); await refresh(); notify(`已导入 ${count} 条凭证。`);
            } catch (error) { if (error instanceof Error && error.message.includes('重新预览')) setPreview(undefined); throw error; }
            finally { proof.secret = ''; }
          })}>确认导入 {preview.ready} 条</button>
          <button type="button" className="btn" disabled={busy} onClick={() => setPreview(undefined)}>返回预览设置</button>
        </div>
      </section>}
    </> : <form className="form" onSubmit={event => {
      event.preventDefault();
      if (busy || !encrypted && !risk) return;
      void work(async () => {
        if (encrypted && exportPassword !== again) throw new Error('两次文件密码不一致。');
        if (!encrypted && !await dialogs.confirm({ title: '导出未加密的凭证？', body: '文件包含完整密码和验证码密钥，也包含回收站中的条目。请只用于迁移，并妥善保管。', confirmLabel: '验证主密码并导出', danger: true })) return;
        const proof = await dialogs.proof({ masterOnly: true });
        try {
          const result = await request<MigrationExport>({ type: 'export-migration', format, encrypted, password: exportPassword, confirmPlaintext: risk, proof });
          download(`Vault-${csv ? 'Logins' : 'Bitwarden'}-${new Date().toISOString().slice(0, 10)}.${csv ? 'csv' : 'json'}`, result.text, csv ? 'text/csv;charset=utf-8' : 'application/json');
          setExportPassword(''); setAgain(''); setRisk(false);
          notify(`已请求下载 ${result.count} 条凭证${result.skipped ? `，跳过 ${result.skipped} 条其他类型` : ''}，请检查下载记录。`);
        } finally { proof.secret = ''; }
      });
    }}>
      <p className="lede">{csv ? '导出登录凭证的名称、首个网站、账号、密码、验证码、备注、标签和回收站状态。支付卡、身份、其他字段和密码历史请使用 JSON 或加密备份。' : '导出为 Bitwarden 兼容 JSON，包含回收站条目。默认使用独立文件密码保护；迁移和备份均需妥善保管文件密码。'}</p>
      {!csv && <SelectField label="文件保护" value={encrypted ? 'encrypted' : 'plain'} disabled={busy} onChange={value => { setEncrypted(value === 'encrypted'); setRisk(false); setExportPassword(''); setAgain(''); }}>
        <option value="encrypted">密码保护（推荐）</option><option value="plain">未加密 JSON</option>
      </SelectField>}
      {encrypted ? <>
        <SecretField label="导出文件密码" value={exportPassword} onChange={setExportPassword} required minLength={12} maxLength={1024} autoComplete="new-password" />
        <SecretField label="再次输入文件密码" value={again} onChange={setAgain} required minLength={12} maxLength={1024} autoComplete="new-password" />
      </> : <>
        <p className="banner banner-warn">文件未加密，拿到文件的人可以读取密码和验证码密钥。CSV 仅用于迁移，请勿直接用表格软件打开。</p>
        <label className="check"><input type="checkbox" checked={risk} disabled={busy} onChange={event => setRisk(event.target.checked)} />我理解文件未加密，会妥善保管</label>
      </>}
      <button className="btn btn-primary" disabled={busy || !encrypted && !risk}>导出{csv ? '登录 CSV' : ' Bitwarden JSON'}</button>
    </form>}
  </>;
}

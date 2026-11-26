import { useId, useRef, useState } from 'react';
import { AUTH_BACKUP_FORMATS, MAX_AUTH_BACKUP_BYTES, request, type AuthBackupFormat, type AuthBackupInput, type AuthBackupPreview } from '../vault-messages';
import { AreaField, SecretField, SelectField } from './components';
import { useDialogs } from './dialogs';
import { useOps } from './Main';

const formats: Record<AuthBackupFormat, { label: string; accept: string; password?: boolean; hint?: string }> = {
  google: { label: 'Google Authenticator', accept: 'image/png,image/jpeg,image/webp' },
  '2fas': { label: '2FAS', accept: '.2fas,.json', password: true },
  aegis: { label: 'Aegis', accept: '.json', password: true },
  raivo: { label: 'Raivo OTP', accept: '.zip,.json', password: true },
  andotp: { label: 'andOTP', accept: '.json,.aes,.bin', password: true,
    hint: '支持明文 JSON 和密码保护的 AES 备份。' },
  stratum: { label: 'Stratum / Authenticator Pro', accept: '.stratum,.authpro,.json', password: true,
    hint: '支持明文和新版加密备份。旧版加密备份请在 Stratum 重新导出。' },
  'freeotp-plus': { label: 'FreeOTP+', accept: '.json,.txt', hint: '在 FreeOTP+ 中选择导出 JSON 或密钥 URI。' },
  winauth: { label: 'WinAuth', accept: '.txt,.zip', password: true, hint: '请选择 WinAuth 导出的 TXT 或 ZIP。仅导入验证码设置，不导入 Steam 会话或应用配置。' },
};

function imageUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => typeof reader.result === 'string' ? resolve(reader.result) : reject(new Error('无法读取图像。'));
    reader.onerror = () => reject(new Error('无法读取图像。'));
    reader.readAsDataURL(file);
  });
}
export default function AuthMigration({ refresh }: { refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const dialogs = useDialogs();
  const field = useRef<HTMLInputElement>(null);
  const imageStatusId = useId();
  const [format, setFormat] = useState<AuthBackupFormat>('google');
  const [files, setFiles] = useState<File[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [links, setLinks] = useState('');
  const [password, setPassword] = useState('');
  const [preview, setPreview] = useState<AuthBackupPreview>();
  const google = format === 'google';
  const descriptor = formats[format];
  const clear = () => {
    setPreview(undefined); setFiles([]); setLinks(''); setPassword('');
    setDragOver(false);
    if (field.current) field.current.value = '';
  };
  const selectFiles = (selection: FileList | null) => {
    setFiles(Array.from(selection ?? []));
    setLinks('');
    setPreview(undefined);
    setPassword('');
  };
  const withInput = async <T,>(consume: (input: AuthBackupInput) => Promise<T>) => {
    if (files.length > 64 || files.reduce((size, file) => size + file.size, 0) > MAX_AUTH_BACKUP_BYTES) throw new Error('请选择最多 64 张图片或一份备份，总计不超过 4 MiB。');
    if (google && files.length) {
      const images = await Promise.all(files.map(imageUrl));
      try { return await consume({ format, images }); } finally { images.fill(''); }
    }
    const raw = google ? new TextEncoder().encode(links.trim()) : new Uint8Array(await files[0]!.arrayBuffer());
    const bytes = Array.from(raw);
    try { return await consume({ format, bytes, password }); } finally { raw.fill(0); bytes.fill(0); }
  };
  const ready = files.length > 0 || (google && !!links.trim());
  const damaged = google && !!preview?.invalid;
  const fileInput = <label className="field">{google ? '迁移二维码图片' : '验证器备份文件'}<input
    ref={field} className="input" type="file" accept={descriptor.accept} multiple={google} disabled={busy}
    aria-describedby={google ? imageStatusId : undefined} onChange={event => selectFiles(event.currentTarget.files)} /></label>;
  return <>
    <form className="form" onSubmit={event => {
      event.preventDefault();
      if (!ready || busy) return;
      void work(async () => { setPreview(undefined); setPreview(await withInput(input => request<AuthBackupPreview>({ type: 'preview-auth-backup', ...input }))); });
    }}>
      <SelectField label="验证器" value={format} disabled={busy} onChange={value => { clear(); setFormat(value as AuthBackupFormat); }}>
        {AUTH_BACKUP_FORMATS.map(value => <option key={value} value={value}>{formats[value].label}</option>)}
      </SelectField>
      {google ? <div className="field auth-image-drop" role="group" aria-label="拖入迁移二维码"
        data-drag-over={dragOver && !busy ? '' : undefined}
        onDragOver={event => {
          if (!event.dataTransfer.types.includes('Files')) return;
          event.preventDefault();
          event.dataTransfer.dropEffect = busy ? 'none' : 'copy';
          setDragOver(!busy);
        }}
        onDragLeave={event => {
          if (event.relatedTarget instanceof Node && event.currentTarget.contains(event.relatedTarget)) return;
          setDragOver(false);
        }}
        onDrop={event => {
          if (!event.dataTransfer.types.includes('Files')) return;
          event.preventDefault();
          setDragOver(false);
          const selection = event.dataTransfer.files;
          if (busy || !selection.length) return;
          if (field.current) field.current.files = selection;
          selectFiles(selection);
        }}>
        {fileInput}
        <p id={imageStatusId} className="hint" role="status">
          {files.length ? `已选择 ${files.length} 张图片。` : '可将同一批的多张图片拖入文件框。'}
        </p>
      </div> : fileInput}
      {google && <AreaField label="或粘贴迁移 URI（每行一个）" value={links} disabled={busy} onChange={value => {
        setLinks(value); setFiles([]); setPreview(undefined); if (field.current) field.current.value = '';
      }} rows={3} />}
      {descriptor.password && <SecretField label="源文件密码（未加密时留空）" value={password} maxLength={4096} autoComplete="off" disabled={busy}
        onChange={value => { setPassword(value); setPreview(undefined); }} />}
      {descriptor.hint && <p className="hint">{descriptor.hint}</p>}
      {!preview && <button className="btn btn-primary" disabled={busy || !ready}>预览迁移内容</button>}
    </form>
    {preview && <section className="section">
      <h2>{preview.missingParts ? '二维码批次不完整' : damaged ? '二维码批次损坏' : `可导入 ${preview.ready} 个验证码`}</h2>
      {preview.missingParts > 0 && <p role="alert" className="banner banner-warn">缺少 {preview.missingParts} 张二维码。请选齐同一批的图片后重新预览。</p>}
      {damaged && <p role="alert" className="banner banner-warn">这批二维码有损坏的条目。请从原验证器重新导出。</p>}
      <p className="hint">重复记录 {preview.skipped} 条，无法读取 {preview.invalid} 条，不支持 {preview.unsupported} 条。{preview.repeatedParts ? `忽略重复图片 ${preview.repeatedParts} 张。` : ''}</p>
      {!!preview.unknownHotpCounters && <p className="banner banner-warn" role="alert">有 {preview.unknownHotpCounters} 个计数型验证码的计数无法核实，不会导入。请保留原验证器。</p>}
      <ul className="facts">{preview.sample.map((row, index) => <li className="fact" key={index}><div className="fact-text">
        <span className="fact-value">{row.title}</span><span className="fact-label">{row.account}</span>
      </div></li>)}</ul>
      <div className="actions">
        <button type="button" className="btn btn-primary" disabled={busy || !preview.ready || !!preview.missingParts || damaged} onClick={() => void work(async () => {
          const proof = await dialogs.proof();
          try {
            const count = await withInput(input => request<number>({ type: 'import-auth-backup', ...input, stamp: preview.stamp, proof }));
            clear(); await refresh(); notify(`已导入 ${count} 个验证码。`);
          } catch (error) { if (error instanceof Error && error.message.includes('重新预览')) setPreview(undefined); throw error; }
          finally { proof.secret = ''; }
        })}>确认导入</button>
        <button type="button" className="btn" disabled={busy} onClick={() => setPreview(undefined)}>返回</button>
      </div>
    </section>}
  </>;
}

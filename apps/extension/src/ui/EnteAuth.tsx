import { useEffect, useRef, useState } from 'react';
import { Download, FileUp } from 'lucide-react';
import { MAX_ENTE_BYTES, request, type EnteMerge, type EntePreview } from '../vault-messages';
import { Ico } from './components';
import { useDialogs } from './dialogs';
import { download } from './lib';
import { useOps } from './Main';

async function readFile<T>(file: File, consume: (bytes: number[]) => Promise<T>): Promise<T> {
  if (!file.size || file.size > MAX_ENTE_BYTES) throw new Error('请选择不超过 2 MiB 的 Ente Auth 文本文件。');
  const raw = new Uint8Array(await file.arrayBuffer());
  const bytes = Array.from(raw);
  try { return await consume(bytes); }
  finally { raw.fill(0); bytes.fill(0); }
}

const kindNames: Record<string, string> = { totp: '时间验证码', hotp: '计数验证码', steam: 'Steam Guard' };

export default function EnteAuth({ refresh }: { refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const dialogs = useDialogs();
  const [mode, setMode] = useState<'import' | 'export'>('import');
  const [file, setFile] = useState<File>();
  const [preview, setPreview] = useState<EntePreview>();
  const [merges, setMerges] = useState<EnteMerge[]>([]);
  const [riskAccepted, setRiskAccepted] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const summary = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (preview) summary.current?.focus(); }, [preview]);

  return <>
    <div className="chips" role="group" aria-label="验证器迁移操作">
      <button type="button" className="chip" disabled={busy} aria-pressed={mode === 'import'} onClick={() => setMode('import')}>导入验证码</button>
      <button type="button" className="chip" disabled={busy} aria-pressed={mode === 'export'} onClick={() => { setMode('export'); setRiskAccepted(false); }}>导出验证码</button>
    </div>
    {mode === 'import' ? <>
      <p className="lede">在 Ente Auth 中导出未加密文本，然后在这里预览。验证码可以单独保存，也可以由你勾选合并到已有登录项。</p>
      <div className="banner banner-warn"><p>文本包含生成验证码的密钥。请勿上传或分享；导入完成后，请妥善处理原文件。</p></div>
      <form className="form" onSubmit={event => {
        event.preventDefault();
        if (!file || busy) return;
        void work(async () => {
          setPreview(undefined); setMerges([]);
          setPreview(await readFile(file, bytes => request<EntePreview>({ type: 'preview-ente', bytes })));
        });
      }}>
        <label className="field">Ente Auth 文本文件<input ref={input} className="input" type="file" accept=".txt,text/plain" required disabled={busy}
          onChange={event => { setFile(event.target.files?.[0]); setPreview(undefined); setMerges([]); }} /></label>
        <p className="hint">支持时间验证码、HOTP 和 Steam Guard。每次最多 2 MiB、5,000 个验证码。</p>
        {!preview && <button className="btn btn-primary" disabled={busy || !file}><Ico of={FileUp} />预览验证码</button>}
      </form>
      {preview && <section className="section">
        <h2 ref={summary} tabIndex={-1}>可导入 {preview.ready} 个验证码</h2>
        <p className="hint">重复跳过 {preview.skipped} 个，无法读取 {preview.invalid} 个。已有验证码和计数器不会被覆盖。</p>
        {preview.invalid > 0 && <p className="hint">请保留原有验证器，检查未能读取的记录。加密文件需要先在 Ente Auth 中另行导出为文本。</p>}
        {preview.trashed > 0 && <p className="hint">其中 {preview.trashed} 个会保留在回收站，不会自动恢复。</p>}
        {preview.sample.length > 0 && <ul className="facts">
          {preview.sample.map((row, index) => <li className="fact" key={index}><div className="fact-text">
            <span className="fact-value">{row.title}</span><span className="fact-label">{row.account ? `${row.account} · ` : ''}{kindNames[row.kind]}</span>
          </div></li>)}
        </ul>}
        {preview.ready > preview.sample.length && <p className="hint">这里只预览前 {preview.sample.length} 个。</p>}
        {preview.suggestions.length > 0 && <fieldset>
          <legend>合并到已有登录项（可选）</legend>
          <p className="hint">网站和账号相符，且登录项还没有验证码。勾选后会保留原密码、备注和查看保护；未勾选的会单独保存。</p>
          {preview.suggestions.map(suggestion => <label className="check" key={suggestion.row}>
            <input type="checkbox" disabled={busy} checked={merges.some(merge => merge.row === suggestion.row)}
              onChange={event => setMerges(old => event.target.checked
                ? [...old, { row: suggestion.row, id: suggestion.id }] : old.filter(merge => merge.row !== suggestion.row))} />
            <span>{suggestion.title} · {suggestion.account}</span>
          </label>)}
        </fieldset>}
        {preview.ready > 0 && <p className="hint">将单独保存 {preview.ready - merges.length} 个验证码，合并到 {merges.length} 条登录凭证。</p>}
        <div className="actions">
          {preview.ready > 0 && <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void work(async () => {
            if (!file) return;
            const proof = await dialogs.proof();
            try {
              const count = await readFile(file, bytes => request<number>({ type: 'import-ente', bytes, stamp: preview.stamp, merges, proof }));
              setFile(undefined); setPreview(undefined); setMerges([]);
              if (input.current) input.current.value = '';
              await refresh(); notify(`已导入 ${count} 个验证码。`);
            } catch (error) {
              if (error instanceof Error && error.message.includes('重新预览')) { setPreview(undefined); setMerges([]); }
              throw error;
            } finally { proof.secret = ''; }
          })}>确认导入 {preview.ready} 个</button>}
          <button type="button" className="btn" disabled={busy} onClick={() => { setPreview(undefined); setMerges([]); }}>返回选择文件</button>
        </div>
      </section>}
    </> : <form className="form" onSubmit={event => {
      event.preventDefault();
      if (!riskAccepted || busy) return;
      void work(async () => {
        if (!await dialogs.confirm({ title: '导出未加密的验证码密钥？',
          body: '拿到这个文件的人可以生成你的验证码。文件包含回收站中的验证码、标签和备注，请只用于迁移，并在迁移后妥善处理。',
          confirmLabel: '验证主密码并导出', danger: true })) return;
        const proof = await dialogs.proof({ masterOnly: true });
        try {
          const text = await request<string>({ type: 'export-ente', proof, confirmPlaintext: true });
          download(`Vault-Ente-Auth-${new Date().toISOString().slice(0, 10)}.txt`, text, 'text/plain;charset=utf-8');
          setRiskAccepted(false); notify('已请求下载验证码文本，请检查浏览器的下载记录。');
        } finally { proof.secret = ''; }
      });
    }}>
      <p className="lede">导出为 Ente Auth 可读取的文本，保留验证码类型、计数器、置顶、标签、备注和回收站状态。</p>
      <div className="banner banner-warn"><p>这是未加密文件，包含生成验证码的完整密钥。如需备份整个密码库，请使用「备份与恢复」中的加密备份。</p></div>
      <label className="check"><input type="checkbox" checked={riskAccepted} disabled={busy} onChange={event => setRiskAccepted(event.target.checked)} />我理解文件未加密，仅用于迁移并会妥善保管</label>
      <button className="btn btn-primary" disabled={busy || !riskAccepted}><Ico of={Download} />导出 Ente Auth 文本</button>
    </form>}
  </>;
}

import { useEffect, useRef, useState } from 'react';
import { FileUp, TriangleAlert } from 'lucide-react';
import { MAX_BROWSER_CSV_BYTES, request, type BrowserCsvPreview } from '../vault-messages';
import { Ico } from './components';
import { useDialogs } from './dialogs';
import { useOps } from './Main';

async function readCsv<T>(file: File, action: (bytes: number[]) => Promise<T>): Promise<T> {
  if (!file.size || file.size > MAX_BROWSER_CSV_BYTES) throw new Error('请选择不超过 2 MiB 的 CSV 文件。');
  const buffer = new Uint8Array(await file.arrayBuffer());
  const bytes = Array.from(buffer);
  buffer.fill(0);
  try { return await action(bytes); }
  finally { bytes.fill(0); }
}

export default function BrowserCsv({ refresh }: { refresh(): Promise<void> }) {
  const { busy, work, notify } = useOps();
  const dialogs = useDialogs();
  const [file, setFile] = useState<File>();
  const [preview, setPreview] = useState<BrowserCsvPreview>();
  const input = useRef<HTMLInputElement>(null);
  const summary = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (preview) summary.current?.focus(); }, [preview]);

  return <>
    <p className="lede">选择浏览器导出的密码 CSV，先预览，再添加到本地密码库。已有凭证不会被覆盖。</p>
    <div className="banner banner-warn"><Ico of={TriangleAlert} /><p>CSV 里的密码没有加密。请勿上传或分享文件；导入后，请自行妥善处理原文件。</p></div>
    <form className="form" onSubmit={event => {
      event.preventDefault();
      if (!file || busy) return;
      void work(async () => {
        setPreview(undefined);
        setPreview(await readCsv(file, bytes => request<BrowserCsvPreview>({ type: 'preview-browser-csv', bytes })));
      });
    }}>
      <label className="field">浏览器密码文件<input ref={input} className="input" type="file" accept=".csv,text/csv" required disabled={busy}
        onChange={event => { setFile(event.target.files?.[0]); setPreview(undefined); }} /></label>
      <p className="hint">识别常见浏览器的 UTF-8 CSV（如 Edge、Chrome、Firefox 和 Safari）。每次最多 2 MiB、5,000 行。</p>
      {!preview && <button className="btn btn-primary" disabled={busy || !file}><Ico of={FileUp} />预览导入</button>}
    </form>
    {preview && <section className="section">
      <h2 ref={summary} tabIndex={-1}>可添加 {preview.ready} 条登录凭证</h2>
      <p className="hint">同站同账号跳过 {preview.skipped} 条，无法读取 {preview.invalid} 条。回收站里的凭证也不会被覆盖。</p>
      {preview.invalid > 0 && <p className="hint">请检查无法读取的行是否缺少密码、不是网页地址，或与表头列数不一致。</p>}
      {preview.ignoredOtp > 0 && <p className="hint">{preview.ignoredOtp} 行含验证码设置，CSV 导入不会带入这些设置。请保留原有验证方式。</p>}
      {preview.sample.length > 0 && <ul className="facts">
        {preview.sample.map((row, index) => <li className="fact" key={index}><div className="fact-text">
          <span className="fact-value">{row.title}</span><span className="fact-label">{row.site}{row.username ? ` · ${row.username}` : ''}</span>
        </div></li>)}
      </ul>}
      {preview.ready > preview.sample.length && <p className="hint">这里只预览前 {preview.sample.length} 条。</p>}
      <div className="actions">
        {preview.ready > 0 && <button type="button" className="btn btn-primary" disabled={busy} onClick={() => {
          if (!file) return;
          void work(async () => {
            const proof = await dialogs.proof();
            try {
              const count = await readCsv(file, bytes => request<number>({ type: 'import-browser-csv', bytes, stamp: preview.stamp, proof }));
              setFile(undefined);
              setPreview(undefined);
              if (input.current) input.current.value = '';
              await refresh();
              notify(`已导入 ${count} 条登录凭证。`);
            } catch (error) {
              if (error instanceof Error && error.message.includes('重新预览')) setPreview(undefined);
              throw error;
            } finally { proof.secret = ''; }
          });
        }}>确认导入 {preview.ready} 条</button>}
        <button type="button" className="btn" disabled={busy} onClick={() => setPreview(undefined)}>返回选择文件</button>
      </div>
    </section>}
  </>;
}

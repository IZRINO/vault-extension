import { useState } from 'react';
import { Dices } from 'lucide-react';
import { request } from '../vault-messages';
import { CopyAction, Ico, SelectField, SwitchRow, TextField } from './components';
import { useOps } from './Main';

export default function Generator() {
  const { busy, work, copy } = useOps();
  const [mode, setMode] = useState('password');
  const [length, setLength] = useState('24');
  const [words, setWords] = useState('6');
  const [symbols, setSymbols] = useState(true);
  const [value, setValue] = useState('');
  return <form className="view" onSubmit={event => { event.preventDefault(); void work(async () => {
    setValue(await request<string>({ type: mode === 'password' ? 'generate-password' : 'generate-passphrase',
      optionsJson: JSON.stringify(mode === 'password' ? { length: Number(length), symbols, minSymbols: symbols ? 1 : 0 }
        : { wordCount: Number(words), separator: '-', includeNumber: false }) }));
  }); }}>
    <h1 className="page-title">密码生成器</h1><p className="lede">每个网站用一个新密码。生成过程在本机完成。</p>
    <SelectField label="类型" value={mode} onChange={next => { setMode(next); setValue(''); }}><option value="password">随机字符</option><option value="passphrase">单词口令</option></SelectField>
    {mode === 'password' ? <>
      <TextField label="字符数" type="number" min={8} max={128} step={1} required value={length} onChange={setLength} />
      <SwitchRow label="包含符号" checked={symbols} onChange={setSymbols} hint="保留大小写字母和数字，排除 0、O、1、l、I 等易混淆字符。" />
    </> : <TextField label="单词数" type="number" min={3} max={12} step={1} required value={words} onChange={setWords} hint="从 EFF 7776 词表中随机选取，以连字符分隔。" />}
    <button className="btn btn-primary" disabled={busy}><Ico of={Dices} />生成</button>
    {value ? <><output className="generated" aria-live="polite">{value}</output><CopyAction onCopy={() => copy(value)} disabled={busy}>复制密码</CopyAction>
      <p className="hint">约 30 秒后自动清理剪贴板；期间复制了其他内容则会保留。</p></> : <p className="hint">点“生成”后，密码会显示在这里。复制前可以再次生成。</p>}
  </form>;
}

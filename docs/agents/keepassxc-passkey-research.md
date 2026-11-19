# T28：KeePassXC 的 KDBX Passkey

调查基于 [KeePassXC 2.8.0](https://github.com/keepassxreboot/keepassxc/releases/tag/2.8.0) 的固定提交 `1c2f23ef5914c0f442a00533def1689857afb5a7`；本仓库映射以调研起点 `7c8634b` 为准。范围是合成凭证的离线导入，不涉及第三方账号。

## 文件里的字段

Passkey 存在同一条目的 `<String><Key>…</Key><Value>…</Value></String>` 属性中，不是附件或数据库 `CustomData`。[字段定义][attributes]、[浏览器写入][store]与 [KDBX XML 写入][xml-write]相互印证：

| 属性（`KPEX_PASSKEY_` 前缀） | KeePassXC 2.8.0 的内容 |
| --- | --- |
| `CREDENTIAL_ID` | 浏览器新建为 32 个随机字节的无 padding base64url；受保护。不要把 32 字节限制用于迁入的外部凭证。[生成][random-id] · [编码][base64] |
| `USER_HANDLE` | 保留注册请求的 `user.id` 字符串，用 base64url 解码检查；受保护。[取值][registration] · [校验][creation-options] |
| `PRIVATE_KEY_PEM` | PKCS#8，标签为 `BEGIN PRIVATE KEY` / `END PRIVATE KEY`；受保护。上游能生成 ES256、Ed25519 和 RS256。[算法与编码][pkcs8] |
| `RELYING_PARTY`、`USERNAME` | 分别是 RP ID 与注册用户的 `name`，不是登录条目的 URL 或用户名替代字段。[取值][registration] |
| `FLAG_BE`、`FLAG_BS` | 浏览器新建均写 `1`；读取时值 `1` 或 `true` 表示置位，字段缺失时均默认 `true`。认证签名计数恒为 `0`。[认证读取][flags] · [默认值][defaults] · [计数][counter] |

## 与本项目的差异

- [现有导入器](../../crates/vault-importers/src/keepass_kdbx.rs) 的核心字段名正确；[PKCS#8 映射](../../crates/vault-passkeys/src/protocol.rs) 仅支持 ES256 和 Ed25519。RS256 应明确跳过。按 [ADR 0003](../adr/0003-passkey-evidence.md)，源 `BS` 不能给目标库置 `BS=1`，源 `BE` 单独处理。缺失 `BE` 和存在但为空的字段在上游有区别。
- 上游 [Bitwarden 导入实现][bitwarden-code]和[测试][bitwarden-test]把 PKCS#8 PEM 的首标签、Base64 正文、尾标签**直接连在一行**，写入同一个 `PRIVATE_KEY_PEM`。调研起点的 [`secret_bytes`](../../crates/vault-importers/src/portable.rs) 按行丢弃标签，会把这种 PEM 整行删除。兼容性验证应覆盖单行和原生换行两种。
- 官方为 StrongBox 兼容而优先读取 `KPEX_PASSKEY_GENERATED_USER_ID`（凭据 ID）和 `KPXC_PASSKEY_USERNAME`（显示账号）。调研起点未采用这些优先级；后者也不在原有的 `KPEX_PASSKEY` 自定义字段排除范围内。这是兼容格式差异，不是 KeePassXC 原生写入差异。[兼容字段读取][aliases]
- KeePassXC 的 KDBX4 AES-KDF **写出** `c9d9f39a628a4460bf740d08c18a4fea` 以兼容 KeePass 等应用，**读取**还接受 `7c02bb8279a74ac0927d114a00648238`，将前者归一为后者。项目依赖 `keepass 0.17.0` 可解析两种，调研起点的预检仅接受前者；如补齐，应保持同一轮数预算。[写出][aes-write] · [读取][aes-read] · [Rust 依赖源码][rust-config]

## 官方夹具与可复现生成

找到了「带 Passkey、口令有出处」的官方公开加密夹具：[demo.kdbx][demo]。下载的文件头为 4.1，SHA-256 为 `8d3fb92bd71c0f639641916a6c3dcab244b238656cf3052d9142f8991b8d0f85`。用 Authenticode 验签有效的 KeePassXC CLI 2.8.0 和[文档口令][demo-readme]运行 `db-info`，确认 AES256 加密、Argon2d（6 次、131,072 KiB）、1 枚 Passkey、1 个 TOTP。其 128 MiB KDF 内存超过项目的 96 MiB 预算，可作超限反例，不能作导入成功或签名验收正例。未导出明文或使用其私钥。

查阅了官方 [2.8.0 完整文件树][tree-280]、[2.7.10 文件树][tree-2710]、[Passkey 单测][passkey-tests]和[导入测试][bitwarden-test]，未确认其他满足口令来源及项目预算的 Passkey KDBX。上游的 `bitwarden_passkey_export.json` 用于在内存中测试映射，不是 KDBX。

若需另取官方 3.1 普通样本，[`NewDatabase.kdbx`][demo-31] 的文件头为 3.1，SHA-256 为 `5fdee9fff96df5ce58c331a56f4b253ad32e864dba1a86b98df14659283daa29`，来源 CLI 测试[加载该文件][demo-31-setup]并[输入其合成口令][demo-31-password]。这不构成 Passkey 证据。

不操作第三方账号也能用官方 CLI 写出等效加密夹具：

1. 参考[官方 XML 测试库][xml-fixture]，用本机新生成的测试 RP、P-256 密钥和合成用户数据准备 XML。`CREDENTIAL_ID`、`USER_HANDLE`、`PRIVATE_KEY_PEM` 的明文 `<Value>` 加 `ProtectInMemory="True"`，不可把明文标成 `Protected="True"`。KeePassXC 读入后，保存时才为这些属性输出内层流加密与 `Protected="True"`。[XML 读入][xml-read] · [XML 写出][xml-write]
2. 对 4.1 样本，在 **组**上放一个非空 `<Tags>fixture</Tags>`；普通 `KPEX_PASSKEY_*` 字符串本身不强制 4.x。CLI 先用默认 AES-KDF（1,000,000 轮），写库时按组标签升为 KDBX 4.1 和 AES-KDBX4。`-t` 是毫秒校准，不是迭代数，夹具无需传入。[读取组标签][group-tags] · [版本选择][format-choice] · [切换 KDF][kdf-upgrade] · [默认轮数][rounds] · [默认 KDF][default-kdf]
3. 以两行相同的显式合成口令经 stdin 调用 `keepassxc-cli import --set-password <input.xml> <new.kdbx>`；命令不覆盖已有输出。重新用一行口令运行 `keepassxc-cli db-info <new.kdbx>`，检查 `Number of passkeys`，另核对文件头版本。只在内存里核对受保护字段与历史，不把解密后的 XML 留在项目、日志或工单。[命令实现][cli-import] · [stdin 及回读测试][cli-test] · [统计输出][cli-info]
4. `db-info` 只证明 KeePassXC 将条目识别为 Passkey。T28 仍需将同一独立测试公钥与凭据 ID 预置在本地 RP，导入 KDBX 后让本地服务端对新挑战的断言验签。CLI 等效夹具证明真实官方 KDBX writer 的兼容性，不等于亲自运行过 KeePassXC-Browser 注册流程。

## 当前回归入口

用 [KeePassXC 2.8.0 官方 Windows x64 便携包][release]（SHA-256 `48ff4f088e9ce70e241da1270e5081528dba77c38b17dae4aa6690ffc50fc828`，本机 CLI 的 Authenticode 状态为 `Valid`）。无需安装，测试不会打开现有 KeePass 库。先构建本项目：

- `node scripts/test-kdbx.cjs --keepassxc-cli <CLI绝对路径>`：每次生成新测试密钥，验证 4.1 加密库的分组、密码历史、TOTP、Base64URL 句柄及原钥验签。包含换行和单行 PKCS#8、StrongBox 别名、ES256/Ed25519；验证错密、截断、预览/重复零写及不采信源 `BS`。
- `VAULT_KEEPASSXC_CLI` 指向同一 CLI、`VAULT_EXTENSION_PATH` 指向生产包的解压目录，再运行 `node scripts/test-passkeys.cjs`：实际扩展预览并凭主密码确认导入，Edge 和 Helium 通过 WebAuthn API 请求断言。回环 RP 签发单次挑战，测试端用源公钥核对签名、RP、挑战和凭证 ID。这不访问第三方 RP，也不以它代签实体认证器。

[release]: https://github.com/keepassxreboot/keepassxc/releases/tag/2.8.0
[attributes]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/EntryAttributes.cpp#L46-L59
[store]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserService.cpp#L834-L874
[registration]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserService.cpp#L653-L658
[random-id]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserPasskeys.cpp#L66-L82
[base64]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserMessageBuilder.cpp#L384-L434
[creation-options]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/PasskeyUtils.cpp#L34-L49
[pkcs8]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserPasskeys.cpp#L239-L332
[flags]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserService.cpp#L773-L790
[defaults]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserPasskeys.h#L28-L31
[counter]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserPasskeys.cpp#L213-L229
[bitwarden-code]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/BitwardenReader.cpp#L86-L116
[bitwarden-test]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/tests/TestImports.cpp#L298-L329
[aliases]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/PasskeyUtils.cpp#L383-L405
[aes-write]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/crypto/kdf/AesKdf.cpp#L51-L59
[aes-read]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KeePass2.cpp#L70-L91
[rust-config]: https://docs.rs/crate/keepass/0.17.0/source/src/config.rs
[tree-280]: https://api.github.com/repos/keepassxreboot/keepassxc/git/trees/1c2f23ef5914c0f442a00533def1689857afb5a7?recursive=1
[tree-2710]: https://api.github.com/repos/keepassxreboot/keepassxc/git/trees/b342be457153aa098c8bbce0f8b0fd3baa8c158f?recursive=1
[passkey-tests]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/tests/TestPasskeys.cpp
[demo]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/share/demo.kdbx
[demo-readme]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/share/demo_readme.md#L1-L3
[demo-31]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/tests/data/NewDatabase.kdbx
[demo-31-setup]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/tests/TestCli.cpp#L90-L91
[demo-31-password]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/tests/TestCli.cpp#L286-L305
[xml-fixture]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/tests/data/NewDatabase.xml
[xml-read]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlReader.cpp#L837-L871
[xml-write]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlWriter.cpp#L416-L446
[group-tags]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlReader.cpp#L519-L525
[format-choice]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KeePass2Writer.cpp#L52-L76
[kdf-upgrade]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KeePass2Writer.cpp#L117-L140
[rounds]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/crypto/kdf/Kdf.h#L26
[default-kdf]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/Database.h#L229-L236
[cli-import]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/cli/Import.cpp#L39-L87
[cli-test]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/tests/TestCli.cpp#L1400-L1427
[cli-info]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/cli/DatabaseInfo.cpp#L54-L74

# T28 后续：KeePass / KeePassXC 明文 XML 与 CSV

范围：[架构 v1.4 §4.5.1](../../密码管理器浏览器插件-技术架构与选型文档.md#451-支持导入的软件与格式全景表)列出 XML/CSV；[T28](../development-tickets.md#t28-从-keepass-加密库迁入可用凭证--28)本身验收的是加密 KDBX，两种明文格式是[单独的后续候选](../development-tickets.md#架构与工单范围的差异)。不能把该表的一整行能力套给每一种文件。本文只核实 KeePass 2.62 和 KeePassXC 2.8.0，不推定 Strongbox、KeePassDX、KeePass 1.x XML 或插件导出的兼容性。

- **KeePass 2.62**：查阅 [2.62 发布页][kp-release] 与 [官方源码包][kp-src]，源码包 SHA-256 `9c07b0539a013ee5e22b26fd806e472c1858bc2f3f7b3b4406f4404774263ac0` 与[官网][kp-integrity]一致。下文给出包内路径与方法。
- **KeePassXC 2.8.0**：查阅 [2.8.0 发布版][xc-release]的固定提交 `1c2f23ef5914c0f442a00533def1689857afb5a7`。另核对 2.7.10 的[同一 CSV writer][xc-csv-old]，与 2.8.0 文件逐字节一致；运行样本只用 2.8.0。

## 明文 XML

两家同用 **`<KeePassFile><Meta>…</Meta><Root><Group>…`** 结构，不是 KeePass 1.x XML。KeePass 2.62 的 `KeePass/DataExchange/Formats/KeePassXml2.cs` → `KdbxFile.Save(..., KdbxFormat.PlainXml, ...)`（[官方源码包][kp-src]）；KeePassXC CLI `export -f xml` 经 [Export][xc-cli]、[Database::extract][xc-extract]到 [KdbxWriter::extractDatabase][xc-xml-extract]，显式关闭内层加密。

| 数据 | 写出和迁移语义 |
| --- | --- |
| 条目、分组、回收站 | `<Group>` 可递归嵌套，`<Name>` 是单级名称；`UUID` 是 16 字节标准 Base64，非十六进制。`Meta/RecycleBinUUID` 指向组而非组名；`Root/DeletedObjects` 是删除记录，不是可恢复的登录。`<Entry>` 下 `<String><Key>…</Key><Value>…</Value></String>` 承载 `Title`、`UserName`、`Password`、`URL`、`Notes` 和自定义字段。标签是独立的 `<Tags>`，不要用它替代组层级；KeePassXC 条目写出用逗号，读入还认分号和制表符。[组、时间、删除记录][xc-xml-group] · [回收站元数据][xc-xml-meta] · [标签][xc-tags] |
| 历史、时间 | 当前条目内 `<History><Entry>…</Entry></History>` 装历史快照；快照与当前条目共用 UUID，历史含自己的字段和 `Times/LastModificationTime`，不应另建登录或恢复历史 OTP/Passkey。两种时间格式都实际出现：KeePass 2.62 `PlainXml` 与 KeePassXC 导出自 3.1 库是 ISO 8601 UTC；KeePassXC 导出自 4.x 库按其格式版本用**标准 Base64 的 8 字节小端秒数**，起点是 `0001-01-01T00:00:00Z`，不是 Unix epoch。按字段解码并检查范围。[KeePass 源码包][kp-src] `KeePassLib/Serialization/KdbxFile.Write.cs`（`WriteEntry`、`WriteObject(string, DateTime)`） · [KeePassXC 历史][xc-xml-history] · [历史 UUID 检查][xc-xml-read-history] · [时间编码][xc-xml-date] |
| 值与保护标记 | `ProtectInMemory="True"` 只保留内存保护意图；内容仍是明文，读取无需源库口令。`Protected="True"` 是加密 KDBX 内层流的标记，不能把这种值当明文、把 Base64 当作“解密”或伪造一层 KDBX。XML 实体由解析器解码，密码与备注不应被任意 trim。[KeePass 源码包][kp-src] `KdbxFile.Write.cs`（`WriteObject(KeyValuePair<string, ProtectedString>, bool)`） · [KeePassXC 写值][xc-xml-values] · [明文风险][xc-guide] |
| OTP | KeePassXC 默认写条目属性 `otp`（`otpauth://totp/…`）。兼容来源另有把 KeeOtp 的 `key`/`size`/`step`/`otpHashMode` 写入 `otp`，以及拆开的 `TOTP Seed`、`TOTP Settings`（`步长;位数` 或 Steam 标记）。KeePass 2.62 原生则用 `TimeOtp-Secret` 或 `-Hex`/`-Base32`/`-Base64` 后缀，配 `TimeOtp-Length`/`Period`/`Algorithm`（缺省 6 位、30 秒、`HMAC-SHA-1`）；HOTP 用 `HmacOtp-Secret*` 和 `HmacOtp-Counter`。这是自定义字符串，不是 `<OTP>` 元素。KeePassXC 同时认识 KeePass 的 Base32 TOTP 表示；不能推断它能转出 KeePass 原生 HOTP。[KeePass OTP][kp-otp] · [KeePassXC 属性和优先序][xc-totp-entry] · [格式定义][xc-totp-fields] · [配置解析与写出][xc-totp] |
| Passkey | KeePassXC 的 `KPEX_PASSKEY_*` 存在**当前条目的 `<String>` 属性**中。`PRIVATE_KEY_PEM` 是 PKCS#8；`CREDENTIAL_ID`、`USER_HANDLE` 是 base64url；`RELYING_PARTY` 是 RP ID，`USERNAME` 是 Passkey 用户名。兼容别名、标志和算法详见[已有 KDBX 调研](keepassxc-passkey-research.md#文件里的字段)。KeePass 2.62 可照写这些自定义字符串（本次跨工具实测），不等于它原生生成、使用或验证 KeePassXC Passkey。迁移时不采信源 `BS`、不把私钥降级成自定义字段；只有可用算法并通过本地 RP 验签的场景才可签收。[KeePassXC 字段写入][xc-passkeys] · [ADR 0003](../adr/0003-passkey-evidence.md) |

附件、自定义图标、Auto-Type 不是本项目候选迁移能力。KeePassXC [指南][xc-guide]不承诺 XML 附件；源码中 3.x XML 可以写 `<Meta/Binaries>`，4.x 明文路径无对应的 KDBX 内层二进制池。不要用附件引用反推存在内容；也不要为忽略附件而解包它们。[二进制池和引用][xc-xml-binaries] · [明文路径][xc-xml-extract]

## 两个不同的 CSV 方言

| 写出者 | 精确表头（按列顺序） | 转义及能迁移什么 |
| --- | --- | --- |
| KeePass 2.62 的 **`KeePass CSV (1.x)`** | `Account, Login Name, Password, Web Site, Comments` | 五列依次是标题、用户名、密码、URL、备注；UTF-8，每格双引号，单个引号写 `\"`、反斜杠写 `\\`，行分隔 CRLF，字段内换行是字面换行，不是 `\n`。遍历各组但不写组名；无分组、OTP、Passkey、历史、时间和附件。该名称虽带 `1.x`，在 KeePass **2.62** 实际可导出；`GenericCsv` 是导入器，不是另一种原生导出。见[官方 CSV 说明][kp-csv]及[源码包][kp-src] `KeePass/DataExchange/Formats/KeePassCsv1.cs`（`Export`、`WriteCsvString`）、`GenericCsv.cs`（`SupportsExport`）。 |
| KeePassXC 2.8.0 **CSV** | `Group, Title, Username, Password, URL, Notes, TOTP, Icon, Last Modified, Created` | UTF-8，每格双引号，双引号写 `""`，反斜杠无特殊转义。writer 本身用 LF，本机 Windows CLI 输出里记录和备注换行都经 CRLF。`Group` 是包含根组的 `/` 拼接路径，不转义名称内的 `/`，不能恢复无歧义的组树、空组、组 UUID 或回收站身份；实测回收站条目也作为普通行写出。`TOTP` 是可复用的 `otpauth://totp/…` 配置（包含种子，不是当期码），由 `totpSettingsString()` 强制转成 URI；`Last Modified`、`Created` 为 ISO 时间，`Icon` 只是编号。无 Passkey、历史、通用自定义字段、标签、附件或 Auto-Type。[CSV writer][xc-csv] · [TOTP 配置写出][xc-totp-csv] · [指南][xc-guide] |

不要从 CSV 的备注猜测 OTP 或 Passkey，不要从组名猜测回收站。尤其不要用表格软件打开真实明文来识别列；内嵌公式按文本处理。只需迁移基本登录时可用 CSV；想保留历史、明确的回收站状态与实际存在的 Passkey，应优先用 KDBX。

## 本机合成夹具：已验证 5 份原生输出

Windows 上运行 [KeePassXC 2.8.0 官方便携 CLI][xc-release]和 [KeePass/KPScript 2.62][kp-script-download]，本机两家可执行文件的 Authenticode 均为 `Valid`。KeePass 官方便携包的 SHA-256 `49b008e4ca9e9db9cb22e1173ec0f7676235b5309d7b47213cf81010cd1bbeed` 与[发布方][kp-integrity]一致。

1. 参考仓库 [`scripts/test-kdbx.cjs`](../../scripts/test-kdbx.cjs) 的合成 XML 生成方式：使用 `fixture.invalid`、临时生成的 P-256 PKCS#8、假 OTP、两级组、回收站、历史和 Unicode 多行备注。调用 `keepassxc-cli import --set-password <synthetic.xml> <fixture.kdbx>`，从 stdin 送两行合成口令。本次非空**组**标签的样本写出 4.1；去掉组标签的同类样本是 3.1，均查了文件头。
2. 对 4.1 库各调用 `keepassxc-cli export --quiet --format xml|csv <fixture.kdbx>`（`xml`、`csv` 分别运行），以原始字节捕获 stdout；对 3.1 库额外导出 XML 验证 ISO 时间。避免在 PowerShell 5.1 用 `>` 重编码。KPScript 对同一 4.1 库分别运行 `-c:Export <fixture.kdbx> -Format:<格式名> -OutFile:<output>`，格式参数作为完整单个 argv 传入。[KeePassXC CLI][xc-cli] · [KPScript 命令][kp-script]。本次 `-pw` 只传明确的合成口令；[文档][kp-script]也支持从 stdin 提示读密钥，不能把真实口令放在命令行。
3. 对三份 XML 实查分组、回收站 UUID、历史与当前 UUID、时间解码、保护标记，核对密码、备注、OTP、PEM 原值；对两份 CSV 实查无 BOM 的 UTF-8、表头、引号、反斜杠、跨行备注，以及“谁有 OTP/分组、谁不含历史或私钥”。临时夹具已清理，没有打开真实库，也没把导出内容或生成的私钥写入仓库或输出日志。**只证实源工具写出与载荷，不是 Vault 已导入、浏览器原生注册或 RP 验签的证据。**

## 对 Vault 的最小接入建议（未实施）

- **共用映射、不共用容器解析。** 保留 [KDBX 的 KDF 与头部检查](../../crates/vault-importers/src/keepass_kdbx.rs)，抽出“限定条目字段、路径、历史、OTP 与 Passkey → `Batch`”供 XML 使用，沿用 `SecretJson`、`secret_bytes`/`Passkey::from_pkcs8`、`add_record`。[`keepass 0.17.0`][rust-keepass] 的 `format::xml_db::parse_xml` 在 crate 私有模块内，`Database::get_xml` 是从加密容器取 XML，不是明文读入 API。不要做假 KDBX 包装。
- **独立的明文入口。** XML 限定 `KeePassFile` 路径结构与 UTF-8，对文档字节、嵌套、总事件/组/条目数、字段与历史设置上限；拒绝 DTD、外部实体、未知实体、敏感键重复、`Protected=True` 等歧义，不解析附件内容或执行 Auto-Type/占位符。只在 `<History>` 路径取历史密码；转换已知 OTP 编码及算法再交给 `vault_otp::parse`（如把 KeePassXC 的 `encoder=steam` 归一成 Steam 模式）。未知或冲突的设置计数告警而不进可填充字段，只在有已知计数时启用 HOTP。CSV 用完整表头辨别方言；KeePassXC 可复用 [现有 CSV 分词器](../../crates/vault-importers/src/lib.rs)，KeePass 五列反斜杠转义单独处理，不放宽其他 CSV。保留现有 CSV/Portable 的 2 MiB/16 MiB 与每批 5,000 行预算；限额要覆盖无效行与历史，不能只数成功记录。
- **复用安全提交路径。** 沿用 [`portable` 预览、去重与封存](../../crates/vault-importers/src/portable.rs)及受信 Worker，预览不返回密码、种子、私钥或历史；提交继续要求目标库主密码。源 XML 的 UUID 不是授权，不能仅凭 UUID 或源自定义字段覆盖目标或为现有条目追加 Passkey；过滤内部迁移标识和保留前缀，按产品策略决定同一 XML/KDBX 的跨格式去重。CSV 没有 UUID；测试重复导入零写、不同组同内容的碰撞及无 URL/无密码但有有效 OTP 的条目，不照搬通用登录 CSV 的过滤。验收再加损坏、超限、重复字段、历史不外漏、算法不支持，以及同源合成 Passkey 导入后的回环 RP 验签；不要将 CSV 的缺列视为导入器可补救的丢失。

[kp-release]: https://keepass.info/news/n261104_2.62.html
[kp-src]: https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.62/KeePass-2.62-Source.zip/download
[kp-integrity]: https://keepass.info/integrity.html#i_KeePass_2_62
[kp-csv]: https://keepass.info/help/base/importexport.html#csv
[kp-otp]: https://keepass.info/help/base/placeholders.html#otp
[kp-script-download]: https://keepass.info/plugins.html#kpscript
[kp-script]: https://keepass.info/help/v2_dev/scr_sc_index.html#export
[xc-release]: https://github.com/keepassxreboot/keepassxc/releases/tag/2.8.0
[xc-guide]: https://keepassxc.org/docs/KeePassXC_UserGuide#_exporting_databases
[xc-cli]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/cli/Export.cpp#L28-L65
[xc-extract]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/Database.cpp#L511-L523
[xc-xml-extract]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxWriter.cpp#L69-L78
[xc-xml-meta]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlWriter.cpp#L153-L169
[xc-xml-group]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlWriter.cpp#L294-L386
[xc-xml-values]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlWriter.cpp#L390-L453
[xc-xml-history]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlWriter.cpp#L512-L521
[xc-xml-read-history]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlReader.cpp#L815-L825
[xc-xml-date]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlWriter.cpp#L547-L571
[xc-xml-binaries]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/KdbxXmlWriter.cpp#L217-L261
[xc-tags]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/Entry.cpp#L717-L740
[xc-csv]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/format/CsvExporter.cpp
[xc-csv-old]: https://github.com/keepassxreboot/keepassxc/blob/b342be457153aa098c8bbce0f8b0fd3baa8c158f/src/format/CsvExporter.cpp
[xc-totp-entry]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/Entry.cpp#L609-L646
[xc-totp-fields]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/Totp.h#L63-L78
[xc-totp]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/Totp.cpp#L85-L210
[xc-totp-csv]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/core/Entry.cpp#L654-L661
[xc-passkeys]: https://github.com/keepassxreboot/keepassxc/blob/1c2f23ef5914c0f442a00533def1689857afb5a7/src/browser/BrowserService.cpp#L834-L874
[rust-keepass]: https://docs.rs/crate/keepass/0.17.0/source/src/lib.rs

# 剩余密码导入格式：原生导出与夹具依据

2026-11-20 核对[架构 v1.4 §4.5.1](../../密码管理器浏览器插件-技术架构与选型文档.md#451-支持导入的软件与格式全景表)及 [#29](https://github.com/IZRINO/vault-extension/issues/29)、[#30](https://github.com/IZRINO/vault-extension/issues/30)、[#35](https://github.com/IZRINO/vault-extension/issues/35) 的延伸范围。下文区分原厂文档、原厂写入器和接收端的兼容夹具。后者能证明一种可测试的布局，不等于原厂所有平台仍生成该布局。本次未用这些商业应用或用户实际密码库做导出。

本项目基线 `151e4fc` 的[登录 CSV 解析器](../../crates/vault-importers/src/migration_csv.rs)识别 Dashlane、NordPass、LastPass 和无表头 Enpass；其余可手工指定列，但要求每行等宽，且网站和密码都非空。底层读法有 UTF-8（含 BOM）、标准双引号与多行支持，以及 2 MiB、5,000 条、64 列上限。[预览路径](../../apps/extension/src/vault-controller.ts#L984-L1033)按登录条目校验网址，不能只靠新增表头映射就导入非登录类型。[原厂归档路径](../../crates/vault-importers/src/vendor_archives.rs)已处理 1PUX v3 和 Proton 明文 JSON/ZIP，没有为这两家做专用 CSV；现有 ZIP/Passkey 测试见[迁移夹具笔记](portable-migration-fixtures.md)。

当前实现增加[类型感知 CSV](../../crates/vault-importers/src/typed_csv.rs)、[Proton PGP ZIP](../../crates/vault-importers/src/proton_pgp.rs)和[Kaspersky 打印 TXT](../../crates/vault-importers/src/kaspersky.rs)，复用本地预览、去重和二次验证；安全备注不作为登录或 API 令牌自动填充。用生产导入 WASM 读过固定提交的公开夹具：

| 文件 | SHA-256 | 结果 |
| --- | --- | --- |
| `roboform.csv` | `c64fb42312fbbb991089b8a132568a769ba60f8b2af5cd0ab57c4fc09392b3df` | 读到 16 条，0 条无效；报告未迁尾字段和样本中的无效 OTP |
| `protonpass.csv` | `2004f2c22c701ae7ece1af0b661c979d44c76ab0177ccd8028c56a0512c59024` | 读到 4 条，0 条无效；别名及无效 OTP 不启用 |
| `kaspersky.txt` | `602274aff1f1b2ffc7205b8d0ddea9a7750da36ad9ff0cf5d998ae322e17e0d0` | 预览 8 条，0 条无效或不支持，预览不写快照 |

浏览器密码入口识别 `url` 或 `origin`（不区分大小写），两列同时出现则报歧义，仍保留备注；不把这项表头兼容测试记作 Opera 原生导出验证。

## 1Password：限定表头的桌面 CSV

- [1Password 官方导出说明][1p-export]确认 8 的 Windows、macOS、Linux 桌面 CSV 仅导出 Login 和 Password 项。字段清单是标题、网站、用户名、密码、一次性密码、收藏状态、归档状态、标签、备注；没有安全问题、自定义字段（含 2FA 备用码）、关联项目和关联应用。这里的 OTP 列不是备用码。支付卡、身份/API 凭证和 Passkey 不在此 CSV 中。桌面 1PUX 也不导出 Passkey；需要在支持的 iOS/Android 源端走凭证交换，不以 CSV 或兼容 1PUX 夹具替代手机实测。
- 官方帮助列的是字段名称，不是原始列名、布尔与标签编码规范。未找到 1Password 自己发布的 8 代字节级 CSV 样本。帮助还列了部分旧版桌面的 CSV 导出；[Bitwarden 的旧 macOS/Windows 接收夹具][1p-legacy]中有 `Title/Type/URL`、`UUID/TITLE/URL/URLS` 等不同布局和更多种类，不应用它们给 8 代立指纹，也不把旧版列为本次验收。
- 自动识别限定为 `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes` 一类表头，保留无网址的 Password 项、有效 OTP、收藏和标签。源归档状态留作惰性字段，不进回收站，也不自动填充。此表头只有合成回归，没有 8 代原生导出或本地化表头的验证；不匹配的布局在通用 CSV 中可手工映射登录字段。

## Proton Pass：CSV 和 PGP ZIP 分开验收

### 明文 CSV

[原厂 Web/扩展界面][proton-form]提供 CSV、ZIP、PGP 三种选项；[导出流程][proton-saga]实际写出独立 `.csv`，明文 ZIP 内才有 `data.json`，独立 JSON 虽是本项目可读输入，却不是该版 Web 导出选项。用于定位源码和测试的版本为 Proton WebClients `e7b57b816903d01d8d6d7c8f7dd56c2deb60a643`，不是宣称所有客户端的最低构建号。

[该提交的 CSV 写入器][proton-csv]依次写：

```csv
type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault
```

- `login` 的 `username` 和 `email` 独立；无 `email` 列的旧布局仍能导入，Proton [读取器][proton-csv-reader]把旧 `username` 当作账号邮箱槽。`totp` 是 `totpUri`，两个时间列是 Unix 秒，`vault` 是库名称。`url` 只含默认模式网址，按 `, ` 拼接。新 `autofillUrls` 是 `{url,mode}` 数组；[官方往返测试][proton-csv-test]覆盖 Default、Exact、Never。必须保留已验证的匹配限制，或保留为不可填充数据并提示；不能把 Exact/Never 降成默认可填充。新结构列损坏也不应静默扩大匹配范围。
- Vault 导入登录（独立邮箱保留为隐藏字段）、安全备注、支付卡和身份。`alias` 不可迁为可管理邮件别名，计入未支持；CSV 没有 Passkey、附加字段、附件或 SSH 私钥。`Default` 沿用本库站点匹配，`Exact` 按同协议、主机和端口处理，`Never` 优先于条目中的正向规则；不可识别的模式不作为正向规则。新结构列错误、超限或禁填网址无效时不会回退到旧的 `url` 列。
- [官方兼容夹具目录][proton-mocks]可直接提供无 `vault`、有 `vault` 但无 `email`、有 `email` 三档历史输入。`protonpass-old-before-vault.csv` 的表头为 `type,name,url,username,password,note,totp,createTime,modifyTime`；`protonpass-old-before-email-username.csv` 在其末尾加 `vault`；`protonpass.csv` 在 `username` 前加 `email`。三份都无 `autofillUrls`，该列用上面的原厂生成器测试补齐。用于锁定夹具的 Git blob 分别为 `2b32cef0db455b6a5a8fd98c944aeab7cae0f453`、`541692db6af7ad9ac020b002fc151d0eb71bd0a2`、`4ef141813220833c93b3e7cb69b84e6a862b0e4b`。追加无网站登录、带逗号的网址、无效/有效 TOTP 和不支持的类型；样本中的短 TOTP 占位不代表有效种子。

### PGP 加密 ZIP

- 原厂[导出表单][proton-form]单独收取新建的文件口令 `passphrase`，[导出控件][proton-reauth]另行要求源账号重新认证；文件口令不是 Proton 账户密码，也不是 Vault 主密码。[归档写入器][proton-archive]把同一份 UTF-8 库 JSON 作为 `Proton Pass/data.pgp` 写进普通 ZIP。[密码学封装][proton-crypto]用口令数组 `passwords: [passphrase]` 生成 armored OpenPGP 消息，不是公钥文件、ZIP 密码或 CSV 加密方言。选了附件时 `Proton Pass/files/…` 不加密，原厂界面明确提示这一点。
- Vault 在一次性 WASM Worker 中处理这类归档：仅接受单个已知名称、体积和包型均受限的 OpenPGP 载荷；单口令 v4 SKESK、AES/SHA-2 迭代加盐 S2K、SEIPDv1 完整性校验，认证成功后才读单一 Literal JSON。不支持公钥、通用 PGP、未认证外层或附件。Worker 在回传前清零线性内存，JS 字符串仍不具备确定性擦除保证。
- [原厂 PGP ZIP 夹具][proton-pgp-zip]只核对过包结构（SHA-256 `327b8a707d07f8d002efe912370474c863ae15394d9ad930340723bce89a4e01`），未验证口令。[本仓合成夹具](../../crates/vault-importers/tests/fixtures/proton-password.pgp)用[原厂封装][proton-pgp-test]所用的 `@protontech/openpgp@6.3.1` 生成（SHA-256 `5ca06f463bcc7fbe5dd7b25c66299676decddae8839decb5921b42dec7425170`）；生产 WASM 回归覆盖正确、错误和空口令，损坏、重复或混合载荷，附件跳过、预览不写、确认后恢复凭证和 TOTP。

## RoboForm：简易导入模板不等于原生扩展 CSV

- [原厂导出说明][robo-export]列浏览器扩展及 Windows/macOS 桌面 CSV；桌面可选 Logins、Bookmarks、Safenotes。本次所查原厂说明未给凭证 JSON 导出。[2026-10-26 的原厂字段说明][robo-fields]确认扩展 CSV 含名称、目录路径、跳转 URL、匹配 URL、用户 ID、密码、备注及附加表单字段，还能带 RoboForm Authenticator 的 TOTP 密钥、Passkey、脚本和登录提示。原厂只承诺它生成的 Passkey 可在 RoboForm 账号间迁移，未公开可移植密钥封装。不能说它不导出 Passkey，也不能声称 Vault 可直接导入或重放脚本。
- [原厂通用 CSV 导入说明和模板][robo-template]为 `Name,URL,Login,Pwd,Note,Folder`，附件模板还带一个末尾空列。可作为通用映射测试，不能代替原生扩展 CSV。Proton Pass 的[公开接收夹具][robo-fixture]头是 `Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2`，且数据行有 7–10 列。[Proton 实际读取逻辑][robo-reader]按前七列及可变尾列读，使用 `MatchUrl` 读取登录、以缺少匹配 URL/账号/密码区分书签或安全备注；尾部兼容 `TOTP KEY$…`，也对登录名和密码中特定开头的单引号作逆转义。该夹具无 Passkey；不是原厂完整字段契约。
- Vault 识别原生变长 CSV 和简易模板，映射登录、安全备注、文件夹和可读 TOTP。原生 `MatchUrl` 使用保守的精确匹配，单独的跳转 URL 不扩大填充范围。不能解释的尾字段计入未支持；不执行脚本、不迁移 RoboForm 专属 Passkey。现有样本不代表当前客户端的所有导出选项。

## Kaspersky Password Manager：迁移输入应是 TXT，不是 CSV/JSON

- [Windows 当前在线帮助][kpm-export]和 [23.1 帮助][kpm-23]都将 UTF-8 `url,username,password,name,extra` 写在**导入**章，表示接收网站账号；Windows 与 My Kaspersky 的「导出供打印」才是原生明文 `.txt`，官方明确包括凭证和备注。[受主密码保护的原生库备份][kpm-backup]是另一流程；[命令行 XML][kpm-settings]导出应用设置，不是凭证 JSON/CSV。不要为 Kaspersky 的接收模板开发专用原生导出指纹。
- 原厂公开帮助未规定 TXT 的字段字节布局。[Proton 接收端夹具][kpm-fixture]是可复查的英文测试输入：`---` 独立行分隔，含 `Website name:`、`Website URL:`、`Login name:`、`Login:`、`Password:`、`Comment:`，也有 `Application:`、`Account name:` 以及备注的 `Name:`、`Text:`。[对应的接收实现][kpm-reader]对 `Text:` 后的类字段行保留为备注；没有 TOTP 和 Passkey 恢复逻辑。这只能确认该英文布局的密码/备注，不证明任意地区版本会导出种子或可恢复的 Passkey。产品新增 Authenticator 或 Passkey 不等于打印导出包含它们。
- Vault 支持上述英文 UTF-8 打印布局。网站 URL 为普通域名时按 HTTPS 同主机保存；应用和离线账号没有填充地址；多行文本和密码空格有独立回归。不猜测其他语言、其他导出布局或受保护的本机备份。

## Bitwarden CSV：有官方样本，可另做类型感知导入

[格式说明][bw-format]注明与原生 CSV 导出相同，供个人库和组织库使用的 UTF-8 表头分别为：

```csv
folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
```

[个人样本][bw-sample]和[组织样本][bw-org-sample]是公开布局参考。[固定版写入器][bw-writer]另写 `archivedDate`，将自定义字段扁平化为 `名: 值` 多行文本；[官方接收实现][bw-reader]将 `login_uri` 当作单行 CSV 读取多个 URI。Vault 根据两种指纹读取登录与安全备注，保留组织集合标签、收藏及 `reprompt`。扁平自定义字段仅作不可填充的隐藏文本；源归档不进回收站，也不自动填充。CSV 不带支付卡、身份、SSH 密钥或 Passkey，[原厂说明][bw-export]另列 JSON 导出差异。

[1p-export]: https://support.1password.com/export/
[1p-legacy]: https://github.com/bitwarden/clients/tree/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/importer/src/importers/spec-data/onepassword-csv
[proton-form]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/components/Export/ExportForm.tsx#L67-L156
[proton-reauth]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/components/Export/Exporter.tsx#L48-L100
[proton-saga]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/store/sagas/export/export.saga.ts#L98-L143
[proton-csv]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/export/csv.ts#L5-L48
[proton-csv-reader]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/protonpass/protonpass.csv.reader.ts#L21-L115
[proton-csv-test]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/export/csv.spec.ts#L52-L106
[proton-mocks]: https://github.com/ProtonMail/WebClients/tree/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/protonpass/mocks
[proton-archive]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/export/archive.ts#L24-L95
[proton-crypto]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/crypto/utils/export.ts#L5-L34
[proton-zip-reader]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/protonpass/protonpass.zip.reader.ts#L21-L45
[proton-pgp-zip]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/protonpass/mocks/pgp-export.zip
[proton-pgp-test]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/export/archive.spec.ts#L105-L132
[robo-export]: https://help.roboform.com/hc/en-us/articles/230425008-How-to-export-your-RoboForm-logins-into-a-CSV-file
[robo-fields]: https://help.roboform.com/hc/en-us/articles/49807281668877-What-data-and-fields-can-I-export-from-RoboForm
[robo-template]: https://help.roboform.com/hc/en-us/articles/4423305900685-How-to-Import-from-a-CSV
[robo-fixture]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/roboform/mocks/roboform.csv
[robo-reader]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/roboform/roboform.reader.ts#L15-L85
[kpm-export]: https://support.kaspersky.com/kpm-for-windows/130515
[kpm-23]: https://support.kaspersky.com/kpm-for-windows/23.1/130515
[kpm-backup]: https://support.kaspersky.com/kpm-for-windows/23.1/126789
[kpm-settings]: https://support.kaspersky.com/kpm-for-windows/159809
[kpm-fixture]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/kaspersky/mocks/kaspersky.txt
[kpm-reader]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/kaspersky/kaspersky.reader.ts#L17-L95
[bw-format]: https://bitwarden.com/help/condition-bitwarden-import/
[bw-export]: https://bitwarden.com/help/export-your-data/
[bw-sample]: https://bitwarden.com/assets/4j3wYIYVQYW2MZUBogVxM3/2299910bb8fc93f6a8916d870be0458c/bitwarden_export.csv
[bw-org-sample]: https://bitwarden.com/assets/YYnGrBJO8O5Xv2O0dFW9Z/6de667ded7567da41dcdf4af5186311a/bitwarden_export_org.csv
[bw-writer]: https://github.com/bitwarden/clients/blob/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/tools/export-vault-core/src/services/base-vault-export.service.ts#L54-L98
[bw-reader]: https://github.com/bitwarden/clients/blob/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/importer/src/importers/bitwarden/bitwarden-csv-importer.ts#L23-L105

# 第三方密码库的原厂 JSON 与导出边界

2026-11-20 按 research 技能核对[架构 §4.5.1](../../密码管理器浏览器插件-技术架构与选型文档.md)与[工单 #35](https://github.com/IZRINO/vault-extension/issues/35)。表中的 `.json` / `.csv` 不能理解成每家都能导出两种格式。#35 的四家 CSV 证据另见[登录 CSV 资料](vendor-csv-sources.md)；JSON 是架构延伸，不替代原票的 CSV 验收。

| 厂商 | 原厂可生成的明文迁移输入 | 没有证据支持的说法 |
| --- | --- | --- |
| Dashlane | Web 与移动端的 CSV；官方 CLI 能按类型输出登录、备注等 JSON 数组。系统凭证交换另走 CXP。 | 网页可下载整库 JSON；`.dash` 是 JSON 或 ZIP。 |
| LastPass | 官方 `lpass export` 输出 CSV；`lpass show --json` 输出匹配项的 JSON 数组。 | `lpass export` 支持 JSON；JSON 保留 OTP、附件或展开后的自定义字段。 |
| Enpass | 桌面版明文 JSON 的 `folders` / `items` 布局；原生 CSV 是另一条路径。 | 加密 Enpass 备份是同一种 JSON，或所有平台、版本和模板字段都兼容。 |
| NordPass | 桌面端和 Web Vault 导出 CSV。 | `additional_urls` 或 `custom_fields` 单元格内的 JSON 是独立导出格式。 |
| RoboForm | 扩展 CSV；Windows 手册也列出 HTML 与 Internet Explorer Favorites。 | `RfFieldsV2` 是独立 JSON，或本地备份目录就是明文迁移 JSON。 |
| Kaspersky Password Manager | Windows、My Kaspersky 和 macOS 的可打印 TXT。 | 官方手册的 CSV 导入示例、设置 XML 或加密 EDB 是凭证 JSON/CSV 导出。 |

## Dashlane

**网页导出。** [官方总览][dashlane-export]列出 CSV、DASH 和 CXP。[浏览器扩展源码的导出分派][dashlane-switch]只接受 `csv` 和 `secure-dashlane`。CSV ZIP 的常见签名为 `50 4b 03 04`，内有 `credentials.csv`、`personalInfo.csv`、`securenotes.csv`、`payments.csv`、`ids.csv`。[ZIP 生成器][dashlane-zip]和[登录表头生成器][dashlane-credentials]给出 `username,username2,username3,title,password,note,url,category,otpUrl`；[较新的官方 CSV 帮助][dashlane-csv]还说明了 `otpSecret` 列及 Passkey 不能靠 CSV 迁移。CXP 是[向支持协议的应用进行系统级传输][dashlane-cxp]，不下载 Dashlane 专用 JSON，也不是 Dashlane 浏览器扩展的入口。

**DASH 备份。** [原厂帮助][dashlane-backup]称 `.dash` 是用导出时设置的密码加密、供 Dashlane 恢复的备份。固定提交 `d8c341a…` 的[写入器][dashlane-secure-writer]以 `-------------------- Dashlane Secured Export ----------------------` 开头，包含 `Id BEGIN/END`、`Data BEGIN/END`、`Files BEGIN/END` 文本段。`Id` 段是分号连接的 ID；`Data` 段是 XML 转 UTF-8 并压缩后加密的结果，导出器删除 `Attachments` 并写空 `Files` 段。[原厂读取器][dashlane-secure-reader]解密、解压再解析 XML。未找到原厂用户可导出的旧版明文 `.json` 或公开 `.dash` 合成夹具；以上封装结论限定于公开源码可核对的版本。

**官方 CLI JSON。** [CLI 使用文档][dashlane-cli-doc]明确支持 `dcli password -o json` 和 `dcli note -o json`（别名 `p`、`n`）。文档示范带筛选的查询，[实际筛选器][dashlane-cli-filter]不传筛选时返回该类型的全部可见条目。[官方安装说明][dashlane-cli-install]提供 Windows、macOS、Linux 的安装途径。[认证说明][dashlane-cli-auth]要求正常注册和解锁 CLI；其适用账户条件以官方说明为准。命令输出与 Web 的整库导出不同，每个命令独立生成根数组，无魔数、版本号或品牌包装。CLI 的 `backup` 只复制其本地 `.db`，不是 JSON；`secret -o json` 和 `id -o json` 也是各自独立的查询，不代表有全库 JSON。[命令定义][dashlane-cli-commands] · [CLI 数据库备份][dashlane-cli-backup]

| 查询 | 原生字段和迁移范围 |
| --- | --- |
| `dcli password -o json` | `id`、`anonId`、`title`、`login`、`email`、`secondaryLogin`、`password`、`url`、`note`、`category`、`otpSecret`、`otpUrl`；还有 `lastBackupTime`、`autoLogin`、`localeFormat` 等字符串元数据。实现取 `AUTHENTIFIANT`，将原 XML 键名仅首字母转小写，然后 `JSON.stringify`。原厂 OTP 计算分支先取 `otpSecret`，再以 `otpUrl` 的结果覆盖；不能把取码命令 `-f otp` 的输出当成种子。 [字段类型][dashlane-cli-types] · [输出和取码][dashlane-cli-password] · [字段转换][dashlane-cli-password-fields] |
| `dcli note -o json` | `id`、`anonId`、`title`、`content`、`secured`、`type`、`localeFormat`、`lastBackupTime`，可能有 `category` 等。实现只查询 `SECURENOTE`；`secret` 在类型层与备注共享许多键，仅凭通用的 `title`/`content` 不宜自动判定来源或子类型。 [字段类型][dashlane-cli-types] · [原厂序列化][dashlane-cli-notes] |

Vault 仅接收上述扁平登录和安全备注形状；来源没有类型区分的 `secret` 必须按备注对待，不作为 API 令牌或 SSH 项启用。`autoProtected` / `secured` 保留二次验证；[原厂网址选择][dashlane-best-url]在 `useFixedUrl` 时优先 `userSelectedUrl`；Vault 对固定目标、`subdomainOnly` 或已提供非根路径用精确 URL，其他用同协议、同主机及同端口。不导入厂商关联域名、自动提交或其它策略，也不把无效的选定网址回退为宽匹配。[原厂匹配规则][dashlane-match]

证据固定在 `Dashlane/dashlane-cli@74c3567d3058a7008084141c07902d7bcaa67f1e`，该提交的[包版本][dashlane-cli-version]为 `6.2647.2`。没有找到原厂发布的 CLI 凭证 JSON 测试文件；据源码自行合成的数组须标作合成测试，不等同于实机导出。保存命令输出可用显式 UTF-8；PowerShell 5.1 默认 `>` 是 UTF-16。CLI 通过[同一个控制台日志输出器][dashlane-cli-logger]写内容及其他级别日志，只有纯 JSON 数组才适合作为输入，不能把 debug、同步消息或命令失败后的输出当成凭证文件。

## LastPass

- [官方 CLI 手册][lastpass-manual]区分 `lpass export`（明文 CSV）和 `lpass show --json`（匹配查询）。[原厂 CSV 生成器][lastpass-csv]默认表头 `url,username,password,extra,name,grouping,fav`。LastPass 网页帮助在调研环境未能通过 TLS 打开，未据此确认浏览器历史版本或其它导出选项。
- 可用 `lpass show --json --expand-multi --basic-regexp '.*'` 输出当前会话可见的匹配账号。`--expand-multi` 避免多个匹配时输出人读列表；`--all` 不是选中全库的参数。正则路径已查源码，未用账户实跑。受保护条目仍走正常再认证；CLI 报错时不能使用可能不完整的输出。 [查找及 JSON 分支][lastpass-show] · [POSIX 正则实现][lastpass-search]
- [原厂 JSON 生成器][lastpass-json]无品牌、版本或文件魔数，根为数组，条目为扁平字符串键值：`id,name,fullname,username,password,last_modified_gmt,last_touch,group,url,note`，共享条目可带 `share`；不存在的 C 字段跳过。JSON 分支早于 `notes_expand`；原厂测试用 `url: "http://sn"` 表示安全备注，`note` 保留正文或类型字段文本，不能拿该 URL 做网站填充。序列化器没有专用 OTP、附件或展开后的自定义字段。 [JSON 和备注分支][lastpass-show] · [原厂安全备注 mock][lastpass-note] · [原厂 JSON 测试][lastpass-fixture]

Vault 导入已核对的字段组合，用 `id` 辅助去重，保留目录、共享目录路径、密码和原始备注。`http://sn` 只作安全备注。CLI 没输出 `pwprotect`，因此导入项默认需要二次验证；不从备注猜测 OTP 或可填充字段。有字段未成功解密的源命令可能同时写部分输出并以失败退出，不把那次输出当成可用导出。

## Enpass

[固定版 Bitwarden 接收实现][enpass-reader]及[字段类型][enpass-types]记录 `{folders,items}`、项目 `uuid`、`template_type`、`favorite`、`archived`、`trashed`，以及带类型的 `fields`。Vault 支持 `login.default`、`password.default`、`note.default` 和[明确列出的电脑、银行账户模板][enpass-templates]；电脑、银行项的 URL 只作源字段保存，不参与网页填充。按数字状态标记保留收藏、归档及回收站；保留已能映射的嵌套文件夹标签和有效 TOTP。来源不支持的模板、无效设置、Android 应用目标分别计数；不迁移加密备份、Passkey、卡片模板或应用填充规则。

独立证据是 Bitwarden 接收端的公开样本，不是本轮操作 Enpass 桌面客户端。已对原始 Git blob 校验，再以 AST 字面量读四份样本；唯一允许展开的引用是固定 Android 样本对同提交登录字段的引用，不执行上游脚本。合成回归另外用公开 RFC 6238 种子独立算码，上游登录样本只有占位符，不作为有效种子。

## 其它平台

- **NordPass：** [原厂步骤][nordpass-export]说从 Windows/macOS/Linux 桌面端或 Web Vault 保存 `.CSV`。[原厂 CSV 模板][nordpass-template]的字段用于向 NordPass 导入，不证明相同字段也可导出。[Proton Pass 读取器][proton-nordpass-reader]将 `additional_urls` 当 CSV 中的 JSON 数组；该仓库的当前合成样本还带 JSON 数组值 `custom_fields`，旧表头没有这两列。NordPass 的[活动日志 API][nordpass-audit]虽用 JSON，但不返回加密条目值或密钥，也不是凭证库导出。
- **RoboForm：** [官方操作说明][roboform-csv]给浏览器、Windows 和 macOS 的 CSV 路径；[Windows 手册][roboform-manual]另列 HTML、Internet Explorer Favorites。[官方扩展 CSV 字段说明][roboform-fields]列出登录、备注、保存的表单字段和 TOTP 密钥，并说明 Passkey 可在 RoboForm 账户之间导出和导入，不能据此推断第三方可移植的密钥表示。下游 CSV 样本表头 `Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2`；实查该样本的非空 `RfFieldsV2` 值均不是 JSON。官方[备份][roboform-backup]与[从目录恢复][roboform-restore]是另一条路径，文档未定义可移植 JSON 文件。
- **Kaspersky Password Manager：** [Windows / My Kaspersky][kaspersky-export]和 [macOS][kaspersky-mac]原厂帮助明确把登录与备注导出为 `.txt`；同一 Windows 页的 `URL,username,password,name` 是导入的 CSV 字段。固定的下游 TXT 样本带 UTF-8 BOM：`ef bb bf` 后接 `Websites`，另有 `Applications`、`Other Accounts`、`Notes` 和 `---` 分隔行，登录键如 `Website name`、`Website URL`、`Login`、`Password`、`Comment`；备注用 `Name`/`Text`。这是英语样本，不能假设所有语言/版本使用相同标题。原厂[备份帮助][kaspersky-backup]指定受主密码保护的加密 `.edb`，[设置导出][kaspersky-settings]则明确是 XML，二者都不是凭证 JSON。 [下游 TXT 读取器][proton-kaspersky-reader]

## 可重复校验的公开夹具

均为上游公开的测试文件或测试中的预期输出。SHA-256 针对 HTTP 200 返回的源文件原始字节，不从 GitHub 网页复制，也不转换换行或 BOM。下游导入器的合成样本用于核对格式，不作厂商客户端的实机出口验收。

| 固定仓库路径 | Git blob | SHA-256 |
| --- | --- | --- |
| `lastpass/lastpass-cli@949bad64e9db1bed89606cba78f32f6708cef3f0` · [`test/tests`][lastpass-fixture] | `b64a1ee4fad33c9c0c61948277dc469700338b8f` | `5104038938e203f4e93616ac1dd2efd9d87b261410f9b1f682df17f41016cbff` |
| `ProtonMail/WebClients@e7b57b816903d01d8d6d7c8f7dd56c2deb60a643` · [`packages/pass/lib/import/providers/dashlane/mocks/dashlane.zip`][proton-dashlane-fixture] | `ad315bcb196de62f65d120e0e996aae453fca988` | `918826152068ee6520c7e429a270379b3e9a92e4ed4062b47f93189546d8e8c0` |
| 同一 Proton 提交 · [`packages/pass/lib/import/providers/nordpass/mocks/nordpass.csv`][proton-nordpass-fixture] | `cbdb610afcce9f47c3457ab7c6baac672ba0a8ae` | `bd82b480a597ce46122c5927f6f7547f4d646098f9dbb5c7fc8f25e3446a6fb2` |
| 同一 Proton 提交 · [`packages/pass/lib/import/providers/nordpass/mocks/nordpass-legacy.csv`][proton-nordpass-legacy] | `13f972e80590c8a6b28d7e16e349a200e33c76f5` | `98ab52324a604cab44e71ab0662066c3bfce56947e29f14a3ece6adfa66bd194` |
| 同一 Proton 提交 · [`packages/pass/lib/import/providers/roboform/mocks/roboform.csv`][proton-roboform-fixture] | `ca9d918e661b943288e6db03ad80b5f9e493927c` | `c64fb42312fbbb991089b8a132568a769ba60f8b2af5cd0ab57c4fc09392b3df` |
| 同一 Proton 提交 · [`packages/pass/lib/import/providers/kaspersky/mocks/kaspersky.txt`][proton-kaspersky-fixture] | `756e86c4cfd30d13b3186314b5d8a8f526594287` | `602274aff1f1b2ffc7205b8d0ddea9a7750da36ad9ff0cf5d998ae322e17e0d0` |
| `bitwarden/clients@a69127380b4b745f6a203fd6da18344dcc03d61a` · [Enpass `login.ts`][enpass-fixtures] | `6626b8c9e4b61cd759eb9ed5e955c92a108a6e66` | `d5f52605d566c502b9faabb5293e7ccb29625b0d1c291827a109d4a360719888` |
| 同一 Bitwarden 提交 · [Enpass `note.ts`][enpass-fixtures] | `37c1658b5175f7f17639ca0331235bbc5fe420b6` | `6d5d6adeb4557bb38194300f665b1c32ca172af9f3ba7a23c642f8ea98530343` |
| 同一 Bitwarden 提交 · [Enpass `folders.ts`][enpass-fixtures] | `9af44f057bfc9feb907b46e4ce411ce3cb1f3262` | `3cc519a9f07633c8a9ae4c533154b84e6ee108aec85573c430b23fccd7c4de8d` |
| 同一 Bitwarden 提交 · [Enpass `login-android-url.ts`][enpass-fixtures] | `91dca5fe99ab14e8172fb7bf5363ced0cbc856d8` | `178533b17ba436863e769368c29fcf0c7197479cdf9b31a49643d9b0590c5f79` |

LastPass `test_show_json` 的 458–471 行是一个可直接解析的单条登录数组，即 here-document 两个分隔行之间的内容。保留最后一个 LF 时，这段片段的 SHA-256 为 `d172623adbb87b81ca5564be35b51d6daf6b57c9eaa99ab33802439b5489fc5d`，不是 CLI 所有输出版本的固定字节签名。Dashlane ZIP 五个 CSV 成员均通过 CRC 检查；NordPass 两种表头、RoboForm 扩展列及 Kaspersky 标题也由上表原字节核对。未登入厂商账户或使用私人库。

扩展中从「其他密码库与 CXF」选定这三种来源，按源字段组合校验，不把任意 `name` / `password` 数组当作厂商凭证。UTF-8 可带 BOM；文件最多 16 MiB、每个数组最多 5,000 项、每个对象最多 256 个字段，拒绝重复的 JSON 键，Enpass 也拒绝重复的来源条目 ID。使用按需内存 Worker，预览不写库，文件和库状态变化时必须重新预览；验证通过后原子写入，不覆盖已存在的来源 ID。相同内容去重也核对收藏、二次验证、回收站和保留字段。普通详情和网页填充不会得到内置保留字段或 OTP 种子。

重放独立样本：在临时目录按上表原名准备四份 Enpass `.ts`，LastPass 的 `test/tests` 存为 `lastpass-tests`；设置 `VAULT_VENDOR_FIXTURE_DIR` 指向目录，运行 `node node_modules/vitest/vitest.mjs run apps/extension/src/migration-wasm.test.ts`。默认回归使用本项目合成样本，不访问网络。`.dash`、`.edb`、HTML、CSV 内部 JSON 和应用设置均不作为这三条 JSON 输入。

[dashlane-export]: https://support.dashlane.com/api/v2/help_center/en-us/articles/202625092.json
[dashlane-csv]: https://support.dashlane.com/api/v2/help_center/en-us/articles/32905278138002.json
[dashlane-backup]: https://support.dashlane.com/api/v2/help_center/en-us/articles/7874554196626.json
[dashlane-cxp]: https://support.dashlane.com/api/v2/help_center/en-us/articles/32907864739474.json
[dashlane-switch]: https://github.com/Dashlane/dashlane-web-extension/blob/d8c341a3468da504c699a3cdf1c4d7d200cda9cd/packages/carbon/src/DataManagement/Export/Services/get-personal-data-export.ts#L138-L195
[dashlane-zip]: https://github.com/Dashlane/dashlane-web-extension/blob/d8c341a3468da504c699a3cdf1c4d7d200cda9cd/packages/carbon/src/DataManagement/Export/Services/get-csv-export.ts#L7-L48
[dashlane-credentials]: https://github.com/Dashlane/dashlane-web-extension/blob/d8c341a3468da504c699a3cdf1c4d7d200cda9cd/packages/carbon/src/DataManagement/Export/Services/get-credentials-export.ts#L19-L43
[dashlane-secure-writer]: https://github.com/Dashlane/dashlane-web-extension/blob/d8c341a3468da504c699a3cdf1c4d7d200cda9cd/packages/carbon/src/DataManagement/Export/Services/get-dashlane-secure-export.ts#L10-L27
[dashlane-secure-reader]: https://github.com/Dashlane/dashlane-web-extension/blob/d8c341a3468da504c699a3cdf1c4d7d200cda9cd/packages/carbon/src/DataManagement/Import/services/parse-data/parse-dash.ts#L12-L64
[dashlane-cli-doc]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/documentation/pages/personal/vault.mdx#L8-L107
[dashlane-cli-filter]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/utils/filterCredentials.ts#L1-L13
[dashlane-cli-install]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/documentation/pages/install.mdx#L6-L59
[dashlane-cli-auth]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/documentation/pages/personal/authentication.mdx#L3-L50
[dashlane-cli-commands]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/commands/index.ts#L50-L134
[dashlane-cli-backup]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/command-handlers/backup.ts
[dashlane-cli-types]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/types.ts#L196-L294
[dashlane-cli-password]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/command-handlers/passwords.ts#L14-L62
[dashlane-cli-password-fields]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/command-handlers/passwords.ts#L103-L128
[dashlane-cli-notes]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/command-handlers/secureNotes.ts#L26-L53
[dashlane-cli-version]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/package.json
[dashlane-cli-logger]: https://github.com/Dashlane/dashlane-cli/blob/74c3567d3058a7008084141c07902d7bcaa67f1e/src/logger.ts#L14-L70
[dashlane-best-url]: https://github.com/Dashlane/dashlane-web-extension/blob/d8c341a3468da504c699a3cdf1c4d7d200cda9cd/packages/carbon/src/DataManagement/Credentials/url/index.ts#L7-L8
[dashlane-match]: https://github.com/Dashlane/dashlane-web-extension/blob/d8c341a3468da504c699a3cdf1c4d7d200cda9cd/packages/autofill-engine/src/implementation/modules/autofill/utils.ts#L97-L143
[enpass-reader]: https://github.com/bitwarden/clients/blob/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/importer/src/importers/enpass/enpass-json-importer.ts
[enpass-types]: https://github.com/bitwarden/clients/blob/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/importer/src/importers/enpass/types/enpass-json-type.ts
[enpass-templates]: https://github.com/bitwarden/clients/blob/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/importer/src/importers/enpass/types/enpass-item-templates.ts
[enpass-fixtures]: https://github.com/bitwarden/clients/tree/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/importer/src/importers/spec-data/enpass-json
[lastpass-manual]: https://github.com/lastpass/lastpass-cli/blob/949bad64e9db1bed89606cba78f32f6708cef3f0/lpass.1.txt#L130-L222
[lastpass-csv]: https://github.com/lastpass/lastpass-cli/blob/949bad64e9db1bed89606cba78f32f6708cef3f0/cmd-export.c#L167-L170
[lastpass-show]: https://github.com/lastpass/lastpass-cli/blob/949bad64e9db1bed89606cba78f32f6708cef3f0/cmd-show.c#L396-L459
[lastpass-search]: https://github.com/lastpass/lastpass-cli/blob/949bad64e9db1bed89606cba78f32f6708cef3f0/cmd.c#L125-L168
[lastpass-json]: https://github.com/lastpass/lastpass-cli/blob/949bad64e9db1bed89606cba78f32f6708cef3f0/json-format.c#L158-L221
[lastpass-fixture]: https://github.com/lastpass/lastpass-cli/blob/949bad64e9db1bed89606cba78f32f6708cef3f0/test/tests#L454-L475
[lastpass-note]: https://github.com/lastpass/lastpass-cli/blob/949bad64e9db1bed89606cba78f32f6708cef3f0/test/http_mock.c#L95-L107
[nordpass-export]: https://support.nordpass.com/api/v2/help_center/en-us/articles/360007646477.json
[nordpass-template]: https://support.nordpass.com/api/v2/help_center/en-us/articles/360002377217.json
[nordpass-audit]: https://support.nordpass.com/api/v2/help_center/en-us/articles/23485641117329.json
[roboform-csv]: https://help.roboform.com/api/v2/help_center/en-us/articles/230425008.json
[roboform-manual]: https://www.roboform.com/manual
[roboform-fields]: https://help.roboform.com/api/v2/help_center/en-us/articles/49807281668877.json
[roboform-backup]: https://help.roboform.com/api/v2/help_center/en-us/articles/360021625572.json
[roboform-restore]: https://help.roboform.com/api/v2/help_center/en-us/articles/360046180791.json
[kaspersky-export]: https://support.kaspersky.com/kpm-for-windows/130515
[kaspersky-mac]: https://support.kaspersky.com/kpm-for-mac/250621
[kaspersky-backup]: https://support.kaspersky.com/kpm-for-windows/126789
[kaspersky-settings]: https://support.kaspersky.com/kpm-for-windows/159809
[proton-dashlane-fixture]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/dashlane/mocks/dashlane.zip
[proton-nordpass-reader]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/nordpass/nordpass.reader.ts#L22-L34
[proton-nordpass-fixture]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/nordpass/mocks/nordpass.csv
[proton-nordpass-legacy]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/nordpass/mocks/nordpass-legacy.csv
[proton-roboform-fixture]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/roboform/mocks/roboform.csv
[proton-kaspersky-fixture]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/kaspersky/mocks/kaspersky.txt
[proton-kaspersky-reader]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/kaspersky/kaspersky.reader.ts#L17-L95

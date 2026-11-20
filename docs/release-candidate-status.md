# Vault Extension 候选包验证记录

2026-11-20。对应[架构 v1.4](../密码管理器浏览器插件-技术架构与选型文档.md)与[工单 T01–T38](development-tickets.md)。生产 ZIP 不等于正式准出；不代签，也不把模拟证据当作系统设备、第三方服务或应用互通的证据。

当前可安装包为 **Vault 0.1.0**。生产构建可解压安装；千条库冷开最近一次双浏览器测量仍未达标，正式准出不能签收。需真实设备、第三方环境的验收由用户日常试用，不代签。

## 当前候选包 0.1.0

- ZIP `test-results/Vault-2026-11-20-03ebf90b5c3d-chrome.zip`，6,158,246 B。SHA-256 `03ebf90b5c3d6415f8bf7f4f30f03c3f1d9e55805e7f607a3c7573f5668f7d0c`。解压 `test-results/release-unpacked-03ebf90b5c3d`，54 个文件与生产构建逐字节一致，树摘要 `1204055dde810710691174382539a0230b733af15ff34de77ab3e28e9010cf02`。
- 新增已知 Proton Pass PGP ZIP、Bitwarden/Proton Pass/RoboForm CSV、限定表头的 1Password CSV、英文 Kaspersky 打印 TXT。浏览器 CSV 兼容 `origin`；同一条登录项内的禁填页优先，不把异常规则降为默认放行；补齐 Apple/iCloud 与京东/3.cn 等价组。安全备注不是 API 令牌；源归档不视为回收站。具体布局、夹具与不支持项见[迁移格式记录](agents/remaining-password-formats.md)。
- **兼容提醒：**新版继续读取旧快照和旧加密 `.vaultpack`。旧客户端遇到新增安全备注类型会拒读，不会按旧格式写回。多设备使用 WebDAV 时，先升级所有设备，再使用新类型；升级前保留一份旧版加密备份。
- Rust **69** 项（另有 vendored 依赖 3 项）、Vitest **122** 项、TypeScript、九个 WASM、旧版 `.vaultpack` 和最终 WASM 的公开验证器样本通过。主核 **250,848 B**（上限 **256,000 B**），迁移 WASM **3,533,982 B**，只进按需的 CSV 和迁移 Worker。与上一候选 `9fce26b79a79` 的差异仅为这两个 Worker；清单、权限、CSP 和其余二进制未变，包内没有 `chrome.identity` 或 `chrome.storage.sync`。
- 最终 ZIP 在 Edge `158.0.4370.33` 与 Helium `157.0.8103.78` 通过二期与迁移回归：`Origin` CSV 与 Proton PGP 预览、取消不写入，错文件密码拒绝，授权后才提交；Bitwarden CSV 类型及 `reprompt` 保留；Google Authenticator 多图、2FAS v4 加密样本、字段映射、标签页截图扫码和取消均通过。该次截图使用扩展页回归，不计作原生工具栏首扫准出。逐文件检查和日志在 `test-results/release-checks-03ebf90b5c3d/`。
- 上一候选 `9fce26b79a79` 的 Edge/Helium 回归另通过数据安全、自动填充、Passkey 和回环 WebDAV（含历史恢复、冲突裁决、主密码轮换、重新安装认领）。该包的固定版 1PUX、KDBX 和浏览器日志在 `test-results/release-checks-9fce26b79a79/`，不算作最终 ZIP 的同包全量矩阵。
- 这次未重新量千条库冷开。之前同口径 Edge/Helium 的 WASM 恢复和原生 Popup 首屏都未过 `<5 ms` / `<50 ms`；[诊断及复测口径](cold-wake-diagnostics.md)。不把回环站点、虚拟认证器或公开合成样本当成实体认证器、真实网站、真实网盘或来源应用验收。

## 离线体检与窄栏候选包 0.1.0

- ZIP `test-results/Vault-2026-11-20-96d24525621a-chrome.zip`，5,176,061 B。SHA-256 `96d24525621a2af4353feb334d83860c86acf7395abd63cbb97c7fe71bf4d971`。解压安装目录 `test-results/release-unpacked-96d24525621a`，54 个文件与生产构建逐字节一致，解压树摘要 `9b3b100ba43a08d92db04eb12f0181a1215cb72b231c2aca0ff3936576037e38`。
- 已完成两项[架构 v1.4 §4.1](../密码管理器浏览器插件-技术架构与选型文档.md)提醒。体检只比对高敏登录项是否在本库关联验证器，不声称知道站点的两步验证设置，也不猜测独立验证器的归属。报告不含密码或种子。锁库会阻止未发送任务读取会话材料，并通知离屏页终止在途体检。开发者列表和详情按 UTC 日期显示「30 天内到期」和「已到期」；无有效日期和回收站项目不提示。
- Rust **59** 项（另有 vendored 依赖测试）、Vitest **113** 项、TypeScript 和九个 WASM 构建检查通过。主核 **250,771 B** / 256,000 B；**259,743 B** 体检 WASM 只打入按需加载的 `audit-worker.js`。比对包内十一份 WASM 与构建产物；清单、权限和 CSP 同 Ente 候选。
- 同一最终布局 ZIP 在 Edge 与 Helium 跑过二期回归。覆盖高敏提示、受保护项再次验证、补挂验证器后提示消失、当期/逾期/无日期与回收站、延长日期后提示消失。测试在审计窗口内未捕获归属扩展的外部 HTTP(S) 请求。330 px 侧栏的复制按钮现不再被裁切，断言在布局修复前实测失败。记录 `test-results/release-checks-96d24525621a/`。可见 HTTP 夹具只检查显示，不用来证明扩展权限。当前包没有重跑冷开或全部 12 项浏览器功能流程。

## Ente 加密迁移候选包 0.1.0

- ZIP `test-results/Vault-2026-11-20-5a759f049e22-chrome.zip`，5,036,883 B。SHA-256 `5a759f049e22df124d5b269e026d5624114e1fade4da8a92221fc78265636e54`。加载解压目录 `test-results/release-unpacked-5a759f049e22`，53 个文件与生产构建逐字节一致；解压树摘要 `be27de5e5c29ca0b7265b4ed14fdef64dc70df75fe1096c69d627cf094f6c021`。
- 从包内校验了主核和 9 份 Worker 内联 WASM。清单、CSP、权限和主核（**255,662 B** / 上限 **256,000 B**）与上一包相同；Ente WASM **197,496 B**，只在导入或导出时加载。没有 `chrome.identity` 或 `chrome.storage.sync`。Rust **58** 项（另有依赖测试）、默认 Vitest **108** 项、TypeScript 和八个 WASM 构建检查通过。
- 新增 Ente 文件密码加密 JSON v1 **本机导入**，保留 Ente 文本导出。独立 libsodium 样本的 8 KiB/1、256 MiB/16、1 GiB/4 三档在生产 WASM 通过；前两档另用官方 CLI 对照。1 GiB 档是合成参数测试，并非原生 App 导出。[样本和预算](agents/ente-auth-encrypted-research.md#样本与独立验算)。
- Edge `158.0.4370.33`、Helium `157.0.8103.78` 同包通过二期回归：明文预览、合并和导出，低成本加密样本导入，缺密码、错密、损坏密文和 header、超限、错版本，全程验证预览不写库、改名不影响导入、去重及 HOTP 不回退。可见 HTTP 夹具只复核界面和错误提示，控制台及失败请求均无异常；真正解密与写库证据来自实际扩展。完整 12/12 功能矩阵仍是 `3a2fa7b7d66f` 的证据。
- 同包 Edge / Helium 各 10 次千条库原生冷开，列表 DOM 中位数 **549.26 / 546.95 ms**，已认证 WASM 恢复 **65.80 / 60.95 ms**，两端均未过 `<50 ms` / `<5 ms`。[分段和报告](cold-wake-diagnostics.md#ente-候选包同包复测)。本机包证据在 `test-results/release-checks-5a759f049e22/`。未推送、未上架。

## Zstd 对照候选包 0.1.0

- ZIP `test-results/Vault-2026-11-20-8a016565deff-chrome.zip`，6,164,200 B。SHA-256 `8a016565deff9f9bf69ac38b60e22285c4bd300ecfaa8b15c81cb4988859d0ab`。加载解压目录 `test-results/release-unpacked-8a016565deff`，52 个文件与 ZIP 逐字节一致；按冷开脚本口径的树摘要 `83593aef506066683068478c87b2a7aef74a089cf9b43da64936c0252d8597e0`。
- 主核 **255,662 B**，上限 **256,000 B**。相对前一包仅核心 WASM 和 7 个引用它的按需 Worker 产物变化，MV3 清单、CSP、权限和前端完全相同。检查实际 ZIP 中的 10 份 WASM 载荷均与对应构建产物一致；导入 WASM **2,518,450 B**，仍只进入按需导入 Worker。包内没有 `chrome.identity` 或 `chrome.storage.sync` 引用。
- Rust **57** 项、带独立夹具的 Vitest **110** 项、TypeScript 和七个 WASM 构建通过。另用旧版 WASM 实际导出的加密 `.vaultpack` 验证预览、错密拒绝、合入和二次验证；KDBX 3.1/4.0、KeePassXC 4.1 原公钥验签，以及 2FAS、Aegis、andOTP 和 Stratum 合成样本通过。
- Edge `158.0.4370.33` 和 Helium `157.0.8103.78` 实际加载同一解压树。系统已锁定时，冷 Worker 两端都加载 WASM、清除有效合成会话且不返回任何条目。未改锁库条件或计时口径。新的解锁态原生冷开在置备阶段中止，没有产生样本；新包未重跑需要解锁桌面的完整双浏览器功能矩阵。**12/12** 功能回归属于前一包。
- Zstd 首次恢复在同密文、独立 Node 进程的对照中位数为 **17.098 → 16.171 ms**，不能代替浏览器准出。无 Vault 业务的最小 Worker 对照中，仅受保护存储准备在这台锁定桌面也至少需要 **6.90 / 6.50 ms**（Edge / Helium）。[分段和换机复测命令](cold-wake-diagnostics.md#wasm-恢复归因)。本机包证据在 `test-results/release-checks-8a016565deff/`。

## 前一候选包 0.1.0（全量浏览器功能回归）

- ZIP `test-results/Vault-2026-11-20-3a2fa7b7d66f-chrome.zip`，6,163,321 B。SHA-256 `3a2fa7b7d66f7db44e7287044659b71da37ba1932434d27feb588daef1c1d8ff`。加载解压目录 `test-results/release-unpacked-3a2fa7b7d66f`，52 个文件逐个与 ZIP 内容一致；冷开脚本的树摘要为 `02388a5bba6880b74749ab31a4064a50a94f4a3717aac1e45e75e01e93a1278f`。
- Rust **57** 项、Vitest **110** 项、TypeScript 检查、全部七个 WASM 模块和 MV3 生产 ZIP 构建通过。主核 `assets/background.wasm` **255,677 B**，上限 **256,000 B**。导入 WASM **2,518,466 B**，只进入 `csv-worker.js`、`ente-worker.js` 和 `migration-worker.js`。生产清单版本改为 `0.1.0`，权限和 CSP 与上一包一致。包内扫描无 `chrome.identity` 或 `chrome.storage.sync` 引用。[Chromium 清单版本规则](https://developer.chrome.com/docs/extensions/reference/manifest/version)
- T27 在“设置 → Bitwarden 密码库迁移 → 启用已保留的通行密钥”预览。确认更新绑定当前库快照并要求二次验证。Edge、Helium 各从加密合成旧库恢复，在设置页预览、取消、验证并更新，核对原条目 ID、密码、OTP 和再次启用为零，再用原公钥完成 ES256 断言。WASM 测试还核对了旧库卡片。无有效私钥的分支只报告，不允许确认。
- T31 支持多图选取、拖放或粘贴迁移 URI。双端覆盖排序、重复片、缺片、混批、损坏 Protobuf、超限及取消。结构完整但混有坏记录的批次也会整批拒绝，后台回归检查快照与 WAL 不变。有效批次提交后与独立 HMAC 结果核对 TOTP 和连续 HOTP。
- T26 使用独立 CXF 1.0 来源、Bitwarden 格式库 `0.4.0` 与原公钥验签。标准交换的私钥为 Base64URL PKCS#8，Vault 在加密库内保存原始标量或种子。带文件密码的 JWE 单独标识。T29 覆盖脱敏 1PUX 数据和兼容结构，对无私钥、附件和未支持类型报告限制。T30 支持 Proton 原生 ES256 / Ed25519 MessagePack 凭证，对未知版本及 PGP 外层给出提示。T35 按厂商布局处理 NordPass 附加网址 JSON 数组和 Dashlane 旧版 OTP。例程与样本版本见[迁移夹具](agents/portable-migration-fixtures.md)、[CSV 来源](agents/vendor-csv-sources.md)。
- 同一 ZIP 在 Edge `157.0.4341.60` 和 Helium `157.0.8103.78` 跑亮码、暗码两轮迁移，均使用独立配置，1000×800 视口与 420 像素码。原生 Popup **首扫候选完成绘制**，Helium **122.2 / 129.0 ms**，Edge **214.7 / 217.4 ms**。热扫分别为 **106.0 / 109.3 ms** 和 **112.3 / 129.3 ms**。Helium 过 `<200 ms` 指标。Edge 同口径前包为 210–239 ms 量级，早期 Edge 161 ms 采用不同测量口径。两轮均实测公开 2FAS v4 加密样本，错密不写入，恢复 5 条，核对 HOTP 连续计数。
- **同包功能回归 12/12 通过**，包括双端原生亮暗码迁移、安装、原生侧栏、二期、自动填充、数据安全、主密码轮换和设备认领、网盘备份合入、Proton 验签、Passkey 与历史恢复，以及旧 Bitwarden 凭证启用。Proton Pass WASM `2.3.4` 生成的两枚凭证在两个浏览器均验签通过。KeePassXC CLI `2.8.0` 的加密 4.1 夹具每端通过 3 次验签。回环 WebDAV 历史恢复确认 `412` 时不覆盖、保留当前密钥包装和已用计数。千条密文快照 **123,752 B**（上限 240,000 B），单变更 WAL **598 B**（上限 600 B）。
- **同一候选包千条库冷开**：Edge `158.0.4370.33`、Helium `157.0.8103.78` 各完成 10 个样本。Popup DOM 中位数 **556.23 / 548.50 ms**，WASM 恢复中位数 **72.00 / 69.20 ms**，两端均未过 `<50 ms`、`<5 ms`。同机当前版本的最小 MV3 对照，最快首脚本 **265.62 / 255.84 ms**。[计时定义及诊断](cold-wake-diagnostics.md#vault-010-前一候选包冷开复测)

本机 `test-results/release-checks-3a2fa7b7d66f/` 保存 `package.json`、`browser-suites.json`、两轮原生扫码分段数据和 `cold-wake-fresh-tabs.log`。冷开原始报告为 `test-results/wakeup-1000.rc-3a2fa7b7d66f.json`。回归记录保留 Proton 漏传夹具参数及旧库测试页需要刷新的两次失败，以及更正命令后通过的证据。

## 实现范围

| 工单 | 本轮实现或继承 | 证据与边界 |
| --- | --- | --- |
| T01–T07、T37、T38 | 原生侧栏、填充/保存/改密、截图扫码、CSV 拖拽与键盘、Bitwarden 与 Ente 文本迁移、Ente 加密 JSON v1 本机导入；整库导出验证当前主密码，明文另确认；日常 TOTP/Steam 返回码、HOTP 严格落盘后返回码，编辑才读种子。 | 扫码只绑定点击时的标签页；切换、导航或取消会让候选失效。双浏览器本地靶场覆盖填充授权、备份确认和 OTP 路径。真实网站/原生右键、Ente 与 Bitwarden 官方应用、实际系统锁屏和实体 Hello 未验证。T01 已按历史决定关闭，不代表性能通过。 |
| T08–T12、T19 | 坚果云/Koofr 预设、只读判库、条件写探测、加入/建库、零条目及批量删除保护、2.5 秒防抖的不可变加密 WAL、熔断、显式开启时差补偿。 | 故障注入覆盖假 ETag、旧 ETag、重启、重放、熔断、锁库零新请求、时钟偏差。同步是最终一致，不能保证两台离线设备的 HOTP 互斥。 |
| T13–T18、T20 | 三方字段合并、加密待裁决区、全页裁决、落选密码历史、主密码旋转、设备认领和加密来源记录、滚动五份历史、历史预览/恢复、异库合入。 | 一个离线登录命中多个远端候选时一同展示；更晚的重叠草稿加密留在本机，无关项仍可同步。双份继承二次验证，同一递增凭证只保留一份可用计数。自动覆盖并发 WAL、条件提交、两处压实中断、30 天回收站边界、历史重放拒绝、计数恢复、不同身份合入。找不到祖先或不能保留新字段时停止写回；两家真实 WebDAV 尚未验收。 |
| T21–T25 | ES256、Ed25519、按站停用、条件式选择、原生回退、UV 二次验证、默认零计数及可选递增、可验证的备份标志。 | 浏览器测试以真实 COSE 公钥验签，模拟网盘与认证加密备份恢复到 Helium。虚拟认证器验证回退，不等同实际 Hello/USB 或真实站点。 |
| T26–T30 | FIDO CXF 1.0 JSON、单独标识的密码保护 JWE、Bitwarden 可迁移 Passkey、KeePass KDBX/XML/CSV、1Password 1PUX、Proton JSON/ZIP 与受支持的 PGP ZIP。 | 公开合成 KDBX 3.1/4.0 样本通过口令导入；官方 KeePassXC CLI 生成的 4.1 加密库在两浏览器验签。错密、截断、超预算拒绝。未代签 KeePassXC-Browser 或其他厂商应用与外部网站的真实互通。 |
| T31–T35 | Google Authenticator 多图/迁移 URI、2FAS、Aegis、Raivo、andOTP、Stratum，另有 FreeOTP+ / WinAuth；Dashlane、NordPass、Enpass、LastPass CSV 自动识别，新增类型感知格式及 Kaspersky TXT，歧义退回手工映射。 | 有独立合成回归，以及 [2FAS、Aegis、andOTP、Stratum 公开夹具](agents/authenticator-backup-fixtures.md)；原生来源样本尚未齐备，不等同厂家或设备验收。 |
| T36 | Edge/Helium 的 MV3 生产 ZIP，检查清单、CSP、主 WASM 和按需模块。 | 解压候选包供试用。千条原生 Popup 冷开 `<50 ms` 未达，正式发布准出和真实站点/设备验收不能签收。 |

### 格式限制

- CXF 标准交换是 1.0 JSON；本项目文件密码包装的 JWE 不是标准 CXF 加密交换，接收端需明确支持该包装。
- Bitwarden 账号绑定加密 JSON 需在来源重新导出为支持的格式；不导入硬件绑定或没有可导出私钥的 Passkey。对无法确认的递增计数暂停取用，不标为可登录。
- 加密 KeePass 须为支持的口令 KDBX（不支持额外密钥文件或挑战响应）；KDF / 解压预算外直接拒绝。1PUX 与 Proton 只迁移允许的版本和可用字段；附件、源文件没提供的秘密及未知版本或加密外层不承诺保留。1Password CSV 的确切表头只有合成证据；没在 8 代客户端上验收。
- Ente 文件密码加密导入支持 v1，内存最多 1 GiB、加密封装最多 3 MiB，不支持云同步数据和应用数据库。资源不足时可能无法导入原生高内存档；无需降参，来源可选择文本导出。反向只导出带 `codeDisplay` 的文本。
- [工单索引末尾](development-tickets.md#架构与工单范围的差异)列出的其余额外格式和可选 RS256，不算已实现。

## 复现

```powershell
pnpm run build
pnpm --filter ./apps/extension zip
cargo test --workspace
pnpm run test:extension
node apps/extension/node_modules/typescript/bin/tsc -p apps/extension/tsconfig.json --noEmit
```

从 `apps/extension/.output` 解压 Chrome ZIP，在 Edge 或 Helium 的扩展管理页启用开发者模式，选择“加载解压缩的扩展”，目录必须包含 `manifest.json`。先用独立浏览器配置，不覆盖已有密码库。正式使用前另存应急恢复码与 `.vaultpack`；应急恢复码不能代替丢失的数据文件。

可把 `VAULT_EXTENSION_PATH` 指向同一个解压目录，再跑 `test:smoke`、`test:phase-2`、`test:autofill`、`test:migration`、`test:data-safety`、`test:sidepanel`、`test:passkeys`。`test:migration` 加 `VAULT_QR_NATIVE=1` 才会操作原生工具栏 Popup 并测到候选可操作且完成绘制；`VAULT_QR_FIRST=dark` 会在新配置中先扫暗码。`test:wakeup` 需可启动原生窗口，`VAULT_WAKE_ITEMS=1000` 另写 `test-results/wakeup-1000.json`。HTTP 可见预览只查界面，不作为浏览器扩展权限或数据证明。

`node scripts/test-passkeys.cjs --history-only` 只跑双端 WebDAV 历史恢复；不带参数时也会执行它。使用独立配置、本机 HTTP WebDAV 和双栈回环 RP，不连接真实网盘。

`node scripts/test-passkeys.cjs --retained-bitwarden-only` 使用当前构建的 WASM 复现旧版导入的保留字段，从加密备份走完整设置页启用和独立验签。`--proton-only <夹具目录>` 验证官方 WASM 生成的凭证，夹具见[来源与复现](agents/portable-migration-fixtures.md#proton-pass)。

`node scripts/test-authenticator-fixtures.cjs --ente` 各在独立进程跑一份 Ente 文件，避免复用已增长的 WASM 堆。`node scripts/test-phase-2.cjs` 从解压候选在 Edge、Helium 跑实际扩展的文本和加密迁移界面。

`node scripts/test-sync-lifecycle.cjs` 验证远端主密码轮换、重新配置本机包装及重装设备认领；使用相同的本机故障服务和独立配置。
加 `--backup-only` 则验证使用目标恢复码加入已有远端库，再合入独立 `.vaultpack`；只在用户显式启用写入并验证条件写后同步。

## 本机记录

- 归档：`test-results/Vault-2026-11-20-6043489c46a1-chrome.zip`，5,985,824 B。SHA-256：`6043489c46a1191d7cc417d16a80654c4963a38f61372fabbbfe186d2810315b`。解压目录：`test-results/release-unpacked-6043489c46a1`。
- MV3 清单、扩展页 CSP、`activeTab` 及可选 `privacy` 核对；生产清单无 `debugger`、`tabs`、`identity` 或 `<all_urls>`。主核 WASM **255,677 B**（预算 256,000 B）；重型迁移、同步、扫码和 Passkey 不进入主核、解锁或自动填充入口。
- Rust 54 项、Vitest 78 项、TypeScript 无错误。1,000 条完整合成凭证（含加密设备来源）快照 **123,752 B**（≤ 240,000 B）；单条变更 WAL **598 B**（≤ 600 B）。
- Edge `157.0.4341.60`、Helium `157.0.8103.78` 从同一解压包通过安装、二期、自动填充、迁移、数据安全、原生侧栏和 Passkey 回归。Passkey 用 COSE 公钥独立验签，覆盖两种算法、错密、Esc、锁库、Abort、导航、Edge 真实超时、默认/递增计数、虚拟认证器回退、独立主密码库合入、上传失败 `BS=0` 与认证副本 `BS=1`。实际扩展双端验证冲突页来源、错密零写、无变化重拉不使预览过期，以及确认双份后本机列表刷新、另一端收到两份。可见界面预览加载成功且无控制台或请求错误；窗口失焦后未完成进一步截图，交互结果来自真实扩展回归。
- 同包装载合成 Google Authenticator PNG：乱序还原、重复片去重；缺片、混批、损坏 Protobuf、超限及取消均不写入。确认后才导入两条；两浏览器的 TOTP 与独立 HMAC 结果一致，HOTP 从导入计数连续出码，普通详情不含种子。
- 1000×800 视口和 420 像素二维码，亮码和暗码分别使用新配置首次扫描。原生工具栏 Popup 点击到**可操作候选完成绘制**：Helium **109.1 / 121.6 ms**，均满足 T03 的 `<200 ms`；Edge **211.8 / 239.3 ms**，其中截图 **147.3 / 160.4 ms**。排除限流等待后的热扫描：Helium **100.5 / 127.7 ms**，Edge **102.0 / 104.4 ms**。无二维码、缺 `activeTab`、切页及取消都不会交付候选或写入凭证；仅选中也不会保存。
- 单条库每浏览器 10 次原生冷开：Edge Popup 中位数 **526.79 ms**，Helium **436.02 ms**；从新 Worker 时间原点计的恢复中位数 **58.00 / 54.50 ms**。
- 千条库每浏览器 10 次原生冷开：Edge Popup 中位数 **587.51 ms**（475.32–614.37 ms），Helium **581.10 ms**（480.40–670.92 ms）；恢复中位数 **70.90 / 65.20 ms**。最早启动 Worker 的样本为 **293.43 / 305.00 ms**。未通过 `<50 ms` Popup 或 `<5 ms` 恢复；`status` 冒烟时延不代替这两项。测量所用解压树的 SHA-256 为 `1d9e0b760dfb88c7b6a72859f83bbb98c5e654c28a525bdbb47f2b393fc6d937`。

[一期同机最小 MV3 对照](phase-1-status.md#t01-冷唤醒补测2026-11-19)的最快工具栏打开也约 430 ms，表明这台机器的冷 Worker 调度已占大头。没有把等待期间的骨架屏、预热 Worker 或修改起点计作通过。候选包未发布；未达性能门禁及需真实环境的验收项不关闭、不代签。

[后续冷开补测](cold-wake-diagnostics.md)独立记录了新构建、原生首屏计时和无后台对照；两项门槛仍未达。

### 恢复计数与 KeePassXC 候选（2026-11-20）

- ZIP：`test-results/Vault-2026-11-20-9708b904a0a1-chrome.zip`（5,994,963 B），SHA-256 `9708b904a0a160d89f6ee814eb3ec53750d33cf314f994148358dbc6586adf0b`。解压目录：`test-results/release-unpacked-9708b904a0a1`，52 个文件，树摘要 `4242e4427327aa1ad5d39b10457ab321b270576d34ce8d69e88a5fc4e0262bf7`。生产 MV3 `0.0.0` 清单、CSP 检查通过，主 WASM 255,677 B。相对冷开补测包只变了 CSV、Ente、迁移和同步 Worker；本轮未重复千条冷开，不能视为性能通过。
- Rust 57 项、Vitest 80 项、TypeScript 无错误。T18/T23 在已认证的历史快照和加密备份恢复链路采用同凭证可信最高计数：无证据暂停；有多份只保留一份可用，优先原本机条目。回收站可供证，不参与可用位置的优先级；重复导入按最终结果记账。纯 WASM 回归用真实加密历史复原 HOTP，并以原注册公钥验两种算法的计数和签名；默认零计数不写快照。这条测试不代表双端 WebDAV 历史发布已经签收。
- Edge `157.0.4341.60`、Helium `157.0.8103.78` 从同一解压树通过安装冒烟、二期、迁移、备份防丢、自动填充、原生侧栏和 Passkey 回归。原生 Popup 亮码首扫候选完成绘制：Edge 229.8 ms，Helium **108.3 ms**（T03 只以 Helium 的 `<200 ms` 为门槛）；这份包未单独重测暗码，先前暗码数据见[冷开补测记录](cold-wake-diagnostics.md)。
- T28 使用 Authenticode 验签有效的 KeePassXC CLI 2.8.0 写加密 4.1 文件，核对分组、密码历史、TOTP 和不透明用户句柄。两种 PKCS#8 PEM 写法及 StrongBox 字段优先级均已覆盖；Edge、Helium 从同一解压包导入后分别用原公钥通过 3 次本机 RP 验签，覆盖 ES256、Ed25519，不把源 `BS` 当目标备份证据。两种 AES-KDF 标识使用原 500 万轮上限，官方 128 MiB Argon2d Demo 在解密前按 96 MiB 预算拒绝。[样本来源和复现](agents/keepassxc-passkey-research.md#当前回归入口)。
- 规范轴审查确认厂商字段按来源限长、备份只协调相关凭证、浏览器测试只用合成数据和回环服务。规格轴将本机验签和真实网站/设备验收分开；实体设备、真实网盘及其它应用互通仍按约定未签收。

### 双端历史恢复候选（2026-11-20）

- ZIP：`test-results/Vault-2026-11-20-3723977d3a21-chrome.zip`（5,994,963 B），SHA-256 `3723977d3a21c374e556b08307df209badd7d59102d4f0c803249d361cf29510`。解压目录：`test-results/release-unpacked-3723977d3a21`，52 个文件，树摘要 `7abbf7b574d4ac97bd6f3cc50942adcdb52e221daaf2d194a90151604d4002fb`。和上一包相比仅 `background.js` 内容变化：历史列表和只读恢复等待全部请求完成后才清除连接凭据。生产 MV3 `0.0.0` 清单、CSP 通过，主 WASM 255,677 B。
- Rust 57 项、Vitest 80 项、TypeScript 通过。Edge `157.0.4341.60`、Helium `157.0.8103.78` 从同一解压目录通过冒烟、二期、迁移、备份防丢、填充、原生侧栏、Passkey 和官方 KeePassXC 夹具回归。两次 Passkey 启动在 Helium 过滤器仪表盘关闭时中断；改为从同一内置后台页读取原就绪条件后，全套通过。未关闭或跳过拦截器。
- T18 从正常建库和空闲压实生成历史。Helium 以当前主密码条件写发布新 epoch，Edge 重拉后逐条匹配恢复结果，旧主密码不能加入。预览、错密、过期确认、缺失或损坏历史，以及重放已被替代的 head 均不更改凭证或远端对象；服务端返回 `412` 时只清理本次尚未发布的快照。另验证只读配置可恢复到本机，后续同步不写网盘。
- T18/T23 在 Edge 用掉 HOTP 计数 0 及两种 Passkey 的计数 1，Helium 恢复后得到 RFC 4226 的计数 1 动态码、并用原公钥验两种算法的新挑战和计数 2。默认零计数断言不增加待备份变更，立即同步无 WAL 上传；缺可信计数暂停另有 Rust/WASM 覆盖。以上是合成凭证和本机服务证据，不替代真实第三方服务或实体认证器操作。
- 同包亮、暗码分别用新配置运行原生 Popup 首扫。可操作候选完成绘制：Helium **109.9 / 122.7 ms**，Edge **239.0 / 235.0 ms**；两项 Helium 实测达 T03 的 `<200 ms`。本轮不重测千条库冷开，仍引用[独立冷开记录](cold-wake-diagnostics.md)，正式发布门槛未达。

同步快照新增的来源记录在认证密文内，当前版可读没有来源的旧快照。旧客户端读不懂新字段时会停止同步写回；先升级各设备再试用新版同步。

### 主密码轮换与设备认领候选（2026-11-20）

- ZIP：`test-results/Vault-2026-11-20-383f3f37b3d4-chrome.zip`（5,995,074 B），SHA-256 `383f3f37b3d40d340f017d1bb38efc36f3b3aca72dcf611ecae990eb144c2012`。解压目录：`test-results/release-unpacked-383f3f37b3d4`，52 个文件，树摘要 `da40147b53f2f821322a53d048e0764c28282afa5f9c79adbfade67d8a2da552`。相对上一历史恢复候选只变 `background.js`；MV3 `0.0.0`、CSP、权限检查通过。主 WASM 未变，255,677 B，57 项 Rust 回归通过；最终 TypeScript 和 82 项 Vitest 通过。
- T15：已认证的新包装与待验证标记同一个 IndexedDB 事务提交，不消费未上传 WAL。模拟 Worker 在事务完成后、旧会话清理前退出，含新标记或旧版缺字段的两种记录都不恢复旧会话；不返回条目、拒绝旧密码且不改本机密文。中断点使用真实 WASM 和持久化状态夹具，不是实机断点强杀。
- Edge `157.0.4341.60` 与 Helium `157.0.8103.78` 从同一解压包通过安装冒烟、主密码轮换、设备认领与历史恢复。T15 的改密码和恢复码重置均只条件更新 `head.bin`；两个客户端锁定期间零新 WebDAV 请求。Helium 重启保留待验证标记和一笔本地 WAL，验证新主密码后续传给 Edge，旧包装、旧口令及旧头均被拒绝；用新主密码重新配置 PIN 和合成 PRF 后可用。合成 PRF 不等同实体 Hello。
- T16：同系统、同浏览器只提示候选，不自动认领。错密不写远端；通过主密码认领后保留原逻辑身份和初次登记时间。原实例仍在线，各自的 WAL 使用不同短码，旧对象不变，各端收到两份编辑且不重复。设备别名与标识不出现在远端文件名或对象明文字节；移除设备元数据不删凭证、不宣称撤销密钥。
- 同系列的 `c236bd5459ff` 阶段包在双端各测 10 次千条库原生冷开：Popup DOM 中位数 Edge **584.27 ms**、Helium **586.79 ms**；WASM 恢复 **71.90 / 68.10 ms**，仍超出 `<50 / <5 ms`。报告为 `test-results/wakeup-1000.key-update-c236bd5459ff.json`。相对[此前补测](cold-wake-diagnostics.md)，差异主要出现在 Worker 时间原点之前；两边认证与解码仍约 17 ms。这不是同次 A/B，不能从两批结果归因。最终包未重复这一同机测量，仍不签收 T01/T36 性能。

### 2FAS 备份兼容候选（2026-11-20）

- ZIP：`test-results/Vault-2026-11-20-fd83a6c5d193-chrome.zip`（5,995,533 B），SHA-256 `fd83a6c5d1938dc071460fc2718bdcc5a8144bbcbceda987cc33dcd27d7fca69`；解压目录 `test-results/release-unpacked-fd83a6c5d193`，52 个文件，树摘要 `09d3b55bcb8e7cd3d1ea7b275edefd27219949487ad66af9ad5763ffd754079d`。相对轮换候选只变 CSV、Ente 与迁移 Worker；修复的导入 WASM（2,396,643 B）按内容哈希确认只位于这三个按需 Worker。生产 MV3、CSP 及权限通过，主核未变（255,677 B）。Rust 57 项，Vitest 86 项，TypeScript 通过。
- T32：原应用的 256 字节盐不再误拒；旧版没有 OTP 类型的条目不再被外层服务类型挡掉。错密、超限、缺段及任一段认证失败仍拒绝，畸形 OTP 元数据不会变成可用的 TOTP。6 份 Aegis 上游公开 `.2fas`（schema 2/3/4 明文、加密）逐条比对账号、参数和独立出码。Aegis、andOTP、Stratum 的另外 5 个夹具经相同测试入口验证解析；原样本分组和未测变体的边界见[复现文档](agents/authenticator-backup-fixtures.md)。
- Edge `157.0.4341.60`、Helium `157.0.8103.78` 从本解压包通过迁移回归：公开 2FAS v4 加密样本预览和错密不写库，确认导入 5 条，以原计数对照 3 个 HOTP，无种子及重复。中间包 `b460fb791b2a` 另通过双端二期、备份防丢；随后只收紧畸形 OTP 字段，最终包不把前一包的二期证据当成同包全量准出。

### 首装备份恢复候选

- ZIP：`test-results/Vault-2026-11-20-0c3c9376ab60-chrome.zip`（5,997,922 B），SHA-256 `0c3c9376ab609137078d96d2c8675adceb19f0f958d2f365b8d742fe7c38db75`。解压目录 `test-results/release-unpacked-0c3c9376ab60`，52 个文件，树摘要 `4221e4b4fdaed86fe2a5b261121f91c8014826106610c9389b86bbe626acccdc`。MV3 版本 `0.0.0`、清单与主核字节未变，CSP 及权限检查通过。主核 **255,677 B**；同步与迁移仍按需加载。Rust **57** 项、Vitest **89** 项、TypeScript、WASM 检查和生产 ZIP 均通过。
- T08：首装自动开一个标签，WebDAV 优先，默认坚果云，可选 Koofr 和自定义；更新不弹。Edge `157.0.4341.60` 和 Helium `157.0.8103.78` 在回环服务实测不存在、空、残缺、已有及不可达。四个目录探测各只发一次 `PROPFIND`，不留下连接凭据、不创建对象或目录。后台回归证实重启后 `404` 不解除 `429` 熔断，手动读到有效目录后才恢复。
- 首装可直接选择本地备份恢复。用新主密码创建独立库、保存新恢复包、再进入既有预览并确认合入。双端测试了下载完成、锁库隐藏恢复码、状态读取失败后重试、错密和取消零写入、二次验证及独立主密码。后台模拟会话清理异常时仍通知面板清除恢复码，该 Worker 的后续读取保持拒绝。可见 HTTP 预览加载首屏且无控制台错误；后续焦点操作失败，交互证据来自真实扩展。
- T10/T13：仅已验证的网盘目标库可用其恢复码验证 `.vaultpack` 的预览与合入，两个阶段都复验。Edge 生成独立库备份，Helium 用正确的目标恢复码加入；源恢复码和文件密码不能证明目标身份。错密、预览和取消不改条目，确认后保留目标库身份、密钥版本和主密码。只读期间保持远端字节不变，显式写验证后才同步给 Edge；整库导出仍只认当前主密码。
- T09 旧格式：从同步引入前的 [8ac6c4d](https://github.com/IZRINO/vault-extension/commit/8ac6c4d4238097be929a94e0bd8cd68e85b1d0c6) 重建旧核心 WASM（SHA-256 `3f6c113fecf9beac80ad6cfb2568f52eb1c3e2b0050cf24df3c9b2036882b3d2`），实际导出合成备份后用当前同步 WASM 预览、合入，保留标题、备注、标签、置顶和二次验证；错文件密码拒绝。复现：将该提交用 `git archive` 解到临时目录，运行 `wasm-pack build <临时源码>/crates/vault-core --target web --release`，再在当前仓库运行 `node scripts/test-legacy-vaultpack.cjs <旧版 pkg 目录>`。
- T34：Raivo 原格式字符串 `pinned` 不再丢失。[兼容夹具](agents/authenticator-backup-fixtures.md#raivo)用独立 7-Zip 生成合成 AES ZIP，并对照 TOTP/HOTP；不算原生 iOS 导出验收。
- 在同一解压包和新浏览器配置分别测原生 Popup 亮码／暗码首扫候选完成绘制：Helium **122.5 / 126.6 ms**，均低于 200 ms；Edge 亮码 **210.5 ms**，不是 Helium 门槛。两轮迁移回归亦通过公开 2FAS v4 加密样本。
- **同包功能回归通过**：安装、备份防丢、网盘恢复码合入、原生侧栏、自动填充、二期、迁移（双端亮码及 Helium 暗码）、主密码轮换／设备认领、Passkey／历史恢复，十轮均退出 0。KeePassXC CLI 2.8.0 样本在两款浏览器均通过原公钥验签。阶段包曾在 Helium 内置过滤器启动检测处超时；最终夹具在原等待期限内重新查找后台目标，仍要求内置拦截器到达就绪状态，没有停用过滤器。

千条原生 Popup 冷开与已认证 WASM 恢复仍无达标证据，见[冷开复测与诊断](cold-wake-diagnostics.md)。实体设备、真实站点／网盘及仍缺独立来源的第三方互通按用户要求跳过人工验收。未上架、未推送、未改工单开关状态。

### 网盘熔断恢复候选

- ZIP：`test-results/Vault-2026-11-20-153b69429618-chrome.zip`（5,998,379 B），SHA-256 `153b69429618c36fb0151dea339dc3eca626dfa3023864f1c3dcce436fd6db31`。解压目录：`test-results/release-unpacked-153b69429618`，52 个文件。MV3 `0.0.0` 的生产权限、CSP 和主核心 `assets/background.wasm` 与上一候选字节相同；主核心 **255,677 B**。Rust **57** 项、Vitest **94** 项、TypeScript 和生产打包通过。
- T08：`401/403/429` 暂停状态和告警角标跨后台重启保留。Koofr 已保存连接需更换应用专用密码，非 Koofr 允许在修正权限后或限流结束时手动重测。不同步到仅由其他目录测试出的端点；`404` 不解除暂停。后台测试验证解锁后的首次轮询在暂停时不发请求，手动只读测试成功后自动重排轮询，并用更新后的账号访问原目录。恢复不会顺带启用上传。
- 同包 Edge `157.0.4341.60`、Helium `157.0.8103.78` 通过 `node scripts/smoke-extension.cjs`：回环服务返回 `401` 后，重测旧配置不发送请求；更换应用密码后只发一次 `PROPFIND`，不改目录和对象，连接配置仍加密保存。另通过 `node scripts/test-sync-lifecycle.cjs --backup-only`：Helium 重开设置仍显示只读，显式验证写入后提示消失，Edge 收到合入的条目。
- 本包仅重验受熔断与状态变更影响的路径。十轮功能回归与 Helium 亮暗首扫为[上一候选](#首装备份恢复候选)的结果，千条冷开两项仍未达 v1.4 门槛。真实供应商和系统设备未签收；未推送、未上架、未改 Issues。

### 外部夹具

`pnpm run test:kdbx <夹具目录>` 读取固定摘要的公开合成文件，不把第三方样本纳入仓库。正例来自 [keepass-rs 测试库](https://github.com/sseemayer/keepass-rs/tree/26cb076aa5cbbe36e175326dfdaf5a19799c4085/tests/resources)，高 KDF 成本拒绝样本来自 [Stratum 测试库](https://github.com/stratumauth/app/tree/86c4e7c520ce30a21fa2887f1ae484442f06225d/Stratum.Test/data)。

设备名默认值在可用时用 [Edge 的平台版本提示](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/how-to-detect-win11)区分 Windows 版本，缺少该提示则使用通用名称。显示名不参与身份判定。

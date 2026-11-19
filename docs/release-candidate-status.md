# Vault Extension 候选包验证记录

2026-11-20。对应[架构 v1.4](../密码管理器浏览器插件-技术架构与选型文档.md)与[工单 T01–T38](development-tickets.md)。生产 ZIP 不等于正式准出；不代签，也不把模拟证据当作系统设备、第三方服务或应用互通的证据。

当前可安装包见[主密码轮换与设备认领候选](#主密码轮换与设备认领候选2026-11-20)。正式准出仍未通过。

## 实现范围

| 工单 | 本轮实现或继承 | 证据与边界 |
| --- | --- | --- |
| T01–T07、T37、T38 | 原生侧栏、填充/保存/改密、截图扫码、CSV 拖拽与键盘、Bitwarden 与 Ente 文本迁移；整库导出验证当前主密码，明文另确认；日常 TOTP/Steam 返回码、HOTP 严格落盘后返回码，编辑才读种子。 | 扫码只绑定点击时的标签页；切换、导航或取消会让候选失效。双浏览器本地靶场覆盖填充授权、备份确认和 OTP 路径。真实网站/原生右键、Ente 与 Bitwarden 官方应用、实际系统锁屏和实体 Hello 未验证。T01 已按历史决定关闭，不代表性能通过。 |
| T08–T12、T19 | 坚果云/Koofr 预设、只读判库、条件写探测、加入/建库、零条目及批量删除保护、2.5 秒防抖的不可变加密 WAL、熔断、显式开启时差补偿。 | 故障注入覆盖假 ETag、旧 ETag、重启、重放、熔断、锁库零新请求、时钟偏差。同步是最终一致，不能保证两台离线设备的 HOTP 互斥。 |
| T13–T18、T20 | 三方字段合并、加密待裁决区、全页裁决、落选密码历史、主密码旋转、设备认领和加密来源记录、滚动五份历史、历史预览/恢复、异库合入。 | 一个离线登录命中多个远端候选时一同展示；更晚的重叠草稿加密留在本机，无关项仍可同步。双份继承二次验证，同一递增凭证只保留一份可用计数。自动覆盖并发 WAL、条件提交、两处压实中断、30 天回收站边界、历史重放拒绝、计数恢复、不同身份合入。找不到祖先或不能保留新字段时停止写回；两家真实 WebDAV 尚未验收。 |
| T21–T25 | ES256、Ed25519、按站停用、条件式选择、原生回退、UV 二次验证、默认零计数及可选递增、可验证的备份标志。 | 浏览器测试以真实 COSE 公钥验签，模拟网盘与认证加密备份恢复到 Helium。虚拟认证器验证回退，不等同实际 Hello/USB 或真实站点。 |
| T26–T30 | FIDO CXF 1.0 JSON、单独标识的密码保护 JWE、Bitwarden 可迁移 Passkey、KeePass KDBX、1Password 1PUX、Proton JSON/ZIP。 | 公开合成 KDBX 3.1/4.0 样本通过口令导入；官方 KeePassXC CLI 生成的 4.1 加密库在两浏览器验签。错密、截断、超预算拒绝。未代签 KeePassXC-Browser 或其他厂商应用与外部网站的真实互通。 |
| T31–T35 | Google Authenticator 多图/迁移 URI、2FAS、Aegis、Raivo、andOTP、Stratum；Dashlane、NordPass、Enpass、LastPass CSV 自动识别，歧义退回手工映射。 | 独立算法生成的合成测试核对 TOTP/HOTP、批次、错密和重复，原生应用导出样本尚未齐备；不能等同厂家验收。 |
| T36 | Edge/Helium 的 MV3 生产 ZIP，检查清单、CSP、主 WASM 和按需模块。 | 解压候选包供试用。千条原生 Popup 冷开 `<50 ms` 未达，正式发布准出和真实站点/设备验收不能签收。 |

### 格式限制

- CXF 标准交换是 1.0 JSON；本项目文件密码包装的 JWE 不是标准 CXF 加密交换，接收端需明确支持该包装。
- Bitwarden 账号绑定加密 JSON 需在来源重新导出为支持的格式；不导入硬件绑定或没有可导出私钥的 Passkey。对无法确认的递增计数暂停取用，不标为可登录。
- KeePass 须为支持的口令 KDBX（不支持额外密钥文件或挑战响应）；KDF / 解压预算外直接拒绝。1PUX 与 Proton 只迁移允许的版本和可用字段；附件、源文件没提供的秘密、加密外层及未知类型不承诺保留。
- [原工单末尾](development-tickets.md#架构有目标分期未定归属的差异)的 Ente 加密 JSON、额外导出格式、提醒、RS256 等仍是未排期项，不算已实现。

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

`node scripts/test-sync-lifecycle.cjs` 验证远端主密码轮换、重新配置本机包装及重装设备认领；使用相同的本机故障服务和独立配置。

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

### 外部夹具

`pnpm run test:kdbx <夹具目录>` 读取固定摘要的公开合成文件，不把第三方样本纳入仓库。正例来自 [keepass-rs 测试库](https://github.com/sseemayer/keepass-rs/tree/26cb076aa5cbbe36e175326dfdaf5a19799c4085/tests/resources)，高 KDF 成本拒绝样本来自 [Stratum 测试库](https://github.com/stratumauth/app/tree/86c4e7c520ce30a21fa2887f1ae484442f06225d/Stratum.Test/data)。

设备名默认值在可用时用 [Edge 的平台版本提示](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/how-to-detect-win11)区分 Windows 版本，缺少该提示则使用通用名称。显示名不参与身份判定。

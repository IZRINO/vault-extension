# Vault Extension 候选包验证记录

2026-11-19。对应[架构 v1.4](../密码管理器浏览器插件-技术架构与选型文档.md)与[工单 T01–T38](development-tickets.md)。生产 ZIP 不等于正式准出；不代签，也不把模拟证据当作系统设备、第三方服务或应用互通的证据。

## 实现范围

| 工单 | 本轮实现或继承 | 证据与边界 |
| --- | --- | --- |
| T01–T07、T37、T38 | 原生侧栏、填充/保存/改密、截图扫码、CSV 拖拽与键盘、Bitwarden 与 Ente 文本迁移；整库导出验证当前主密码，明文另确认；日常 TOTP/Steam 返回码、HOTP 严格落盘后返回码，编辑才读种子。 | 双浏览器本地靶场覆盖填充授权、备份确认和 OTP 路径。真实网站/原生右键、Ente 与 Bitwarden 官方应用、实际系统锁屏和实体 Hello 未验证。T01 已按历史决定关闭，不代表性能通过。 |
| T08–T12、T19 | 坚果云/Koofr 预设、只读判库、条件写探测、加入/建库、零条目及批量删除保护、2.5 秒防抖的不可变加密 WAL、熔断、显式开启时差补偿。 | 故障注入覆盖假 ETag、旧 ETag、重启、重放、熔断、锁库零新请求、时钟偏差。同步是最终一致，不能保证两台离线设备的 HOTP 互斥。 |
| T13–T18、T20 | 三方字段合并、加密待裁决区、落选密码历史、主密码旋转、设备认领、滚动五份历史、历史预览/恢复、异库合入。 | 自动覆盖并发 WAL、条件提交、两处压实中断、30 天回收站边界、历史重放拒绝、计数恢复、不同身份合入。恶意或不兼容服务、找不到祖先、重叠草稿无法安全裁决时暂停写入，保留本机密文与草稿。两家真实 WebDAV 尚未验收。 |
| T21–T25 | ES256、Ed25519、按站停用、条件式选择、原生回退、UV 二次验证、默认零计数及可选递增、可验证的备份标志。 | 浏览器测试以真实 COSE 公钥验签，模拟网盘与认证加密备份恢复到 Helium。虚拟认证器验证回退，不等同实际 Hello/USB 或真实站点。 |
| T26–T30 | FIDO CXF 1.0 JSON、单独标识的密码保护 JWE、Bitwarden 可迁移 Passkey、KeePass KDBX、1Password 1PUX、Proton JSON/ZIP。 | 合成样本验出码和登录签名；独立公开的 KDBX 3.1/4.0 样本通过口令导入，错密/截断/超预算拒绝。KeePassXC Passkey、历史/OTP 的原生样本及其他厂商官方应用互通不代签。 |
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

可把 `VAULT_EXTENSION_PATH` 指向同一个解压目录，再跑 `test:smoke`、`test:phase-2`、`test:autofill`、`test:migration`、`test:data-safety`、`test:sidepanel`、`test:passkeys`。`test:wakeup` 需可启动原生窗口，`VAULT_WAKE_ITEMS=1000` 另写 `test-results/wakeup-1000.json`；`VAULT_QR_FIRST=dark` 会在新配置中先扫暗码。HTTP 可见预览只查界面，不作为浏览器扩展权限或数据证明。

## 本机记录

- 归档：`test-results/Vault-2026-11-19-8ecfb8cd63d1-chrome.zip`，5,950,435 B。SHA-256：`8ecfb8cd63d1d2c27c0d7b35d02f1646c5b32ea233439983d8283c6b46fa1302`。解压目录：`test-results/release-unpacked-8ecfb8cd63d1`。
- MV3 清单、扩展页 CSP、`activeTab` 及可选 `privacy` 核对；生产清单无 `debugger`、`tabs`、`identity` 或 `<all_urls>`。主核 WASM **255,563 B**（预算 256,000 B）；重型迁移、同步、扫码和 Passkey 不进入主核、解锁或自动填充入口。
- Rust 53 项、Vitest 72 项、TypeScript 无错误。1,000 条完整合成凭证加密快照 **118,632 B**（≤ 240,000 B）；单条变更 WAL **598 B**（≤ 600 B）。
- Edge `157.0.4341.60`、Helium `157.0.8103.78` 从同一解压包通过安装、二期、自动填充、迁移、数据安全、原生侧栏和 Passkey 回归。Passkey 用 COSE 公钥在测试端验签，覆盖两种算法、错密、Esc、锁库取消、默认/递增计数、虚拟认证器回退、独立主密码库合入、上传失败 `BS=0` 与认证副本 `BS=1`。
- 使用 1000×800 视口和 420 像素二维码，亮码/暗码分别用新配置首次扫描。请求到有效结果的耗时：Edge **113 / 131 ms**，Helium **153 / 168 ms**。排除限流等待的后续扫描为 Edge **120 / 92 ms**、Helium **102 / 91 ms**（首次亮/暗对应）。已验证无二维码和未授予 `activeTab` 均不返回结果；这些数字不含 Popup 最终绘制，不代替 T03 严格呈现验收。
- 单条库每浏览器 10 次真实冷开：Edge Popup 中位数 **506.89 ms**，Helium **478.79 ms**；恢复中位数 **52.00 / 54.75 ms**。早期原生 CDP 有一次读取超时，改为在门槛时间之后同步读取页面内部标记后成功。
- 千条凭证每浏览器 10 次真实冷开：Edge Popup 中位数 **574.83 ms**（469.46–610.99 ms），Helium **580.56 ms**（480.01–620.74 ms）；从新 Worker 时间原点计的恢复中位数为 **66.20 / 65.35 ms**。最快样本仍在约 292 ms 后才启动 Worker。没有通过 `<50 ms` Popup 或 `<5 ms` 恢复硬指标；`status` 冒烟时延不代替这两项测量。

[一期同机最小 MV3 对照](phase-1-status.md#t01-冷唤醒补测2026-11-19)的最快工具栏打开也约 430 ms，表明这台机器的冷 Worker 调度已占大头。没有把等待期间的骨架屏、预热 Worker 或修改起点计作通过。候选包未发布，工单原状态与依赖保留。

### 外部夹具

`pnpm run test:kdbx <夹具目录>` 读取固定摘要的公开合成文件，不把第三方样本纳入仓库。正例来自 [keepass-rs 测试库](https://github.com/sseemayer/keepass-rs/tree/26cb076aa5cbbe36e175326dfdaf5a19799c4085/tests/resources)，高 KDF 成本拒绝样本来自 [Stratum 测试库](https://github.com/stratumauth/app/tree/86c4e7c520ce30a21fa2887f1ae484442f06225d/Stratum.Test/data)。

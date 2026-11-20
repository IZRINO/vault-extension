# 千条库原生 Popup 冷开补测

2026-11-20，本机 Windows。[T01](https://github.com/IZRINO/vault-extension/issues/1) 和 [T36](https://github.com/IZRINO/vault-extension/issues/36) 的补测，不替代[候选包的功能及准出记录](release-candidate-status.md)。

## WASM 恢复归因

从原候选 `3a2fa7b7d66f` 各 10 个冷开样本拆段，中位数如下。后台入口、准备入口和 WASM 就绪均从 Worker 时间原点累计，不能把 `wasm-loaded` 的时刻当成单独的编译耗时。

| 路径 | Edge | Helium |
| --- | ---: | ---: |
| 工具栏动作 → Popup 发出第一个 `open` | 377.45 ms | 363.70 ms |
| 工具栏动作 → Worker 时间原点 | 380.00 ms | 366.00 ms |
| Worker 时间原点 → 后台入口 | 17.15 ms | 17.00 ms |
| Worker 时间原点 → 开始准备恢复 | 39.35 ms | 43.85 ms |
| Worker 时间原点 → WASM 就绪 | 50.95 ms | 51.50 ms |
| `restore_from_session` 前后时标差 | 18.30 ms | 16.80 ms |

保留函数名的优化构建用于 CPU 采样，热点是 Zstd 解压，尤其是反向位读取；BLAKE3 和 XChaCha20 也占一部分。优化只改变满 8 字节时的读取方式，字不足仍补零。没有改压缩格式、解压上限、快照认证、锁库条件或 WASM 加载时机。回填读取窗口的试验没有额外收益，未保留。

Node `v26.13.1` 对照先在父进程生成一份千条合成库，再用同一密钥、包装、头和密文在**独立进程**交错采样，每臂 20 次。独立进程避免原版复用夹具生成时的 V8 编译结果。计时后核对每次恢复的完整摘要指纹。

| WASM | 初始化模块中位数 | 首次 `restore_from_session`（最短 / 中位数 / 最长） | 主核大小 |
| --- | ---: | ---: | ---: |
| 原候选同字节 | 1.215 ms | 16.707 / 17.098 / 17.491 ms | 255,677 B |
| 满字直接读取 | 1.212 ms | 15.751 / 16.171 / 18.660 ms | 255,662 B |

首次调用中位数缩短 **0.927 ms**，不表示每个样本都更快。另一轮禁用 V8 惰性编译，原版模块初始化中位数增加约 4.6 ms，首次调用变短，初始化加恢复仍约 17 ms；不能把编译前移当作恢复达标。以上都是独立诊断，不包含浏览器刚启动 Worker 时的调度、存储或原生 Popup，也不替代 `<5 ms` / `<50 ms` 门禁。原始 A/B 为 `test-results/restore-probe/paired-default.json`。

### 最小 Worker 存储对照

剥除 Vault 业务、WASM 与工具栏 Popup，在普通扩展页面发送消息，触发已停止的最小 MV3 Worker。等待 `TRUSTED_CONTEXTS` 设置完成，再并发读合成的 `storage.session`、`storage.local`、IndexedDB 与 `idle`。两浏览器各 10 次，从 Worker 时间原点计时：

| 浏览器 | 首行脚本最短 / 中位数 | 读齐最短 / 中位数 |
| --- | ---: | ---: |
| Edge `158.0.4370.33` | 4.30 / 4.55 ms | 6.90 / 7.15 ms |
| Helium `157.0.8103.78` | 4.10 / 4.45 ms | 6.50 / 6.95 ms |

这批样本的系统状态均为 `locked`。此对照只说明本机即使不做认证与解码，安全存储路径仍有数毫秒开销；它不是其他机器或解锁桌面的性能下限。新 ZIP `8a016565deff` 的解锁库冷开在准备夹具时因系统锁库中止，没有产生新样本。另用同一 ZIP 在当前锁定状态验证：重启 Worker 后两端都加载 WASM、清除合成会话、拒绝返回列表，没有认证恢复时标。此验证未制造实体锁屏动作，不替代现场验收。本机证据：`test-results/restore-probe/worker-floor-1795148290787.json`、`test-results/release-checks-8a016565deff/locked-desktop.json`。

## Vault 0.1.0 前一候选包冷开复测

生产 ZIP `3a2fa7b7d66f`。52 个解压文件逐字节与 ZIP 内文件一致，冷开脚本按路径和内容计算的树 SHA-256 为 `02388a5bba6880b74749ab31a4064a50a94f4a3717aac1e45e75e01e93a1278f`。Edge `158.0.4370.33`、Helium `157.0.8103.78` 各完成 10 个样本，每库 1,000 条合成凭证。

| 浏览器 | 从工具栏到列表 DOM（最短 / 中位数 / 最长） | WASM 恢复（最短 / 中位数 / 最长） |
| --- | --- | --- |
| Edge | 424.59 / 556.23 / 670.82 ms | 49.50 / 72.00 / 119.40 ms |
| Helium | 417.19 / 548.50 / 702.97 ms | 53.50 / 69.20 / 120.00 ms |

- 两端各 10 个样本均未达到 `<50 ms` Popup DOM 或 `<5 ms` WASM 恢复；命令保存报告后以性能断言退出。仅 Worker 时间原点之前的耗时中位数就是 380.00 / 366.00 ms，WASM 内部认证和解码中位数为 18.30 / 16.80 ms。
- 同机同版浏览器各 10 次无 Worker、无权限的最小 MV3 对照，原生工具栏动作到执行首脚本最短 265.62 / 255.84 ms，操作就绪最短 266.52 / 256.84 ms。这是 CDP 原生动作的测量，不是物理点击，也不是其他硬件上的下限。
- 修正测试夹具：只监听 `page` 目标事件可能漏报 Popup，改为直接查询浏览器目标；每个样本使用新的动作标签页，在停 Worker 前等待窗体稳定。每次确认 Worker 已停才触发原生工具栏动作，检查恢复时间及列表提交顺序。没有预热、改变计时起点或修改包内代码。
- 本机证据：`test-results/wakeup-1000.rc-3a2fa7b7d66f.json`、`test-results/wakeup-popup-floor-1795146360897.json`。复现时指向 `test-results/release-unpacked-3a2fa7b7d66f`，设置 `VAULT_WAKE_ITEMS=1000`、`VAULT_WAKE_SAMPLES=10`、`VAULT_WAKE_REPORT_LABEL=rc-3a2fa7b7d66f`，运行 `node scripts/test-wakeup.cjs`。

## 早期生产包复测

Edge `157.0.4341.60`、Helium `157.0.8103.78`。

- ZIP：`test-results/Vault-2026-11-20-0020ce897c36-chrome.zip`，5,986,049 B。SHA-256：`0020ce897c36ff7ae95efd0dae00db90f8e40398cb8d494ed8bf59c56458567c`。解压目录：`test-results/release-unpacked-0020ce897c36`；解压树摘要：`5ffd748de830b892786a5f7490f3afb827a38182cd03e5e63f5e3eff441b7e10`。主 WASM 未变，255,677 B。
- 1,000 条合成凭证；每次先停后台，再触发原生扩展工具栏动作，每浏览器 10 次。Popup 从动作计时到条目 DOM 提交，随后检查合成条目可见、启用且中心命中；WASM 从本次冷 Worker 时间原点计时到已认证快照恢复完成。额外记录双 `requestAnimationFrame`，它跨过一次绘制机会，不保证像素已经上屏，且不替代 DOM 门槛。
- TypeScript、Vitest 79 项、生产打包及同包双浏览器冒烟、二期、自动填充、迁移、数据安全、原生侧栏和 Passkey 回归通过。主 WASM 与前一候选字节相同。新增的锁库竞态测试验证：即使后台已计算出摘要，在续期尚未完成时锁库，也不会返回摘要。千条列表另在扩展标签页验证搜索、32 条分页、屏外条目聚焦、Enter 打开详情；不是实体键盘在原生 Popup 上的签收。
- 同包亮、暗码分别在新配置中测量，原生候选绘制 Edge 237.4 / 237.6 ms，Helium **108.0 / 124.1 ms**，后者符合 T03 的 `<200 ms`。Passkey 回归最初在 Helium 加载本机验证页时超时，服务端零请求；隔离对照发现 `localhost` 连接 `::1`。夹具分别监听 `::1` 和 `127.0.0.1` 后，真实浏览器跨端签名、备份恢复和虚拟认证器回退通过。不改生产权限、RP、原生回退或远端同步路径。

| 浏览器 | 从工具栏到列表 DOM（最短 / 中位数 / 最长） | 双帧中位数 | WASM 恢复（最短 / 中位数 / 最长） |
| --- | --- | --- | --- |
| Edge | 476.58 / 489.15 / 595.87 ms | 503.15 ms | 64.10 / 65.75 / 74.80 ms |
| Helium | 472.84 / 488.08 / 616.27 ms | 501.93 ms | 65.10 / 70.15 / 84.80 ms |

两项门槛在两浏览器均未通过。本组仅 WASM 内部认证和解码中位数就为 17.10 / 16.55 ms，从前端应用开库回复到 DOM 提交另需 93.35 / 96.85 ms。保留浏览器安全设置生效前仅并行编译静态 WASM、后台会话续期与摘要并行；不提前读取密钥，不绕过锁库检查。同步挂载 React、强制同步提交首条结果和列表布局隔离都未得到稳定收益，未保留。

## 对照与限制

- 无权限、无 Worker、只有 HTML 和极小外部脚本的 MV3 Popup，使用相同原生工具栏动作。各 10 次中，首条脚本执行最短 Edge **287.77 ms**、Helium **296.54 ms**；按钮绑定就绪最短 **288.47 / 297.44 ms**，以程序点击验证绑定。这不是物理点击，不代表其他设备或浏览器版本的普遍下限。
- Edge 独立启动对照：同一最小扩展和启动参数，每组 5 次，后置读取计时；不连接 Playwright 时首脚本最短 / 中位数 **187.27 / 209.02 ms**，另连 Playwright 时 **183.93 / 222.37 ms**。这不能证明完全没有自动化开销，但等待在不连接 Playwright 的组仍存在，自动附加不足以解释这次超时。
- 最终构建的 Edge 诊断轨迹中，一次样本从应用回复到列表 DOM 为 90.63 ms，最长的单段布局耗时 44.67 ms（`test-results/wakeup-1000.final-trace.json`）。这是单样本定位，不作门禁或提速证据。没有用骨架、预热、`status` 回复或改计时起点计作通过。

## 复现与本机证据

在根目录，以 `VAULT_EXTENSION_PATH` 指向上述解压树，设置 `VAULT_WAKE_ITEMS=1000`、`VAULT_WAKE_SAMPLES=10`、`VAULT_WAKE_REPORT_LABEL=cold-followup`，运行 `node scripts/test-wakeup.cjs`；解压路径和解压树 SHA-256 会记录于 `test-results/wakeup-1000.cold-followup.json`。`node scripts/probe-popup-floor.cjs` 生成带时间戳的无后台对照报告；本次文件为 `test-results/wakeup-popup-floor-1795112072342.json`。Edge 独立 A/B 的本机脚本是 `test-results/probe-popup-debugger-ab.cjs`，报告是 `test-results/wakeup-popup-debugger-ab-1795113649479.json`。这些是本机记录，不把浏览器临时配置或样本库提交到仓库。

在另一台电脑复测时，用最新 [候选包](release-candidate-status.md#当前候选包-010) 的解压目录替换 `VAULT_EXTENSION_PATH`，设 `VAULT_WAKE_ITEMS=1000`、`VAULT_WAKE_SAMPLES=10` 和一个新的 `VAULT_WAKE_REPORT_LABEL`，保持桌面解锁、不要切走浏览器窗口。如果浏览器安装路径与脚本默认值不同，设置 `VAULT_BROWSER_PATH` 为该浏览器可执行文件，分别运行 `node scripts/test-wakeup.cjs edge` 或 `node scripts/test-wakeup.cjs helium`，每次用不同的报告标签。脚本会先保存 JSON 再判定门槛，不会改用户现有库。

如只定位渲染慢段，设置 `VAULT_WAKE_TRACE=1` 并给一个独立报告标签；首样本会录制 Chromium 轨迹，只写耗时摘要，不作为准出测量。

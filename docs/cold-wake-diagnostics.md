# 千条库原生 Popup 冷开补测

2026-11-20，本机 Windows，Edge `157.0.4341.60`、Helium `157.0.8103.78`。这是 [T01](https://github.com/IZRINO/vault-extension/issues/1) 和 [T36](https://github.com/IZRINO/vault-extension/issues/36) 的补测，不替代[原候选包的功能及准出记录](release-candidate-status.md)。

## 生产包复测

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

如只定位渲染慢段，设置 `VAULT_WAKE_TRACE=1` 并给一个独立报告标签；首样本会录制 Chromium 轨迹，只写耗时摘要，不作为准出测量。需要新的设备或浏览器构建上的同口径证据，才能说明原生路径是否能满足门槛。

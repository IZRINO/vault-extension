# 未提交实现与工单核对 · 2026-11-26

基线为 `ce08fab9ca8ca0c3a1331340ef12d986aceaf277` 对当前工作区，含未跟踪的本机登录框标记。已读取 [GitHub Issues](https://github.com/IZRINO/vault-extension/issues) 中全部 50 个工单的正文与评论，直接对照本批涉及的 14 个审计项，以及第五期已经启动的本机功能。工单开放不等于功能未实现，本地回归通过也不等于第三方应用、实体设备或正式发布已签收。[原始审计](repository-audit-2026-11-21.md)保留原样。

## Standards：规范与边界

- **日常取码不广播可复用的秘密。** 后台只广播一次性工作编号；计算输入只在浏览器核验离屏文档身份后，以响应形式交给该文档，结果只返回发起的后台任务。Edge 的离屏发送者可能没有 `documentId`：这时必须核实相同精确地址只有一个扩展上下文，且确为离屏页。锁库、失败及来源不明确时不会回退到广播输入。见 [ADR-0001](adr/0001-secret-use-and-export.md)、[传输实现](../apps/extension/src/bridge.ts)、[Chrome 离屏文档与上下文说明](https://developer.chrome.com/docs/extensions/reference/api/offscreen)。
- **手动登录框标记按表单和步骤隔离。** 原实现每个来源和路径只保留一条规则，第二张表单会覆盖第一张。现在同一路径可分别保留普通表单和不换网址的登录步骤；部分字段无法唯一定位时不向该字段填写，并提示重新标记。显式选择、来源及路径限制、条目二次验证保持不变。规则仍是本机加密偏好，**没有**随 `.vaultpack` 或 WebDAV 迁移，也未实现同步角标。见[分期计划 §5](../分期开发与验证计划.md)。
- **同步保守失败。** 目录读取仍以 8 MiB / 750 件为限；未经验证的条件写能力不允许发布或清理。旧客户端本身不会遵守新登记协议，不把新端之间的并发测试说成混合版本的全局保证。见 [ADR-0002](adr/0002-webdav-write-boundary.md)。

## Spec：逐工单核对

| 工单 | 工作区核对结果 |
| --- | --- |
| [#19](https://github.com/IZRINO/vault-extension/issues/19) | 修复评论补充的持续校时条件：普通 HTTPS 轮询（包括没有增量）更新样本，不调用另一项时间服务。补偿已开启但无有效样本时，界面明确显示使用本机时间；恢复通信后详情与网页填码均可恢复校正。 |
| [#38](https://github.com/IZRINO/vault-extension/issues/38) | 修复的是**中间请求**而不只是最终返回值。Popup 和侧栏同时打开，分别观察 TOTP、HOTP、Steam 的日常查看、复制请求和主动填码；测试只保留消息计数和违规标志。 |
| [#39](https://github.com/IZRINO/vault-extension/issues/39)、[#43](https://github.com/IZRINO/vault-extension/issues/43) | 网页改密由后台在整库匹配，不复用菜单的 30 条上限；只更新已确认目标的密码和历史，保留验证器、迁移字段及二次验证。修复真实表单跳转时丢保存提示的问题：以**原始提交页**匹配账号，以**当前文档**校验确认动作。同源成功页上的同名精确匹配凭证不会被改写；重名、取消和未通过验证不写入。 |
| [#40](https://github.com/IZRINO/vault-extension/issues/40)、[#47](https://github.com/IZRINO/vault-extension/issues/47) | 修复相交场景：不同 Bitwarden 来源的账号即使共用 HOTP，也不能整条去重。保留两个账号；重复计数型验证器不能发出第二份旧码。HOTP 身份忽略不用于出码的时间步长，TOTP 不忽略。 |
| [#41](https://github.com/IZRINO/vault-extension/issues/41) | 同修订号也用实际内容识别陈旧编辑。修复拒绝后没有可用恢复操作的问题：用户可载入最新版并带回自己的修改，重叠字段显式选择，保留可信计数和恢复字段；预览不写库，仍须独立确认保存。 |
| [#42](https://github.com/IZRINO/vault-extension/issues/42) | 修复原先仅为第二台客户端估算余量、4–8 MiB 批次在空目录也可能永久待传的问题。新版按条件写登记在途容量、所需祖先与加密增量，其他参与端可在原设备掉线后验证并代送。不能安全追加时可走条件快照，仍须经远端回放确认才清除待同步状态。三端同时追加，以及连续压实、历史恢复与迟到写入重叠均有回归。 |
| [#44](https://github.com/IZRINO/vault-extension/issues/44)、[#45](https://github.com/IZRINO/vault-extension/issues/45) | 条件式请求在同一文档等待，不延长用户选中后的确认期。取消、导航、锁库会作废旧请求；排除列表命中的重复注册在用户同意后向网站返回一次 `InvalidStateError`，不新增凭证。 |
| [#46](https://github.com/IZRINO/vault-extension/issues/46) | 修复有祖先时仍可能被中间无关大快照阻挡的问题：直接回放不取历史；确需祖先时只取经过认证的增量所要求的版本，仍核验其真实性并遵守累计读取限额。 |
| [#48](https://github.com/IZRINO/vault-extension/issues/48) | Aegis、2FAS、Raivo 导入保留有效的零和正计数；未知或不合法的计数单独报告，不当作零，不产生可用旧码。 |
| [#49](https://github.com/IZRINO/vault-extension/issues/49) | 两条 Bitwarden 导出路径均按最终写入的凭证统计；修复旧库保留字段中有效 Passkey 已写出却报零。已写入但无法核实的厂商记录不冒充可用密钥。 |
| [#50](https://github.com/IZRINO/vault-extension/issues/50) | 修复自家 CSV 在网址为空、仅名称或回收状态不同时仍会误去重的问题。5 条合成输入从原先的 3 条恢复为 5 条，原值保留，重导不增项；不放宽其他来源校验。 |

## 已验证及限制

- `cargo test --workspace --locked`：81 项通过。`pnpm run test:extension`：15 个测试文件、216 项通过、0 跳过，已配置[公开认证器样本](agents/authenticator-backup-fixtures.md)。TypeScript 检查、9 个 WASM 模块的生产构建与 WXT 打包通过；主核 **250,433 字节**，上限 256,000 字节。
- 最终生产目录 SHA-256：`05c7822479b6bd4eda06fa19a04d994ff0fd431cdfc1889eef3a96410eca961f`（不是 ZIP 哈希）。Edge 与 Helium 均通过：`scripts/test-data-safety.cjs`、`scripts/test-autofill.cjs`、`scripts/test-login-marks.cjs`、`scripts/test-migration.cjs`、`scripts/test-passkeys.cjs --audit-ceremonies`、`scripts/test-phase-2.cjs`。迁移两端均报告 `encrypted2fasFixture: true`；两端同时打开 Popup 与侧栏时，三类动态码的查看、复制请求和网页填码均未观察到违规离屏消息。
- 同步使用合成加密库和回环 WebDAV。双浏览器同步生命周期回归覆盖离线编辑送达、密钥轮换、重启、锁库停止请求和设备认领；这不是真实网盘提供商的现场验收。
- **混合版本仍有风险。** 多个完全不参与登记的旧客户端并发，或单个旧端写入超过新版预留的 4 MiB，都没有全局容量保证，建议同库设备一起升级。已由其他设备代送的包会保守保留一份额度，以容纳可能迟到的原请求；后续可能更多使用快照。无法安全发布时本机编辑继续待同步。
- 没有操作用户的实际密码库、真实网盘或系统剪贴板。第三方原生应用、实体 Windows Hello 和正式 ZIP 的人工验收仍按原工单执行。本次未提交、推送，也未修改 GitHub 工单状态。

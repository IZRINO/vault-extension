# Vault Extension 全仓代码审计 · 2026-11-21

审计基准：`main@3b3504e8199f1305e90d45432d5af1110337b471`，包括工作树中尚未提交的两份设计文档。以全仓 254 个受版本控制文件为范围，不只审最后一次提交。按实际发布入口追踪 Popup／侧栏、后台、内容脚本、离屏页、Worker、Rust 内核、迁移和 WebDAV 路径；不是对每个第三方依赖的逐行安全认证。

**结论：14 个独立问题，5 项 P1、9 项 P2。建议修完 P1 再正式发布。** P1 指会让已保存的数据丢失、同步库不可恢复读取，或违反日常凭证使用的保密边界；P2 指在特定数据、时序或网站流程下发生的功能错误。三项用合成数据和真实 WASM 另做了验证；其余为可定位的代码路径结论，不冒充双浏览器实测。

## Standards：规范与边界（6 项）

| 编号 | 触发条件与实际后果 | 代码及依据 | 建议回归 |
| --- | --- | --- | --- |
| S1 · P1 | **网页改密会移除已绑定的验证器。** 在网站接受“更新密码”后，保存流程读取用于展示的详情，再将它整条写回。详情已去除 `totpUri` 和内部迁移字段；Rust 只对密码历史及已有 Passkey 做保留。旧密码进了历史，但登录项可能从此不能生成动态码，迁移来源信息也可能丢失。 | [网页保存](../apps/extension/src/autofill-controller.ts#L192)；[详情脱敏](../apps/extension/src/vault-controller.ts#L1157)；[缺字段变为 None](../crates/vault-core/src/model/mod.rs#L894)；[整条替换](../crates/vault-core/src/model/mod.rs#L535)。[二期要求：更新密码并归档旧值](../分期开发与验证计划.md#L132)。 | 后台只更新指定账号的密码，别让种子回到日常详情。分别对带 TOTP、HOTP 和迁移字段的账号网页改密；核对新旧密码、原有验证器与来源均保留。 |
| S2 · P1 | **日常取码响应不含种子，但另一条扩展消息含有种子。** 后台把完整设置 URI 当作离屏计算参数，用 `runtime.sendMessage` 发送。`target` 是载荷字段，不限制投递对象；已打开且正在监听消息的 Popup、侧栏也会收到该请求。这是扩展内部越界，不是发现普通网页已读到种子。 | [出码参数](../apps/extension/src/vault-controller.ts#L382)；[传输](../apps/extension/src/bridge.ts#L9)；[界面监听](../apps/extension/src/ui/App.tsx#L46)；[ADR-0001](adr/0001-secret-use-and-export.md#L5)、[工单 #38](https://github.com/IZRINO/vault-extension/issues/38)。[Chrome 的投递规则](https://developer.chrome.com/docs/extensions/reference/api/runtime#method-sendMessage)。 | 秘密只走已核验的后台与离屏页专用连接。用合成凭证检查普通扩展页面收到的**全部请求**，而非仅检查 `read-otp` 的返回值。 |
| S3 · P1 | **Bitwarden 的不同凭证会被跳过。** 两个来源 ID 不同的普通条目仍会退回按内容去重；对非 SSH 的 Bitwarden 条目，指纹不含自定义字段、二次验证和回收站状态。同名同正文的两条安全备注，即使隐藏恢复信息不同，第二条也会被当作重复。**WASM 实测：输入 2，实际写入 1，重复 1，无效 0。** 原导出文件未改，目标库漏项。 | [指纹](../crates/vault-importers/src/portable.rs#L269)；[来源 ID 不同仍回退并跳过](../crates/vault-importers/src/portable.rs#L319)；[迁移字段保留约定](phase-2-status.md#L43)。 | 区分“同一个来源条目”和“可见内容相似”；不同恢复信息或保护策略不得默默折叠。同一文件再次导入仍应幂等。 |
| S4 · P2 | **网页改密拿菜单里的前 30 条判断账号是否存在或唯一。** 目标排在第 31 条时会新建重复凭证；两个同名候选刚好分处上限两侧时，本应要求人工选择，却会更新可见的那一个。 | [菜单上限](../apps/extension/src/vault-controller.ts#L1101)；[保存目标选择](../apps/extension/src/autofill-controller.ts#L188)；[网页更新约定](phase-2-status.md#L29)。 | 展示可分页，保存判定必须遍历完整匹配集。分别验证“仅第 31 项命中”和“第 1、31 项同名”。 |
| S5 · P2 | **条件式 Passkey 登录在用户还没点输入框前便自行失效。** 已接管的条件式请求后台固定 120 秒取消，网页桥另设 125 秒上限。打开登录页后稍晚回来点用户名框，网站已收到取消异常，不能继续原来的登录请求。 | [后台计时](../apps/extension/src/passkeys/controller.ts#L107)；[网页端计时](../apps/extension/entrypoints/passkey.content.ts#L43)；[四期对条件式登录的承诺](../分期开发与验证计划.md#L233)；[WebAuthn §5.1.4](https://www.w3.org/TR/webauthn-3/#sctn-getAssertion)。 | 将等待用户选择与选中后的交互期限分开；模拟进入页面两分钟后才选账号，另验导航和显式取消仍能清理请求。 |
| S6 · P2 | **重复注册 Passkey 没有向网站返回“已登记”。** 用户同意后，Rust 能识别排除列表中的已有凭证，但错误只显示在扩展确认页，网站的注册请求没有结束，最终会按取消或超时收到 `NotAllowedError`，而非 `InvalidStateError`。 | [内核判重](../crates/vault-passkeys/src/vault.rs#L141)；[确认分支](../apps/extension/src/passkeys/controller.ts#L193)；[提示页](../apps/extension/entrypoints/passkey-prompt/main.tsx#L43)；[WebAuthn §5.1.3.1](https://www.w3.org/TR/webauthn-3/#sctn-create-request-exceptions)。 | 区分仍可重试的口令输入错误和必须结束的协议错误；由调用网站断言同意后的异常名称与完成时机。 |

维护性观察，不计入以上问题：[后台](../apps/extension/src/vault-controller.ts#L37)通过中文字段名判断哪些数据属于内部迁移元数据，Rust 导入器另行维护相同名称。修改文案或增加来源时容易漏掉隐藏规则；这是使用显示字符串表示领域类型的风险，不是另一项已证实泄露。

## Spec：功能与逻辑（8 项）

| 编号 | 触发条件与实际后果 | 代码及依据 | 建议回归 |
| --- | --- | --- | --- |
| F1 · P1 | **同步已合并的字段可以被旧编辑窗口静默写回。** 两端都从版本 1 修改不同字段，各得版本 2；合并使用两者版本号的最大值，后台保存旧表单又只检查该版本号。**WASM 实测：**A 改标题、B 改备注，合并后两项都在，旧草稿和合并结果版本号同为 2；按现有校验保存草稿后，B 的备注消失。若 B 改的是 HOTP 计数，相同的整条覆盖路径也可能把计数写回旧值；本次实测的是备注。 | [合并取最大值](../crates/vault-sync/src/merge.rs#L70)；[保存只比较 revision](../apps/extension/src/vault-controller.ts#L1168)；[编辑器保有草稿](../apps/extension/src/ui/ItemEditor.tsx#L11)。[不同字段无损合并验收](../分期开发与验证计划.md#L202)。 | 让提交校验能区分同修订号但内容不同的版本，或按字段提交带基线的修改。双端并发、同步前打开编辑器，随后验证过期草稿被拒并保留本地未保存输入。 |
| F2 · P1 | **客户端可以向网盘发布自己随后读不回的增量。** 下载限制是全部增量合计 8 MiB、最多 750 件；追加前没有对应的总量／件数准入，上传后按单件 16 MiB 回读。合法的批量迁移或连串离线编辑使远端越界时，另一端、首次恢复，以及需先读取这些增量的自动压实都会受阻。不是密文损坏，也不等于原设备的数据已丢。 | [读取上限](../apps/extension/src/sync/bootstrap.ts#L5)；[累减总预算](../apps/extension/src/sync/bootstrap.ts#L64)；[发布与确认](../apps/extension/src/sync/run.ts#L268)；[压实及双端收敛验收](../分期开发与验证计划.md#L204)。 | 在发布前保证新状态能被当前协议读取，并覆盖两台设备同时追加时的上限。用临界字节数、临界件数验证新客户端加入和自动压实；不以取消读取限额代替修复。 |
| F3 · P2 | **仍可正常同步的库，新设备却可能无法加入。** 只要远端有增量且有旧快照，新设备就先下载全部可见历史，历史合计上限 8 MiB。即使这一笔增量直接基于当前快照、根本用不到旧版本，几份合法历史超过预算也会阻止加入。已有设备反而在确实缺少祖先时才读取历史。 | [新设备加入](../apps/extension/src/sync/bootstrap.ts#L128)；[历史预算](../apps/extension/src/sync/bootstrap.ts#L81)；[已有设备按需读取](../apps/extension/src/sync/run.ts#L139)；[已有库先拉取恢复](../分期开发与验证计划.md#L184)。 | 用当前快照先回放，只有确需祖先才按需取历史。以单个小增量、多个较大但不需要的历史快照验新设备加入。 |
| F4 · P2 | **经常同步也不能维持 TOTP 校时。** 手动测试／保存连接时记录服务器时间，正常轮询却丢弃时间样本。超过 30 分钟便按零偏移出码，但“已开启补偿”的状态仍可为真。系统时间有偏差时，显示和填入的码重新偏离服务器时间。 | [轮询只保留文件清单](../apps/extension/src/sync/bootstrap.ts#L55)；[样本过期](../apps/extension/src/sync/connection.ts#L16)；[补偿开关与有效样本分别报告](../apps/extension/src/sync/connection.ts#L75)；[规格“每次 WebDAV 通信”](../分期开发与验证计划.md#L180)。 | 以正常 HTTPS 轮询更新合格样本，并让出码读取最新值。让模拟时钟跨过 30 分钟，同时验证网络持续可用和真正离线两种情况。 |
| F5 · P2 | **同一 HOTP 只因导出工具写了不同的 `period`，就可能变成两个可用条目。** Rust 将步长算入凭证身份，但 HOTP 出码不用时间步长。较早的导出因此可能绕过正常去重，产生从较低计数开始的第二个可用副本；恢复时的计数协调也使用这一身份。 | [身份计算](../crates/vault-otp/src/lib.rs#L199)；[出码](../crates/vault-otp/src/lib.rs#L285)；[Ente 去重](../crates/vault-ente-auth/src/lib.rs#L199)；[恢复计数协调](../crates/vault-sync/src/merge.rs#L179)；[ADR-0002](adr/0002-webdav-write-boundary.md#L11)。 | 对同种子、算法、位数的 HOTP，仅改变步长和来源计数，验证重导与恢复后只留一个有效计数；TOTP 仍需区分步长。 |
| F6 · P2 | **部分导入器把未知 HOTP 计数当成已知的 0。** 对 Aegis、2FAS、Raivo 的 HOTP，缺少计数或计数不能解析时，公共转换会补 0，再把条目当作正常凭证导入。对已经使用过的验证码，这会从错误位置出码；正常含有效计数的文件不受影响。 | [公共转换](../crates/vault-importers/src/authenticators.rs#L98)；[Aegis](../crates/vault-importers/src/authenticators.rs#L210)、[2FAS](../crates/vault-importers/src/authenticators.rs#L261)、[Raivo](../crates/vault-importers/src/authenticators.rs#L316)；[HOTP 的计数要求](phase-2-status.md#L14)。 | 区分真值 0 与缺失／无效；预览报出或将条目标为待核实，未核实不发码。 |
| F7 · P2 | **Bitwarden 导出未告诉用户哪些 Passkey 没导出。** 导出器对不支持的密钥有单独的 `skippedPasskeys` 计数，界面只读取凭证条数和整条跳过数。只依赖 Ed25519 Passkey 的账号可能显示已导出一条，目标文件却不含可用于登录的密钥。这里的问题是漏报，不是要求 Bitwarden 支持所有算法。 | [密钥筛选](../crates/vault-importers/src/portable.rs#L456)；[导出结果](../crates/vault-importers/src/portable.rs#L497)；[Bitwarden 下载提示](../apps/extension/src/ui/Migration.tsx#L175)；对照 [CXF 下载提示](../apps/extension/src/ui/PortableMigration.tsx#L88)。 | 用仅支持和不支持的密钥各一条，核对文件和界面所报的凭证、可用密钥及跳过数。 |
| F8 · P2 | **本库导出的通用 CSV 不能读回其中部分登录项。** 导出会接收所有登录项，回读却要求网址和密码都非空。**WASM 实测：**一条离线登录、一条有网址的对照登录，导出报告 2 条、跳过 0；按文件自己的表头回读，只返回对照项，另 1 条标为无效。独立验证器的空密码也落入同一分支。此结论只针对通用 CSV，不涉及 `.vaultpack`。 | [导出并计数](../crates/vault-importers/src/migration_csv.rs#L250)；[回读准入](../crates/vault-importers/src/migration_csv.rs#L197)；[通用迁移的适用范围](phase-2-status.md#L46)。 | 让可识别的本库 CSV 无损读回其声称支持的行，或导出前明确告知哪些行不能恢复。不要给离线账号编造网站或密码。 |

## 验证记录与范围

| 本次检查 | 结果 |
| --- | --- |
| `cargo test --workspace --locked` | 80 项通过（含 vendored 依赖测试及其文档测试），0 失败。 |
| `pnpm --filter ./apps/extension compile` | TypeScript 编译检查通过。 |
| `pnpm run test:extension` | 默认 165 通过、4 项因缺外部夹具跳过。随后按[夹具约定](agents/authenticator-backup-fixtures.md#L53)从固定上游提交取得 5 个公开合成文件，逐个核对 SHA-256 后重跑：**14 个测试文件、169/169 通过，0 跳过**。 |
| `node scripts/check-wasm.cjs` | 9 个现有 WASM 模块均有效；主核 250,433 字节，低于 256,000 字节上限。此项不是重新打包或对生产 ZIP 的签收。 |
| 针对性合成数据检查 | 使用实际 Rust/WASM 入口在内存核对 S3、F1、F8。F1 使用实际同步及写入函数，并单独比较后台所用版本条件；没有声称运行了两台浏览器。 |

没有操作真实密码库、写入真实网盘、修改实现或发布工单。本轮未重跑原生 Edge／Helium 全套 E2E、实体 Windows Hello 或第三方应用现场验收。已在[冷开结案决定](cold-wake-diagnostics.md#结案决定)撤销的 Popup 50 ms 门槛，不列为缺陷；独立的 WASM 恢复性能目标按[候选记录](release-candidate-status.md#L5)仍无达标证据，本次没有重测。[Phase 5](../分期开发与验证计划.md#L250)明确在前四期签收后才启动，未实现不计为偏离。

# 第一轮开发与验收记录

记录日期：2026-11-12。

第一阶段的本地密码库代码闭环与自动回归已完成。实体 Windows Hello、实际系统锁屏事件和交互式浏览器侧栏仍需人工验收，因此分期计划的完整 Exit Gate 尚未勾选。此记录只描述当前实现；架构文档中自动填充、OTP、WebDAV 和软 Passkey 仍属于后续阶段。

## 已实现

- 主密码建库、可选 Argon2id 性能校准、应急恢复包下载、恢复码重设和主密码修改。修改主密码只重包头文件，不重加密快照。
- Offscreen 文档按需启动独立 Web Worker 执行耗时派生；后台维护 WASM 会话引擎。会话密钥和包装密文只存储于受限的 storage.session，后台被停止后可恢复；超时和主动锁定清理会话。
- 6–12 位本机 PIN；验证前持久化尝试次数，第五次失败移除 PIN 包装记录；正确的第五次尝试允许成功并重置计数。二次验证使用相同计数器。
- 平台 WebAuthn PRF 注册、两次断言验证确定性输出、32 字节密钥包装及解锁；无 PRF 时提示改用 PIN，且不写入半成品记录。
- Popup、SidePanel 和完整标签页共用管理界面。登录、支付卡、身份与地址、API 令牌、软件许可证、SSH 密钥的创建、编辑、搜索、置顶、回收站、自定义字段和密码历史。
- 受保护条目的读取和修改必须由后台验证实际主密码或 PIN，忽略界面伪造的“已验证”标记。复制字段在已授权打开的编辑会话中进行。
- 随机密码和 EFF 单词口令生成、本地弱密码与重复密码分析、用户显式授权后的 HIBP 前缀查询。
- 原生 .vaultpack 加密导入导出、十次变更备份提醒、可选关闭浏览器原生保存密码提示。
- 复制后约 30 秒由 alarm 唤起离屏文档，比对摘要后清理；如果中途复制了其他内容则保留。完成后关闭离屏文档。

## 存储与权限

IndexedDB 的 vault 表按单条事务保存 head 和 snap 的 Uint8Array 密文；pendingChanges 表预留给后续同步。storage.local 仅保存设置、失败次数和本机包装密文。storage.session 仅向受信任扩展上下文开放。

当前没有 Content Script 和必选站点权限；背景只接受自身 Popup、SidePanel 的消息，校验 sender.id、sender.url、sender.origin 以及存在时的 sender.tab.url。privacy 和 HIBP 域名权限均为用户按需授权。

未包装 DEK 保持在 WASM 内。主密码输入、单条凭证显示和剪贴板操作必须经过 JavaScript 字符串；该区域受浏览器垃圾回收管理，不能承诺确定性擦除或“所有秘密只存在于 WASM”。Rust 的密钥、Argon2 工作区、凭证对象及中间 JSON/压缩缓冲区已补充释放擦除。

## 本轮修复的缺陷

1. wasm-opt 使用 --all-features 生成当前运行时无法加载的导入编码。改用明确的稳定特性集合，并把实际加载校验与体积限制加入构建脚本。
2. 会话恢复未对照头文件检查快照版本、库编号和状态认证码。补齐校验并增加旧快照回退测试。
3. 外部备份的 Argon2 参数只有下限。增加 256 MiB、10 轮、16 路上限，拒绝超出资源预算的参数及不支持的格式版本。
4. 复制空选择区返回成功却没有清除剪贴板。通过 copy 事件显式写入空文本，并在清理前再次检查当前内容。
5. 凭证 MessagePack 数组声明了 12 个字段，实际写入 13 个。修正计数，并通过 rmp-serde 交叉验证；旧头格式仍可读取。快照认证直接验证存储字节，避免重编码变化使旧快照失效。
6. 补齐 Argon2 工作内存、临时凭证克隆和中间 JSON 字符串的释放擦除。
7. 开发模式通过 Vite `?worker` 生成 localhost Worker 地址，建库时触发 Edge 的 `DWH_INVALID_SCRIPT_URL_ORIGIN` 并终止扩展进程。将密钥 Worker 改为 WXT 独立脚本入口，通过扩展自身地址加载；浏览器回归脚本增加 `VAULT_EXTENSION_PATH`，覆盖开发版产物。

## 自动验证

环境：Windows，Node.js 26.13.1，Edge 157.0.4341.46，Helium 157.0.8103.38。浏览器使用临时独立配置与 headless 模式，未修改日常浏览器配置。

| 检查 | 结果与范围 |
| --- | --- |
| Rust | vault-core 12 项、vault-importers 1 项通过；导入器这一项仍是脚手架基础测试 |
| 编码互操作 | rmp-serde 解码并重编码凭证；Node 自带 libzstd 验证压缩输出，并交叉测试标准压缩等级 1、3、9、19 |
| Vitest | 8 项通过；使用真实 WASM 和模拟存储覆盖会话重建、过期、PIN 熔断、受保护条目、并发写入、恢复和锁库竞态 |
| TypeScript | tsc --noEmit 通过 |
| WASM 构建 | 两个模块均通过 WebAssembly.validate；主核 246,113 字节，低于 250 KiB 门禁 |
| Edge / Helium | 建库、凭证保存、落盘无测试明文、后台强杀恢复、PIN 熔断、备份导入导出、恢复码重设、虚拟 PRF 与不支持时降级、剪贴板清理和防误删、弹出面板及窄屏侧栏通过 |

开发模式 Worker 修复后，Edge / Helium 分别对 `edge-mv3-dev` 开发产物和 `chrome-mv3` 生产产物完成整套回归，四种组合全部通过；TypeScript 编译与 8 项后台集成测试同时通过。

浏览器报告和截图生成在 test-results；该目录不提交到 Git。唤醒时间是本机单条凭证测试的观测值，不是所有库容量和设备上的性能保证。实体认证器与操作系统事件不由虚拟认证器结果替代。

复现命令：

~~~powershell
pnpm run build
pnpm run test:rust
pnpm run test:extension
pnpm --filter ./apps/extension compile
pnpm run test:smoke
~~~

标准压缩互操作测试要求 Node.js 提供 node:zlib 的 Zstandard API。若已完整缓存 Cargo 依赖但注册表暂时不可达，可用 cargo test --workspace --offline。

smoke-extension.cjs 默认查找 Windows 标准安装位置，可单独执行 node scripts/smoke-extension.cjs edge 或 helium。非标准路径可通过 VAULT_BROWSER_PATH 指定。PRF 测试使用 CDP 虚拟平台认证器，不触发用户的真实 Windows Hello。

## 防丢库补验（2026-11-14）

- 清空回收站时显示回收站总数，并提醒搜索未显示的条目也会被删除。后台校验确认时的条目集合，若已变化则不删除。
- 快照写入和读取均使用 32 MiB 的未压缩上限，超限保存保留原快照。`.vaultpack` 导出和导入均限制为 16 MiB（含包头），文件格式不变。
- 导出加密备份后，由用户确认文件已保存；只消除这次备份覆盖的改动，未保存或后续修改仍计入提醒。未增加浏览器权限。
- `pnpm run test:data-safety` 用独立临时配置在 Edge 和 Helium 验证回收站搜索后清空、浏览器取消下载后提醒仍在、导出后新改动未被清除，以及在全新配置中用不同主密码恢复。错误的备份密码不会写入数据；正确恢复保留了密码历史、隐藏自定义字段和条目二次验证。截图在 `test-results/`。
- Rust 核心 13 项、导入器脚手架 1 项、后台集成 11 项及 TypeScript 检查通过；主 WASM 为 246,176 字节，低于 250 KiB 门禁。

## T01 冷唤醒补测（2026-11-19）

Popup 打开时并行加载界面和库数据，用一次受信消息读取状态与凭证摘要。后台并行读取设置、密文、会话并初始化 WASM，在恢复前检查系统锁定、会话有效期和密文认证。主 WASM 作为独立资源加载，大小为 255,548 字节。

构建后运行 `pnpm run test:wakeup`。Edge 和 Helium 使用各自的隔离配置及同一生产包，各测 10 次，每库 1 条合成凭证。每次先关闭上一份 Popup 并确认 Worker 已停止，再用 CDP 调用浏览器原生工具栏动作。脚本确认 Worker 的时间原点晚于动作发出时间。

- WASM 恢复从新 Worker 的 `performance.timeOrigin` 量到密码库通过认证并在 WASM 内可用。
- Popup 首屏从发出工具栏动作量到凭证列表提交 DOM。脚本在原生 Popup 内核对合成凭证行已渲染且可操作。

| 浏览器 | WASM 恢复中位数（最小–最大） | Popup 首屏中位数（最小–最大） |
| --- | ---: | ---: |
| Edge 157.0.4341.60 | 107.05 ms（71.70–174.30） | 631.56 ms（584.02–773.72） |
| Helium 157.0.8103.78 | 114.35 ms（60.50–332.80） | 638.62 ms（469.32–856.39） |

生产包内容 SHA-256 为 `074977c1b9ab2223a979306792ae03e3cba725f89ceafac0340955408dff1dea`。逐次样本和分段耗时在 `test-results/wakeup.json`。冒烟报告的 `wakeMs` 继续表示停掉 Worker 后的 `status` 请求往返时间。

两项性能实测均高于门槛（`< 5 ms` 和 `< 50 ms`）。维护者决定以当前实现关闭 T01，保留实测记录。同机用只含静态按钮和一次消息往返的 MV3 对照包各测 3 次，Edge 和 Helium 的 Popup 最快值分别为 429.94 ms 和 431.88 ms。对照 Worker 从启动到处理消息的最快值为 36.4 ms 和 44.5 ms。

生产构建、主 WASM 大小门禁、Rust 33 项、TypeScript、后台 38 项及 Edge/Helium 安装冒烟通过。真实 WASM 集成测试覆盖会话过期、会话损坏、清理期间收到请求以及模拟系统已锁定四种情况。

## T02 原生侧栏补验（2026-11-19）

在 `ad45298` 的生产包上运行 `pnpm run test:sidepanel`。Edge 157.0.4341.60 和 Helium 157.0.8103.78 分别使用独立配置，点击扩展的「打开浏览器侧栏」进入。脚本通过 `runtime.getContexts()` 确认浏览器将面板登记为 `SIDE_PANEL`，再向面板发送鼠标和键盘事件。[侧栏 API](https://developer.chrome.com/docs/extensions/reference/api/sidePanel) · [扩展上下文类型](https://developer.chrome.com/docs/extensions/reference/api/runtime#type-ContextType)

初次双浏览器回归通过新增、搜索、编辑合成登录项、取消二次验证、拒绝错误主密码、正确验证后查看和保存。取消受保护条目的复制时没有创建剪贴板清理任务。浏览器设置可在未取得 `privacy` 时打开，手动锁库后侧栏回到解锁界面。两端均无侧栏脚本错误。脚本每次成功时将结果写入 `test-results/sidepanel.json`。

密码和网页取码共用剪贴板清理流程。复制、登记清理任务和闹钟清理按顺序执行，旧任务无法删除新复制的清理记录。后台回归先复现了新值到期后仍残留的问题，修复后通过。

浏览器设置在写入前检查控制权，写入后复读实际状态。策略或其他扩展阻止写入时会显示原因。撤回 `privacy` 前先清除 Vault 自己的覆盖设置。用同一生产包的设置页接入模拟浏览器接口，验证了拒绝授权、策略限制、正常关闭、恢复并撤回，未发现页面错误或请求失败。[设置控制权](https://developer.chrome.com/docs/extensions/reference/api/types) · [可选权限](https://developer.chrome.com/docs/extensions/reference/api/permissions)

当前生产构建、主 WASM 体积（255,548 字节）、Rust 33 项、TypeScript 和 Vitest 39 项通过。`pnpm run test:sidepanel` 在创建测试库前检查锁屏状态。桌面解锁后，Edge 和 Helium 在当前构建上均通过原生侧栏新增、搜索、编辑、二次验证、取消复制、手动锁库和模拟权限流程，侧栏控制台均无错误。

## T02 原生侧栏剪贴板（2026-11-21）

在本地集成分支的产品提交 `1928ffd` 上构建了同一份生产扩展，目录 SHA-256 为 `b687c83e0fff983ec015bfaa65dc12571d83f574b55b4208bf7ac48cf1aa968f`。两端均确认是 `SIDE_PANEL` 原生上下文。通过二次验证复制含 Windows 换行的合成密码，读到原值后实际停止该扩展的 Service Worker。第二轮重新验证并复制，在第 10 秒改贴普通文本，直至清理任务完成。

| 浏览器 | 第一轮观察到密码清空 | 第二轮改贴普通文本 | 确认普通文本仍在 |
| --- | ---: | ---: | ---: |
| Edge 158.0.4370.33 | 29.952 秒 | 10.031 秒 | 30.092 秒 |
| Helium 156.0.8078.47 | 29.947 秒 | 10.007 秒 | 30.023 秒 |

耗时从侧栏读到刚复制的文本起算。两端的新增、搜索、编辑、取消二次验证、取消复制和手动锁库也通过，侧栏控制台错误均为零。两端均报告可用的平台认证器。`privacy` 的拒绝、策略限制和撤回仍用模拟接口验证。

这次修复了两类残留：清理摘要登记失败时仍写入密码，以及 `textarea.value` 归一化换行导致摘要比对失败。现在先登记摘要和闹钟，成功期限按实际写入时刻计算，清理时按粘贴事件提供的原始文本比对。浏览器会话中途停止后台后，可凭先前登记的摘要接续清理。单测还覆盖慢存储、写入后丢失回执、旧的一次性闹钟丢失和连续复制失败。Rust 80 项、含公开夹具的 Vitest 169 项、TypeScript 与生产构建通过。主核 WASM 为 250,433 字节，低于 256,000 字节上限。

同包 `node scripts/smoke-extension.cjs` 在两款浏览器均通过安装、密文落盘、后台恢复、虚拟 PRF 和无 PRF 时的 PIN 引导，以及剪贴板回归。报告位于 `test-results/t02-smoke-b687c83e/browser-smoke.json`。

复现原生侧栏测试用 `node scripts/test-sidepanel.cjs --clipboard`。此命令会覆盖 Windows 当前剪贴板，结束时保留普通测试文本。末尾可加 `edge` 或 `helium`。默认的 `pnpm run test:sidepanel` 在复制验证弹窗点取消。两个入口分别写入 `test-results/sidepanel-clipboard.json` 和 `test-results/sidepanel.json`。

## 尚待人工验收

- 在测试库注册 Windows Hello，手动锁库后用「系统解锁」验证断言。记录系统和设备是否提供 PRF。遇到不支持 PRF 的设备时检查 PIN 引导及系统解锁状态。
- 在库解锁时用 `Win+L` 锁定 Windows。重新登录后打开原生侧栏，确认密码库仍处于锁定状态。
- 用隔离配置操作「设置 → 浏览器设置」，验收拒绝及授予 `privacy`。关闭提示后选择「恢复浏览器设置并撤回权限」，确认浏览器恢复此前的设置且权限已撤回。有受管理的测试配置时，记录策略限制和界面反馈。
- 真实 HIBP 请求待验。实测需要用合成凭证逐次同意联网。本地 SHA-1 前缀和响应匹配已有测试。

加载目录：apps/extension/.output/chrome-mv3。首次正式使用前保存应急恢复包及独立加密备份。恢复码用于解密仍存在的密码库，不能替代已删除数据的备份。

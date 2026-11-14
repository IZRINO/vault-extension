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

## 尚待人工验收

- 用实际 Windows Hello 注册并解锁，确认当前系统是否能提供 PRF。虚拟认证器已验证支持与不支持两条分支，但不能证明本机物理认证器的能力。
- 实际锁定 Windows，解锁系统后确认密码库仍处于锁定状态。
- 在交互式 Edge 与 Helium 中使用浏览器原生侧栏及可选 privacy 权限开关，确认权限提示与浏览器策略行为。
- HIBP 在线请求未访问真实服务；本地 SHA-1 前缀和响应匹配逻辑有测试，网络失败分支由后台处理。

加载目录：apps/extension/.output/chrome-mv3。首次正式使用前保存应急恢复包及独立加密备份。恢复码用于解密仍存在的密码库，不能替代已删除数据的备份。

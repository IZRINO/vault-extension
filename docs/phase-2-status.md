# 二期开发记录

更新于 2026-11-17。本轮补齐网页填充/保存/改密、截图扫码、Bitwarden JSON 迁移和通用 CSV 映射/导出；功能回归通过，二期完整 Exit Gate 尚未通过。Helium 首次扫码仍超过 200 ms，人工验收项见文末。

## 已实现

- 从「设置 → 导入浏览器密码」选择浏览器导出的 UTF-8 CSV，预览可添加、重复和无法读取的条目；输入主密码或 PIN 确认后，才将新增凭证一次写入加密快照。依据网站地址的主机与端口、账号去重，已存在或在回收站的凭证不覆盖。期间文件或快照变化会要求重新预览。
- 单次最多 2 MiB、5,000 条。支持带 BOM、引号、逗号和换行的字段。CSV 只在本机读取，不改原文件，不导入 CSV 内的验证码设置；预览会提示这部分跳过。只导入 HTTP(S) 登录凭证。
- 登录凭证的编辑页可手动添加、修改或移除 Base32 密钥或 `otpauth://totp|hotp|steam/` 链接。时间验证码支持 SHA-1 / SHA-256 / SHA-512、6–8 位和链接指定的周期；Steam Guard 输出 5 位字符。倒计时不足 5 秒时显示下一期验证码。受保护凭证仍须通过后台二次验证。
- 沿用一期快照及 `.vaultpack` 数据格式。浏览器 CSV、迁移、OTP、扫码和网站偏好加密各有独立按需 Worker，第三方解析与二维码模块不进入日常解锁或网页填充路径。

### 验证器与 Ente Auth 迁移

- HOTP 链接必须含 `counter`；使用字符串跨越 JavaScript 边界，支持完整 `u64` 计数，溢出时拒绝取码。取码请求由后台串行处理，先提交加密快照和计数器，再返回验证码；写入失败恢复已提交快照，不返回或消耗验证码。复制已生成的码不推进计数。受保护条目每次生成均重新验证。
- HOTP 计数更新与 `pendingChanges['hotp-snapshot']` 在同一笔严格持久化的 IndexedDB 事务提交。当前记录是合并保留的最新 HOTP 加密快照；三期再接入 WAL 增量编码与实际同步，当前不会联网同步。
- 「设置 → Ente Auth 验证器迁移」支持 UTF-8、每行一个 `otpauth://` 的未加密 `.txt`，最多 2 MiB、5,000 个验证码。预览只返回脱敏摘要，文件和快照摘要绑定确认；主密码或 PIN 验证后一次性合入快照。保留置顶、标签、备注、回收站及 `codeDisplay` 中的额外显示字段。
- 兼容裸 `#` 账号、Base32 空格/连字符、`Algorithm.sha256` 等 Dart 枚举、`issuer` 粘连的 `period=` 和旧版 JSON 尾部 `} #`。错误记录计数提示，不向错误信息输出密钥。重复验证码（包括回收站）跳过；HOTP 去重忽略计数器和名称，避免旧导出或改名后再导入造成计数倒退。
- 合并向导根据小型品牌域名字典和精确账号建议匹配，默认不勾选。仅给无验证码、非回收站且唯一匹配的登录项建议；用户勾选才合并，保留密码、密码历史、查看保护，拼合备注、标签与置顶。未合并验证码单独建登录项，不猜测网站匹配规则。
- 导出 Ente Auth 文本需要风险勾选、危险操作确认和主密码验证（PIN 不允许）。包含回收站验证码与元数据，导出 Worker 仅收到所需验证码字段，不接收登录密码。导入器只在迁移或 CSV 任务时加载，不进入日常解锁路径。
- 独立验证码在详情页明确标为「两步验证码」，不显示不存在的密码或泄露检查，也不计入弱密码体检；有密码的登录项保持原有体检逻辑。
- OTP 模块提供时钟偏移参数；当前界面使用本机时间，尚未接入三期 WebDAV 时间校准。网页填充时不足 2 秒改用下一期验证码。

### 防钓鱼自动填充与密码捕获

- HTTP(S) 网页的可见输入框可通过 Vault 图标、`Alt+Shift+L` 或右键「使用 Vault 填充」打开账号菜单，选择后才填入。支持登录、分步用户名、验证码、支付卡、身份地址及当前表单可见的同名自定义字段；不向内容脚本发送整库或完整条目。
- 候选菜单位于 Closed Shadow DOM 内的扩展源 iframe。内容脚本只拿到 120 秒随机句柄；后台绑定浏览器提供的标签、帧、文档和实际 URL，验证菜单文档、顶层导航及原输入框后，才解密选中的字段。句柄不写入 URL 或网页 DOM 属性，成功/关闭/锁库后失效。
- 使用 Public Suffix List（含私有后缀）、内置及自定义关联域名组；支持主域名、主机、前缀、精确、正则和从不匹配规则。正则使用线性时间 RE2JS；本地名称与 IP 强制保持协议/主机/端口边界，禁止正则放宽。HTTPS 凭证不降级匹配 HTTP，跨站 iframe 或 HTTP 均需额外确认；跨源提交的表单拒绝填充。
- 可见性、尺寸、命中测试过滤隐藏/透明/屏幕外的蜜罐。原生 setter 和事件链支持 React 受控表单、Open Shadow DOM、分步登录及 OTP 分格。受保护条目仍由后台验证主密码/PIN。
- 提交或跳转时提示保存新凭证、更新密码；已保存的相同账号密码不重复提示。只在点击确认后写入快照，更新保留旧密码历史；未确认的捕获值到期丢弃。
- 快速跳转时以新网页请求为准，旧页面的异步捕获或填充完成回调只清理自己的授权，不会使新菜单失效。
- 登录填充后可复制时间验证码，默认勾选、可取消，约 30 秒后按哈希检查并清理剪贴板。HOTP 不随登录填充推进；只有明确选择填入 HOTP 时先原子落盘再发送验证码。
- 密码库列表提供当前站点的填充图标、保存提示及未来 Passkey 接管三项开关；设置可编辑关联域名组。Passkey 开关目前仅保存偏好。

### 截图扫描验证码

- 在二维码所在网页点击工具栏 Vault 图标授予 `activeTab`，然后在登录凭证编辑页展开两步验证码，选择「扫描当前网页二维码」。侧栏使用前也需先点该网页的工具栏图标；缺少授权会给出操作提示。
- 后台截取当前视口，在特权离屏文档转为灰度，再交由独立 `vault-qr` WASM（`rqrr`）处理。支持亮色、暗色二维码及多个有效结果，只返回合法 `otpauth://` 设置。页面的 canvas 被阻断也不影响扫描。
- 只在本机内存处理截图，限制 8192×8192、总计 1600 万像素；切换目标网页会取消结果。选中二维码后写入当前编辑表单，仍需保存凭证。没有二维码时提示手动输入密钥。

### Bitwarden / Vaultwarden 与通用 CSV

- 「设置 → Bitwarden 密码库迁移」支持明文 JSON、`passwordProtected` 可移植加密 JSON 的导入/导出。兼容 PBKDF2-SHA256、Argon2id，按官方 HKDF 与 AES-256-CBC/HMAC EncString 格式处理，认证通过后解密；KDF 参数有资源上限。加密导出默认 PBKDF2 600,000 轮、独立文件密码。
- 支持登录及 OTP、支付卡、身份、安全备注四类。保留文件夹标签、置顶、回收站、二次验证、密码历史和自定义字段；未映射字段随条目加密保留，导出再还原。安全备注在本库以「安全备注」开发者条目呈现。源 Passkey 字段仅保留，尚不能登录；独立 SSH 类型及附件内容不导入，需继续保留原密码库。
- 「设置 → CSV 字段映射与导出」通过下拉选择对应源列，支持名称、网站、账号、密码、备注、OTP、标签和回收站。网站及密码为必选；支持 BOM、多行、逗号和引号，禁止复用源列。无法识别的 OTP 原值作为隐藏字段保留并提示。
- Bitwarden 限 16 MiB、CSV 限 2 MiB，单次最多 5,000 条。预览只发送摘要，确认绑定原文件、字段映射和当前密文快照；验证后一次性写入。重复项及回收站中的已有项不会覆盖，HOTP 去重忽略计数器，旧导出不能使已保存令牌的计数倒退。
- 全库迁移导出强制主密码验证，PIN 不接受。明文 JSON/CSV 另须风险勾选和确认；加密 JSON 使用独立文件密码。CSV 只导出登录项及首个 URI，明确报告跳过的其他类型；完整备份仍用 `.vaultpack`。密码原值不为表格公式转义而改写，CSV 只供迁移，勿直接用表格软件打开。

### 权限与本地边界

- 新增 HTTP(S) 站点权限、`activeTab`、右键菜单和内容脚本，用于用户触发的填充与截图；浏览器升级安装时可能再次要求接受权限。没有 `<all_urls>`、文件网址或 Google 服务依赖。
- `storage.local` 与 `storage.session` 均在处理网页请求前设为仅可信上下文可访问；网页填充消息与密码库管理消息独立授权，inline-menu/content/offscreen 均不能发起整库管理操作。
- 网站开关和关联域名组通过独立 `vault-preferences` WASM 加密后存于受限的 `storage.local`，域名不会明文落盘。复用会话包装的 DEK，通过专用 HKDF 域派生配置密钥，并绑定密码库 ID、认证加密和 256 字节分桶；换主密码及重新解锁后保持可读。该偏好只属于本机，不包含在凭证迁移或 `.vaultpack` 中。
- 网站偏好解锁后才读取，锁库清除内存缓存；密文损坏时拒绝填充，不用空设置覆盖。开发版遗留的明文偏好只有在加密保存成功后才移除。保留的第三方元数据与未识别验证码种子均不能通过自定义填充带出。
- 站点权限覆盖泄露查询服务，因此后台另行要求每次请求带本次联网确认；不会因自动填充权限自动发起在线泄露检查。

## 验证

2026-11-17 本轮补齐：

- `cargo test --workspace --offline`：33 项通过（主核 14、导入器 12、OTP 5、二维码 1、网站偏好 1）；`pnpm run build`、TypeScript 检查通过。`pnpm run test:extension`：4 个文件、34 项通过，包括来源/导航/句柄、旧异步请求与新菜单隔离、失效预览、原子回滚、HOTP 去重、主密码限定导出、逐次联网确认，以及网站偏好的密文存储、改密恢复、篡改拒绝和开发版迁移中断恢复。
- `WebAssembly.validate` 通过：主核 **255,548 字节**、导入器 277,135 字节、OTP 59,842 字节、二维码 174,076 字节、网站偏好 261,817 字节。主核距 250 KiB（256,000 字节）上限仅余 452 字节；新增逻辑均留在独立 Worker。构建检查确认后台、派生 Worker、内容脚本不含迁移或扫码入口。
- `pnpm run test:autofill`：Edge / Helium 通过 React 受控表单、分步登录、隐藏蜜罐、Closed/Open Shadow DOM、跨域确认、内网端口隔离、OTP 分格、受保护填充、可见自定义字段、支付卡与身份地址、跳转后捕获、更新历史、快捷键与关闭，以及网站开关禁用/恢复和磁盘域名零明文。页面错误均为空。
- `pnpm run test:migration`：Edge / Helium 通过四类型迁移、预览不写入、取消、二次验证、重复导入、CSV 映射/原值/导出、实际下载核对，以及亮暗截图二维码和无二维码场景。Node 独立实现的 PBKDF2/Argon2id/AES/HMAC 夹具与 WASM 结果交叉验证，错误密码与篡改文件被拒绝。测试通过实际浏览器工具栏动作取得截图授权，没有伪造权限或读取网页 canvas。
- 首次扫码端到端最近观测：Edge **161 ms**、Helium **236 ms**（1000×800 视口、420 像素二维码）；此前 Helium 241–303 ms。**Helium 未达到 `< 200 ms` 指标，不能将二期 Exit Gate 标为通过。** 连续截图按浏览器限流间隔等待，以上数字不代表所有窗口/设备的性能。
- `pnpm run test:phase-2`、`pnpm run test:data-safety`、`pnpm run test:smoke`：Edge 157.0.4341.60、Helium 157.0.8103.78 通过，原有 OTP/Ente、备份恢复、密文落盘、后台恢复、虚拟 PRF 与剪贴板清理/防误删无回归。后台唤醒最近观测 53 / 52 ms；没有将一期性能目标改为已满足。
- 已检查 400×600 弹窗、330 宽侧栏和跨域内联菜单截图；新增界面的 Impeccable 静态检测零报告。Helium 的新网页测试使用实际窗口并等待内置拦截器正常初始化，无头模式本机导航不稳定；测试不修改拦截设置或日常浏览器配置。
- 内置可见浏览器工具发现返回 `unsupported call`；证据来自真实 Edge / Helium 的 Playwright 自动回归及截图，不代表原生侧栏、实体系统能力或交互式人工验收。

2026-11-17 验证器与 Ente Auth 批次：

- `cargo test --workspace --offline`：28 项通过（主核 14、导入器 9、OTP 5），含 RFC 4226 十组 HOTP、RFC 6238 三算法全量标准向量、Steam 固定向量、64 位计数器、下一期/偏移、Ente 元数据往返和独立验证码不误报弱密码。
- `pnpm run build` 和 TypeScript 检查通过。主 WASM **255,548 字节**，低于 250 KiB（256,000 字节）；导入器 157,721 字节，OTP 59,842 字节，三个模块通过 `WebAssembly.validate`。
- `pnpm run test:extension`：19 项通过，新增并发计数/Worker 重建、磁盘写入失败回滚、二次验证、失效预览、可选合并、钓鱼域名不匹配及明文导出授权检查。
- `pnpm run test:phase-2` 在独立临时 Edge、Helium 配置通过，覆盖 CSV 旧流程、导入取消/预览/合并、回收站保留、HOTP 原子落盘/复制/生成后编辑、Steam 与下一期预览、导出取消与主密码限定、实际下载文件的计数器和元数据核对。两个浏览器页面错误及扩展失败请求均为空。自动截图已检查 400×600 弹窗及 330 宽侧栏；界面静态检测零报告。
- `pnpm run test:data-safety`、`pnpm run test:smoke` 也在 Edge 157.0.4341.60、Helium 157.0.8103.78 通过，覆盖回收站清空范围、取消下载提醒、跨主密码备份恢复、密文落盘、Worker 唤醒、虚拟 PRF 与剪贴板清理/防误删；控制台错误为空。唤醒观测均为 40 ms，不代表所有设备的性能保证。
- 内置可见浏览器工具发现调用返回 `unsupported call`，本轮浏览器证据来自真实 Edge / Helium 的 Playwright 自动回归及截图，不代表交互式人工验收。

2026-11-14 首批：

- `cargo test --workspace --offline`：18 项通过，含 RFC 6238 三算法向量和 Chromium / Firefox / Safari 风格的 CSV 样本。
- `pnpm run build`、`pnpm --filter ./apps/extension compile`、`pnpm run test:extension` 通过：主 WASM 254,723 字节，低于 250 KiB；13 项后台集成测试含去重、预览不写入、失效预览拒绝、旧凭证保留及验证码密钥从密文恢复。
- `pnpm run test:phase-2`、`pnpm run test:data-safety` 在独立 Edge 和 Helium 配置通过。验证了取消确认、验证码轮换、受保护详情解锁、复制请求及一期备份恢复；二期复制测试不改系统剪贴板。两套真实扩展页面均未记录控制台错误。

## 未通过项与格式限制

- Helium 首次扫码 `< 200 ms` 性能门禁仍未通过。真实 Google/Microsoft/GitHub 登录、右键菜单、实体 Windows Hello、系统锁屏及原生侧栏交互仍需人工验收；一期要求沿用 [一期记录](phase-1-status.md)。
- Bitwarden 账号绑定的加密导出依赖原账号密钥，不能仅凭主密码直接解密；会提示在 Bitwarden 中重新选择「密码保护」或明文 JSON。Argon2id 导入上限为 16–256 MiB、2–10 轮、1–16 路且内存×轮数不超过 1024；PBKDF2 为 5,000–2,000,000 轮。超出上限的文件需在源应用中重新导出。
- Ente Auth 仅支持未加密 URI 行文本，不解密其加密 JSON。Bitwarden / Ente Auth 原生应用实际导入验收未进行，当前互通证据为官方格式源码、独立密码学实现和往返夹具。
- CSV 不承载完整条目、附件或 Passkey；不用于替代 `.vaultpack` 备份。通用映射以明确的源列下拉选择实现。
- WebDAV 同步、服务端时间校准与 Passkey 签名/接管属于三、四期，尚未开始。

格式依据（2026-11-17 核对）：

- [Ente Code / URI 模型](https://github.com/ente-io/ente/blob/main/mobile/apps/auth/lib/models/code.dart)
- [Ente CodeDisplay 模型](https://github.com/ente-io/ente/blob/main/mobile/apps/auth/lib/models/code_display.dart)
- [Ente 文本解析](https://github.com/ente-io/ente/blob/main/mobile/apps/auth/lib/ui/settings/data/import/plain_text_import_parser.dart)
- [Bitwarden 加密导出种类与限制](https://bitwarden.com/help/encrypted-export/)
- [Bitwarden 密码保护导入器](https://github.com/bitwarden/clients/blob/main/libs/importer/src/importers/bitwarden/bitwarden-password-protected-importer.ts)
- [Bitwarden 导出实现](https://github.com/bitwarden/clients/blob/main/libs/tools/export-vault-core/src/services/base-vault-export.service.ts)
- [Bitwarden KDF 与盐值约定](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-crypto/src/keys/kdf.rs)
- [Chrome tabs.captureVisibleTab 权限与频率限制](https://developer.chrome.com/docs/extensions/reference/api/tabs#method-captureVisibleTab)

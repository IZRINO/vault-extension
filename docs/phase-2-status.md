# 二期开发记录

更新于 2026-11-17。浏览器密码 CSV、手动 TOTP、HOTP / Steam Guard 和 Ente Auth 文本双向迁移已实现；二期尚未验收。

## 已实现

- 从「设置 → 导入浏览器密码」选择浏览器导出的 UTF-8 CSV，预览可添加、重复和无法读取的条目；输入主密码或 PIN 确认后，才将新增凭证一次写入加密快照。依据网站地址的主机与端口、账号去重，已存在或在回收站的凭证不覆盖。期间文件或快照变化会要求重新预览。
- 单次最多 2 MiB、5,000 条。支持带 BOM、引号、逗号和换行的字段。CSV 只在本机读取，不改原文件，不导入 CSV 内的验证码设置；预览会提示这部分跳过。只导入 HTTP(S) 登录凭证。
- 登录凭证的编辑页可手动添加、修改或移除 Base32 密钥或 `otpauth://totp|hotp|steam/` 链接。时间验证码支持 SHA-1 / SHA-256 / SHA-512、6–8 位和链接指定的周期；Steam Guard 输出 5 位字符。倒计时不足 5 秒时显示下一期验证码。受保护凭证仍须通过后台二次验证。
- 沿用一期快照及 `.vaultpack` 数据格式，没有新增站点权限或网页内容脚本。CSV 解析和 TOTP 验证使用独立的按需 Worker，详情页显示验证码时才加载 TOTP 模块。

### 本轮新增：验证器与迁移（2026-11-17）

- HOTP 链接必须含 `counter`；使用字符串跨越 JavaScript 边界，支持完整 `u64` 计数，溢出时拒绝取码。取码请求由后台串行处理，先提交加密快照和计数器，再返回验证码；写入失败恢复已提交快照，不返回或消耗验证码。复制已生成的码不推进计数。受保护条目每次生成均重新验证。
- HOTP 计数更新与 `pendingChanges['hotp-snapshot']` 在同一笔严格持久化的 IndexedDB 事务提交。当前记录是合并保留的最新 HOTP 加密快照；三期再接入 WAL 增量编码与实际同步，当前不会联网同步。
- 「设置 → Ente Auth 验证器迁移」支持 UTF-8、每行一个 `otpauth://` 的未加密 `.txt`，最多 2 MiB、5,000 个验证码。预览只返回脱敏摘要，文件和快照摘要绑定确认；主密码或 PIN 验证后一次性合入快照。保留置顶、标签、备注、回收站及 `codeDisplay` 中的额外显示字段。
- 兼容裸 `#` 账号、Base32 空格/连字符、`Algorithm.sha256` 等 Dart 枚举、`issuer` 粘连的 `period=` 和旧版 JSON 尾部 `} #`。错误记录计数提示，不向错误信息输出密钥。重复验证码（包括回收站）跳过；HOTP 去重忽略计数器和名称，避免旧导出或改名后再导入造成计数倒退。
- 合并向导根据小型品牌域名字典和精确账号建议匹配，默认不勾选。仅给无验证码、非回收站且唯一匹配的登录项建议；用户勾选才合并，保留密码、密码历史、查看保护，拼合备注、标签与置顶。未合并验证码单独建登录项，不猜测网站匹配规则。
- 导出 Ente Auth 文本需要风险勾选、危险操作确认和主密码验证（PIN 不允许）。包含回收站验证码与元数据，导出 Worker 仅收到所需验证码字段，不接收登录密码。导入器只在迁移或 CSV 任务时加载，不进入日常解锁路径。
- 独立验证码在详情页明确标为「两步验证码」，不显示不存在的密码或泄露检查，也不计入弱密码体检；有密码的登录项保持原有体检逻辑。
- OTP 模块提供时钟偏移参数；当前界面使用本机时间，尚未接入三期 WebDAV 时间校准。网页填充时不足 2 秒改用下一期验证码，仍随自动填充开发。

## 验证

2026-11-17 本轮：

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

## 尚未实现

Bitwarden 互通、通用 CSV 字段映射/导出、屏幕扫码和网页自动填充。Ente Auth 目前只处理未加密 URI 行文本，不解密其加密 JSON 备份；真实 Ente Auth 应用中的导入验收尚未进行，互通依据官方解析源码和往返夹具验证。

本轮未新增网页权限；接入内容脚本前，先限制 `storage.local` 只对可信上下文可见，并将网页消息与现有密码库管理消息分开授权。实体 Windows Hello、系统锁屏和原生侧栏的人工验收仍依 [一期记录](phase-1-status.md)。

格式依据（2026-11-17 核对）：

- [Ente Code / URI 模型](https://github.com/ente-io/ente/blob/main/mobile/apps/auth/lib/models/code.dart)
- [Ente CodeDisplay 模型](https://github.com/ente-io/ente/blob/main/mobile/apps/auth/lib/models/code_display.dart)
- [Ente 文本解析](https://github.com/ente-io/ente/blob/main/mobile/apps/auth/lib/ui/settings/data/import/plain_text_import_parser.dart)

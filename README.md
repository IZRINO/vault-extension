# Vault Extension

**本地优先、零服务端的端到端强加密浏览器密码与通行密钥管理器**

> **English**: A local-first, serverless, zero-knowledge end-to-end encrypted browser credential manager built with **Rust/WebAssembly** and **WXT (Manifest V3)** — unifying passwords, Passkeys (WebAuthn), built-in 2FA (TOTP/HOTP/Steam), and lock-free WebDAV delta sync, tailored for **Microsoft Edge** and **Helium Browser**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/Chromium_MV3-Edge_%7C_Helium_%7C_Chrome-0f766e.svg)](#目标浏览器适配)
[![Core](https://img.shields.io/badge/Security_Core-Rust_%2B_WASM-b45309.svg)](#系统架构与安全边界)
[![Sync](https://img.shields.io/badge/Sync-Serverless_WebDAV-4f46e5.svg)](#纯-webdav-极简增量同步引擎)

---

> **项目状态（2026-11-19）**：本地加密库、网页填充、OTP 与迁移在原实现上收尾，已加入 WebDAV 增量同步、软件 Passkey 和四期计划内迁移格式。可以构建 MV3 安装候选包；千条凭证的原生 Popup 冷开尚未达到准出指标，实体设备、真实网盘和第三方应用验收未签收。当前证据与格式限制见 [候选包验证记录](./docs/release-candidate-status.md)，历史基准见 [一期](./docs/phase-1-status.md) 和 [二期](./docs/phase-2-status.md)。下文全景包含尚未排期的架构目标。

## 设计目标与安全红线

`vault-extension` 旨在提供一款**不依赖任何官方中心化服务器、数据 100% 由用户自主掌控且可完整代码审计**的现代浏览器全能凭证管理扩展：

1. **真正的零知识架构（Zero-Knowledge）**：无官方后端；主密码（Master Password）永不离开本机内存，网站域名（URL / RP ID）、2FA 密钥、备注及条目精确字节长度等全部元数据均经认证加密并按 `256 Bytes` 分桶填充隐藏。
2. **Rust / WASM 内存隔离与即时擦除**：密钥派生、AEAD 加解密、Passkey 私钥签名、TOTP/HOTP/Steam 口令计算及第三方加密备份解析全部运行于 **Rust 编译的 WebAssembly 线性内存**中，核心密钥材料与 Rust 敏感缓冲区通过 `Zeroize` 擦除。输入和显示密码时仍会经过 JavaScript 字符串，不能承诺浏览器 GC 内存的确定性擦除。
3. **全链路加密传输与最小权限隔离**：外部 WebDAV 同步强制要求 `HTTPS (TLS 1.2/1.3)` 叠加应用层 `XChaCha20-Poly1305` 端到端加密与 BLAKE3 状态树防回滚校验；内部 `Content Script ↔ Background Service Worker` 严格校验 `sender.origin` / `tab.url`，仅向页面上下文传递脱敏候选摘要与句柄，绝不下发整库或私钥。
4. **纯 WebDAV 无锁极简增量同步**：无需自建同步后端，采用 **LSM-Tree 思想的紧凑快照（Snapshot）+ 预写增量日志（WAL Delta）+ HLC 三路合并（3-Way Merge）**；内置**坚果云**与 **Koofr** 官方地址预设，1,000 条全量凭证快照仅 `~200 KB`，单次修改增量传输仅 `~320–512 B`。
5. **开放生态与零锁定迁移（Zero Lock-in）**：一等公民双向兼容 **Ente Auth 纯文本导出格式**（完整保留置顶、标签、备注等扩展元数据）与 **FIDO CXF 1.0** 行业凭证交换标准，支持主流密码管理器及验证器本地内存直解迁移。

---

## 核心功能全景

### 1. 全类型凭证库与本地安全体检
- **多合一凭证模型**：
  - **登录项（Login）**：账号密码、自动保留最近 20 次变更的 `passwordHistory[]`、多 URI 独立匹配规则（`eTLD+1`、`精确主机 Host`、`前缀 StartsWith`、`完全一致 Exact`、`正则 Regex`、`从不匹配 Never`）。
  - **通行密钥（Passkey / FIDO2）**：支持挂载于同一网站登录项下聚合管理或独立成项，支持 `ES256`（P-256）与 `EdDSA`（Ed25519）。
  - **两步验证（Built-in 2FA）**：原生支持 `TOTP`（RFC 6238，`SHA-1/256/512`，自定义位数与步长）、`HOTP`（RFC 4226）及 **5 位 Steam Guard 令牌**。
  - **支付卡与身份地址**：卡号默认仅展示后 4 位、自动识别卡组织品牌，支持网页结账（`cc-*`）与收货/政务/开票表单快速填充。
  - **开发者密钥（折叠模板）**：轻量收纳 API Token、软件 License Key 与 SSH 密钥对，兼顾日常清爽界面与第三方全量导入无损还原。
- **精细安全控制**：支持单条目**高敏二次验证（`requireReprompt`）**、多标签、收藏置顶、30 天软删除回收站、CSPRNG 随机密码与 EFF 7776 词助记口令（Passphrase）生成、纯离线弱密码/重用检测，以及基于 Have I Been Pwned **k-Anonymity 协议**（仅发送 SHA-1 前 5 位前缀）的可选泄露检查。

### 2. 防窃密自动填充引擎（Autofill & Anti-Exfiltration）
- **零静默填密红线**：严禁页面加载时零交互自动填入密码，必须由用户显式点击内联锁图标、快捷键（默认 `Alt+Shift+L`）或右键菜单触发，彻底免疫隐藏 `<input type="password">` 蜜罐窃密。
- **渲染与通信隔离**：内联候选菜单采用 **`Closed Shadow DOM` 包裹扩展源 `Iframe`**，阻断宿主网页 JS 嗅探账号列表或伪造点击事件（强制校验 `event.isTrusted`）。
- **智能匹配与防钓鱼校验**：
  - **跨域 `<iframe>` 强告警**：顶层站点与嵌套子帧跨域且非关联域名时，禁止一键静默填充并高亮弹窗二次确认。
  - **关联域名等价组**：内置常见跨域名统一账号体系词典（如 `taobao.com ↔ tmall.com ↔ alipay.com`、`microsoft.com ↔ live.com ↔ office.com`、`google.com ↔ youtube.com` 等）并支持自定义扩展。
  - **内网与本地端口隔离**：识别 `localhost`、回环地址与局域网私有 IP（`10.x` / `172.16-31.x` / `192.168.x` / `.local`）时自动将默认匹配收紧为 **`Host + Port`**，避免同 IP 不同端口服务（如 NAS 与容器面板）串弹密码。
  - **按站三项独立开关**：支持按域名一键独立禁用「内联图标注入」「自动保存提示」或「Passkey 拦截接管」。
  - **现代前端兼容**：通过原生原型 Setter 与完整事件链写入 React / Vue / Angular 受控输入框，支持分步登录状态机与 Open Shadow DOM 穿透。

### 3. Passkey 软认证器与原生无缝回退
- 采用 `MAIN` World（`document_start`）桥接 `navigator.credentials` 的行业成熟方案（避免 `chrome.webAuthenticationProxy` 全局挂起系统生物识别与物理硬件密钥）：
  - 用户选择扩展 Passkey 后，软认证器校验 RP ID 并返回 `PublicKeyCredential`（默认 `fmt: "none"`、`signCount = 0`）。网站要求验证用户时，不能用库已解锁或点击凭证代替本次验证。备份资格 `BE` 在创建时确定；只有确认已有可恢复副本才报告 `BS=1`；
  - 用户选择「使用系统 / 硬件密钥」→ 直接透传原生 WebAuthn 接口，无缝唤起 **Windows Hello 或物理 YubiKey**。
- 支持 `Conditional UI`（`autocomplete="username webauthn"`）输入框内联一键无密登录。

### 4. 极致内置 2FA 体验
- **网页二维码一键截图识别**：后台调用 `chrome.tabs.captureVisibleTab()` 截取当前视口并在 WASM 内通过 `rqrr` 毫秒级解码，不依赖页面 `<canvas>` 读取，天然免疫反指纹噪声与跨域图片污染。
- **平滑跨期与分格填充**：倒计时 `< 5 秒` 时同屏预览**下一期验证码（Next Code）**；填充密码后自动复制 TOTP（30 秒后通过 `Offscreen Document` 比对哈希安全清空剪贴板），并支持自动填入单框或 **6 个独立 `<input maxlength="1">` 分格输入框**。
- **零成本时钟校准**：复用 WebDAV 同步响应头中的标准 HTTPS `Date` 时间戳检测本机时钟偏差（`>= 15 秒` 告警并支持 WASM 内偏移量自动补偿），无需请求第三方 NTP 服务。

---

## 目标浏览器适配

一期聚焦 Chromium Manifest V3 桌面生态，针对 **Microsoft Edge** 与 **Helium Browser**（[`imputnet/helium`](https://github.com/imputnet/helium)）做了专项工程适配，同时兼容 Chrome、Brave、Vivaldi、Arc：

| 适配维度 | Microsoft Edge | Helium Browser | 工程实现策略 |
| :--- | :--- | :--- | :--- |
| **云服务依赖** | 剥离 Google 同步 | **彻底移除全部 Google 服务**（无 `chrome.identity` / `storage.sync`） | 零 Google API 依赖，统一采用 `IndexedDB` + `storage.local` + WebDAV |
| **原生密码气泡** | 内置微软保存弹窗易冲突 | 官方不内置密码管理器，天然无冲突 | 提供可选 `privacy` 权限一键接管并关闭浏览器内置密码保存提示 |
| **反指纹噪音** | 标准 Chromium 行为 | 默认向页面 `<canvas>` / 音频 / 硬件注入反指纹噪声 | 绝不使用设备指纹派生密钥；2FA 扫码走后台特权截图 + WASM 解码 |
| **常驻交互视图** | 支持 `chrome.sidePanel` | 支持 `chrome.sidePanel` | 同时提供工具栏 `Popup` 快捷面板与 `SidePanel` 侧边栏常驻视图 |
| **生物识别解锁** | 支持 Windows Hello | 支持系统原生 WebAuthn | 基于 WebAuthn `PRF (hmac-secret)` 闭环自检接入系统生物识别，不支持时平滑降级本地 PIN |

---

## 系统架构与安全边界

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          不可信网页环境 (Web Page)                            │
│  ┌───────────────────────────────┐    ┌──────────────────────────────────┐  │
│  │  Content Script (MAIN World)  │    │  Content Script (ISOLATED World) │  │
│  │  - 拦截 navigator.credentials │◄──►│  - 表单/OTP框探测 & 受控组件填充 │  │
│  │  - 支持一键回退 Windows Hello │    │  - Closed Shadow DOM + 扩展Iframe│  │
│  └───────────────────────────────┘    └─────────────────┬────────────────┘  │
└─────────────────────────────────────────────────────────┼───────────────────┘
                                                          │ 受控 IPC 消息
                                                          │ (强制校验 sender.origin / tab.url)
┌─────────────────────────────────────────────────────────▼───────────────────┐
│                     扩展特权上下文 (chrome-extension://)                      │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              Background Service Worker (核心调度层 - TS)               │  │
│  │  - 会话锁管理 (Idle/Alarm/Session)   - Origin 与 eTLD+1 防钓鱼校验    │  │
│  │  - WebDAV 增量同步与版本留存调度     - 按需拉起 Offscreen 清空剪贴板  │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                 Rust / WASM Vault Core (安全内核)                │  │  │
│  │  │  - Argon2id + HKDF 密钥树         - XChaCha20-Poly1305 AEAD     │  │  │
│  │  │  - Passkey CTAP2/WebAuthn 签名机  - TOTP/HOTP/Steam 口令引擎     │  │  │
│  │  │  - MsgPack + Zstd 紧凑编码器      - HLC 三路合并与冲突检测引擎   │  │  │
│  │  │  - Zeroize 内存即时擦除                                          │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └──────────────┬───────────────────────────────────────┬────────────────┘  │
│                 │                                       │                   │
│  ┌──────────────▼──────────────┐         ┌──────────────▼────────────────┐  │
│  │ 本地持久化与会话层           │         │ 扩展 UI 层 (React + Tailwind) │  │
│  │ - IndexedDB (密文快照+本地WAL)│         │ - Popup / SidePanel (日常使用)│  │
│  │ - storage.local (加密同步配置)│         │ - 管理台 & Git 冲突对比合并页 │  │
│  │ - storage.session (会话密钥) │         │ - Offscreen 剪贴板清理宿主页  │  │
│  └──────────────┬──────────────┘         └───────────────────────────────┘  │
└─────────────────┼───────────────────────────────────────────────────────────┘
                  │ HTTPS (TLS 1.3) + AEAD 密文分桶流
                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│    用户自有 WebDAV 存储 (默认可选: 坚果云 / Koofr；兼容 Nextcloud / NAS)    │
│   head.bin + 最新 5 个 snap_<id>.bin (~200KB/个) + wal/<hlc>_<dev>.bin      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 密码学设计要点

- **双路包装三层密钥树（改密零全库重加密 + 遗忘主密码兜底）**：
  - 建库时由 CSPRNG 生成真正的 `256-bit Vault Master DEK`，分别由**主密码分支**（独立 Web Worker 中运行 `Argon2id`：`64 MiB, t=3, p=4` → `HKDF`）与**256-bit 应急恢复码分支**（`Vault-Emergency-Kit`）双路独立包装存入 `head.bin`。
  - 日后修改主密码仅需重加密 32 字节的 `wrapped_dek_master` 并递增 `key_epoch`，无需重传整库；万一遗忘主密码，凭应急恢复码即可无损恢复 `DEK`。
  - `Master DEK` 经 `HKDF-SHA256` 派生独立的快照密钥、WAL 密钥与 BLAKE3 状态树签名密钥；未超时锁库前通过纯内存驻留、关浏览器即焚的 `chrome.storage.session` 托管临时会话包装密钥，唤醒恢复 `< 5ms`。
- **为什么选择 `XChaCha20-Poly1305`**：
  - **192-bit（24 字节）超长随机 Nonce** 彻底消除无中心协调器下多设备并发写入的 Nonce 碰撞隐患；
  - 纯 ARX 整数运算在缺少硬件 `AES-NI` 直通的 WASM 沙箱中天然具备**常量时间抗缓存侧信道**优势与高吞吐；
  - 每个加密信封强制将 `{ magic, schema_version, file_role, object_id, hlc_epoch }` 作为 `AAD` 参与认证，严防远端密文跨角色调包与回滚重放。

---

## 纯 WebDAV 极简增量同步引擎

摒弃“改一个字重传整个大文件”或“几千条密码拆成几千个碎文件触发网盘限流”的做法，通过四步二进制紧凑编码（**原始字节类型化 → `MessagePack` 整数键序列化 → `Zstandard` 压缩 → `256B` 对齐填充**，且不同步 Favicon 图标）将体积压缩 **85%+**：

- **存储开销**：单条完整凭证（密码 + TOTP + Passkey + 备注）仅 `~180–240 B`；千级凭证全量快照 `snap_*.bin` 仅 `~200 KB`；单次增量日志 `wal/*.bin` 仅 `~320–512 B`。
- **网盘开箱预设与专项保护**：
  - **坚果云（Nutstore）**：自动拼接独立子目录并按序执行 `MKCOL` 建库，单次轮询仅 1 次 `PROPFIND`（`< 2 KB`），远低于免费版限流阈值。
  - **Koofr**：固化区分大小写的 `/dav/Koofr/` 标准路径；内置 **`401/403/429` 鉴权防锁号熔断器**，避免后台重试触发 Koofr 1 小时封禁；全程采用不可变追加写，不发 `LOCK` 请求，彻底规避 `423 Locked` 锁残留。
  - **自定义 WebDAV**：可配置 Nextcloud、群晖 NAS、OpenList 等 HTTPS 服务。不能证明服务会拒绝过期条件写时，只支持读取恢复，不建库、不上传、不清理。
- **防丢库与多端冲突治理**：
  - **首屏 WebDAV 优先引导 & 空库熔断**：首次连接先探测远端，有数据则直接进入拉取恢复；本地有效条目归零或单次骤减 `>= 50%` 时硬拦截静默推送。
  - **端到端加密设备溯源（`DeviceMetadata`）**：精准识别本机历史包防幂等自冲突，支持重装系统后认领旧电脑身份。
  - **三路合并与 Git 风格可视化冲突对比页**：99% 不同条目或同条目不同字段变更静默无损合并；真冲突隔离至待合并区并唤醒双栏差异合并页（支持全局一键选边、拆双份及逐字段挑拣，**未被选中的落选密码自动归档至 `passwordHistory[]`**，确保任何点击零数据丢失）。
  - **并发安全 Compaction 与 5 版本快照回滚**：精确按已吸收清单清理 `wal/`，并在远端滚动保留最近 **5 个历史快照**（总占用仅 `~1 MB`），随时可一键回滚恢复。

---

## 导入与导出生态矩阵

所有第三方备份（含加密格式）均在**本地懒加载模块 `vault-importers.wasm` 内存中直接解密转换**，无需生成明文中间文件：

| 类别 | 来源软件 / 标准 | 支持格式 | 可迁移内容 |
| :--- | :--- | :--- | :--- |
| **行业标准** | **FIDO Credential Exchange (CXF 1.0)** | `.cxf` / `.json` | 密码 + Passkey 私钥 + 2FA + 备注 |
| **全功能密码库** | **Bitwarden / Vaultwarden** | 明文/加密 `.json`、`.csv` | 密码 + Passkey + 2FA + 支付卡 + 身份信息 + 自定义字段 |
| **全功能密码库** | **KeePassXC / KeePass / Strongbox** | `.kdbx` (v3.1 / v4.x)、`.xml`、`.csv` | 密码 + Passkey (`KPEX_PASSKEY_*`) + 2FA + 分组/历史 |
| **全功能密码库** | **1Password** | `.1pux`、`.csv` | 密码 + Passkey + 2FA + 支付卡 + 身份地址 + API 密钥 |
| **全功能密码库** | **Proton Pass** | `.zip` / `.json` / PGP 包 / `.csv` | 密码 + Passkey + 2FA + 备注 |
| **主流密码库 & 浏览器** | **Edge / Chrome / Firefox / Brave / Safari / Dashlane / NordPass / Enpass / LastPass** | `.json` / `.csv` | 密码 + 网址 + 备注（含表头自动嗅探与可视化映射兜底） |
| **二步验证（一等公民）** | **Ente Auth** | **纯文本 `.txt`**、加密 `.json` | **双向无损互通**：TOTP + HOTP + Steam + `codeDisplay`（置顶/标签/备注/回收站）+ 智能合并入已有密码项 |
| **二步验证** | **Google Authenticator / 2FAS / Aegis / Raivo / andOTP / Stratum** | `otpauth-migration://` 二维码、`.2fas`、加密 `.json`、`.txt` | 批量 TOTP / HOTP / Steam（支持本地直解 2FAS 与 Aegis 加密备份） |

**规划的导出格式**：原生加密备份（`.vaultpack`）、FIDO CXF 1.0（`.cxf`）、Bitwarden JSON、Ente Auth 文本及通用 CSV。所有整库导出均须重新验证当前库主密码，PIN 和独立文件密码不可替代；明文另需风险确认。原生备份尚需按 [#37](https://github.com/IZRINO/vault-extension/issues/37) 对齐此规则；日常看码、填码不交付种子的修正见 [#38](https://github.com/IZRINO/vault-extension/issues/38)。

---

## 技术栈选型

| 层级 | 技术方案 | 说明 |
| :--- | :--- | :--- |
| **扩展工程框架** | [WXT](https://wxt.dev/) + Vite | 原生 Chromium MV3 支持，`MAIN` / `ISOLATED` 双世界脚本编排与极速 HMR |
| **前端 UI 与状态** | React 19 + TypeScript 5 + Tailwind CSS v4 + shadcn/ui + Zustand | 轻量高响应（Popup 冷启动目标 `< 50ms`），完备键盘流无障碍导航 |
| **常驻安全主核** | Rust (Edition 2024) → `vault-core.wasm` (`wasm-bindgen`) | `argon2`、`hkdf`、`chacha20poly1305`、`blake3`、`p256`、`ed25519-dalek`、`ciborium`、`rqrr`、`rmp-serde`、`zstd`、`zeroize`（目标体积 `~200 KB`） |
| **按需导入解析包** | Rust → `vault-importers.wasm` | 独立懒加载分包（`keepass`、`prost`、`zip` 等），保持后台 Service Worker 极致精简 |
| **本地存储与同步** | `IndexedDB` (`idb`) + `chrome.storage.local` + `chrome.storage.session` + 纯 `fetch` WebDAV 客户端 | 适配 MV3 Service Worker 无 DOM 环境，零 Polyfill 负担 |
| **质量与回归测试** | `cargo test` + Vitest + Playwright | 密码学/合并引擎单测 + Edge / Helium 真实浏览器端到端回归 |

---

## 目录结构

```text
vault-extension/
├── Cargo.toml                                # Rust Workspace 根配置
├── package.json                              # Monorepo 脚本入口
├── pnpm-workspace.yaml                       # pnpm 工作区定义
├── 密码管理器浏览器插件-技术架构与选型文档.md # 完整技术架构与协议设计规范 (v1.4)
├── 分期开发与验证计划.md                     # Phase 1–4 研发任务拆解与测试验收清单
├── crates/
│   ├── vault-core/                           # 常驻核心安全引擎 WASM 包 (密码学/Passkey/2FA/同步编解码/三路合并)
│   └── vault-importers/                      # 按需懒加载导入导出 WASM 包 (CXF/Ente/Bitwarden/KDBX/1PUX/OTP)
├── apps/
│   └── extension/                            # WXT + React 19 + Tailwind CSS v4 浏览器扩展主体
│       ├── entrypoints/                      # background / content scripts / popup / sidepanel / options / offscreen
│       └── wxt.config.ts                     # MV3 最小化权限与 WASM CSP 配置
└── tests/
    └── e2e/                                  # Playwright 自动化测试套件 (Edge & Helium)
```

---

## 本地开发与构建

### 环境要求

- **Rust**：`rustc >= 1.85`（支持 Edition 2024），已安装 `wasm32-unknown-unknown` 目标与 [`wasm-pack`](https://rustwasm.github.io/wasm-pack/)
- **Node.js**：支持 `node:zlib` Zstandard API 的版本及 `pnpm`；本次验证为 Node.js 26.13.1（标准格式互操作测试需要该 API）
- **浏览器**：Microsoft Edge、Helium Browser 或任意 Chromium 内核桌面浏览器

```bash
# 确保已添加 WASM 编译目标
rustup target add wasm32-unknown-unknown
```

### 常用命令

```bash
# 1. 安装工作区依赖
pnpm install

# 2. 编译 Rust WASM 模块 (vault-core & vault-importers)
pnpm run build:wasm

# 3. 启动扩展开发热重载模式
pnpm run dev

# 4. 构建生产环境 MV3 扩展包
pnpm run build

# 5. 运行 Rust 工作区单元测试
pnpm run test:rust

# 6. 后台集成测试（先生成 WASM 包）
pnpm run test:extension

# 7. 类型检查与 Edge / Helium 独立配置冒烟
pnpm --filter ./apps/extension compile
pnpm run test:smoke
```

### 在浏览器中加载调试

执行 `pnpm run build`（或 `pnpm run dev`）后：
1. 在 Edge 中打开 `edge://extensions`（Helium / Chrome 打开 `chrome://extensions`）；
2. 开启右上角/左侧的 **开发人员模式（Developer mode）**；
3. 点击 **加载解压缩的扩展（Load unpacked）**，选择 `apps/extension/.output/chrome-mv3` 目录即可体验。

---

## 实施路线图（Roadmap）

> 每一期的详细模块拆解、单元测试矩阵、安全靶场用例与实机准出红线见 [《分期开发与验证计划》](./分期开发与验证计划.md)。

- [ ] **Phase 1：密码学底座与本地密码库闭环（MVP）**
  - 跑通 `WXT + React + Rust/WASM` 构建链路及 Edge / Helium 加载验证
  - 实现 `vault-core` 的 Argon2id 异步 Worker 派生、256-bit 应急恢复码双路包装、HKDF + XChaCha20-Poly1305 密钥树、`storage.session` 无感唤醒恢复、PIN / Windows Hello (`PRF` 自检降级) 解锁与 `IndexedDB` 密文存储
  - 完成 Popup / SidePanel 基础增删改查 UI、密码/助记词生成器、高敏二次验证与 Offscreen 剪贴板定时清理
- [ ] **Phase 2：自动填充引擎 + 内置 2FA + Ente Auth 互通**
  - 已实现浏览器密码 CSV 预览导入与登录凭证手动 TOTP，见[二期开发记录](./docs/phase-2-status.md)
  - 实现 `ISOLATED` 表单探测、Closed Shadow DOM 隔离填充菜单、跨域 `<iframe>` 防钓鱼确认、关联域名等价组、内网端口隔离、按站黑名单开关与受控输入框填充/捕获保存
  - 实现 TOTP / HOTP / Steam Guard、网页二维码截图识别、下一期预览与分格验证码自动填充
  - 落地 Ente Auth 纯文本双向导入导出、浏览器 CSV / Bitwarden JSON 导入及「密码 + 2FA 智能合并向导」
- [ ] **Phase 3：WebDAV 极简无锁增量同步引擎**
  - 实现 MsgPack + Zstd + 256B 分桶紧凑编码、加密 `DeviceMetadata` 设备溯源与 HLC 三路合并冲突检测引擎
  - 落地安装首屏 WebDAV 优先引导、空库/批量删除同步熔断警告、Git 风格可视化冲突对比合并页、坚果云/Koofr 预设与鉴权熔断器、HTTPS `Date` 时钟校准及 5 版本快照留存回滚
- [ ] **Phase 4：Passkey 软认证器与全格式生态扩展**
  - 实现 `MAIN` World WebAuthn 桥接（含原生 Windows Hello / 硬件密钥一键回退）与 Conditional UI
  - 完成 Rust 侧 ES256 / EdDSA 通行密钥生成、签名与 RP ID 强校验
  - 补齐 FIDO CXF 1.0、KeePass `.kdbx`、1Password `.1pux`、Google Authenticator Protobuf、2FAS / Aegis 等全生态导入导出与 Playwright E2E 安全回归测试

---

## 开源协议

本项目基于 [MIT License](./LICENSE) 开源。

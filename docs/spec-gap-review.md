# 密码库规格：8 个需要定规则的问题

初次核对日期：2026-11-18。两份附件与[当时的 v1.3 仓库版本](https://github.com/IZRINO/vault-extension/tree/4ce8c3d531f598da8ca20ddc43e5bd46e58b3d27)逐字节一致。当时读了 #1–#36 的正文、验收项、评论和阻塞依赖：全部开放、均无评论。下文保留当时的问题和取舍，不将原规格的表述误当成现行规则。

**8 项均已确认并回填。** 当前以[架构 v1.4](../密码管理器浏览器插件-技术架构与选型文档.md)、[分期计划](../分期开发与验证计划.md)和[工单索引](development-tickets.md)为准。第 1、2 项见 [ADR-0001](adr/0001-secret-use-and-export.md)，第 3–7 项见 [ADR-0002](adr/0002-webdav-write-boundary.md)，第 8 项见 [ADR-0003](adr/0003-passkey-evidence.md)；术语见[项目术语表](../GLOSSARY.md)。前两项仍是待修正的实现差异，后六项是后续阶段的约束，本次没有改代码或代签验收。

| 决定 | GitHub 上的实施与签收 |
| --- | --- |
| 1. 整库导出只认主密码 | [#37](https://github.com/IZRINO/vault-extension/issues/37) 修正，[#7](https://github.com/IZRINO/vault-extension/issues/7) 签收；CXF 沿用 [#26](https://github.com/IZRINO/vault-extension/issues/26)。 |
| 2. 日常看码、填码不交付种子 | [#38](https://github.com/IZRINO/vault-extension/issues/38) 修正，#7 签收。 |
| 3. 备份迁入保留目标库身份 | [#10](https://github.com/IZRINO/vault-extension/issues/10) 验证目标库，[#13](https://github.com/IZRINO/vault-extension/issues/13) 验证合并。 |
| 4. 锁库后不发新请求 | [#8](https://github.com/IZRINO/vault-extension/issues/8) 约束首次探测，[#12](https://github.com/IZRINO/vault-extension/issues/12) 验证锁库与续传。 |
| 5. 条件写不可靠只读恢复 | #8、#10 和 [#17](https://github.com/IZRINO/vault-extension/issues/17) 分别约束探测、建库与压实。 |
| 6. 旧端不能无损写回就停写并保留编辑 | #13 实施；第 3–7 项的三期行为由 [#20](https://github.com/IZRINO/vault-extension/issues/20) 签收。 |
| 7. 恢复不回退已用计数，未知就暂停 | [#18](https://github.com/IZRINO/vault-extension/issues/18) 验 HOTP，[#23](https://github.com/IZRINO/vault-extension/issues/23) 验四期递增签名。 |
| 8. Passkey 按事实报告验证与备份 | [#22](https://github.com/IZRINO/vault-extension/issues/22) 验本次用户验证，[#25](https://github.com/IZRINO/vault-extension/issues/25) 验实际备份。 |

## 当前版本：先定两条安全边界

1. **能把整个库带走的导出，是否一律重新验证主密码？** 现在[原生 `.vaultpack` 导出](../apps/extension/src/vault-controller.ts#L469-L474)接受[主密码或 PIN](../apps/extension/src/vault-controller.ts#L107-L113)，文件密码由导出者另设；[Bitwarden 加密导出](../apps/extension/src/vault-controller.ts#L274-L278)却只认主密码。**建议：按能导出的内容，而不是文件是否加密来授权。** PIN 可用于日常查看；带走整库须主密码。可在 [#7](https://github.com/IZRINO/vault-extension/issues/7) 验收同一个 PIN 能查看已授权条目，但不能导出两种整库文件。

2. **日常显示或填入动态码时，扩展界面是否只应拿到验证码，而不是长期种子？** [旧计划第 20 行](https://github.com/IZRINO/vault-extension/blob/4ce8c3d531f598da8ca20ddc43e5bd46e58b3d27/分期开发与验证计划.md#L20)写敏感材料仅在 WASM 中；[一期记录](phase-1-status.md#存储与权限)已说明主密码输入会经过 JavaScript。实际[TOTP 详情组件](../apps/extension/src/ui/ItemDetail.tsx#L58-L60)也收到原始设置密钥；这是受信扩展界面，不是普通网页。**建议：区分“使用秘密”和“取出秘密”。** 日常界面只收条目句柄、当前/下一期码及到期时间；只有显式录入、编辑或授权迁移才传所需原值。未包装的库数据密钥留在内核；不承诺能确定性擦除浏览器中的 JavaScript 字符串。

## 三期：开放 WebDAV 写入前

3. **用旧 `.vaultpack` 恢复后连接原网盘，是加入原库，还是用备份重建它？** [现有导入](../crates/vault-core/src/lib.rs#L424-L435)只取条目合入当前库，不恢复原库密钥；[#10](https://github.com/IZRINO/vault-extension/issues/10)、[#13](https://github.com/IZRINO/vault-extension/issues/13)规定非空库先验证和预览，但没有选定合并后沿用哪套恢复码。**建议：保留目标远端库身份。** 用原主密码或恢复码加入远端，再用独立文件密码打开备份、预览并迁入。不能验证远端就保留为独立本地库，不覆盖，也不认领旧设备。

4. **锁库那一刻，尚未上传的改动还可以继续发往网盘吗？** [#8](https://github.com/IZRINO/vault-extension/issues/8)规定首次手动探测只读，[#12](https://github.com/IZRINO/vault-extension/issues/12)规定后台定时同步；两者没定义锁库后的联网权限。**建议：首次手输的网盘密码只在内存暂存，建库或解锁后才加密保存；锁库停止发起新请求。** 待上传改动保留为本地密文，下次解锁后核对已提交进度再续传。验收“已保存、未上传就锁库”，确认远端未被后台续写，本地改动也没丢。

5. **自建 WebDAV 不可靠地执行条件写时，是否只支持读取恢复？** 单有 `ETag` 不代表服务器会拒绝基于旧版本的覆盖。[#10](https://github.com/IZRINO/vault-extension/issues/10)、[#17](https://github.com/IZRINO/vault-extension/issues/17)要求并发建库不互相覆盖、无可靠 ETag 不盲删，却未划定此时能开放的写操作。**建议：默认只读恢复。** 能证明条件写有效才开放建库、更新 `head` 和清理旧文件；用忽略条件头的模拟网盘验两端并发，确认原库未被覆盖。

6. **旧设备无法确认共同版本，或不认识新版凭证字段时，能否自动写回？** [#9](https://github.com/IZRINO/vault-extension/issues/9)要求旧备份可读；[#13](https://github.com/IZRINO/vault-extension/issues/13)、[#17](https://github.com/IZRINO/vault-extension/issues/17)要求合并不丢字段、已删记录不复活。这不等于旧客户端可安全改写新版库。**建议：找不到可验证的共同版本，或不能原样保留新字段时，停写、保留本地编辑，再引导升级或显式合并。** 用长期离线端和携带新 Passkey 字段的库各验一次。

7. **恢复旧快照时，是否把已用过的计数器排除在回退之外？** [#18](https://github.com/IZRINO/vault-extension/issues/18)要求把历史内容恢复为新版本；[#12](https://github.com/IZRINO/vault-extension/issues/12)、[#23](https://github.com/IZRINO/vault-extension/issues/23)分别约束 HOTP 和开启递增的 Passkey 签名计数。**建议：同一凭证保留可信的最高计数；只剩旧副本、不能确认时，暂停该凭证的发码或签名，引导重新同步或在网站重新登记。** 验收“一端发码或签名，另一端恢复昨天的快照，再使用”。不承诺两台离线设备能互斥发放 HOTP；默认 `signCount = 0` 的 Passkey 不受影响。

## 四期：Passkey 向网站证明什么

8. **网站要求验证用户、或询问凭证是否已备份时，扩展拿什么作证？** [旧计划第 207 行](https://github.com/IZRINO/vault-extension/blob/4ce8c3d531f598da8ca20ddc43e5bd46e58b3d27/分期开发与验证计划.md#L207)写 `UV=1 / BE=1 / BS=1`，而 [#22](https://github.com/IZRINO/vault-extension/issues/22)、[#25](https://github.com/IZRINO/vault-extension/issues/25)要求标志反映事实。[W3C 用户验证定义](https://www.w3.org/TR/webauthn-3/#user-verification)与[备份状态规则](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)区分在场、验证、备份资格和实际备份状态。**已选择：库开着或只点选不算本次用户验证；站点要求验证且本次没有依据时重新验证。** 可同步不等于已备份，用独立服务端核对纯本地无备份、首次上传失败及已有可恢复副本三个状态。

## 不另开问题

- **既有验收条件不需重新决定。** [#1](https://github.com/IZRINO/vault-extension/issues/1)要分测 WASM 会话恢复 `<5 ms` 与 Popup 首屏 `<50 ms`；[#2](https://github.com/IZRINO/vault-extension/issues/2)等实体 Hello、锁屏和原生侧栏。Helium 首扫最近 **236 ms**，未过 [#3](https://github.com/IZRINO/vault-extension/issues/3) 的 **`<200 ms`**。先签 #1/#2；#3–#6、#37、#38 收尾后才能签 #7；#7 前不开三期，#20 前不开四期。这次没有重跑性能或代签实机。
- **不把“能解析”写成“能迁移”。** [#6](https://github.com/IZRINO/vault-extension/issues/6)已有 Bitwarden/Ente 原生应用往返验收；[#26](https://github.com/IZRINO/vault-extension/issues/26)要求 CXF 指明格式、版本和接收端。Ente 加密 JSON 等额外格式已列在[未定分期的差异表](development-tickets.md#架构有目标分期未定归属的差异)，不自动成为 [#36](https://github.com/IZRINO/vault-extension/issues/36) 的发布门槛。

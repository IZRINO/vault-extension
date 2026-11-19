# Passkey 只报告有依据的用户验证和备份状态

网站要求验证用户时，若扩展只知道密码库已解锁，必须为这次请求重新验证；不能用“库开着”或“用户点过这枚凭证”代替验证成功。只有满足本次请求的用户验证才能报告 `UV=1`。

可同步是备份资格（BE），并不等于有备份（BS）。只有能确认这枚凭证已有可恢复的副本，才报告 `BS=1`；纯本地且没有备份、或首次上传失败时，报告 `BS=0`。这样网站能区分用户实际可用的恢复手段，而不是把排队上传当作已有第二份凭证。

依据：[WebAuthn 用户验证](https://www.w3.org/TR/webauthn-3/#user-verification)、[凭证备份规则](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)。这一决定已回填[分期计划四期验收](../../分期开发与验证计划.md#43-phase-4-验证方案与验收清单)、[工单 #22](https://github.com/IZRINO/vault-extension/issues/22) 和 [#25](https://github.com/IZRINO/vault-extension/issues/25)；不得沿用旧规格固定置位的写法。

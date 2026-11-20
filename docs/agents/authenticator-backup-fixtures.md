# 验证器备份的公开测试样本

用于 T32（2FAS）、T33（Aegis）和 T34（Raivo、andOTP、Stratum）的离线兼容核验。只加载公开测试夹具或生成的合成数据，不复制个人备份进仓库，也不输出验证码种子。

## 2FAS

- 2FAS Android [盐生成器](https://github.com/twofas/2fas-android/blob/4ad83b2b94967993db55dd36dcb2e258646eb7b6/core/cipher/src/main/java/com/twofasapp/cipher/backup/internal/BackupSaltGeneratorRandom.kt)生成 256 字节的盐。[密钥派生器](https://github.com/twofas/2fas-android/blob/4ad83b2b94967993db55dd36dcb2e258646eb7b6/core/cipher/src/main/java/com/twofasapp/cipher/backup/internal/BackupKeyGeneratorPbkdf.kt)使用 PBKDF2-HMAC-SHA256、10,000 轮、256 位密钥。[备份加密器](https://github.com/twofas/2fas-android/blob/4ad83b2b94967993db55dd36dcb2e258646eb7b6/core/cipher/src/main/java/com/twofasapp/cipher/backup/BackupCipherImpl.kt)独立认证 `reference` 和 `servicesEncrypted`；两段都存在才可读加密备份。
- 在[原应用的数据模型](https://github.com/twofas/2fas-android/blob/4ad83b2b94967993db55dd36dcb2e258646eb7b6/data/services/src/main/java/com/twofasapp/data/services/domain/BackupService.kt)中，条目外层的 `type` 是服务类型，OTP 类型是 `otp.tokenType`。旧版缺失或为 `null` 时，按 [Aegis 上游兼容验证](https://github.com/beemdevelopment/Aegis/blob/d6f4e5925a97e4e91593f1542085eae03432a759/app/src/test/java/com/beemdevelopment/aegis/importers/DatabaseImporterTest.java)使用 TOTP；其它畸形或不支持的 OTP 类型不按 TOTP 读取。
- 库中原有的短盐兼容范围保留；仅补 256 字节盐，不接受更大的盐。加密字段类型不对、只出现一段、或任一段认证失败，都不能回退读取 `services`。

同一 [Aegis 公开夹具目录](https://github.com/beemdevelopment/Aegis/tree/d6f4e5925a97e4e91593f1542085eae03432a759/app/src/test/resources/com/beemdevelopment/aegis/importers)的 `.2fas` 文件，在发布用 WASM 中读取结果如下。账号、算法、位数、周期或计数，以原样本独立解密结果为准；实际 TOTP、HOTP 和 Steam 码另以 Node HMAC 对照。

| Schema | 样本内的来源版本 | 明文 / 加密各恢复 | 验证内容 |
| --- | --- | --- | --- |
| 2 | Android 3.8.2 | 4 | 缺 `otp.tokenType` 的 TOTP，非默认位数与周期 |
| 3 | Android 4.0.0 | 6 | TOTP、HOTP，三种算法和计数 |
| 4 | Android 5.1.0 | 5 | TOTP、三条 HOTP、Steam 类型 |

将这六份 `.2fas` 和下节的五个 JSON 样本按原名放在同一测试目录，运行 `node scripts/test-authenticator-fixtures.cjs <目录>`；脚本先核对 11 个固定的 SHA-256，再验证版本结果、验证码与错误密码。保留合法 `reference` 并翻转 `servicesEncrypted` 的认证标签时也必须失败。六份 2FAS 原样本没有分组；分组映射有按原应用结构独立生成的 WASM 测试，不计为原样本分组证据。

浏览器回归使用该目录的 `2fas_authenticator_encrypted_v4.2fas`，SHA-256 为 `0e769224ea2778f9b2d6467d9185efdcba2e4914541c3d3f36b687018bf789c9`。测试入口只接受这个公开样本的字节，不传入个人备份。

```powershell
$env:VAULT_EXTENSION_PATH = 'test-results/release-unpacked-<候选包摘要>'
$env:VAULT_2FAS_FIXTURE_PATH = (Resolve-Path -LiteralPath '<已下载的公开样本绝对路径>' -ErrorAction Stop).Path
node scripts/test-migration.cjs
```

两边均需输出 `encrypted2fasFixture: true`：预览和错密不写库，确认后导入五条，常规详情不含种子，从原有计数生成三个独立对照过的 HOTP；再次预览不产生重复条目。未配置样本时普通迁移回归输出 `"skipped"`，不算此项通过。

## Aegis 与早期互通样本

同一上游目录中的 `aegis_plain.json`、`aegis_encrypted.json`、`andotp_plain.json`、`stratum_plain.json` 分别恢复 7 条，涵盖 TOTP、HOTP、Steam，无解析跳过。Aegis 的分组样本同样恢复 7 条，其中三条有标签。移动应用的现场试用待验收。[Aegis 分组样本](https://github.com/beemdevelopment/Aegis/blob/d6f4e5925a97e4e91593f1542085eae03432a759/app/src/test/resources/com/beemdevelopment/aegis/vault/aegis_plain_grouped_v2.json)

## andOTP 与 Stratum 加密备份

在「设置 → 导入其他验证器」选择来源，用源文件密码预览。导入另需 Vault 的二次验证。明文和加密备份共用 4 MiB 输入上限。

- andOTP v0.9 格式的 `.json.aes` 以大端整数记录迭代次数，从 12 B 盐派生 256 位密钥，再用 12 B nonce 做 AES-GCM 认证解密。PBKDF2-HMAC-SHA1 的可接受范围是原厂写入器生成的 140,000–160,000 次。旧版 AES 和 OpenPGP 需要先在来源导出明文 JSON 或转换到受支持的加密格式。[原厂写入器](https://github.com/andOTP/andOTP/blob/v0.9.0.1/app/src/main/java/org/shadowice/flocke/andotp/Utilities/BackupHelper.java#L102) · [迭代范围](https://github.com/andOTP/andOTP/blob/v0.9.0.1/app/src/main/java/org/shadowice/flocke/andotp/Utilities/Constants.java#L123)
- Stratum 新版 `AUTHENTICATORPRO` 使用 Argon2id v19，64 MiB、3 轮、4 lanes，后接 AES-256-GCM。旧版 `AuthenticatorPro` CBC 缺少认证标签，需从原应用重新导出。分组名称映射为标签。账号图标、自定义图标和分组排序暂未映射。[新版加密](https://github.com/stratumauth/app/blob/86c4e7c520ce30a21fa2887f1ae484442f06225d/Stratum.Core/src/Backup/Encryption/StrongBackupEncryption.cs) · [旧版加密](https://github.com/stratumauth/app/blob/86c4e7c520ce30a21fa2887f1ae484442f06225d/Stratum.Core/src/Backup/Encryption/LegacyBackupEncryption.cs)
- 原厂参数超出 Vault 的 OTP 范围时计入不支持。无有效计数的 HOTP 计入无法读取。Stratum Steam 依原应用固定使用 SHA1、5 字符和 30 秒。文件错密或损坏时拒绝整包。重导旧的 HOTP 时按种子与参数去重，保留已有计数。

夹具均在固定版本的 Stratum 上游测试目录。andOTP 的两份文件来自该项目的互通测试。加密样本与独立计算的出码结果已在生产用 WASM 中核对。原厂 Android 应用的现场导出待验收。[公开夹具](https://github.com/stratumauth/app/tree/86c4e7c520ce30a21fa2887f1ae484442f06225d/Stratum.Test/data) · [andOTP 互通测试](https://github.com/stratumauth/app/blob/86c4e7c520ce30a21fa2887f1ae484442f06225d/Stratum.Test/src/Converter/AndOtpBackupConverterTest.cs#L51)

| 文件 | SHA-256 | 验证结果 |
| --- | --- | --- |
| `backup.strong.authpro` | `e8b5f262cde2ddef20db3867d628f0c5533d0adee755f2cd3f6c70821caebbd8` | 恢复 6 条，1 条 9 位 TOTP 不支持。核对算法、非默认步长、HOTP 计数和实际验证码 |
| `backup.legacy.authpro` | `b541ec0d1b7c767442d292107d5a94deb3f987cc3e77a51abc02243415345593` | 提示重新导出 |
| `backup.unencrypted.authpro` | `ab49c51b3d3809d45e7677c8889504149c342600cb25c138084c0ae3605aaca8` | 恢复 2 条并核对分组和出码，12 条种子未过严格 Base32 校验，1 条类型不支持 |
| `andotp.encrypted.bin` | `d7274dae68b819536c62bfc1ab6edd614d6789e9e9a7a87f90b8a15a89d804ae` | 恢复 7 条并核对标签、非默认步长、HOTP 计数和实际验证码，9 位 TOTP 与 mOTP 各跳过 1 条 |
| `andotp.unencrypted.json` | `b5ca6ff1ec1e3ab22c0a54f50117e1eb023cc0407be3b6c5bbf86c69635b77d8` | 映射结果与加密样本一致 |

将五份公开夹具按原名存到同一测试目录。Vitest 核对 SHA-256，然后使用构建出的 WASM 运行认证、映射和后台回归。

```powershell
$env:VAULT_AUTH_FIXTURE_DIR = (Resolve-Path -LiteralPath '<公开夹具目录>' -ErrorAction Stop).Path
node node_modules/vitest/vitest.mjs run apps/extension/src/migration-wasm.test.ts apps/extension/src/vault-controller.test.ts
```

## Raivo

[Raivo iOS 导出实现](https://github.com/raivo-otp/ios-application/blob/8ea4901b49996b9237d8e937aa2fa14890f2d43d/Raivo/Features/DataExportFeature.swift)会把 `raivo-otp-export.json` 和 `.html` 打进不压缩的 AES ZIP。[导出字段定义](https://github.com/raivo-otp/ios-application/blob/8ea4901b49996b9237d8e937aa2fa14890f2d43d/Raivo/Models/Password.swift)将 `digits`、`timer`、`counter`、`pinned` 等写为字符串。旧解析器读出参数但丢弃 `pinned`；现保留置顶。

`node scripts/test-authenticator-fixtures.cjs --raivo` 用本机 `7z`（或 `VAULT_7ZIP_PATH`）在临时目录生成含同名两份成员的 AES-256 ZIP，核对封装类型，再调用发布用 WASM 恢复两条 OTP。账号、签发方、位数、置顶和步长／计数按生成数据核对，实际生成值另以 Node HMAC 对照；错密或截断整个拒绝。另有 Vitest 覆盖原始 JSON 和未加密 ZIP。此处没有运行来源 iOS 应用，不算原生样本验收；HTML 与外部图标不导入、不联网读取。

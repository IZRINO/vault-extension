# 验证器备份的公开测试样本

用于 T32（2FAS）、T33（Aegis）和 T34（andOTP、Stratum）的离线兼容核验。下列文件是上游测试夹具，不是实际账号。只读使用，不复制进仓库，也不输出验证码种子。

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

## Aegis、andOTP 和 Stratum

同一上游目录中的 `aegis_plain.json`、`aegis_encrypted.json`、`andotp_plain.json`、`stratum_plain.json` 分别恢复 7 条，涵盖 TOTP、HOTP、Steam，无解析跳过。[Aegis 的分组样本](https://github.com/beemdevelopment/Aegis/blob/d6f4e5925a97e4e91593f1542085eae03432a759/app/src/test/resources/com/beemdevelopment/aegis/vault/aegis_plain_grouped_v2.json)同样恢复 7 条，其中三条有标签。这里验证的是公开夹具和当前解析器，不是最新移动应用的人工迁移；也不包含 Raivo 原生导出、andOTP/Stratum 的加密变体或其它未实测格式。

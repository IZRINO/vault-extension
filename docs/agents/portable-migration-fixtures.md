# Proton Pass、1PUX 和 CXF 迁移夹具

2026-11-20 核对 #26、#29、#30。以下输入都是公开测试资料或回环测试生成的凭证。第三方样本和接收库放在临时目录，产品包不包含这些文件。

## Proton Pass

[官方导出帮助][proton-export]列出明文 ZIP 和 PGP ZIP。[Web 导出选择器][proton-selector]将应用版本写到根级 `version`，并另外保留 `contentFormatVersion`。两份[上游测试 ZIP][proton-mocks]使用 `Proton Pass/data.json`，分别包含 `1.17.4-rc3` 的旧 `username` 和 `5.0.999.999` 的新账号字段。样本覆盖条目内容版本 4、6、8。两份 ZIP 的短 OTP 占位会报告为已跳过。

[Passkey 序列化代码][proton-payload]把凭证编码成两层 MessagePack，Web 端再[转成 Base64][proton-base64]。导入器验证封装版本、内外身份和公私钥一致性。测试通过 Proton 发布的 WASM 为 `localhost` 生成 ES256 和 Ed25519，再由 Edge 与 Helium 的 Vault 扩展对独立挑战签名。断言用生成端的原公钥验证，导入后本地备份状态 `BS=0`。支持已有的私钥 DER/PEM 兼容结构、无 HMAC 扩展的原生 ES256/Ed25519；缺有效私钥、含未支持扩展或需要核实签名计数时，预览分别报告跳过或暂不可用。`data.pgp` 提示重新导出明文。

从固定提交下载 `protonpass_1.17.zip` 和 `protonpass.zip` 到同一临时目录。在临时目录解压 [官方 npm 包 `@protontech/pass-rust-core@2.3.4`][proton-npm]，把其中的 `package/worker/` 放在两个 ZIP 旁边。依赖版本可在[官方工作区配置][proton-lock]核对。测试启动前会检查 ZIP 和 WASM 入口的 SHA-256。单独核对 ZIP 内的字段时使用支持 `-xOf` 的 `tar`。

```powershell
$env:VAULT_PROTON_FIXTURE = '<含两个 ZIP 及 worker 目录的路径>'
$env:VAULT_EXTENSION_PATH = '<可安装的解压目录>'
node scripts/test-passkeys.cjs --proton-only $env:VAULT_PROTON_FIXTURE
```

## 1Password 1PUX

[官方格式说明][pux-format]指定版本 3 归档的 `export.attributes`、`export.data` 和附件目录。[官方导出说明][pux-export]说明桌面 1PUX 不导出 Passkey，移动端可使用凭证交换。用于核对字段的 [Bitwarden 脱敏样本][pux-fixture]是处理过的 `export.data` 内容，测试只读取 TypeScript 字面量并补上测试 ZIP 的目录结构。涵盖密码、卡、身份、API 凭证和许可证，短种子占位报告跳过。有效 OTP 与携带可用私钥的兼容 1PUX 结构由本项目的独立合成向量验签和出码。

```powershell
$env:VAULT_ONEPUX_FIXTURE = '<下载的 sanitized-export.ts 绝对路径>'
git hash-object --no-filters $env:VAULT_ONEPUX_FIXTURE
# bf1e87c9c1d8e61223873c83e5dd9a997f603ffb
```

## FIDO CXF

两份[Proton 上游 CXF 1.0 夹具][cxf-fixtures]置于同一目录。登录夹具省略了规范允许为空的 TOTP 用户名，全库夹具包含两枚 Passkey、密码、TOTP 与独立备注，并涵盖 Vault 报告为不支持的类型。

| 文件 | Git blob |
| --- | --- |
| `login_passkey_totp_scope.json` | `a0f9812f7b3efa76fcd56ec626475664a7221af5` |
| `full_library_baseline.json` | `aa2966742368ae6b2ba4cb5a838a4611f515ac74` |

离线接收端用 [Bitwarden CXF 格式库 0.4.0][cxf-receiver]反序列化 Vault 通过标准 CXF 1.0 输出的文档。Node 根据上游密钥推导公钥和独立 HMAC 动态码，也用接收端回传的 PKCS#8 生成断言签名。该接收端的证据范围为 Bitwarden 库级互操作。额外的文件密码 JWE 包装用 Vault 自身验证认证、错密与往返。

在临时 Rust 项目依赖 `credential-exchange-format = "=0.4.0"` 和 `serde_json = "1"`，锁定的格式库校验和为 `288cce1d17f7263796be2c92ce6abe994d0b5257614bbc02b92129fb6bea5224`。用于接收端验证的 `src/main.rs` 可用以下程序。只对此文列出的公开合成文件运行该程序。

```rust
use credential_exchange_format::{Credential, Header};
use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin().take(1_048_577).read_to_end(&mut input)?;
    let document: Header = serde_json::from_slice(&input)?;
    assert_eq!((document.version.major, document.version.minor), (1, 0));
    for item in document.accounts.iter().flat_map(|account| &account.items) {
        assert!(item.credentials.iter().all(|credential| matches!(credential,
            Credential::BasicAuth(_) | Credential::Passkey(_) | Credential::Totp(_) | Credential::Note(_))));
    }
    serde_json::to_writer(io::stdout().lock(), &document)?;
    Ok(())
}
```

```powershell
$env:VAULT_CXF_FIXTURE = '<含两份 CXF 文件的目录>'
$env:VAULT_CXF_RECEIVER = '<cargo build 得到的接收程序绝对路径>'
node node_modules/vitest/vitest.mjs run apps/extension/src/migration-wasm.test.ts
```

[proton-export]: https://proton.me/support/pass-export
[proton-selector]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/store/selectors/export.ts#L22-L98
[proton-mocks]: https://github.com/ProtonMail/WebClients/tree/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/import/providers/protonpass/mocks
[proton-payload]: https://github.com/protonpass/proton-pass-common/blob/806b7b9dbf9e58bbcb36009b60ff31fce2c8155d/proton-pass-common/src/passkey/passkey_handling.rs#L77-L100
[proton-base64]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/packages/pass/lib/passkeys/utils.ts#L11-L43
[proton-npm]: https://registry.npmjs.org/@protontech/pass-rust-core/-/pass-rust-core-2.3.4.tgz
[proton-lock]: https://github.com/ProtonMail/WebClients/blob/e7b57b816903d01d8d6d7c8f7dd56c2deb60a643/pnpm-workspace.yaml
[pux-format]: https://support.1password.com/1pux-format/
[pux-export]: https://support.1password.com/export/
[pux-fixture]: https://github.com/bitwarden/clients/blob/a69127380b4b745f6a203fd6da18344dcc03d61a/libs/importer/src/importers/spec-data/onepassword-1pux/sanitized-export.ts
[cxf-fixtures]: https://github.com/protonpass/proton-pass-common/tree/806b7b9dbf9e58bbcb36009b60ff31fce2c8155d/proton-pass-common/test_data/cxf
[cxf-receiver]: https://crates.io/crates/credential-exchange-format/0.4.0

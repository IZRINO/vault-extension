# FlClash 备份与 Vault 首次建库的 WebDAV 请求

核对日期 2026-11-27。FlClash 当前正式版 v0.9.5（`deba70d`）的连接指示只验证基础地址能响应 `OPTIONS`。备份成功另能说明服务器接受了那一次文件上传。Vault 要同步多台设备的编辑，还需要验证服务器会拒绝覆盖新版本的旧请求。[FlClash 正式版](https://github.com/chen08209/FlClash/releases/tag/v0.9.5) · [连接、上传与下载入口](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/dav_client.dart#L23-L48) · [Vault 的写入边界 ADR-0002](../adr/0002-webdav-write-boundary.md)

## FlClash v0.9.5

该版使用仓库内的 Dart `DAVTransport`，底层 `dio` 锁定为 **5.11.1**。下表的 `<base>` 是用户填的 WebDAV 地址，保留其路径前缀。应用子目录是 `FlClash/`，远端文件名默认 `backup.zip`，可在设置中更改。[传输实现与地址拼接](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/webdav.dart#L32-L73) · [依赖锁](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/pubspec.lock#L251-L258) · [目录名](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/constant.dart#L12) · [默认文件名](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/models/common.dart#L445) · [设置入口](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/views/backup_and_restore.dart#L204-L225)

| 操作 | 请求与结果 |
| --- | --- |
| 连接测试 | `OPTIONS <base>/` 返回 `200` 或 `204` 即显示连接成功，`404` 会使 `ping()` 返回失败。它只检查状态码，备份子目录和 ZIP 即使尚未创建也可以亮绿灯。上游测试断言这一步只有一个 `OPTIONS`，并核对基础路径前缀。[判定](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/webdav.dart#L71-L73) · [请求失败处理](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/webdav.dart#L147-L175) · [回环测试](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/test/common/dav_client_test.dart#L241-L276) |
| 备份上传 | 每次先 `MKCOL <base>/FlClash/`，接受 `200/201/204/405`（客户端把 `405` 当作目录已在），再 `PUT <base>/FlClash/<文件名>`，接受 `200/201/204`。因此首次备份可以创建这一级子目录。`MKCOL` 自己收到 `404` 就报错。上传是无条件 `PUT`，应用设置内容类型、长度及适用的认证头。同名时，服务器接受的后一次写入可覆盖前一次。[方法与状态码](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/webdav.dart#L75-L97) · [请求头](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/webdav.dart#L178-L199) · [上传顺序与重复备份测试](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/test/common/dav_client_test.dart#L256-L285) |
| 备份恢复 | 直接 `GET <base>/FlClash/<文件名>`，读取 `200` 或经 `Content-Range` 验证覆盖整个文件的 `206`，然后在本机处理归档。缺少目录或文件时，服务器返回的 `GET 404` 会作为恢复错误显示。此路径只读取远端。[下载判定](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/common/webdav.dart#L99-L133) · [本地恢复](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/lib/providers/actions/backup.dart#L20-L42) · [缺失文件测试](https://github.com/chen08209/FlClash/blob/deba70d80d2af509171f9c6465de9d14719f0399/test/common/dav_client_test.dart#L287-L308) |

## 旧版的 Dart WebDAV 依赖

v0.8.96（`e2f6789`）使用 `webdav_client 1.2.2`。pub.dev 发布归档的 SHA-256 与 FlClash 锁文件一致（`682fffc50b61dc0e8f46717171db03bf9caaa17347be41c0c91e297553bf86b2`），其中 `lib/` 下 11 份 Dart 源文件与依赖仓库提交 `5a8dd0d` 逐字节相同。[旧版依赖锁](https://github.com/chen08209/FlClash/blob/e2f678909dd9738015a5c032a8e25288ed79d4f1/pubspec.lock#L1732-L1739) · [pub.dev 原包与摘要](https://pub.dev/api/packages/webdav_client/versions/1.2.2) · [依赖版本声明](https://github.com/flymzero/webdav_client/blob/5a8dd0d9a82bac86e5ed326f648c2b0871478d8f/pubspec.yaml#L1-L5)

- 连接测试对基础地址发 `OPTIONS`，只接受 `200`。**备份和恢复**都先调用 `mkdir('/FlClash')`，此处 `MKCOL` 接受 `201/405`，`404` 会报错。因此旧版恢复也可能创建远端目录。[FlClash 调用链](https://github.com/chen08209/FlClash/blob/e2f678909dd9738015a5c032a8e25288ed79d4f1/lib/common/dav_client.dart#L14-L46) · [ping](https://github.com/flymzero/webdav_client/blob/5a8dd0d9a82bac86e5ed326f648c2b0871478d8f/lib/src/client.dart#L50-L56) · [mkdir](https://github.com/flymzero/webdav_client/blob/5a8dd0d9a82bac86e5ed326f648c2b0871478d8f/lib/src/client.dart#L85-L93)
- 文件传输先对文件路径发 `OPTIONS`，要求 `200`。上传再确保父目录存在，以无条件 `PUT` 写入，下载接着 `GET` 并要求 `200`。包另有用 `PROPFIND` 读属性的 API，但 FlClash 的这两条调用链均未用 ETag、`If-Match` 或 `If-None-Match` 做并发控制。[流式上传](https://github.com/flymzero/webdav_client/blob/5a8dd0d9a82bac86e5ed326f648c2b0871478d8f/lib/src/webdav_dio.dart#L485-L515) · [流式下载](https://github.com/flymzero/webdav_client/blob/5a8dd0d9a82bac86e5ed326f648c2b0871478d8f/lib/src/webdav_dio.dart#L285-L326) · [独立的属性 API](https://github.com/flymzero/webdav_client/blob/5a8dd0d9a82bac86e5ed326f648c2b0871478d8f/lib/src/client.dart#L63-L83)

## Vault 的首次建库与 404

以 Vault 提交 `275395a` 为对照。只读测试向**所选同步目录**发 `PROPFIND`（`Depth: 1`）。`404` 表示目标缺失，凭据与写权限仍待验证。`207` 则校验目录清单，区分空目录、已有库和不完整目录。普通测试一律返回 `writeAllowed: false`。已暂停连接收到 `404` 时保持暂停。[目录请求](https://github.com/IZRINO/vault-extension/blob/275395a2b8db5c3e7348bcd9bbb56fbdcc3f79ae/apps/extension/src/sync/webdav.ts#L257-L267) · [分类结果](https://github.com/IZRINO/vault-extension/blob/275395a2b8db5c3e7348bcd9bbb56fbdcc3f79ae/apps/extension/src/sync/webdav.ts#L365-L374) · [暂停判定](https://github.com/IZRINO/vault-extension/blob/275395a2b8db5c3e7348bcd9bbb56fbdcc3f79ae/apps/extension/src/sync/connection.ts#L115-L141)

`createRemoteVault` 接受同步目录为空或尚未创建。它先调用 `proveConditionalWrites`，在用户准备的独立、已存在且为空的同级测试目录写随机文件，检查重复的 `If-None-Match: *` 创建、带错误或过期强 ETag 的 `If-Match` 更新及删除均返回 `412`，并读回字节确认原对象完整。正确标签更新后还要取得新的强 ETag，用它删除对象后 `GET` 才应返回 `404`。验证通过，再复查同步目录，按需 `MKCOL` 创建它，准备 `wal/`，依次用 `If-None-Match: *` 发布快照和 `head.bin`。这里的 `404` 必须连同**请求方法、所查对象和所处阶段**解读。[验证目录与条件写探测](https://github.com/IZRINO/vault-extension/blob/275395a2b8db5c3e7348bcd9bbb56fbdcc3f79ae/apps/extension/src/sync/webdav.ts#L318-L354) · [条件头及 412 判定](https://github.com/IZRINO/vault-extension/blob/275395a2b8db5c3e7348bcd9bbb56fbdcc3f79ae/apps/extension/src/sync/webdav.ts#L213-L242) · [建库发布顺序](https://github.com/IZRINO/vault-extension/blob/275395a2b8db5c3e7348bcd9bbb56fbdcc3f79ae/apps/extension/src/sync/bootstrap.ts#L22-L51)

## Koofr 首次建库的现场对照（2026-11-27）

这次开发浏览器先收到目标目录的 `PROPFIND 404`，随后在独立测试目录创建了 32 字节随机文件（`PUT 201`）。接下来两次 `GET 200` 分别来自首次读回和失败后的清理。两次响应头都声明 `Content-Length: 32`，带相同的强 ETag，DevTools 导出的响应正文均为空。调用栈止于读回校验，重复创建、旧版本覆盖和删除的验证均在其后。[当时的验证流程](https://github.com/IZRINO/vault-extension/blob/275395a2b8db5c3e7348bcd9bbb56fbdcc3f79ae/apps/extension/src/sync/webdav.ts#L333-L361)

从 Koofr 网页下载同一文件，32 个字节与上传样本逐一相同。再让开发扩展用原有 `WebDavClient.get` 只读该文件，后台实际读到 **0 字节**，且能读取强 ETag。同版 Chrome 在本机 HTTP/2 服务收到完整 32 字节时，用相同读法能还原该样本，包括 `text/plain; charset=utf-8` 响应。[后台流式读取](../../apps/extension/src/sync/webdav.ts#L113) · [GET 状态与标签判定](../../apps/extension/src/sync/webdav.ts#L244)

在同一对象上指定完整区间 `bytes=0-31`，服务端返回 `206` 和 `Content-Range: bytes 0-31/32`，扩展仍收到 0 字节。分别使用原应用密码和新应用密码对照 Koofr 的文件 API，两次均能查询主挂载（`200`），读取这个文件均收到 `403`，当次请求随即停止。拒绝原因需由 Koofr 按请求编号确认。Koofr 说明，免费账户的部分文件类型受 WebDAV 和其他第三方访问限制，账户持有人仍可通过官方应用下载。公开列表只举例说明了部分类型，未明确 `.bin`。[Koofr 官方限制](https://koofr.eu/help/share-files-and-folders/i-have-a-free-account-and-cannot-share-certain-files-why/) · [支持入口](https://koofr.eu/help/other/my-question-is-not-answered-here-how-can-i-contact-you/)

独立文本对照进一步查明了当前端点的写入行为。在授权的测试目录里，新文件先返回 `404`。第一次带 `If-None-Match: *` 写入版本 A 返回 `201`，随后完整读回 67 字节并取得强 ETag。用相同条件写版本 B 时又收到 `201`，读回的 67 字节也变成版本 B。用最新强 ETag 删除这一个测试文件后返回 `204`，最后 `GET 404` 确认清理。若把同样的请求用于 `head.bin` 或不可变日志，后写入的设备就可能覆盖先写入的设备。这个端点因此只可执行读取操作，二进制读回还取决于服务能否完整交付文件。[写入边界](../adr/0002-webdav-write-boundary.md)

Koofr 预设现在先在独立空测试目录验证普通文本的排他创建。若同名写入成功，插件指出覆盖风险，清理核对过的测试文件，并保持密码库目录只读。通过该步骤后，插件继续验证实际二进制格式的读回、过期更新及删除。用本机服务复现上述覆盖行为，从正式构建的建库按钮进入，测试结束时剩余测试对象为 0，密码库目录写入次数为 0。其他 WebDAV 地址沿用原有二进制验证。[建库验证入口](../../apps/extension/src/sync/webdav.ts#L355)

修复后的客户端对未压缩文件流核对声明和实际长度。正文提前结束或中途报错会显示已收到的字节数，遇到 Koofr 空响应还会显示服务端提供的标准 UUID 请求编号。压缩传输的头部长度和解码后的文件长度分别处理。建库测试指出失败的步骤，并用实际读回的测试数据和强 ETag 决定是否可以安全清理。新增回归覆盖空正文、部分正文、压缩响应、同长度内容变更及拒绝过期写入。原回环服务用于验证完整传输和正常同步。[下载回归](../../apps/extension/src/sync/webdav.test.ts#L12) · [建库回归](../../apps/extension/src/sync/bootstrap.test.ts#L109) · [双浏览器回环服务](../../scripts/webdav-fixture.cjs#L38-L59)

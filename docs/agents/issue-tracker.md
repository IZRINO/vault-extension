# 工单约定：GitHub Issues

技能需要读取工单或发布规格时，目标是 [IZRINO/vault-extension 的 Issues](https://github.com/IZRINO/vault-extension/issues)。使用 `gh`，显式指定仓库，不依赖当前目录推断远端。首次写入前，用 `gh repo view IZRINO/vault-extension --json nameWithOwner,hasIssuesEnabled` 核对目标。

| 操作 | 命令 |
| --- | --- |
| 列出未关闭工单 | `gh issue list -R IZRINO/vault-extension --state open` |
| 读取正文、标签和讨论 | `gh issue view <编号> -R IZRINO/vault-extension --json number,title,body,labels,comments` |
| 发布工单或规格 | `gh issue create -R IZRINO/vault-extension --title "<标题>" --body-file "<UTF-8 正文文件>"` |
| 关联子工单 | `gh issue edit <父工单> -R IZRINO/vault-extension --add-sub-issue <子工单>` |
| 记录阻塞依赖 | `gh issue edit <被阻塞工单> -R IZRINO/vault-extension --add-blocked-by <前置工单>` |

仓库公开。发布或评论前确认用户已授权，正文、日志和附件只用脱敏示例，不得包含真实密码、验证码种子或用户的密码库导出。

**PRs as a request surface: no.** 不把外部拉取请求自动当作待分拣工单。

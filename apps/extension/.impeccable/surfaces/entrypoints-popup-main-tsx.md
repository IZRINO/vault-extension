---
version: 1
slug: "entrypoints-popup-main-tsx"
primary_target: "entrypoints/popup/main.tsx"
related_targets: ["entrypoints/sidepanel/main.tsx"]
---

# Vault 扩展界面（弹窗 / 侧栏 / 整页）

范围：`apps/extension` 的工具栏弹窗、浏览器侧栏和整页标签共用的一套界面，Operate 模式。

受众与任务：登录或结账进行到一半的个人用户（包括不懂技术的家人或同事），几秒内找到条目并复制或填充，然后回到网页。

内容与约束：第一阶段的全部功能保留；冒烟脚本依赖的文案和控件名保持可用；文案直白，术语放进说明里。

用户确认的验收重点（2026-11-13）：取用效率、成品观感、结构和导航重排。方向由用户交给我定，采用抽到的方向。

未决事项：无。

## Direction contract

THESIS: 密码像寄存在取件柜里的包裹，凭码开门，取了就走。不做这类产品惯用的「深蓝外壳、蓝紫强调、圆角卡片」，也不延续旧版的「米白加深绿」。

OWN-WORLD: 喷塑钢板的浅灰底，白色柜门面板，橙红柜门色用在顶栏和锁定屏，石墨色文字；绿色只表示「刚刚取到」。数字用 DIN 式粗体等宽数字，放在固定的格口里。

STORY: 用户先看到「已解锁」状态灯和搜索框，在条目行上直接复制账号或密码，看到绿色的「已复制」后回到网页。

FIRST VIEWPORT: 400×600。顶部橙红栏里是字标、状态灯、侧栏、展开和锁定，栏内放搜索框；下面是筛选条和「新建」；白色条目行左侧是格口牌，中间是名称与账号，右侧是复制动作；底部是四项导航。

FORM: 取件柜与取件码，候选清单第 3 位；seed:651fd4f0659aa3cc。标志性做法是取件码格：验证码、恢复码这类码一律用固定格口的大号数字，变化时原位更新。锁定屏是一整面关着的柜门，解锁时门收起成顶栏。

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

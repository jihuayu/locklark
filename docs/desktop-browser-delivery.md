# 桌面、浏览器与第 1–4 条持续交付

用户追加要求：桌面必须使用 MyGo，浏览器界面必须使用 Next.js，完成迁移、日常桌面、浏览器/手机、团队/同步四条完整范围；不能完成一个基础切片就结束推进。本记录保留该持续任务，编译、原型或 mock 不代表整条完成。

桌面 PR #23 已合入 main `de7ba5a`；当前分支 `codex/nextjs-management` 接 Web 管理。MyGo 采用 `github.com/egoist/mygo` v0.7.4（要求 Go 1.27.3），原生 `ui` 处理因素输入和敏感操作；Next.js 只处理获准的非秘密管理/状态。浏览器扩展和 native messaging 属于独立来源认证链，Next.js 页面不能冒充已认证扩展。

推进顺序：真实个人桌面会话与原生交互 → Next.js 非秘密界面及受限接口 → 完整迁移模型/对账与桌面接入 → 浏览器配对/填充/保存/更新 → 团队邀请、密文同步、新鲜度/离线冲突 → 平台与手机/Passkey/系统解锁验收。每批保留 Luna/max 复核、失败先行、真实运行和精确 head CI，再通过 PR 合并接下一批。

尚未完成：以上各批均须实际证据逐项更新；MyGo 原生应用、会话和系统解锁适配器已合并；Next.js 本机只读团队管理已实现，正在独立复审/CI 验收。系统生物识别、Safari、移动真机、真实 1Password 复杂导出对照、签名发布、独立密码评审和物理灾难恢复不能用云端 mock 代替，但不阻止可开发的实现和自动验收。


使用流程参考 1Password：首次完整解锁 → 安全设置主动启用系统快捷解锁 → 自动或主动锁定 → 系统验证再次解锁；失败、到期或金库密钥槽变化回到完整解锁。参考来源：[Windows Hello 使用](https://support.1password.com/windows-hello/)、[安全属性](https://support.1password.com/windows-hello-security/)。这是交互参考，并不声称实现与 1Password 的内部密码协议相同。

# 未关闭 issues 的逐项完成记录

2026-11-07 本轮补充：原八项关闭七项后，已将 #39 遗留范围及外部 worker/剪贴板问题拆成 #50–#59，每项附复现或验收标准。旧段落的“仅剩 #39”是拆分前状态；当前实现与安全边界见[专项验收](ui-performance-security-validation.md)。

日期：2026-11-07。起点 `main` `41e31f77b18ad842db3be7c6c30f293329bcaf63`（[PR #45](https://github.com/jihuayu/locklark/pull/45)），最终开发 head `5e990dd` 六项 CI 均成功。起始有 8 个未关闭 issues，无未合并 PR。以实际实现和验收完成状态关闭 issue，史料中的旧提交复现不自动代表当前 main 仍有同一缺陷。

## 本批对账

| Issue | 当前实现与证据 | 本批处理 |
| --- | --- | --- |
| [#24](https://github.com/jihuayu/locklark/issues/24) | Awesome MyGo 的收录通知，作者明确可关闭。 | README 增加项目目录回链。可选许可证选择、评分和版本发布建议不作为通知的关闭条件。 |
| [#32](https://github.com/jihuayu/locklark/issues/32) | PR #43 已增加独立 clipboard/display/idle timers，经原生 dispatch 和 lease/session generation 校验；不依赖 `View`。 | 主代理重跑无渲染到期、外部剪贴板所有者、连续复制及重解锁竞态。 |
| [#33](https://github.com/jihuayu/locklark/issues/33) | PR #43 的普通 edit/state 已使用原生 mutation gate；数据库等待期间锁库先赢则不写，提交先赢则保留未知结果。 | 实际 bbolt 锁阻塞的 edit/archive/trash、提交后锁库及输入清理回归已重跑。 |
| [#34](https://github.com/jihuayu/locklark/issues/34) | PR #43 已统一 query/state refresh，过滤条件与界面代次绑定，变更提交与刷新失败分开。 | 现有筛选保持、query ABA、scope 变化和迟到 mutation refresh 回归已重跑。 |
| [#36](https://github.com/jihuayu/locklark/issues/36) | PR #43 的普通 fill 已在取得 writer slot 后才消费秘密，并检查 cancel epoch、会话与期限。 | 原队列锁库回归保留；新增认证取消、请求/配对到期、错误能力与重复取消不影响新操作。主代理独立定向 race 通过。 |
| [#38](https://github.com/jihuayu/locklark/issues/38) | PR #43 已记录 `injectionStarted`，对派发后的未确认结果保留 `fillUnknown`。 | 新增丢失注入回执、成功注入后 probe 挂起、导航/锁库/断开、派发前明确拒绝及迟到操作不覆盖新操作；扩展全量测试通过。 |
| [#35](https://github.com/jihuayu/locklark/issues/35) | PR #47 已合并并关闭；前缀复用、密文逐字节检查与完整回退均通过篡改回归。 | 10k 事件基准及最终精确六项 CI 见历史性能验收。 |
| [#39](https://github.com/jihuayu/locklark/issues/39) | PR #43–45 已覆盖多步、保存/更新、生成器、附加类型、编辑、附件、Passkey 独立管理和三浏览器受控真实验收；整项仍有缺口。 | 条件式输入框账号列表、Signal APIs、系统 UV、平台与发布验收逐项推进；不以一个 Passkey 删除入口关闭整个 epic。 |

主代理独立运行（起始代码）：

```sh
go test ./internal/desktop ./internal/browserhost ./internal/personal -run 'TestDesktop(Clipboard|Idle|EditAndState|MutationsPreserve|LateRefresh)|TestFillQueued|TestNativeFieldEdit' -count=1 -v
node --test --test-name-pattern='password injection|post-injection|ordinary fill|lost.*fill|definite.*fill|lock status survives late fill|late fill completion' browser-extension/test/background.test.js
```

两组均通过，日志 `/workspace/issues-existing-go-verification.log`、`/workspace/issues-existing-fill-verification.log`。Go 原始定向组实际执行 8 个顶层测试及其子场景；Node 原始定向组执行 4 项，未将零匹配或文件存在当作通过。

补测后主代理独立运行全部扩展测试：193 通过、0 失败、0 跳过（`/workspace/issues-node-final-verification.log`）。`go test -race ./internal/browserhost -run 'TestFillQueued' -count=1` 通过，19.211 秒（`/workspace/issues-fill-queue-independent-race.log`）。本批仅增加测试和文档，不重新声称实现已经存在的主修复；最终 PR 精确 head 的六项 CI 及合并回执为关闭依据。

桌面六组相关顶层回归也经主代理独立 `go test -race ./internal/desktop -run 'TestDesktop(Clipboard|Idle|EditAndState|MutationsPreserve|LateRefresh)' -count=1` 通过，47.252 秒，日志 `/workspace/issues-desktop-independent-race.log`。这验证了真实 Session/bbolt、独立 timer/dispatch 和代次判断；测试使用合成剪贴板，不将其称为新增真实硬件平台验收。外部 worker 另行重跑同类队列 race 与 193 项 Node，结果一致，无需新增生产修补。

## 并行实现与边界

主代理负责架构和独立验收；已安装的外部 DeepSeek workers 分别复核旧修复、实现缺失回归、调研并实现历史性能、调研并实现条件式 Passkey。实现位于隔离工作区，避免审计核心和浏览器改动互相干扰。静态复核不等于实际执行，达到调用上限或网络超时不计任务完成。

浏览器调研中“已立即触发原生审批”的初步推断，经主代理读取 `content.js` 撤回：当前桥接实际先等待用户点击。待补的是符合条件的输入框聚焦账号列表及条件式请求生命周期，不更改标准 WebAuthn 响应之外的网页披露边界。账号候选只留在扩展隔离的 closed-shadow UI。

真实硬件、平台浏览器组合、签名分发与独立评审证据分别记录；无法取得的证据继续保持未完成，不用构建、模拟或其他平台绿色结果替代。


## PR #47 已合并

最终 head ab9aca635ef1db33e2e4be637f55c96e4253a73e 六项检查全部成功且 mergeStateStatus=CLEAN，正常 squash 合入 main 2fc96e7a89b9ad9b141fb09c9e9e3cecf59a6af5（2026-11-07 08:51:33 UTC），树与验证 head 完全一致。#35 已自动关闭，当前只剩 #39。检查 run 42356042635、移动 run 42356042631；精确回执 /workspace/issue-completion-tasks/pr47-ci-final.json 与 pr47-merged.json。期间两个测试 fixture 缺陷与逐次修复、未采用旧 head 绿色结果的过程见[性能验收](audit-history-performance-validation.md)。

#39 的条件式/共存实现接入此基线；见[设计](conditional-passkey-design.md)和[真实验收](conditional-passkey-validation.md)。其开放状态保留直到各子项及真实平台条件分别核实。


## PR #48 已合并与本批 #39 增量

最终 head b2905ffcbc3598eeb372b665bafd3e85b91a0d67 六项检查成功且 CLEAN，2026-11-07 09:16:47 UTC 正常 squash 到 main 9cbc34cfe487d9a226a12a63c1cd35ed707fa11c，树完全一致。检查 run 42357749369/42357749279；回执 pr48-ci-final.json、pr48-merged.json。条件式账户建议、生命周期/槽位竞态及软件验证器共存已完成，不能继续列作未开发。

仅 #39 仍开放。本批实现 Signal APIs 原生确认、每次新鲜系统 UV 接口、相关来源回退、公共站点精简 fixture 及未签名发布准备；[综合验收](browser-completion-validation.md)记录 293 项扩展测试、212 项统一 E2E 的真实分类、实际浏览器和仍缺的硬件/平台/跨设备/分发条件。未签名 ZIP 或跨平台构建不等于整项完成。

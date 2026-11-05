# Windows ConPTY 输出排空修复

## 基线与失败证据

main 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`；从 PR #1 实际 head `38b308d2f32b6d97b88bd15ba4ca9a5c5469e268` 接续，分支 `codex/first-preview`，没有覆盖并发提交。

[run 41941551085 attempt 2](https://github.com/jihuayu/locklark/actions/runs/41941551085/attempts/2) 已实际运行：Ubuntu 成功；Windows 的 Go 全仓测试和 MCP/PowerShell 验收通过，但 personal_acceptance.py 的 backup 步骤失败：`RuntimeError: backup: missing JSON response`。因此此前付款/额度未启动不再是该次运行的阻塞，不能继续沿用旧结论。

原 ConPTY 驱动在子进程退出后仅调用一次非阻塞 read，随后查找 JSON。新增合成测试模拟进程先退出、输出在多次空读取后才到达，旧代码实际报相同错误；未输出终端原始内容或凭据。

## 修改及本地验证

首轮实现 `45f2e792bc5458773ee3da13e3ca67273f2f57b5` 退出后排空到 EOF，但 [run 41943060681](https://github.com/jihuayu/locklark/actions/runs/41943060681) Windows 原生测试发现 ConPTY 不一定结束传输：init 报 `ConPTY output did not close`。Ubuntu 通过。此首轮修复未通过原生验收。

修正 `dd68eef`：成功退出必须等到完整 JSON 响应，再等 0.5 秒输出静默；失败退出也排空到静默，5 秒总截止时间避免无限等待，若传输发 EOF 则直接完成排空。仍缺响应时明确失败。加入不发送 EOF 的合成传输测试。仍在完成排空后执行退出状态、秘密回显、发钥次数、恢复拒绝及 JSON 检查，不跳过备份或降低验收。

CI 接入 `020622f5d364ac783fadccf5fdf137e26e84dde2`：两个平台均运行 Python 合成传输回归。随后补充延迟隐藏输入回显负测，验证排空后仍拒绝泄漏；本交接提交同时包含该测试。

实际本地运行 `python3 -m unittest discover -s scripts -p test_personal_windows.py`，3 项通过；`git diff --check` 通过。本轮只改终端验收传输和 CI，不改库数据、密钥或审计协议。合成驱动不是 Windows 原生验收，远端结果须单独记录。终端完整恢复用例仍核对恢复审计，MCP/PowerShell 仍核对执行与回执；没有新增免审计入口。

## 复核与下一步

自查已核对退出后输出、延迟泄漏和超时路径；独立复核尚未完成，不标通过。PR #1 保留，未合并 main。优先检查新 head 的 Windows 原生 CI 结果，若出现新错误继续定位；随后关闭此前独立复核缺口，满足门槛后 squash 合并，再从最新 main 接续个人 CLI 受控单字段披露。真机移动、硬件故障、真实 1Password 对照和独立密码评审仍未完成。

## 修正版远端结果

实现 head `dd68eefdb0dc744436403299b382b3ebfbeb1fa5` 的 [run 41943464262](https://github.com/jihuayu/locklark/actions/runs/41943464262) 最终 success，Ubuntu 与 Windows 两个 job 均成功。实际运行包括 Go 全仓测试（PyKeePass/Bun 集成）、Bun 测试、模块校验、vet、三项 Python 传输回归，以及平台对应的个人终端验收和 MCP/PowerShell 验收。此次结果关闭该 ConPTY 失败；仅证明此提交和工作流所覆盖的原生 Windows 场景，不代表全部 Windows 产品范围、桌面集成或硬件验收完成。

本交接文档随后独立提交，文档 head 见 git 历史；新 head 的 CI 应以 PR 实际结果为准，不把实现 head 的结果冒充文档 head 的结果。

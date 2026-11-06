# 单次可信命令凭据

```text
locklark personal run-cli --file owner.ll --id ID --revision REV --profile gh --name GH_TOKEN --cwd ABS_DIR --timeout 30 --helper-path ABS_DIR_LIST -- ABS_GH_PROGRAM [ARG...]
locklark personal run-cli --file owner.ll --id ID --revision REV --profile token --name OPENAI_API_KEY --cwd ABS_DIR --timeout 30 -- ABS_PROGRAM [ARG...]
```

此入口仅把当前 login 精确 ID/revision 的 password 披露给一次明确批准的可信本机程序。主程序必须是绝对路径，Windows 必须显式 `.exe`；不通过 shell 或 PATH 查找主程序。参数边界原样保留，包括空参数。`--helper-path` 使用平台路径列表分隔符（Unix `:`、Windows `;`），仅允许显式绝对目录；省略时子进程的 PATH 为空。

CLI 在单独打开的控制终端隐藏输入完整因素（Unix `/dev/tty`；Windows 真实 `CONIN$`/`CONOUT$` console 句柄），展示实际程序、完整 argv、工作目录、变量名、profile、超时、辅助 PATH 与披露边界，输入 RUN 后先恢复终端模式，再启动子进程。因素与确认仅走控制终端，不消费子进程 stdin，也不把提示写入子进程 stderr。三个子进程标准流直接继承 Locklark 的原始文件描述符，可分别连接用户管道；没有控制终端则在认证/意图前拒绝。包装器不读取、遮罩、缓冲或记录子进程正文，不在正文后附加 JSON 回执。正常退出码作为 Locklark 的退出码保留。固定失败信息仅描述启动/超时/取消/未知结果或临时目录清理失败，不包含子进程错误正文。

新 API `personal.RunCLI` 固定使用 `os.Stdin/Stdout/Stderr`。认证、当前快照/历史校验、ID/revision/password 定位及 `item.run.password` 意图复用真实事务；事务提交且数据库关闭成功后才执行。独立 HKDF/HMAC 域绑定平台、profile、实际继承标准流策略、空环境加显式变量策略、完整 argv、程序/目录/超时、辅助 PATH 和本次生成的精确临时根目录。审计与 API 回执仅保存摘要，不保存 argv、路径、变量名或原值；没有远端操作成功声明。旧 `RunEnv` 的默认摘要、空环境与空标准流语义保持不变。

子环境只含所选单一 token、明确配置的 PATH、独立临时 HOME/GH_CONFIG_DIR/XDG 配置/数据/缓存目录与临时目录；Windows 额外从 OS 取得 SystemRoot，并将 USERPROFILE/APPDATA/LOCALAPPDATA 指向本次目录。不继承 SSH_AUTH_SOCK、其他 token、GH_HOST、代理、debug 或加载器变量。临时根在意图前创建并进入摘要，目录采用 owner-only 权限。Unix 先解析调用者配置的临时父路径，仅使用其规范路径；从根逐级核验所有权与不可被其他用户替换的权限，最终父目录只接受当前用户私有目录或 root 所有的 sticky 临时目录。Windows 从 OS 已知 LocalAppData 取得父目录，不使用 TEMP/TMP/USERPROFILE/LOCALAPPDATA 环境文本，并逐级核验 owner/DACL、拒绝 reparse/非本地路径。无可信位置时以固定 before-start 错误拒绝，不回退到未经验证的父路径；包装器不把 token 写入其中，全部返回路径均尝试清理。OS/文件系统拒绝清理会明确报错。可信子进程若自行保存或传递凭据，不能靠目录清理收回。

`gh` profile 固定使用 GH_TOKEN，拒绝 `auth login`/`auth setup-git`；原值为空或全由 Unicode 空白组成时，在任何子进程启动前拒绝，避免 gh 将其视为未设置而回退认证来源。此前可能已记录意图，但不记录为执行成功。包装器不会运行登录命令或改写用户全局 gh 配置。`token` profile 允许常见大写 TOKEN、API_KEY、`*_TOKEN`、`*_API_KEY`、`*_ACCESS_KEY` 单变量名，拒绝 PATH、加载器/解释器配置、代理/debug、Git 配置等系统控制变量。没有继承父环境或配置任意环境覆盖的选项。需要额外网络配置的验收仅使用明确受信任的测试包装器，由它设置本次测试代理/CA 后 exec 真实 gh；产品不提供传输绕过入口。

这是向可信程序披露原值，不是沙箱或秘密回收机制。程序及后代可读取、打印、联网、保存或继续传递 token，同用户/管理员也可能检查环境；Go 字符串与 OS 环境不保证物理擦除。程序、脚本、依赖、辅助目录及本机文件系统须可信；绑定路径不等于固定二进制内容。超时为 1–300 秒，仅从执行阶段开始，尝试终止直接子进程，不保证终止后代。取消在启动前胜出则不启动；启动后取消/信号终止只能报告未知结果。CLI 信号沿返回路径清理临时目录，不在子进程期间直接退出绕过清理。

本地定向测试使用真实加密库与实际子进程，验证意图先行、继承 stdin/stdout/stderr、精确 argv、正常非零退出、启动后取消/超时、父环境隔离、临时目录清理、不同目标/profile 绑定，以及准备/执行/清理失败。旧 RunEnv 定向测试同时回归空标准流语义。初始缺失 API 的 red 日志为 `/tmp/locklark-validation/run-cli-red.log`；normal/race 与真实 gh/TLS/PTY 的具体通过证据见下方；假执行器不替代真实命令验收。平台交叉编译也不代表原生终端/gh 验收通过。

实现定向 normal 已通过（personal 43.372s），RunCLI/旧 RunEnv 定向 race 通过（81.381s），最终无 PBKDF 的取消/进程/策略增量 race 通过（2.083s）；personal/CLI vet、实际 CLI 构建和 Windows personal/CLI 测试包交叉编译通过。私有证据分别为 `/tmp/locklark-validation/run-cli-targeted.log`、`run-cli-race.log`、`run-cli-final-policy-race.log`、`run-cli-vet.log`。真实 gh/TLS/PTY 的独立证据另列于下方；原生 Windows 结论不由这些实现检查推定。

临时父路径漏洞的实际权限 red 为 `/tmp/locklark-validation/run-cli-temp-parent-red.log`，修复后的真实不安全父目录/祖先、规范别名和进程回归 race 为 `run-cli-temp-parent-green.log`。控制终端的 detached-session 拒绝与独立提示 writer 定向 race 为 `run-cli-control-console-tests.log`；POSIX 实际管道 stdin/stderr 的独立通过证据另列于下方，Windows ConPTY 的原生通过证据见下方。

独立 POSIX 实际 gh/TLS/PTY 验收已通过 11 组，私有证据 `/tmp/locklark-validation/run-cli-wohknwye`：真实 gh 成功/403 与原退出码、stdin 管道 JSON 原样到达受控 TLS 端点、stderr 管道仅含子进程输出、原 TTY 输入仍可用、无控制终端零启动、取消/旧修订/错误因素零启动，以及 timeout/SIGINT/SIGTERM 后的固定未知结果和临时目录清理。所选 token 仅由私有 TLS oracle 检验 Authorization，不进入公开证据；生产没有传输覆盖选项。Windows 原生 ConPTY/ACL 的结果见下方；这里的真实 gh/TLS 11组属于 POSIX，不声称 Windows gh/TLS 同样已验收。

父代理独立重建的候选二进制 SHA-256 为 `bc3433693d5bb04df4d4e08d5d6b2f28fda3d10214cebc70af875d192ab1e271`，再次完整运行 11 组真实 gh/TLS/控制终端/独立管道/信号场景全部通过；私有证据 `/tmp/locklark-validation/run-cli-ucygz35a` 与 `run-cli-parent-final.log`。9 项工具负测也通过。此证据证明当前 POSIX 候选的真实行为，不是 Windows/macOS 原生通过声明；Windows ConPTY/ACL 和 macOS 对应平台测试结果另列如下；Windows gh/TLS 全流程未单独验收。

精确提交 `de61512309094113a90e6fb72b84d66ae5945f1d` 的 [CI 42183790639](https://github.com/jihuayu/locklark/actions/runs/42183790639) 四组全部通过。Windows 实际运行普通 CLI，通过五组外部 ConPTY 验收：隐藏因素与明确 RUN、三个独立管道、原退出码23且无额外正文、临时目录清理；拒绝零子进程；真实无 console 在因素前拒绝；恰好一个精确目标的签名意图；完整私有 ACL 与输出 canary 核对。新的子进程目录策略用例也在 Windows 实际通过，不是交叉编译替代运行。

Windows 工具先前错误地在隔离的子进程内重新查询宿主 LocalAppData。现在由正常宿主环境中的 launcher 先从 OS 获取并验证父目录，把该公开路径作为精确批准 argv 的一部分交给子进程；子进程仍核对根目录关系、owner/DACL 与整棵树无 reparse，父进程前后仍核对 OS KnownFolder。产品环境策略没有放宽。私有完整证据为 `ssh-pr41-fifth-windows-connector.log` 和 `ssh-pr41-de615123-ci-evidence.json`。

同一精确提交的 macOS 平台检查与真实 OpenSSH 传输检查通过；Linux 的完整 Go/Web/MyGo 及真实 gh 验收通过。平台操作系统密钥保护、完整 GUI 和生物识别真机验收是不同范围，不从 CLI/SSH 传输结果推定。

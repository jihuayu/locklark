# 个人程序环境注入

基线 main `b9edaa83135b53fbadd8aaaa950e6e8bf0e71086`（标题搜索 PR #21），分支 `codex/personal-run-env`。

```text
locklark personal run-env --file owner.ll --id ID --revision REV --field password --name TOKEN --cwd ABS_DIR --timeout 30 -- ABS_PROGRAM [ARG...]
```

人工 CLI 隐藏输入主密码/Secret Key，展示条目 ID/修订/字段、环境变量名、逐个 ASCII 转义的 argv（Go 字符串显示语法，不是 JSON 输入）、绝对程序路径和工作目录、超时及披露边界后输入 RUN。只支持当前 login 的 username/password；归档可显式按 ID 使用，回收站拒绝。取消、认证失败、修订冲突、事务回滚或关库失败不执行。CLI 成功退出表示收到了回执；程序自己的非零退出码保留在 `exit_code`，并不作为 locklark 的进程退出码。

`single-env-direct-process-v1` 直接启动绝对路径，禁止相对程序/PATH 查找，不自动调用 shell、不拼接后重解析 argv。Windows 要求显式 `.exe` 后缀和存在的精确普通文件，避免 PATHEXT 补全；Unix 可使用带 shebang 的可信脚本，其解释器行为仍由脚本决定。最多 64 个参数、总计 16 KiB UTF-8，程序/目录各最多 4096 字节；NUL 和无效 UTF-8 拒绝，空参数和空格保留。变量名为 ASCII 标识符、最多 64 字节，各平台忽略大小写拒绝 SystemRoot。timeout 是 1–300 秒，从进程执行阶段计时，不为先前认证/文件系统访问提供硬截止。

子环境不继承父环境，仅包含指定变量；Windows 另由 OS 查询设置 SystemRoot，不采用父进程同名值。stdin/stdout/stderr 均接空设备，不建立输出缓冲、不回传错误原文。环境无法表达 NUL，含 NUL 的字段在意图后拒绝，不启动程序。空值可注入。退出码只说明直接进程结束，不能证明业务成功；启动失败、超时、信号终止等返回固定未知结果错误，不返回目标/原值/子进程文本。

认证、快照/历史校验、精确修订定位及 `item.run.username` 或 `item.run.password` 意图在同一事务完成；字段由动作名绑定，ID/修订由事件绑定。独立 HKDF/HMAC 绑定原始 argv 边界、程序/目录/变量名/超时、profile、平台及环境/标准流策略。只在事务提交且数据库关闭成功后释放值并启动。运行不改变条目修订，备份恢复保留意图。审计不存 argv、路径、变量名或原值，回执仅含状态/session/意图摘要/目标 HMAC/exit_code。相同库相同目标可以关联。没有持久执行结果事件，崩溃后仅有意图属于未知，不自动重试；旧客户端不识别新动作会拒绝，须升级。

这是向用户选择的可信本地程序**披露**字段，不是插件沙箱、无值 invoke 或无人值守机器授权。程序有当前 OS 用户权限，可联网、读写文件、检查其他文件、把值传给后代；同用户/管理员可能检查进程环境。清空环境和空标准流不约束恶意程序的其他通道，退出码也由程序控制。绑定的是路径/参数，不是二进制内容签名；程序、目录、脚本/依赖及本机文件系统必须可信，同用户替换文件不在防护范围。argv 会出现在进程列表和确认提示中，不应放秘密。Go 字符串/OS 环境不保证安全擦除。timeout 只尝试终止直接子进程，后代可能继续运行；终止 locklark 本身也不保证终止后代。CLI 等待期间维持隐藏终端模式，不能依赖键盘 Ctrl-C 中断，须使用有限 timeout 或 OS 进程管理。

失败先行 `/tmp/locklark-validation/run-env-red.log`：RunRequest/RunEnv 和 commandOption 尚不存在。Go 测试用实际测试子进程验证字段值、精确参数（空参数/空格/shell 符号）、空 stdin、父环境/PATH/PATHEXT 不继承、非零退出/超时/不存在程序、意图先行、HMAC 各目标/跨库绑定、修订不变、备份恢复，以及授权/事务/关闭/取消失败零启动。真实 PTY 脚本 `scripts/run_env_acceptance.py` 启动独立 Python 子进程故意打印合成秘密，核对无输出回流、确认取消、错误因素、成功/非零/超时、过期修订/回收站拒绝和审计；同脚本加入 Ubuntu PTY/Windows ConPTY CI。

SSH Agent、Git 签名、多字段/模板注入、交互式子程序输出、受控环境继承及固定 op v2 合同行为仍待完成。本切片不关闭第七条产品线全部范围，也不改变第三方插件执行关闭状态。

本地主任务验证命令及证据：

```sh
LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun /tmp/locklark-tools/go/bin/go test -count=1 ./...
/tmp/locklark-tools/go/bin/go test -race ./internal/personal ./cmd/locklark -run TestRunEnv -count=1
/tmp/locklark-tools/go/bin/go vet ./...
python3 scripts/run_env_acceptance.py /tmp/locklark-tools/locklark
```

全量通过（personal 203.873s、preview 144.289s）；最终定向 race 通过（personal 77.492s、CLI 1.032s）；vet、diff-check、真实 PTY 及 Windows CLI/测试包交叉编译通过。日志为 `/tmp/locklark-validation/run-env-all.log`、`run-env-race-final.log`。首轮 race 在正常 helper 退出的 1 秒预算失败（Go race runtime 退出等待），已独立复现并只将正常用例预算改为 10 秒，超时负测仍为 1 秒；原失败日志保留为 `run-env-race.log`。交叉编译不代替 Windows 原生验收，最终独立复核及精确 head 的双平台 CI 见本批 PR。

Luna/max 已独立复核完整实现、CLI 与文档，无阻塞发现；独立运行 personal/CLI 定向测试、vet、构建及真实 PTY 均通过。审阅指出确认提示使用 Go `QuoteToASCII` 而非严格 JSON，文档已明确；这是安全显示格式，参数执行仍直接使用原始字符串切片，不解析提示文本。

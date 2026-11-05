# 1PUX v3 只读清点：验收与交接

## 接手与发布

已 fetch 最新 main、原分支和 PR ref；main 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支 `codex/first-preview`，接手 head 为 `4e0a721524873da3f205eb913ae8f611c537411d`。本地/远端/PR 一致，工作树干净，未见其他开发测试进程。已重读 design/progress/development-goal 并核对远端差异，无新增 AGENTS 指令，不依赖 Ryugi。

[PR #1](https://github.com/jihuayu/locklark/pull/1) 仍开放、未合并。实现提交 `3dc0f9fdabb9822a401af3f4d36bcba24c9df473` 已普通快进推送原分支；提交前重新 fetch 未发现并发新 head。未覆盖后续提交、从空 main 重做、强推或修改 main。文档最终 head 由本文件所在提交和 PR 实际 head 确定，最终状态见 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks)。

## 实现范围

`onepux.Inspect` 只读取调用者提供的不可变归档字节，不接受文件路径，不解压到磁盘、不上传、不执行内容、不创建金库。未来文件入口仍须限量读取用户指定的普通文件；此次没有完成该产品入口或其审计。

已读取 [1Password 官方 1PUX 格式说明](https://support.1password.com/1pux-format/)：v3 含 export.attributes、export.data 和 files；条目 UUID 只在库内唯一，字段 ID 不保证唯一。预检按账号/库作用域判重，不把重复字段记录强行变成稳定目标 ID。名字、标题、账号/库/条目 ID、文件路径及字段原值不进入 Report 或错误；类别代码须为三位 ASCII 数字，报告只含受限计数与固定原因码。计数仍是私有库存信息，不能据此向未授权 Agent 或普通日志公开。

- 输出账号/库/条目数、类别分组、active/archived/未知状态及归档文件数量/字节数。条目 ID 可在不同库重用，库 ID 可在不同账号重用；同一作用域的重复 ID、非法标识与不明确层级拒绝。
- Version 只接受规范整数 3，description 须为已知格式标签，createdAt 为规范非负 int64 Unix 秒。标签与 CRC 都不能证明归档来自 1Password 或历史可信。
- MappingVerified 始终为 false，UnmappedItems 始终等于 Items；即使空库也保留 mapping-not-implemented 原因。清点成功不等于可迁移、已迁移或允许发布目标。
- 文件只统计，不推断附件关联、缺失或未引用文件。源 file/documentAttributes 存在时明确标记 file-linkage-unverified。区段、登录表单、密码历史、未知类别/状态与已巡视层级的额外键标记固定待核对原因；深层字段值不做语义映射。unknown-category 表示本预览没有已审核的对应规则，不表示该数字代码一定不是官方类别；001/114 也未获得通用映射证明。
- 属性键只接受 ASCII、最多 256 字节；拒绝重复及大小写别名重复键、非法 UTF-8、孤立 UTF-16 代理项和尾随 JSON。数字用 json.Number 保留，避免先转 float64。未知内容不改写或静默归并，完整条目/关联/字段类型映射仍待实现。

## 归档边界与上限

目录计数在 archive/zip 分配条目对象前检查；前置扫描与标准库必须选中同一末尾记录，并验证实际目录记录数量。只接受单磁盘、非 ZIP64 EOCD、Store/Deflate；本地 ZIP64 大小扩展仍经标准库解析和普通容量限制。EOCD/记录跨磁盘、加密和不支持的压缩特性拒绝。ZIP 注释不能制造与标准库不一致的末尾记录，尾随载荷拒绝。

所有头在解压前核验。只接受两个元数据文件、可选 files/ 目录与其直接文件；拒绝绝对/穿越路径、反斜线、冒号、控制字符、尾点/空格、重复及小写归并重名、特殊文件和未知根条目。完整文件类型检查拒绝符号链接与目录后缀混合模式。每个普通条目都限量读取至 EOF 并核对 CRC 与实际长度，包括不保留在内存中的附件；不依赖扩展名判断内容。

| 边界 | 当前上限 |
| --- | --- |
| 压缩归档输入 | 8 MiB |
| 全部展开内容 / 单条目 | 16 MiB / 8 MiB |
| 每份 JSON | 4 MiB |
| ZIP 条目 / 路径 | 1024 条 / 1024 字节 |
| 账号+库+条目 | 4096 个 |
| 每份 JSON 节点 / 深度 | 100000 / 32 |

容量独立返回 ErrLimit，结构/完整性错误为 ErrInvalid，不支持特性为 ErrUnsupported；所有失败都返回零 Report 和固定文本，不泄漏底层 ZIP/JSON 错误。该内存清点不证明各平台文件名落盘行为，也不是通用迁移完整性证书。

## 失败先行、自查修复与审计

先写 API 空实现和合成测试，运行 `go test -count=1 ./internal/onepux` 实际失败：有效清点、作用域、错误分类和 Unicode 正例不满足，随后实现并转绿。不是已有生产漏洞的声明；临时日志为 `/tmp/locklark-validation/onepux/red.log`。

自查继续写并实际运行以下失败负测，修复后重新验证：

- 谎报末尾记录计数时，条目上限原来在标准库解析后才检查；改为先扫描实际目录。尾随载荷原来可接受，现拒绝。证据 directory-red.log；未量测实际内存峰值，不把错误分类回归写成已完成资源耗尽实验。
- 单条目录记录声明其他磁盘仍可接受，现明确拒绝；证据 disk-red.log。
- files/ 目录后缀可掩盖符号链接类型，现检查完整 Mode.Type；证据 symlink-red.log。模块始终不解压，未发生文件系统写入。
- 前置扫描原可跳过后面的异常末尾签名、选较早记录，与 Go 1.26.8 reader.go 的选择不同；现按最后签名拒绝歧义，保证目录预算作用于实际读取视图。证据 eocd-red.log。

其他合成负例包括 CRC 损坏、穿越/特殊文件、声明大小/展开总量/JSON/目录对象超限、重复 JSON 键、非法代理项和未来版本。两个 fuzz 层分别变异 ZIP 及重新封装有效 CRC 的 export.data，避免 JSON 检查总被 ZIP 校验挡住；检查源字节不变、固定错误、零部分报告、计数一致与不授予迁移。

审计回归先核验既有真实加密演练的签名审计及独立 witness，再读回快照并清点其原生迁出归档。报告与审计序列化扫描未出现标题、密码、OTP 或文件名。已有 fixture.import 等事件只证明既定合成来源，不能冒充通用清点/迁移事实；没有新增产品迁移/预检审计入口。

## 实跑检查

Cloud Linux，Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0；下表 go 为 `/tmp/locklark-tools/go/bin/go`，产物目录为 `/tmp/locklark-validation/onepux`。自查修复后重新运行相关检查，表中 Go/race/fuzz/交叉编译为最终实现结果。

| 检查 | 实际命令与结果 |
| --- | --- |
| 单测与来源 | `go test -count=1 ./internal/onepux ./internal/preview -run 'TestInventory\|TestDirectory\|TestOnepux'` 通过；最后边界修复后核心单测再次通过 |
| 全仓 Go | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python`，`go test -count=1 ./...` 通过，含 KDBX 独立实现互操作和 Bun 子进程；preview 85.741 秒 |
| 定向 race | `go test -race -count=1 -timeout=5m ./internal/onepux ./internal/preview -run 'TestInventory\|TestDirectory\|TestOnepux'` 通过，分别 2.008 秒、14.837 秒 |
| ZIP fuzz | `go test ./internal/onepux -run '^$' -fuzz='^FuzzInventory$' -fuzztime=20s -parallel=2` 通过，256165 次执行 |
| JSON fuzz | `go test ./internal/onepux -run '^$' -fuzz='^FuzzInventoryJSON$' -fuzztime=20s -parallel=2` 通过，200688 次执行 |
| 静态/模块 | `go mod verify`、`go vet ./...`、`git diff --check` 通过；最后边界修复后 vet 再通过 |
| 个人真实 PTY | 构建 locklark 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/onepux/locklark` 通过：错误恢复材料、损坏备份、已有目标不发钥/不留库，FIFO/旧格式/迟到目标和建库/重开回归通过 |
| Bun/MCP | `bun test ./plugins/github-pull-reader` 2 pass/0 fail；Bun 加入 PATH 后 `python3 scripts/mcp_acceptance.py /tmp/locklark-validation/onepux/locklark` 通过；此后边界修复只涉及尚无 CLI 调用者的新内存模块 |
| Windows 编译 | 对 `./internal/onepux`、`./internal/preview` 分别执行 `GOOS=windows GOARCH=amd64 go test -c -o ...`，通过，仅编译 |
| macOS 编译 | 对上述两包分别执行 `GOOS=darwin GOARCH=arm64 go test -c -o ...`，通过，仅编译 |

本轮未验收原生 Windows/macOS、移动真机、硬件故障/断电、真实 1Password 导出/op 对照、所有 ZIP 方言或外部密码评审。此前 preview 全包 race 超时的缺口仍保留；定向检查不替代它。

## 远端、复核与下一项

实现 [run 41930107883](https://github.com/jihuayu/locklark/actions/runs/41930107883) 的 [Ubuntu job 126924555439](https://github.com/jihuayu/locklark/actions/runs/41930107883/job/126924555439) failure，[Windows job 126924555640](https://github.com/jihuayu/locklark/actions/runs/41930107883/job/126924555640) cancelled，均零 steps。当前 annotations 明确写明 Ubuntu 因近期付款失败或需提高 spending limit 未启动，Windows 因矩阵失败取消。没有远端测试通过证据；保留 PR，不绕过保护合并。

上述自查不是独立复核。本轮 PR reviews/review comments 无新意见；本切片及此前恢复/引用/生成核心与 `4932c8d..a0d8ab1` 等已标待复核范围仍未完成独立复核。main 未动，未 squash；全部设计与逐平台验收尚未完成，持续目标保持进行。

下一项：为 1PUX 增加显式附件关联及缺失/未引用文件核对，不猜文件命名规则、不据此声称完整条目可迁移。通用导入写入、产品预检/生成器和人工取值仍待既有 PR 检查/独立复核满足并合并后，从最新 main 接入可信事务、身份与审计。

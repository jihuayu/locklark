# 1PUX 显式文件关联：验收与交接

## 接手与提交

已 fetch 最新 main、原分支和 PR ref；main 为 `3901bc8d8c91c8da039fa02d83e1521746c3c5aa`，工作分支为 `codex/first-preview`，接手 head 为 `1c191e799f05b5559cc97f54fb571aa9401626b5`。本地/远端/PR 一致，工作树干净，未见其他开发测试进程。已重读 design/progress/development-goal 并核对远端差异，无新增 AGENTS 指令，不依赖 Ryugi。

[PR #1](https://github.com/jihuayu/locklark/pull/1) 开放、未合并；实现 `b2347ac8c0d637f653c271944232e433ce2f60f9` 已普通快进推送原分支。提交前重新 fetch 未发现并发新 head，未覆盖后续提交、从空 main 重做、强推或修改 main。文档最终 head 由本文件所在提交与 PR 实际 head 确定，最终远端状态见 [PR checks](https://github.com/jihuayu/locklark/pull/1/checks)。

## 本轮支持的关联子集

[官方格式说明](https://support.1password.com/1pux-format/) 的结构列出 item.file.attrs/path，并描述 documentAttributes。文档没有穷尽 file.path 的所有取值；本轮只接受合成向量已覆盖的、以 files/ 开头的归档相对路径，与已通过 CRC 和实际长度校验的 ZIP 文件名逐字节匹配。此处不声称所有真实导出都采用该路径形式。

Inspect 新增 Report.file_references，仅含八项计数，不返回源路径、ID、文件名、字段值或逐文件摘要：

| 计数 | 精确定义 |
| --- | --- |
| explicit / matched / missing | 显式路径引用次数；其中存在/不存在的次数。重复指向同一缺失目标仍按引用次数计，不冒充缺失文件的唯一数量 |
| repeated | 同一字面路径首次引用后的次数，跨条目/库共享也计入；只提示复核，不自动判错 |
| linked_files | 被这些显式引用命中的唯一归档文件数 |
| files_without_explicit_links | 未被当前子集显式引用覆盖的实际文件数；可能是图标或其他未实现布局，不能称孤儿或据此删除 |
| items_without_explicit_path | 声明 file/documentAttributes 或属于文档类别，但没有显式路径的条目数；不猜 documentId/fileName 拼接规则 |
| size_mismatches | 已匹配引用中，声明 decryptedSize 与实际长度不相等的次数；无声明时不推断大小一致 |

路径大小写、百分号和 Unicode 形式均不归一化、不 URL 解码，不补 files/ 前缀。空文件与缺失文件通过 map 命中状态区分。裸文件名返回 ErrUnsupported；非法路径、目录/元数据目标、非字符串声明和畸形对象返回 ErrInvalid；路径超过 1024 字节返回 ErrLimit。所有错误沿用零 Report 和固定文本，不携带路径或底层解析错误。

可选 decryptedSize 只接受规范非负 uint64 整数；不先转 float64，也不按声明分配内容。已匹配但大小不同、重复引用或缺失引用输出固定待核对原因，保留只读报告。非空 file.attrs 整体标为未映射，未知键也标记待核对。

MappingVerified 始终 false，UnmappedItems 仍等于 Items，file-linkage-unverified 继续保留。存在性/长度相同不证明附件内容、归属、源身份或完整迁移。现有内置演练只有 documentAttributes，没有显式路径，仍明确未验证；源归档、金库/备份格式和 CLI/MCP 工具集没有改版，也未新增文件读取或产品预检入口。

## 失败先行和审计验收

先新增报告类型和合成测试，运行 `go test -count=1 ./internal/onepux -run '^TestFileReferences'` 实际失败：旧清点返回零关联计数，匹配/缺失/重复/大小统计及声明拒绝尚未满足。随后实现并转绿。该失败属于新增能力，不声称旧版曾错误猜中关联或已经实施迁移。临时日志为 `/tmp/locklark-validation/attachments/red.log`，不保证跨环境保留。

回归覆盖零长度文件、缺失目标、重复引用/大小差异、跨库重用条目 ID、缺少路径、仅有文档属性、大小写/百分号/Unicode 字节差异、非法目标、空/错误类型、非规范数值和 uint64 边界。源字节不变，Report 的 JSON/fmt 不回显合成私有标记。ZIP/JSON fuzz 加入显式引用种子；JSON 变异重新封装有效 CRC 和固定附件，检查引用/文件计数关系、零部分结果和不授予迁移。

真实加密演练的回归先核验签名审计和独立 witness，再读回当前原生迁出归档。除报告不泄露标题/密码/OTP/文件名外，新增断言：即使来源历史可信，缺少显式路径仍是一个未解析条目与一个未被当前显式引用覆盖的文件，不能借历史验签推断关联已验证。已有 fixture.import 等来源事件不冒充通用文件核对或迁移事实；生产预检/迁移审计入口仍待实现。

## 实跑检查

环境 Cloud Linux，Go 1.26.8、Bun 1.4.4、PyKeePass 4.2.0。下表 go 为 `/tmp/locklark-tools/go/bin/go`，产物目录 `/tmp/locklark-validation/attachments`。

| 检查 | 实际命令与结果 |
| --- | --- |
| 切片与原边界 | `go test -count=1 ./internal/onepux ./internal/preview -run 'TestInventory\|TestDirectory\|TestFileReferences\|TestOnepux'` 通过 |
| 全仓 Go | 设置 `LOCKLARK_TEST_BUN=/tmp/locklark-tools/bun-linux-x64/bun`、`LOCKLARK_TEST_PYKEEPASS=/tmp/locklark-tools/python/bin/python` 后，`go test -count=1 ./...` 通过，含 KDBX 独立实现互操作和 Bun 子进程；preview 85.525 秒 |
| 定向 race | `go test -race -count=1 -timeout=5m ./internal/onepux ./internal/preview -run 'TestInventory\|TestDirectory\|TestFileReferences\|TestOnepux'` 通过，分别 2.170 秒、14.946 秒 |
| ZIP fuzz | `go test ./internal/onepux -run '^$' -fuzz='^FuzzInventory$' -fuzztime=20s -parallel=2` 通过，650560 次执行 |
| JSON fuzz | `go test ./internal/onepux -run '^$' -fuzz='^FuzzInventoryJSON$' -fuzztime=20s -parallel=2` 通过，115570 次执行 |
| 静态/模块 | `go mod verify`、`go vet ./...`、`git diff --check` 通过 |
| 个人真实 PTY | 构建 locklark 后，`python3 scripts/personal_acceptance.py /tmp/locklark-validation/attachments/locklark` 通过：错误恢复材料、损坏备份、已有目标不发钥/不留库，FIFO/旧格式/迟到目标及建库/重开回归通过 |
| Bun/MCP | `bun test ./plugins/github-pull-reader` 2 pass/0 fail；Bun 加入 PATH 后 `python3 scripts/mcp_acceptance.py /tmp/locklark-validation/attachments/locklark` 通过 |
| Windows 编译 | 对 `./internal/onepux`、`./internal/preview` 分别运行 `GOOS=windows GOARCH=amd64 go test -c -o ...`，通过，仅编译 |
| macOS 编译 | 对上述两包分别运行 `GOOS=darwin GOARCH=arm64 go test -c -o ...`，通过，仅编译 |

本轮未运行原生 Windows/macOS、移动真机、硬件故障/断电、真实 1Password 导出/op 对照或外部密码评审。其他关联布局和完整条目迁移未验证；此前 preview 全包 race 超时的缺口仍保留，定向检查不替代它。

## 远端、复核与下一项

实现 [run 41937243743](https://github.com/jihuayu/locklark/actions/runs/41937243743) 的 [Windows job 126948691199](https://github.com/jihuayu/locklark/actions/runs/41937243743/job/126948691199) failure，[Ubuntu job 126948691562](https://github.com/jihuayu/locklark/actions/runs/41937243743/job/126948691562) cancelled，均零 steps。本轮 annotations 确认 Windows 因近期付款失败或需提高 spending limit 未启动，Ubuntu 因矩阵失败取消。没有远端测试通过证据；保留 PR，不绕过保护合并。

已自查精确匹配、作用域、零长度/缺失区分、计数与整数边界、私有数据流向，未发现新增问题；自查不是独立复核。PR reviews/review comments 无新意见。本切片及此前恢复/引用/生成/清点核心、`4932c8d..a0d8ab1` 等已标待复核范围均继续保留。main 未动，未 squash；全部设计和逐平台验收未完成，持续目标保持进行。

下一项可独立开发：1PUX 区段/字段值类型与重复标识清点，保留源作用域，不把重复字段 ID 强行唯一化或将值统一降成字符串。完整映射、通用写入和产品入口仍待既有 PR 检查/独立复核满足并合并后，从最新 main 接入可信事务、身份与审计。

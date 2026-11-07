# Passkey 系统验证验收

日期 2026-11-07；#39 增量，设计见 passkey-system-verification-design.md。以下本地 fake-adapter 组件回归与 Windows/macOS 硬件验收严格分开。

## 本地实际运行

- adapter worker：Linux build/vet/test、race；Linux 和其他平台类型断言确认普通 store 不满足 PasskeyStore。Windows CGO=0 cross-compile/vet 通过；macOS CGO=0 只验证 unavailable 分支，不能算 Objective-C helper 编译。
- approval worker：native/personal/desktop 聚焦 race 通过，分别约 45.9/46.8/8.8 秒；复核修复部分 JSON 解码 Identity 清零和认证后再次校验 capsule 时限。未声称完整仓库套件已跑完。
- 主代理独立 go test -race ./internal/browserhost ./internal/personal ./internal/osunlock -run 'Test(PasskeySystem|SystemPasskey|SystemUnlock)' -count=1：全部通过，45.177 / 60.212 / 1.013 秒。日志 /workspace/issue-completion-tasks/passkey-os-independent-race.log。
- 组件检查每次调用重新释放 capsule、先前 system unlock 不能免验证、错库/错 slot/错身份/畸形/过期拒绝、等待期间 Lock/取消/期限拒绝、不能持 Session/Connection 锁等 OS 返回、真实软件签名的 UP/UV 和因素入口兼容。fake adapter 不是 OS 验证成功证据。
- 新的 decode 拒绝回归断言 Identity 已解码后遇未知字段或截断时不留下非零字节。认证后时限回归直接覆盖 finish 阶段的有效、过期、未来时间和错误跨度；没有把直接 helper 调用当系统提示成功。

外部独立只读复核已完成。其命令误用了系统中同名的游戏程序，未实际执行 Go 测试，故仅计静态证据。复核指出原 Windows usage 位检查会接受 decrypt+sign / decrypt+agreement：已改为严格的 usage=1/cache=1/export=0 tuple，新增实际调用生产 policy helper 的 Windows 表驱动回归，Windows 编译/vet 通过，运行结果须由最终 Windows CI 给出。没有把额外用途仍需要 gesture 作为忽略该缺陷的理由。

另两项按实际边界记录：systemUnlockOperations 有意串行登记/删除/逐次释放，避免这些操作互相覆盖；OS 提示期间它会阻塞其他系统解锁管理操作，但不阻塞 Session.Lock。输出授权点是取得 writer slot 后的 grant；撤销先于 grant 则拒绝，grant 后已开始发布的数据不能取回，不能宣称锁定可追溯撤销所有管道字节。延迟/失败输出仍有原有 watchdog 与不确定结果处理。此次不为缩短这段不可召回窗口而让立即锁库等待管道 I/O。实现进入 PR 前仍需全包、vet、最终精确 head 六项 CI，尤其真实 macOS cgo/Objective-C 编译。

## 仍需真实平台证据

当前机器为 Linux，尚未实际完成 Windows Hello / Touch ID 成功或拒绝。Windows cross-compile、Linux fake store、CI 的类型/invalid-id 测试均不能替代以下验收：

1. 在真实 Windows/macOS 登记本设备 capsule；同一会话两次 Passkey 操作各触发新的系统验证，拒绝第二次不得签名。记录系统政策（Hello PIN/生物识别，Touch ID 或系统密码）。
2. 系统提示等待时取消/锁库/睡眠/超时，恢复后不交付旧签名；改条目修订或删除凭据后也不得交付。
3. 系统 capsule 过期、未登记、系统服务不可用和验证拒绝均失败关闭；仍可重新发起并使用完整因素路径。
4. 实际浏览器 RP 独立验证 origin/challenge/RP/账户/签名及真实 UP/UV；不记录因素、capsule、私钥或 OTP 种子。

未取得这些证据前不勾选 #39 的“实际系统 UV 验收完成”，不称完整多端 1:1。

整合到 main 9cbc34c 后，全仓 vet、293 项扩展测试及统一 E2E 的系统 UV 组件契约均通过，具体分类和最终精确 head 合并门槛见[综合验收](browser-completion-validation.md)。真实 Windows/macOS 硬件条件仍按上节保留。

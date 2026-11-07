# Passkey 的逐次系统验证

对应 #39 的 Windows Hello / Touch ID 接入。主代理设计授权流程，外部 DeepSeek workers 分别实现系统适配器和 personal/browserhost/native UI；本地硬件成功验收仍是独立门槛。

本功能复用已经由完整因素解锁后登记、有效期固定 24 小时的系统 capsule，不创造新的持久格式或“verified”网页参数。新的 native-only structural interface 仅有 LoadForPasskeyVerification(id)。Windows Hello 和 macOS keychain 实现它；Linux Secret Service 及不支持平台不实现，普通钥匙串读取不能计为 UV。

每次点击 native 账户旁的系统验证按钮，先捕获当前 pending 请求与精确 item/revision，再在不持有 Connection/Session 锁时调用一次新的 OS release。以前解锁过库、以前成功验证或内存中的 Session 都不能跳过这次调用。按钮只在可信 store 实现此接口时出现，需事先启用系统快捷解锁；主密码与 Secret Key 的原路径保留。

Windows 每次新开 Passport KSP key handle，沿用非导出、解密用途、NgcCacheType=1 和每次解密前 PinCacheIsGestureRequired=1 的强制检查；不降级软件 KSP、DPAPI 或仅弹窗布尔结果。macOS 使用原 scoped userPresence item，新建 LAContext、复用时长 0、显式 kSecUseAuthenticationContext，返回后 invalidate/release。Touch ID 或系统密码均是实际政策，不能称仅限指纹。native 缓冲区由适配器清零释放。

personal 校验有界 capsule 的精确字段、路径、slot、身份材料、Created/Expires 和 24 小时跨度，再只读认证当前库的 slot/签名快照/schema/完整历史。OS 等待期间 Session.Lock 不被阻塞；认证关闭后再次检查会话和时间，防止等待跨过有效期。部分 JSON 解码失败也清除已分配 Identity。验证本身不写审计、不续 idle，秘密不进入扩展、日志或 UI 回执。

批准公共路径在系统/因素验证后重新检查同一 pending 指针、Session、capability、generation、Passkey 撤销 epoch、期限和 gate，再提交原有 PerformPasskey；事务仍核对原请求、来源/RP/options、账户和修订。锁定、取消、导航失效或到期不能让迟到验证签名。提交先赢而交付不确定时沿用 unknown，不伪报失败或自动重试；排队输出还要重新验证授权。UV 只来自本次成功因素验证或本次经过所有核对的强 OS release。

内部 adapter 是 native 信任边界，不是来自页面的证明；不接受页面/扩展传入 verified、store 或 capsule。该设计不新增远程证明、跨设备 UV、反回滚或硬件安全保证。

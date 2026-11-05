# 1PUX 密码历史结构清点

基于 PR #6 合并后的 main `83ba76752194d606ce49c5e70289c1d1f27ff4bc`，工作分支 `codex/onepux-password-history`。只扩展内存只读 `onepux.Inspect`；实现 head、独立 Luna/max 复核和最终双平台检查记录在 PR。

## 保留来源，不推断可迁移

`password_history` 报告包含历史记录数，以及 value/time 各自的缺失、null、object、array、string、number、boolean 形状。公开 [1PUX 格式说明](https://support.1password.com/1pux-format/)称 value 是旧密码字符串、time 是 Unix timestamp；本清点保留其他形状并用固定原因标记，不把它们转成字符串或自动修补。非空历史始终保留 `password-history-unmapped`，所有条目仍未映射，MappingVerified 永远 false。

数字时间全程保持 json.Number。只有词法没有小数点或指数、且可精确解析为 int64 的数字进入 IntegerTimes；数值小于零另计，`-0` 不算负数。其余小数、指数和 int64 溢出进入 OtherNumberTimes，不能据此声称是非法时间。没有浮点转换、任意精度指数展开或可信时钟判断。

只比较原数组真正相邻且双方都是上述整数的时间，分别计上升、相等、下降；中间有缺失或其他时间形状就断开，绝不跳过记录。负数和 int64 极值直接比较，不做可能溢出的减法。比较不受 value 形状影响，不说明来源要求升序或降序，也不重排数组。

每条目内对实际字符串 value（包括空串）和数字 time 的原始字面表示统计首次之后的重复次数；不跨条目，不大小写折叠或 Unicode 规范化。`0`、`-0`、`0.0`、`0e0` 的重复身份不同；数值整数比较中 `0` 和 `-0` 相等。值、时间、哈希、标题和未知属性均不输出，只有计数与固定原因。原始内存归档不会改变。

历史条目与区段、区段字段、登录字段全归档共用 4096 上限。passwordHistory 非数组、任何非对象条目、超限等错误返回固定错误与全零报告；不会保留前面的有效部分。缺失或空数组不制造历史。既有 ZIP/CRC、大小、严格 JSON、深度与节点限制继续生效。

## 验证证据与边界

先新增 `TestPasswordHistory*` 并执行，旧实现因缺少历史报告接口编译失败，日志 `/tmp/locklark-validation/password-history-red.log`。实现后覆盖所有值/时间形状、大于 2^53 的精确相邻比较、int64 两端和溢出、负数/-0、小数/指数、空串重复、每种非整数时间断开比较、跨条目状态重置、混合预算精确上限及遍历顺序、秘密扫描和输入不变。

既有真实加密合成来源通过审计/独立检查点验证后读回预检，确认没有凭空制造该来源不存在的历史；新增非空历史覆盖来自合成 ZIP，不能冒称真实用户导出或已认证非空历史迁移。定向 fuzz 保持 ZIP/外层层级有效以直达 passwordHistory，检查形状/数字分类守恒、相邻比较上限和错误零报告。

本轮执行全仓 Go（含 Bun/PyKeePass）、onepux/preview 定向 race、20 秒 history fuzz、vet、模块校验和 macOS arm64 测试包交叉编译；Luna/max 独立复核与 Ubuntu/Windows 最终 CI 以 PR 最终 head 的实际结果为准。这不是通用历史导入、密码历史查看入口、真实 1Password 对照或完整产品验收。下一步优先接通可用的、经过认证与审计的迁移预检入口，再做完整映射及可逆迁出。

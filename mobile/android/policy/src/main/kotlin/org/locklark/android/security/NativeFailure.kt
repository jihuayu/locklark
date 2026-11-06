package org.locklark.android.security

/** Fixed user-facing categories. Never display a native exception body. */
enum class NativeFailureCode(val userText: String) {
    LOCKED("金库已锁定，请重新解锁。"), CLOSED("金库已关闭。"), INVALID("输入内容不符合要求。"),
    CONFLICT("条目已变化，请刷新后核对。"), CANCELLED("操作已取消。"), UNKNOWN("结果未确认，请核实金库后再决定。"),
    EXPIRED("本次显示授权已过期。"), UNAVAILABLE("金库或设备认证暂不可用，或完整因素未通过。"),
    EXISTS("金库已存在，请用完整因素打开。"), CAPACITY("请先隐藏已有显示内容。"), OTHER("操作暂不可用。")
}
enum class NativePhase(val userText: String) { OPERATION("操作"), CAPTURE("准备操作"), CREATE("创建金库"), UNLOCK("解锁"), REFRESH("刷新列表") }
class NativeCallFailure(val phase: NativePhase, val code: NativeFailureCode) : Exception("Native operation refused")

object NativeFailures {
    private val known = mapOf(
        "vault is locked; unlock again" to NativeFailureCode.LOCKED,
        "vault is closed" to NativeFailureCode.CLOSED,
        "invalid mobile vault request" to NativeFailureCode.INVALID,
        "item changed; refresh and review before retrying" to NativeFailureCode.CONFLICT,
        "operation cancelled before persistence" to NativeFailureCode.CANCELLED,
        "operation result unknown; inspect the vault before retrying" to NativeFailureCode.UNKNOWN,
        "disclosure expired or already consumed" to NativeFailureCode.EXPIRED,
        "vault or authenticated system storage unavailable" to NativeFailureCode.UNAVAILABLE,
        "vault already exists; unlock the existing vault" to NativeFailureCode.EXISTS,
        "too many pending disclosures; clear an existing disclosure" to NativeFailureCode.CAPACITY,
        "Native authentication unavailable or cancelled" to NativeFailureCode.UNAVAILABLE,
    )
    fun classify(error: Throwable): NativeFailureCode = when (error) {
        is NativeCallFailure -> error.code
        is ObsoleteWork -> NativeFailureCode.CANCELLED
        else -> known.entries.firstOrNull { error.message?.endsWith(it.key) == true }?.value ?: NativeFailureCode.OTHER
    }
    fun <T> call(phase: NativePhase, action: () -> T): T = try { action() }
        catch (error: Exception) { throw NativeCallFailure(phase, classify(error)) }
}

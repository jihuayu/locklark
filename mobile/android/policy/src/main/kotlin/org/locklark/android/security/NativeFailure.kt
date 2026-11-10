package org.locklark.android.security

/** Fixed user-facing categories. Never display a native exception body. */
enum class NativeFailureCode(val userText: String) {
    LOCKED("金库已锁定，请重新验证解锁。"), CLOSED("金库连接已关闭。"), INVALID("输入格式或长度不符合安全要求。"),
    CONFLICT("凭据已被更新，请刷新列表后重试。"), CANCELLED("操作已取消。"), UNKNOWN("结果未确认，请核实金库状态后再操作。"),
    EXPIRED("单次显示授权已到期，请重新读取。"), UNAVAILABLE("金库或本机认证暂不可用，或双因素验证未通过。"),
    EXISTS("本机金库已存在，请使用完整双因素解锁。"), CAPACITY("当前已有展开的敏感字段，请先隐藏后再试。"), OTHER("当前操作暂不可用。")
}
enum class NativePhase(val userText: String) {
    OPERATION("操作"), CAPTURE("准备操作"), CREATE("创建金库"), UNLOCK("解锁"), REFRESH("刷新列表"),
    DEVICE_SETUP("准备设备认证"), DEVICE_READY("检查设备认证"), DEVICE_KEY("准备设备认证密钥"),
    DEVICE_CIPHER("准备设备加密"), DEVICE_PROMPT("设备认证"), DEVICE_WAIT("等待设备认证"),
    DEVICE_AAD("绑定设备授权"), DEVICE_CRYPTO("处理设备授权"), DEVICE_READ("读取设备授权"), DEVICE_WRITE("保存设备授权")
}
enum class NativeExceptionKind {
    NONE, USER_NOT_AUTHENTICATED, KEY_INVALIDATED, INVALID_KEY, INVALID_PARAMETER,
    KEYSTORE, PROVIDER, SECURITY, IO, ILLEGAL_ARGUMENT, ILLEGAL_STATE, TIMEOUT, INTERRUPTED, OTHER
}
enum class NativeAuthError { NONE, HARDWARE_UNAVAILABLE, UNABLE_TO_PROCESS, TIMEOUT, NO_SPACE, CANCELLED,
    LOCKOUT, VENDOR, PERMANENT_LOCKOUT, USER_CANCELLED, NO_BIOMETRICS, NO_HARDWARE, NEGATIVE_BUTTON,
    NO_DEVICE_CREDENTIAL, SECURITY_UPDATE_REQUIRED, OTHER }
class NativeCallFailure(val phase: NativePhase, val code: NativeFailureCode,
                        val exceptionKind: NativeExceptionKind = NativeExceptionKind.NONE,
                        val authError: NativeAuthError = NativeAuthError.NONE) : Exception("Native operation refused")

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
        catch (error: Exception) { throw failure(phase, error) }

    fun failure(phase: NativePhase, error: Throwable): NativeCallFailure =
        error as? NativeCallFailure ?: NativeCallFailure(phase, classify(error), exceptionKind(error))

    fun exceptionKind(error: Throwable): NativeExceptionKind = when (error.javaClass.name) {
        "android.security.keystore.UserNotAuthenticatedException" -> NativeExceptionKind.USER_NOT_AUTHENTICATED
        "android.security.keystore.KeyPermanentlyInvalidatedException" -> NativeExceptionKind.KEY_INVALIDATED
        "java.security.InvalidKeyException" -> NativeExceptionKind.INVALID_KEY
        "java.security.InvalidAlgorithmParameterException" -> NativeExceptionKind.INVALID_PARAMETER
        "java.security.KeyStoreException", "android.security.KeyStoreException", "java.security.UnrecoverableKeyException" -> NativeExceptionKind.KEYSTORE
        "java.security.ProviderException" -> NativeExceptionKind.PROVIDER
        "java.lang.SecurityException" -> NativeExceptionKind.SECURITY
        "java.io.IOException", "java.io.FileNotFoundException", "android.system.ErrnoException" -> NativeExceptionKind.IO
        "java.lang.IllegalArgumentException" -> NativeExceptionKind.ILLEGAL_ARGUMENT
        "java.lang.IllegalStateException" -> NativeExceptionKind.ILLEGAL_STATE
        "java.util.concurrent.TimeoutException" -> NativeExceptionKind.TIMEOUT
        "java.lang.InterruptedException" -> NativeExceptionKind.INTERRUPTED
        else -> NativeExceptionKind.OTHER
    }

    fun authError(code: Int): NativeAuthError = when (code) {
        1 -> NativeAuthError.HARDWARE_UNAVAILABLE; 2 -> NativeAuthError.UNABLE_TO_PROCESS
        3 -> NativeAuthError.TIMEOUT; 4 -> NativeAuthError.NO_SPACE; 5 -> NativeAuthError.CANCELLED
        7 -> NativeAuthError.LOCKOUT; 8 -> NativeAuthError.VENDOR; 9 -> NativeAuthError.PERMANENT_LOCKOUT
        10 -> NativeAuthError.USER_CANCELLED; 11 -> NativeAuthError.NO_BIOMETRICS; 12 -> NativeAuthError.NO_HARDWARE
        13 -> NativeAuthError.NEGATIVE_BUTTON; 14 -> NativeAuthError.NO_DEVICE_CREDENTIAL
        15 -> NativeAuthError.SECURITY_UPDATE_REQUIRED; else -> NativeAuthError.OTHER
    }

    /** All fields are fixed enums; never interpolate Throwable text, class names, or paths. */
    fun diagnostic(failure: NativeCallFailure): String =
        "stage=${failure.phase.name} code=${failure.code.name} exception=${failure.exceptionKind.name} os=${failure.authError.name}"
}

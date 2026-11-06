package org.locklark.android.security

/** A single live operation; neither keys nor plaintext are retained here. */
interface PerUseCryptoOperation {
    fun authenticate()
    fun addAuthenticatedData()
    fun finish(): ByteArray
}

object PerUseCrypto {
    fun finish(checkCurrent: () -> Unit, operation: PerUseCryptoOperation): ByteArray {
        checkCurrent()
        operation.authenticate()
        checkCurrent()
        operation.addAuthenticatedData()
        val result = operation.finish()
        try { checkCurrent(); return result }
        catch (error: Exception) { result.fill(0); throw error }
    }
}

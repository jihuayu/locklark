package android.view.autofill

/**
 * JVM-only stand-in for the platform final class (a stub in android.jar). Only
 * the text value used by the Autofill result mapping is modeled; a non-text
 * value (e.g. an empty-string substitute) reports [isText] false.
 */
open class AutofillValue protected constructor(private val text: CharSequence?) {
    val isText: Boolean get() = text != null
    val textValue: CharSequence? get() = text

    override fun toString(): String = "[autofill value]"

    companion object {
        @JvmStatic fun forText(value: CharSequence): AutofillValue = AutofillValue(value)
    }
}

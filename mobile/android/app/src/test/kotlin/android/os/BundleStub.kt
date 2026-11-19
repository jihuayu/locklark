package android.os

/**
 * JVM-only stand-in for the platform final class (a stub in android.jar):
 * enough of the Parcelable extras container to assert the authentication
 * result shape without an Android runtime.
 */
class Bundle {
    private val values = LinkedHashMap<String, Any?>()

    constructor()
    constructor(other: Bundle) { values.putAll(other.values) }

    fun isEmpty(): Boolean = values.isEmpty()
    fun size(): Int = values.size
    fun containsKey(key: String): Boolean = values.containsKey(key)

    fun putString(key: String, value: String?) { values[key] = value }
    fun getString(key: String): String? = values[key] as? String

    fun putInt(key: String, value: Int) { values[key] = value }
    fun getInt(key: String, defaultValue: Int): Int = values[key] as? Int ?: defaultValue

    fun putParcelable(key: String, value: Parcelable?) { values[key] = value }
    fun <T : Parcelable> getParcelable(key: String): T? {
        @Suppress("UNCHECKED_CAST")
        return values[key] as? T
    }

    fun putBundle(key: String, value: Bundle?) { values[key] = value }
    fun getBundle(key: String): Bundle? = values[key] as? Bundle

    override fun toString(): String = "[bundle]"
}

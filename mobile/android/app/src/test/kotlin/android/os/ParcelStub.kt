package android.os

/** JVM-only stand-in with just the parcel round-trip sizing the cache uses. */
class Parcel private constructor() {
    private var bytes = 0

    fun writeParcelable(value: Parcelable?, flags: Int) {
        if (failed) throw IllegalStateException("[parcel failure]")
        if (value != null) bytes += 1
    }
    fun setDataPosition(position: Int) {}
    fun <T : Parcelable> readParcelable(loader: ClassLoader?): T? = null
    fun dataSize(): Int = bytes
    fun recycle() {}

    companion object {
        /** When set, every write fails like an unmeasurable response. */
        @Volatile
        @JvmStatic
        var failed: Boolean = false

        @JvmStatic fun obtain(): Parcel = Parcel()
    }
}

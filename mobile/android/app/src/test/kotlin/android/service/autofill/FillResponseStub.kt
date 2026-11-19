package android.service.autofill

import android.os.Parcel
import android.os.Parcelable

/**
 * JVM-only stand-in for the platform final response: identity plus Parcelable
 * shape so result construction and cache policy are testable without a device.
 */
class FillResponse : Parcelable {
    override fun describeContents(): Int = 0
    override fun writeToParcel(dest: Parcel, flags: Int) {}
}

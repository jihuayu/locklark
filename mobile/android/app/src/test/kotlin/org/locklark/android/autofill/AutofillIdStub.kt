package android.view.autofill

/**
 * JVM-only stand-in for the platform final class, which is not in the unit-test
 * classpath (the app source also references it). Mirrors platform identity
 * semantics (equals/hashCode). Compiled only into the app unit-test source set.
 */
class AutofillId(private val id: Int)

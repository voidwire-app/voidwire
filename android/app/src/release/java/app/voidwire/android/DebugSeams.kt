package app.voidwire.android

import uniffi.voidwire_core.PhoneInterface

/**
 * Release variant: no test seams. The app always uses the real core
 * ([Core.phone]); there is nothing to set. The debug variant of this file
 * (src/debug) is what instrumented tests use; it never reaches a release APK.
 */
internal object DebugSeams {
    fun phone(): PhoneInterface? = null
}

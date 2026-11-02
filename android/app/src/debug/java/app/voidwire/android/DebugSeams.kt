package app.voidwire.android

import uniffi.voidwire_core.PhoneInterface

/**
 * DEBUG BUILD ONLY (src/debug; the release variant in src/release always
 * returns null). Lets instrumented tests (androidTest ScreenshotFlowTest, run
 * by .github/workflows/android-qa.yml) seed the main screen with a fake
 * phone instead of pairing with a live PC. Nothing in the app sets it.
 */
internal object DebugSeams {
    @Volatile var fakePhone: PhoneInterface? = null

    fun phone(): PhoneInterface? = fakePhone

    /**
     * Stands in for PackageManager.canRequestPackageInstalls() in tests:
     * changing the real app-op from a test kills the app process.
     */
    @Volatile var installAllowed: Boolean? = null

    fun canInstall(): Boolean? = installAllowed
}

package app.voidwire.android

import android.content.Context

/**
 * Installs the Android JVM + application Context into the Rust core (QA M1
 * re-check C1). iroh's DNS resolver reads the system DNS config through JNI
 * and aborted the process ("android context was not initialized") when this
 * was missing. Must run before the first `Phone()`; [Core.phone] does it.
 *
 * `Phone()` refuses with `PhoneException.NotInitialized` (never a crash) if
 * this didn't succeed. Idempotent and thread-safe.
 */
object NativeInit {
    @Volatile private var done = false

    /** `true` once the core has the context. `context` may be null only on the host JVM (tests). */
    fun init(context: Context?): Boolean {
        if (done) return true
        synchronized(this) {
            if (!done) {
                done = try {
                    // Same libvoidwire_core.so that UniFFI loads through JNA.
                    System.loadLibrary("voidwire_core")
                    nativeInit(context?.applicationContext ?: context)
                } catch (e: UnsatisfiedLinkError) {
                    false
                }
            }
        }
        return done
    }

    @JvmStatic private external fun nativeInit(context: Context?): Boolean
}

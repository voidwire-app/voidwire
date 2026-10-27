//! Platform initialisation for the mobile FFI (QA M1 re-check C1).
//!
//! iroh's DNS resolver (n0-dns-resolver) and netdev read the Android system
//! configuration through JNI and need a JavaVM + application `Context`
//! published to `ndk_context` **before** the first endpoint is built. Without
//! it they hit `ndk_context::android_context()`'s "android context was not
//! initialized" panic (an abort under `panic = "abort"`).
//!
//! The app calls `NativeInit.init(applicationContext)` (Kotlin, `Core.kt`)
//! before constructing `Phone()`. That lands in
//! [`Java_app_voidwire_android_NativeInit_nativeInit`], which stores the VM and
//! a global ref to the application context exactly once. `Phone::new` refuses
//! with `PhoneError::NotInitialized` (an error, never an abort) until this has
//! succeeded, on every platform, so host JVM tests exercise the same contract.
//!
//! The JNI entry point is a plain `extern "system"` symbol: the app loads the
//! same `libvoidwire_core.so` with `System.loadLibrary` (for JNI) and through
//! JNA (for UniFFI); both resolve to the one mapped library.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static READY: AtomicBool = AtomicBool::new(false);
static INIT_LOCK: Mutex<()> = Mutex::new(());

/// Whether the platform context has been installed (always the case after a
/// successful `NativeInit.init`).
pub(crate) fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Kotlin: `app.voidwire.android.NativeInit.nativeInit(context: Context): Boolean`
/// (`@JvmStatic external`). Idempotent; returns `true` once the context is
/// installed. On Android a null context is refused. On other platforms (host
/// JVM unit tests) there is nothing to install and the context may be null.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv` and a local ref (or null).
#[no_mangle]
pub unsafe extern "system" fn Java_app_voidwire_android_NativeInit_nativeInit(
    env: *mut jni_sys::JNIEnv,
    _class: jni_sys::jclass,
    context: jni_sys::jobject,
) -> jni_sys::jboolean {
    // Never let a panic cross the JNI boundary.
    let ok = std::panic::catch_unwind(|| unsafe { init(env, context) }).unwrap_or(false);
    if ok {
        jni_sys::JNI_TRUE
    } else {
        jni_sys::JNI_FALSE
    }
}

unsafe fn init(env: *mut jni_sys::JNIEnv, context: jni_sys::jobject) -> bool {
    let _g = INIT_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if is_ready() {
        return true;
    }
    if !install(env, context) {
        return false;
    }
    READY.store(true, Ordering::Release);
    true
}

#[cfg(target_os = "android")]
unsafe fn install(env: *mut jni_sys::JNIEnv, context: jni_sys::jobject) -> bool {
    if env.is_null() || context.is_null() {
        return false;
    }
    let iface = unsafe { &**env };
    let (Some(get_vm), Some(new_global)) = (iface.GetJavaVM, iface.NewGlobalRef) else {
        return false;
    };
    let mut vm: *mut jni_sys::JavaVM = std::ptr::null_mut();
    if unsafe { get_vm(env, &mut vm) } != jni_sys::JNI_OK || vm.is_null() {
        return false;
    }
    // Lives for the life of the process (the application context does too).
    let global = unsafe { new_global(env, context) };
    if global.is_null() {
        return false;
    }
    // ndk_context asserts it's initialised only once; INIT_LOCK + READY
    // guarantee this runs at most once per process.
    unsafe { iroh::dns::install_android_jni_context(vm.cast(), global.cast()) };
    true
}

#[cfg(not(target_os = "android"))]
unsafe fn install(_env: *mut jni_sys::JNIEnv, _context: jni_sys::jobject) -> bool {
    true
}

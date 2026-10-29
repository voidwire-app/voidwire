import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.github.jk1.dependency-license-report")
}

// Single source of truth for the public identity: ../branding.properties
val branding = Properties().apply {
    rootProject.file("../branding.properties").inputStream().use { load(it) }
}
fun brand(key: String): String = branding.getProperty(key) ?: error("$key missing from branding.properties")

// The project license (CC0 1.0 with MIT fallback) ships inside the APK as assets/LICENSE.
// This is the Android equivalent of Cargo's `license-file = "LICENSE"`.
val licenseFile = rootProject.file("../LICENSE")
val licenseAssetsDir = layout.buildDirectory.dir("generated/licenseAssets")
// D8: plus the generated third-party notices (Rust crates in the .so + Gradle
// runtime libraries), written by scripts/gen-third-party.py android before
// assembling (scripts/build-android.sh). Missing file = build failure.
val thirdPartyFile = rootProject.file("../build/licenses/android/THIRD-PARTY-LICENSES.txt")
val copyLicense by tasks.registering(Copy::class) {
    doFirst {
        check(thirdPartyFile.isFile) {
            "missing $thirdPartyFile: run scripts/gen-third-party.py android (scripts/build-android.sh does)"
        }
    }
    from(licenseFile)
    from(thirdPartyFile)
    into(licenseAssetsDir)
}

android {
    // Internal code namespace (R class, Kotlin packages). NOT the store ID.
    namespace = "app.voidwire.android"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = brand("PACKAGE_ID")
        minSdk = 26
        targetSdk = 35
        versionCode = 17
        versionName = "0.5.1-m4.1"
        resValue("string", "app_name", brand("APP_NAME"))
        // C1 on-device smoke test (src/androidTest, scripts/android-smoke.sh).
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }

    sourceSets["main"].assets.srcDir(licenseAssetsDir)

    // Release signing: a local dev key kept OUTSIDE the repo (scripts/build-android.sh
    // creates ~/.voidwire/android-dev-release.jks on first use). M1 test builds
    // only; the store/upload key is a separate decision (docs/M1-TEST-SHEET.md).
    val ks = System.getenv("VOIDWIRE_ANDROID_KEYSTORE")
    signingConfigs {
        if (ks != null) {
            create("devRelease") {
                storeFile = file(ks)
                storePassword = System.getenv("VOIDWIRE_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("VOIDWIRE_ANDROID_KEY_ALIAS") ?: "voidwire-dev"
                keyPassword = System.getenv("VOIDWIRE_ANDROID_KEYSTORE_PASSWORD")
            }
        }
    }
    buildTypes {
        release {
            // UniFFI/JNA bindings are reflection-heavy; no shrinking for M1.
            isMinifyEnabled = false
            if (ks != null) signingConfig = signingConfigs.getByName("devRelease")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
        resValues = true
    }
    packaging {
        // Keep third-party license texts in the APK (JNA ships AL2.0 + LGPL2.1).
        resources.pickFirsts += listOf("/META-INF/AL2.0", "/META-INF/LGPL2.1")
    }
    testOptions {
        // Robolectric (ShareActivityTest) needs the merged resources/manifest.
        unitTests.isIncludeAndroidResources = true
        unitTests.all {
            it.maxHeapSize = "1g"
            // Host build of voidwire-core (cargo build -p voidwire-core --features ffi)
            // so the generated Kotlin bindings can be exercised on the JVM.
            // VOIDWIRE_CORE_LIB_DIR: set by scripts/build-android.sh from cargo metadata (D10).
            val coreLibDir = System.getenv("VOIDWIRE_CORE_LIB_DIR") ?: rootProject.file("../target/debug").absolutePath
            it.systemProperty("jna.library.path", coreLibDir)
            // NativeInit (C1) loads the same library through System.loadLibrary.
            it.systemProperty("java.library.path", coreLibDir)
        }
    }
}

tasks.named("preBuild") { dependsOn(copyLicense) }

licenseReport {
    outputDir = layout.buildDirectory.dir("reports/dependency-license").get().asFile.path
    configurations = arrayOf("releaseRuntimeClasspath")
    renderers = arrayOf(
        com.github.jk1.license.render.TextReportRenderer("THIRD-PARTY-LICENSES.txt"),
        com.github.jk1.license.render.CsvReportRenderer("licenses.csv"),
    )
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.13.1")
    // QR scanning without Google Play services: CameraX + ZXing core (both Apache-2.0).
    val camerax = "1.3.4"
    implementation("androidx.camera:camera-camera2:$camerax")
    implementation("androidx.camera:camera-lifecycle:$camerax")
    implementation("androidx.camera:camera-view:$camerax")
    implementation("com.google.zxing:core:3.5.3")
    // UniFFI's Kotlin bindings call into the Rust core through JNA.
    // JNA is dual-licensed LGPL-2.1-or-later OR Apache-2.0; we use it under Apache-2.0.
    implementation("net.java.dev.jna:jna:5.15.0@aar")

    testImplementation("junit:junit:4.13.2")
    // Robolectric (MIT) runs ShareActivity on the JVM for the QA M1 High tests.
    // Test-only: never in the APK (not on releaseRuntimeClasspath).
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("net.java.dev.jna:jna:5.15.0")
    // On-device smoke test (C1). Test APK only; never in the app APK.
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:core-ktx:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    // S1: DeviceSmokeTest clicks the real Send button with injected touches.
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    // android-qa.yml screenshot flow (ScreenshotFlowTest): Compose test driver +
    // camera grant. Test APK only; never in the app APK.
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}

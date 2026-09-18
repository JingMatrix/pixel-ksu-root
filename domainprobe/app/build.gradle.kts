plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.pixelksu.domainprobe"
    ndkVersion = "29.0.14206865"
    // compileSdk / minSdk / targetSdk are set in settings.gradle.kts (release 37)

    defaultConfig {
        applicationId = "dev.pixelksu.domainprobe"
        versionCode = 1
        versionName = "1"
        ndk { abiFilters += "arm64-v8a" }
        externalNativeBuild { cmake { arguments += "-DANDROID_STL=none" } }
    }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt") } }
    buildFeatures { compose = true; aidl = true }
    buildTypes { release { isMinifyEnabled = false } }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
    packaging { jniLibs { useLegacyPackaging = true } }   // extract the cli binary to disk
}

dependencies {
    val compose = platform("androidx.compose:compose-bom:2026.02.01")
    implementation(compose)
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
    implementation("androidx.core:core-ktx:1.16.0")
    // Lift the non-SDK (hidden-API) blocklist process-wide, in pure Java (no
    // native code -- important because the system_server payload has no execmem).
    // This exposes hidden libcore.io.Os wrappers (setxattr, prctl, ioctlInt,
    // mmap/mprotect, ...) to the app classloader the Telecom pivot runs under.
    implementation("org.lsposed.hiddenapibypass:hiddenapibypass:6.1")
}

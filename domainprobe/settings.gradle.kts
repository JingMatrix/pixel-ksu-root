@file:Suppress("UnstableApiUsage")

pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
    plugins {
        val agp = "9.3.0"
        id("com.android.application") version agp
        id("com.android.settings") version agp
        val kotlin = "2.3.0"
        id("org.jetbrains.kotlin.plugin.compose") version kotlin
    }
}

dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}

// SDK versions live here (com.android.settings), which is how android-37.0 and
// the API-37 manifest attributes (nativeService) resolve.
plugins { id("com.android.settings") }
android {
    compileSdk { version = release(37) { minorApiLevel = 0 } }
    minSdk { version = release(29) }
    targetSdk { version = release(37) }   // devices are Android 17 (API 37)
    buildToolsVersion = "37.0.0"
}

rootProject.name = "domainprobe"
include(":app")

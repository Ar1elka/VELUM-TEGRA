plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// Distribution signing is intentionally local-machine only. Nothing secret is stored in the
// canonical project or FULL snapshots. A completely absent configuration builds unsigned
// release artifacts for readiness checks; a partially configured environment fails closed.
val releaseSigningEnvironment = mapOf(
    "storeFile" to System.getenv("VELUM_RELEASE_STORE_FILE"),
    "storePassword" to System.getenv("VELUM_RELEASE_STORE_PASSWORD"),
    "keyAlias" to System.getenv("VELUM_RELEASE_KEY_ALIAS"),
    "keyPassword" to System.getenv("VELUM_RELEASE_KEY_PASSWORD"),
)
val releaseSigningConfiguredValues = releaseSigningEnvironment.filterValues { !it.isNullOrBlank() }
check(releaseSigningConfiguredValues.isEmpty() || releaseSigningConfiguredValues.size == releaseSigningEnvironment.size) {
    "Release signing environment is partially configured. Set all of " +
        "VELUM_RELEASE_STORE_FILE, VELUM_RELEASE_STORE_PASSWORD, VELUM_RELEASE_KEY_ALIAS and " +
        "VELUM_RELEASE_KEY_PASSWORD, or unset all four for an unsigned readiness build."
}
val releaseSigningConfigured = releaseSigningConfiguredValues.size == releaseSigningEnvironment.size
if (releaseSigningConfigured) {
    check(rootProject.file(requireNotNull(releaseSigningEnvironment.getValue("storeFile"))).isFile) {
        "VELUM_RELEASE_STORE_FILE does not point to an existing keystore file."
    }
}

android {
    namespace = "com.velumtegra.xuimobile"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.velumtegra.xuimobile"
        minSdk = 24
        targetSdk = 37
        versionCode = 4
        versionName = "2.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                storeFile = rootProject.file(requireNotNull(releaseSigningEnvironment.getValue("storeFile")))
                storePassword = requireNotNull(releaseSigningEnvironment.getValue("storePassword"))
                keyAlias = requireNotNull(releaseSigningEnvironment.getValue("keyAlias"))
                keyPassword = requireNotNull(releaseSigningEnvironment.getValue("keyPassword"))
            }
        }
    }

    buildTypes {
        debug {
            // Allows VELUM//TEGRA Next to coexist with the reference app during migration.
            applicationIdSuffix = ".next"
            versionNameSuffix = "-next"
        }
        release {
            isMinifyEnabled = false
            if (releaseSigningConfigured) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
        isCoreLibraryDesugaringEnabled = true
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    // Keep minSdk 24 while safely using java.time from the pure Kotlin foundation on API 24/25.
    coreLibraryDesugaring(libs.desugar.jdk.libs)

    implementation(project(":feature:home"))
    // The app-level composition root wires public domain/model contracts explicitly; Gradle
    // implementation dependencies of infrastructure modules are intentionally not transitive.
    implementation(project(":core:model"))
    implementation(project(":core:domain"))
    // Production composition root owns the exact persistence/secrets/transport/runtime graph.
    // UI still does not call these infrastructure modules directly.
    implementation(project(":core:data"))
    implementation(project(":core:secrets"))
    implementation(project(":core:ssh"))
    // Package Phase 7 WebPanel infrastructure through the Android gate before UI entry is wired.
    implementation(project(":core:webpanel"))
    implementation(project(":core:runtime"))
    implementation(project(":core:runtime-android"))
    // Phase 10 packages the migrated Reality Scanner engine/service plus its UI result contracts.
    implementation(project(":core:scanner"))
    implementation(project(":core:scanner-android"))
    // Phase 11.14 exposes only the pure Site review boundary to the Android presentation layer.
    implementation(project(":core:site"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.core.ktx)
    // Service lifecycle integration launches only the cancellation-safe exact runtime admission bridge.
    implementation(libs.kotlinx.coroutines.core)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)

    // Phase 2.7 integration gates only. Production UI still has no persistence/secrets dependency.
    androidTestImplementation(project(":core:model"))
    androidTestImplementation(project(":core:domain"))
    androidTestImplementation(project(":core:data"))
    androidTestImplementation(project(":core:secrets"))
    // Phase 11.10A real-device Site observation acceptance exercises the concrete read-only SSH adapter.
    androidTestImplementation(project(":core:site"))
    androidTestImplementation(libs.androidx.room3.runtime)
    androidTestImplementation(libs.androidx.sqlite.framework)
    androidTestImplementation(libs.kotlinx.coroutines.core)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    // Phase 11.15 drives the real production Compose tree on one real Android device.
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}

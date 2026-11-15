plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.velumtegra.xuimobile.core.scanner.android"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        minSdk = 24
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(project(":core:scanner"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.maxmind.geoip2)

    testImplementation(libs.junit)
}

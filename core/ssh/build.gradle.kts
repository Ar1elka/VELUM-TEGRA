plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

dependencies {
    implementation(project(":core:model"))
    implementation(project(":core:domain"))
    implementation(project(":core:site"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.mwiede.jsch)

    testImplementation(libs.junit)
    // Test-only deterministic loopback SSH server. Never packaged into production APK.
    testImplementation(libs.apache.sshd.core)
    // Phase 11.11A host-only bounded SFTP fixture. Never packaged into production APK.
    testImplementation(libs.apache.sshd.sftp)
}

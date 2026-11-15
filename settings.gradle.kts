pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "VELUM-TEGRA-Next"
include(":app")
include(":core:model")
include(":core:domain")
include(":core:runtime")
include(":core:runtime-android")
include(":core:data")
include(":core:secrets")
include(":core:ssh")
include(":core:webpanel")
include(":core:scanner")
include(":core:scanner-android")
include(":core:site")
include(":feature:home")

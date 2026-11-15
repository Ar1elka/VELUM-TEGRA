# Reference draft inventory — Apk.zip

The uploaded draft is intentionally frozen as reference material.

Observed structure:
- 1 Android application module (`:app`).
- 54 Kotlin production files under the main package.
- 30 Kotlin JVM/instrumentation test files.
- 5 foreground services in the manifest.
- Current reference package: `com.velumtegra.xuimobile`.
- Reference version observed: `1.0.30.14.20` / code 69.

Large files that demonstrate why boundaries are being reset rather than patched forward:
- `MainActivity.kt`: ~5033 lines.
- `RealityScannerScreen.kt`: ~1930 lines.
- `XuiManageScreen.kt`: ~1603 lines.
- `XuiInstallerForegroundService.kt`: ~998 lines.
- `XuiInstallerJobManager.kt`: ~959 lines.
- `SshProgrammerSessionStore.kt`: ~800 lines.
- `SecretStore.kt`: ~735 lines.

Functional knowledge to preserve as specifications, not copy blindly:
- Web panel via SSH tunnel.
- Exact SSH host-key pinning.
- Multi-server ownership lessons.
- Installer discovery/install/verify behavior.
- Management lightweight vs deep diagnostics split.
- Recovery verification and transport-loss lessons.
- Lifecycle/uninstall/reinstall verification contracts.
- Reality Scanner foreground/session behavior and export/history features.
- GeoIP updater/resolver behavior.
- Existing real-E2E safety guards and test scenarios.

Build/caches present in the reference archive (`build/`, `.kotlin/`, `.codex-gradle-home/`) are not part of the new source tree and must never be migrated.

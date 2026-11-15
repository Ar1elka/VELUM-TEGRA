# VELUM//TEGRA Next — Privacy Policy Draft

**Status: internal draft only. A public URL and final human/legal review are required before public distribution.**

VELUM//TEGRA Next is an Android administration utility for user-selected infrastructure. The app can store connection records, identifiers, configuration, scan history/results, operation history and credentials needed for explicit user-requested actions. Sensitive credentials are intended to remain protected by the app's local secret-storage boundary rather than being written into project files or release artifacts.

The app can connect to infrastructure selected or configured by the user, including 3x-ui/web-panel endpoints, SSH/SFTP targets, Reality Scanner network targets and Site Deployer destinations. Network traffic therefore goes to endpoints chosen by the user or required by an explicitly started operation.

The current canonical release baseline does not define a public analytics, advertising, crash-reporting or tracking service contract. This draft must not be used to claim that no data is processed: server details, credentials, scan inputs/results and operational diagnostics can be processed locally and can be transmitted to the exact remote systems selected by the user when an operation requires it.

Users should be able to remove app data through Android application-data controls or uninstall. Any external server-side data created by explicit deployment or administration actions remains governed by the selected remote system and is outside an Android-app uninstall.

Before publication, this draft must be reviewed against the final application behavior, the final permission set, the chosen distribution channel's data-safety questions, the support contact, and the final public privacy-policy URL.

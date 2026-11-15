package com.velumtegra.xuimobile.core.model

/**
 * Service actions share the existing installation mutation journal and replay fence.
 * Preserve legacy restart checkpoint names so operations created by older builds can resume.
 */
enum class ExistingInstallationServiceAction {
    START,
    STOP,
    RESTART,
    XRAY_RESTART,
    ENABLE_AUTOSTART,
    DISABLE_AUTOSTART;

    val autostartState: String?
        get() = when (this) {
            ENABLE_AUTOSTART -> "enabled"
            DISABLE_AUTOSTART -> "disabled"
            else -> null
        }

    fun phaseName(restartPhaseName: String): String {
        require(restartPhaseName.startsWith("RESTART_"))
        return if (this == RESTART) restartPhaseName else "SERVICE_" + name + "_" + restartPhaseName.removePrefix("RESTART_")
    }

    companion object {
        fun fromPhaseName(phaseName: String): ExistingInstallationServiceAction =
            entries.firstOrNull { it != RESTART && phaseName.startsWith("SERVICE_" + it.name + "_") }
                ?: RESTART

        fun nextPhaseName(currentPhaseName: String, restartPhaseName: String): String {
            val action = fromPhaseName(currentPhaseName)
            val evidence = if (action == XRAY_RESTART) currentPhaseName.substringAfter('#', "") else ""
            return action.phaseName(restartPhaseName) + if (evidence.isEmpty()) "" else "#$evidence"
        }
    }
}

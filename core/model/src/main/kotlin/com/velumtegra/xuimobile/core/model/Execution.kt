package com.velumtegra.xuimobile.core.model

enum class ConnectivityState {
    ONLINE,
    OFFLINE,
    UNKNOWN,
}

enum class ExecutionState {
    IDLE,
    RUNNING,
    WAITING_FOR_NETWORK,
    RECONNECTING,
    RECONCILING,
    COMPLETED,
    FAILED,
}

enum class InterruptionReason {
    ACTIVITY_RECREATED,
    APP_BACKGROUNDED,
    NETWORK_LOSS,
    PROCESS_DEATH,
    SYSTEM_STOP,
    USER_FORCE_STOP,
    DEVICE_REBOOT,
}

sealed interface CommandCompletion {
    data object ConfirmedSuccess : CommandCompletion
    data class ConfirmedFailure(val reason: String, val exitCode: Int? = null) : CommandCompletion
    data class Unknown(val reason: String) : CommandCompletion
}

enum class RemoteVerificationState {
    VERIFIED,
    UNVERIFIED,
    CONTRADICTED,
}

package com.velumtegra.xuimobile.core.model

import java.time.Instant

/** Only this finite projection may leave the SSH parsing boundary. No remote text fields. */
enum class ServiceLogCategory {
    CONNECTION_REFUSED, TIMEOUT, TLS_ERROR, PERMISSION_DENIED, ADDRESS_IN_USE, OTHER_REDACTED,
}

data class ServiceLogEntry(
    val recordedAt: Instant,
    val priority: Int?,
    val category: ServiceLogCategory,
) {
    init { require(priority == null || priority in 0..7) }
}

data class ServiceLogSnapshot(
    val scope: ManagementScope,
    val entries: List<ServiceLogEntry>,
    val hasOlder: Boolean,
    val observedAt: Instant,
) {
    init { require(entries.size <= 100) }
}

enum class ServiceLogFailure {
    TARGET_NOT_VERIFIED, COMMAND_UNAVAILABLE, COMMAND_FAILED, TRANSPORT_UNCERTAIN,
    OUTPUT_LIMIT, MALFORMED_OUTPUT, INCOMPLETE_ACCESS, INTERNAL_CONTRACT,
}

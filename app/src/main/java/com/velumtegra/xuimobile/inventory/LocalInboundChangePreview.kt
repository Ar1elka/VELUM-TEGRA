package com.velumtegra.xuimobile.inventory

/**
 * Strictly offline proposal validation. This file intentionally has no transport, repository,
 * persistence, URL, credential, or remote-write dependency. The user provides both sides of
 * the comparison manually; they are NOT read or verified against a server.
 */
internal data class LocalInboundChangeInput(
    val inboundId: String,
    val currentPort: String,
    val proposedPort: String,
    val currentlyEnabled: Boolean,
    val proposedEnabled: Boolean,
)

internal enum class LocalInboundChangeIssue {
    INVALID_INBOUND_ID,
    INVALID_CURRENT_PORT,
    INVALID_PROPOSED_PORT,
    NO_CHANGES,
}

internal sealed interface LocalInboundChangeResult {
    data class Invalid(val issue: LocalInboundChangeIssue) : LocalInboundChangeResult
    data class Preview(
        val inboundId: Int,
        val currentPort: Int,
        val proposedPort: Int,
        val currentlyEnabled: Boolean,
        val proposedEnabled: Boolean,
        val portWillChange: Boolean,
        val enabledWillChange: Boolean,
    ) : LocalInboundChangeResult
}

internal object LocalInboundChangePlanner {
    private val idPattern = Regex("[1-9][0-9]{0,9}")
    private val portPattern = Regex("[1-9][0-9]{0,4}")

    fun preview(input: LocalInboundChangeInput): LocalInboundChangeResult {
        val id = input.inboundId.takeIf { idPattern.matches(it) }?.toIntOrNull()
            ?.takeIf { it > 0 }
            ?: return LocalInboundChangeResult.Invalid(LocalInboundChangeIssue.INVALID_INBOUND_ID)
        val current = input.currentPort.takeIf { portPattern.matches(it) }?.toIntOrNull()
            ?.takeIf { it in 1..65535 }
            ?: return LocalInboundChangeResult.Invalid(LocalInboundChangeIssue.INVALID_CURRENT_PORT)
        val proposed = input.proposedPort.takeIf { portPattern.matches(it) }?.toIntOrNull()
            ?.takeIf { it in 1..65535 }
            ?: return LocalInboundChangeResult.Invalid(LocalInboundChangeIssue.INVALID_PROPOSED_PORT)
        val portChange = current != proposed
        val enableChange = input.currentlyEnabled != input.proposedEnabled
        if (!portChange && !enableChange) {
            return LocalInboundChangeResult.Invalid(LocalInboundChangeIssue.NO_CHANGES)
        }
        return LocalInboundChangeResult.Preview(
            inboundId = id, currentPort = current, proposedPort = proposed,
            currentlyEnabled = input.currentlyEnabled, proposedEnabled = input.proposedEnabled,
            portWillChange = portChange, enabledWillChange = enableChange,
        )
    }
}

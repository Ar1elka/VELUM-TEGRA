package com.velumtegra.xuimobile.inventory

/**
 * Extra offline review of a MANUALLY typed list of ports assigned to other inbounds.
 * This review knows nothing about the actual server, listener interfaces, port occupancy,
 * TLS credentials or Xray configuration. It cannot authorize or execute a server change.
 */
internal enum class LocalInboundSafetyIssue {
    INVALID_OTHER_PORTS,
    TOO_MANY_OTHER_PORTS,
    DUPLICATE_OTHER_PORT,
}

internal sealed interface LocalInboundSafetyResult {
    data class Invalid(val issue: LocalInboundSafetyIssue) : LocalInboundSafetyResult
    data class Review(
        val possibleProposedPortCollision: Boolean,
        val possibleBaselineMismatch: Boolean,
        val reversePreview: LocalInboundChangeResult.Preview,
    ) : LocalInboundSafetyResult
}

internal object LocalInboundSafetyReviewer {
    private const val MAX_OTHER_PORTS = 24
    private const val MAX_PORT_TEXT_LENGTH = 256
    private val portPattern = Regex("[1-9][0-9]{0,4}")

    fun review(
        preview: LocalInboundChangeResult.Preview,
        manuallyListedOtherPorts: String,
    ): LocalInboundSafetyResult {
        if (manuallyListedOtherPorts.length > MAX_PORT_TEXT_LENGTH) {
            return LocalInboundSafetyResult.Invalid(LocalInboundSafetyIssue.TOO_MANY_OTHER_PORTS)
        }
        val numbers = if (manuallyListedOtherPorts.isEmpty()) {
            emptyList()
        } else {
            val tokens = manuallyListedOtherPorts.split(',')
            if (tokens.size > MAX_OTHER_PORTS) {
                return LocalInboundSafetyResult.Invalid(LocalInboundSafetyIssue.TOO_MANY_OTHER_PORTS)
            }
            val parsed = ArrayList<Int>(tokens.size)
            for (token in tokens) {
                // Only normal ASCII spaces around each token; no newlines, unicode spaces,
                // signs, zero padding, comments or arbitrary text accepted.
                val cleaned = token.trim(' ')
                val number = cleaned.takeIf { portPattern.matches(it) }?.toIntOrNull()
                    ?.takeIf { it in 1..65535 }
                    ?: return LocalInboundSafetyResult.Invalid(
                        LocalInboundSafetyIssue.INVALID_OTHER_PORTS,
                    )
                parsed.add(number)
            }
            if (parsed.size != parsed.toSet().size) {
                return LocalInboundSafetyResult.Invalid(LocalInboundSafetyIssue.DUPLICATE_OTHER_PORT)
            }
            parsed
        }
        val listed = numbers.toSet()
        val reverse = LocalInboundChangeResult.Preview(
            inboundId = preview.inboundId,
            currentPort = preview.proposedPort,
            proposedPort = preview.currentPort,
            currentlyEnabled = preview.proposedEnabled,
            proposedEnabled = preview.currentlyEnabled,
            portWillChange = preview.portWillChange,
            enabledWillChange = preview.enabledWillChange,
        )
        return LocalInboundSafetyResult.Review(
            possibleProposedPortCollision = preview.portWillChange && preview.proposedPort in listed,
            possibleBaselineMismatch = preview.currentPort in listed,
            reversePreview = reverse,
        )
    }
}

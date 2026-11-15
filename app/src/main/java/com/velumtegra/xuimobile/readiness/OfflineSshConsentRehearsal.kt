package com.velumtegra.xuimobile.readiness

/** An in-memory, time-limited OFFLINE rehearsal, never a transport/session/secret capability. */
data class OfflineSshConsentReceipt internal constructor(
    val marker: String,
    val exactDraft: OfflineSshConnectionDraft,
    val createdAtElapsedMs: Long,
    val expiresAtElapsedMs: Long,
) {
    val permitsNetwork: Boolean get() = false
    val permitsSecretRead: Boolean get() = false
    val permitsSshAuthentication: Boolean get() = false
    val permitsVpsCommands: Boolean get() = false
}

sealed interface OfflineSshConsentResult {
    data class Armed(val receipt: OfflineSshConsentReceipt) : OfflineSshConsentResult
    data object SimulatedOnce : OfflineSshConsentResult
    data class Blocked(val reason: String) : OfflineSshConsentResult
}

/**
 * Ephemeral fail-closed state machine. It is NOT wired to a network adapter, Room, Keystore,
 * SSH authentication or command execution. 'Use' only marks an offline rehearsal consumed.
 */
class OfflineSshConsentRehearsal {
    companion object {
        const val VALIDITY_MS: Long = 60_000L
        private const val DENIED = "Офлайн-согласие отклонено. Проверьте цель, метаданные и подтверждение заново."
    }

    private var outstanding: OfflineSshConsentReceipt? = null
    // Invalidates any local metadata read that was still suspended when consent was cancelled/rearmed.
    private var revision: Long = 0L
    @Synchronized fun revoke() { outstanding = null; revision++ }

    /** Claim BEFORE the suspendable repository read. The receipt cannot be reclaimed/replayed. */
    @Synchronized internal fun takeForFreshRead(receipt: OfflineSshConsentReceipt): Long? {
        val isCurrent = outstanding === receipt
        outstanding = null
        if (!isCurrent) { revision++; return null }
        return revision
    }

    @Synchronized internal fun isFreshReadClaimCurrent(claimRevision: Long): Boolean =
        revision == claimRevision


    @Synchronized fun arm(
        draft: OfflineSshConnectionDraft,
        freshlyRead: LocalSshReadinessResult,
        typedTarget: String,
        acknowledgedOfflineOnly: Boolean,
        nowElapsedMs: Long,
        marker: String,
    ): OfflineSshConsentResult {
        revoke()
        if (!acknowledgedOfflineOnly || marker.isBlank() || marker.length > 128 || nowElapsedMs < 0 ||
            nowElapsedMs > Long.MAX_VALUE - VALIDITY_MS ||
            typedTarget != "${draft.username}@${draft.host}:${draft.port}" ||
            !matches(draft, freshlyRead)) return OfflineSshConsentResult.Blocked(DENIED)
        val receipt = OfflineSshConsentReceipt(marker, draft, nowElapsedMs, nowElapsedMs + VALIDITY_MS)
        outstanding = receipt
        return OfflineSshConsentResult.Armed(receipt)
    }

    @Synchronized fun simulateOneTimeUse(
        receipt: OfflineSshConsentReceipt,
        freshlyRead: LocalSshReadinessResult,
        typedTarget: String,
        acknowledgedOfflineOnly: Boolean,
        nowElapsedMs: Long,
    ): OfflineSshConsentResult {
        val expected = outstanding
        // Every attempt, including a failed one, irreversibly consumes this local rehearsal.
        outstanding = null
        revision++
        if (expected == null || expected !== receipt || !acknowledgedOfflineOnly ||
            nowElapsedMs < receipt.createdAtElapsedMs || nowElapsedMs > receipt.expiresAtElapsedMs ||
            typedTarget != "${receipt.exactDraft.username}@${receipt.exactDraft.host}:${receipt.exactDraft.port}" ||
            !matches(receipt.exactDraft, freshlyRead)) return OfflineSshConsentResult.Blocked(DENIED)
        return OfflineSshConsentResult.SimulatedOnce
    }

    private fun matches(draft: OfflineSshConnectionDraft, latest: LocalSshReadinessResult): Boolean {
        val current = (latest as? LocalSshReadinessResult.MetadataPresent)?.summary ?: return false
        return draft.serverId.isNotBlank() && draft.accessId.isNotBlank() &&
            current.accessId == draft.accessId && current.host == draft.host &&
            current.port == draft.port && current.username == draft.username &&
            current.authLabel == draft.authLabel && current.savedFingerprint == draft.savedFingerprint &&
            current.credentialRefDigest == draft.credentialRefDigest &&
            draft.savedFingerprint.isNotBlank() && !draft.authorizesNetworkAccess &&
            !draft.authorizesSshAuthentication && !draft.authorizesVpsMutation
    }
}

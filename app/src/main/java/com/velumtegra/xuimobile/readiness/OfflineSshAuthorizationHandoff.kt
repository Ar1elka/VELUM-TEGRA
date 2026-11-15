package com.velumtegra.xuimobile.readiness

import kotlinx.coroutines.CancellationException

/** Display-only result: never a transferable authorization, credential or executable SSH capability. */
sealed interface OfflineSshHandoffResult {
    data class Inspected(
        val serverId: String,
        val accessId: String,
        val exactTarget: String,
        val pinnedFingerprint: String,
    ) : OfflineSshHandoffResult {
        val authorizesNetwork: Boolean get() = false
        val authorizesSecretRead: Boolean get() = false
        val authorizesSshSession: Boolean get() = false
        val authorizesVpsCommands: Boolean get() = false
    }

    data class Blocked(val reason: String) : OfflineSshHandoffResult
}

/**
 * Offline-only, fail-closed consumption boundary. No SSH transport, Keystore, secrets repository,
 * socket factory, persisted authorization, callback or command runner is accepted by this API.
 * Every attempt consumes the one-shot rehearsal before any follow-up target check.
 */
class OfflineSshAuthorizationHandoff(private val rehearsal: OfflineSshConsentRehearsal) {
    private fun denied() = OfflineSshHandoffResult.Blocked(
        "Офлайн-передача заблокирована: согласие, SSH-цель или свежие метаданные не совпадают. Создайте новое согласие.",
    )

    /** Legacy synchronous, purely local fixture. Not a network/SSH authorization. */
    fun inspectOnce(
        receipt: OfflineSshConsentReceipt,
        selectedServerId: String,
        selectedAccessId: String,
        freshlyRead: LocalSshReadinessResult,
        typedTarget: String,
        confirmedOfflineOnly: Boolean,
        nowElapsedMs: Long,
    ): OfflineSshHandoffResult {
        val consumption = rehearsal.simulateOneTimeUse(
            receipt, freshlyRead, typedTarget, confirmedOfflineOnly, nowElapsedMs,
        )
        if (consumption !is OfflineSshConsentResult.SimulatedOnce) return denied()
        return inspectMetadata(receipt, selectedServerId, selectedAccessId, freshlyRead,
            typedTarget, confirmedOfflineOnly, nowElapsedMs)
    }

    /**
     * The screen cannot inject a supposedly fresh result: this boundary performs its own exact
     * LOCAL repository read, after irrevocably claiming the in-memory receipt. It NEVER opens SSH.
     * Cancellation and repository failures are fail-closed. Revoking during a suspended read
     * invalidates its result, even when the repository returns the old metadata afterwards.
     */
    suspend fun inspectWithFreshLocalRead(
        receipt: OfflineSshConsentReceipt,
        selectedServerId: String,
        selectedAccessId: String,
        localPort: SshReadinessPort,
        typedTarget: String,
        confirmedOfflineOnly: Boolean,
        elapsedRealtimeMs: () -> Long,
    ): OfflineSshHandoffResult {
        val claimRevision = rehearsal.takeForFreshRead(receipt) ?: return denied()
        val draft = receipt.exactDraft
        if (!confirmedOfflineOnly || selectedServerId.isBlank() || selectedAccessId.isBlank() ||
            selectedServerId != draft.serverId || selectedAccessId != draft.accessId ||
            typedTarget != "${draft.username}@${draft.host}:${draft.port}") return denied()
        val fresh = try {
            localPort.previewExact(selectedServerId, selectedAccessId)
        } catch (cancel: CancellationException) {
            rehearsal.revoke()
            throw cancel
        } catch (_: Exception) {
            return denied()
        }
        val timestamp = try { elapsedRealtimeMs() } catch (cancel: CancellationException) {
            rehearsal.revoke()
            throw cancel
        } catch (_: Exception) {
            return denied()
        }
        if (!rehearsal.isFreshReadClaimCurrent(claimRevision)) return denied()
        val result = inspectMetadata(receipt, selectedServerId, selectedAccessId, fresh,
            typedTarget, confirmedOfflineOnly, timestamp)
        // Defend against revocation from another thread between metadata validation and UI return.
        if (!rehearsal.isFreshReadClaimCurrent(claimRevision)) return denied()
        return result
    }

    private fun inspectMetadata(
        receipt: OfflineSshConsentReceipt,
        selectedServerId: String,
        selectedAccessId: String,
        freshlyRead: LocalSshReadinessResult,
        typedTarget: String,
        confirmedOfflineOnly: Boolean,
        nowElapsedMs: Long,
    ): OfflineSshHandoffResult {
        val draft = receipt.exactDraft
        val summary = (freshlyRead as? LocalSshReadinessResult.MetadataPresent)?.summary ?: return denied()
        if (!confirmedOfflineOnly || nowElapsedMs < receipt.createdAtElapsedMs ||
            nowElapsedMs > receipt.expiresAtElapsedMs ||
            selectedServerId.isBlank() || selectedAccessId.isBlank() ||
            selectedServerId != draft.serverId || selectedAccessId != draft.accessId ||
            summary.accessId != draft.accessId || summary.host != draft.host ||
            summary.port != draft.port || summary.username != draft.username ||
            summary.authLabel != draft.authLabel || summary.savedFingerprint != draft.savedFingerprint ||
            summary.credentialRefDigest != draft.credentialRefDigest ||
            typedTarget != "${draft.username}@${draft.host}:${draft.port}") return denied()
        return OfflineSshHandoffResult.Inspected(
            draft.serverId, draft.accessId, typedTarget, draft.savedFingerprint,
        )
    }
}

package com.velumtegra.xuimobile.readiness

import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult

/** An ephemeral, local-only rehearsal; this is NOT a credential, approval, token or transport capability. */
data class OfflineSshConnectionDraft(
    val serverId: String,
    val accessId: String,
    val host: String,
    val port: Int,
    val username: String,
    val authLabel: String,
    val savedFingerprint: String,
    /** Bound to the local non-secret credential reference, never a decryptable secret. */
    val credentialRefDigest: String = "",
) {
    val authorizesNetworkAccess: Boolean get() = false
    val authorizesSshAuthentication: Boolean get() = false
    val authorizesVpsMutation: Boolean get() = false
}

sealed interface OfflineSshConnectionDraftResult {
    data class Prepared(val draft: OfflineSshConnectionDraft) : OfflineSshConnectionDraftResult
    data class Blocked(val reason: String) : OfflineSshConnectionDraftResult
}

/**
 * Fail-closed offline boundary. A second repository read must return exactly the metadata previously
 * reviewed by the user. This method intentionally accepts neither a SecretStore nor SSH transport.
 */
object OfflineSshConnectionDraftPolicy {
    fun expectedConfirmation(summary: LocalSshAccessSummary): String =
        "${summary.username}@${summary.host}:${summary.port}"

    fun prepare(
        serverId: String,
        accessId: String,
        previouslyReviewed: LocalSshReadinessResult?,
        freshlyRead: LocalSshReadinessResult,
        typedTarget: String,
        acknowledgedNoNetwork: Boolean,
    ): OfflineSshConnectionDraftResult {
        fun deny() = OfflineSshConnectionDraftResult.Blocked(
            "Черновик заблокирован: выбор, параметры SSH или подтверждение не совпадают. Повторите локальную проверку.",
        )
        if (!acknowledgedNoNetwork || serverId.isBlank() || accessId.isBlank()) return deny()
        val previous = (previouslyReviewed as? LocalSshReadinessResult.MetadataPresent)?.summary ?: return deny()
        val current = (freshlyRead as? LocalSshReadinessResult.MetadataPresent)?.summary ?: return deny()
        if (previous != current || previous.accessId != accessId || current.accessId != accessId) return deny()
        if (current.host.isBlank() || current.port !in 1..65535 || current.username.isBlank() ||
            current.authLabel !in setOf("Пароль (ссылка на секрет)", "Приватный ключ (ссылка на секрет)")) return deny()
        if (CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(current.savedFingerprint)) !is HostKeyFingerprintParseResult.Valid) return deny()
        if (typedTarget != expectedConfirmation(current)) return deny()
        return OfflineSshConnectionDraftResult.Prepared(
            OfflineSshConnectionDraft(serverId, accessId, current.host, current.port,
                current.username, current.authLabel, current.savedFingerprint,
                current.credentialRefDigest),
        )
    }
}

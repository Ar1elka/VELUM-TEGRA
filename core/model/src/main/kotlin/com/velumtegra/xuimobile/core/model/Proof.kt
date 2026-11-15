package com.velumtegra.xuimobile.core.model

import java.time.Instant

/** Read-only evidence that an exact known installation was observed through an exact access path. */
data class InstallationProof(
    val id: TargetProofId,
    val installationId: XuiInstallationId,
    val serverId: ServerId,
    val serverAccessId: ServerAccessId,
    val observedIdentity: InstallationIdentity,
    val observedAt: Instant,
    val validUntil: Instant,
) {
    init {
        require(!validUntil.isBefore(observedAt)) { "Proof validity cannot end before observation" }
    }
}

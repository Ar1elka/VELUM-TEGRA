package com.velumtegra.xuimobile.discovery

import com.velumtegra.xuimobile.core.domain.DiscoveryProofAttempt
import com.velumtegra.xuimobile.core.domain.DiscoveryProver
import com.velumtegra.xuimobile.core.model.DiscoveryClassification
import com.velumtegra.xuimobile.core.model.DiscoveryEvidence
import com.velumtegra.xuimobile.core.model.DiscoveryProofId
import com.velumtegra.xuimobile.core.model.DiscoveryProofSignal
import java.util.UUID

/**
 * Ephemeral, non-authorizing read-only structural evidence for a 3x-ui candidate.
 * Does NOT identify a persisted installation or grant any management permission.
 */
data class XuiCandidateIdentityEvidence(
    val serviceUnit: String,
    val binaryPath: String,
    val rootPath: String,
    val databasePath: String,
)

/** Reuses the reviewed Phase5 classifier/prover. No SSH command, persistence or fallback. */
object XuiCandidateIdentityProofPolicy {
    fun project(
        evidence: DiscoveryEvidence,
        classification: DiscoveryClassification,
    ): XuiCandidateIdentityEvidence? {
        if (classification !is DiscoveryClassification.SupportedCandidate) return null
        val attempt = DiscoveryProver.prove(
            evidence, classification, DiscoveryProofId(UUID.randomUUID().toString()),
        )
        if (attempt !is DiscoveryProofAttempt.Proven) return null
        val proof = attempt.proof
        if (proof.scope != evidence.scope || !proof.supportingSignals.containsAll(REQUIRED_SIGNALS)) return null
        val identity = proof.observedIdentity
        return XuiCandidateIdentityEvidence(
            serviceUnit = identity.serviceUnit,
            binaryPath = identity.binaryPath,
            rootPath = identity.rootPath,
            databasePath = identity.databasePath,
        )
    }

    private val REQUIRED_SIGNALS = setOf(
        DiscoveryProofSignal.SERVICE_UNIT,
        DiscoveryProofSignal.BINARY_PATH,
        DiscoveryProofSignal.ROOT_PATH,
        DiscoveryProofSignal.DATABASE_PATH,
    )
}

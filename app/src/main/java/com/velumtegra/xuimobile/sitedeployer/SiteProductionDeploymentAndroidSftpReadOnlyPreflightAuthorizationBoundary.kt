package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPolicy
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import java.security.MessageDigest

/** Phase 11.35 non-network approval for one exact fixture-only read-only SFTP preflight. */
internal object SiteProductionDeploymentAndroidSftpReadOnlyPreflightAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 8_000L
    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        sftpChannelOpenReceipt: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        targetRoot: String,
        stagingRoot: String,
        backupRoot: String,
        expectedTargetEntryNames: List<String>,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft {
        SiteProductionDeploymentAndroidSftpChannelOpenHandoffConsumptionBoundary.validateReceipt(sftpChannelOpenReceipt)
        require(sftpChannelOpenReceipt.singleUseConsumed)
        require(sftpChannelOpenReceipt.requiresSeparateBoundedSftpOperationsBoundary)
        require(serverAccess.id.value == sftpChannelOpenReceipt.serverAccessId)
        require(serverAccess.endpoint.host == sftpChannelOpenReceipt.remoteHostIdentity)
        require(serverAccess.endpoint.host == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST) {
            "Phase 11.35 authorizes only the adb-reverse loopback fixture endpoint"
        }
        require(serverAccess.endpoint.port == sftpChannelOpenReceipt.remotePort)
        require(credentialLease.serverAccessId == sftpChannelOpenReceipt.serverAccessId)
        require(credentialLease.secretReferenceType == sftpChannelOpenReceipt.secretReferenceType)
        require(credentialLease.secretReferenceSha256 == sftpChannelOpenReceipt.secretReferenceSha256)
        val currentSecretType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        require(currentSecretType == sftpChannelOpenReceipt.secretReferenceType)
        require(secretReferenceSha256(serverAccess, currentSecretType) == sftpChannelOpenReceipt.secretReferenceSha256) {
            "Read-only SFTP preflight raw SecretId binding mismatch"
        }
        require(serverAccessBindingSha256(serverAccess, sftpChannelOpenReceipt) == sftpChannelOpenReceipt.serverAccessBindingSha256) {
            "Read-only SFTP preflight ServerAccess binding mismatch"
        }
        require(evaluatedAtEpochMillis >= sftpChannelOpenReceipt.consumedAtEpochMillis)
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS)
        require(canonicalId.matches(authorizationAttemptId))
        val target = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        val staging = SiteRemoteDeployPolicy.prepareTargetRoot(stagingRoot)
        val backup = SiteRemoteDeployPolicy.prepareTargetRoot(backupRoot)
        require(setOf(target, staging, backup).size == 3)
        require(parent(target) == parent(staging) && parent(target) == parent(backup))
        val expected = expectedTargetEntryNames.sorted()
        require(expected.isNotEmpty() && expected.size <= SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(expected.distinct().size == expected.size)
        require(expected.all(::safeEntryName))
        val requestSha = requestSha256(target, staging, backup, expected)
        val expires = minOf(
            safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis),
            sftpChannelOpenReceipt.authorizationExpiresAtEpochMillis,
            credentialLease.authorizationExpiresAtEpochMillis,
        )
        val blockers = buildList {
            if (evaluatedAtEpochMillis > sftpChannelOpenReceipt.authorizationExpiresAtEpochMillis ||
                evaluatedAtEpochMillis > credentialLease.authorizationExpiresAtEpochMillis
            ) add(SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationBlocker(
                "READ_ONLY_PREFLIGHT_CREDENTIAL_WINDOW_EXPIRED", "Credential/SFTP authorization window expired before preflight authorization"))
            if (expires <= evaluatedAtEpochMillis) add(SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationBlocker(
                "NO_SAFE_READ_ONLY_PREFLIGHT_WINDOW", "No positive read-only preflight authorization window remains"))
        }
        val status = if (blockers.isEmpty()) SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationStatus.AWAITING_READ_ONLY_PREFLIGHT_APPROVAL
            else SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationStatus.BLOCKED
        val challenge = sha256("phase11.35-read-only-sftp-preflight\n${sftpChannelOpenReceipt.sftpChannelOpenConsumptionReceiptSha256}\n$requestSha\n$authorizationAttemptId\n$expires\n")
        val base = SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft(
            contractVersion = CONTRACT_VERSION, status = status, authorizationOnly = true,
            fixtureEndpointRequired = true, credentialLeaseMaterialRead = false,
            authorizesSingleReadOnlyPreflightHandoff = false, authorizesMutation = false,
            authorizesCoordinatorInvocation = false, exposesDeployUiAction = false, realVpsAccessAllowed = false,
            requiresExplicitApproval = true, requiresDurableOneShotConsumptionBeforeExecution = true,
            requiresSeparateMutationBoundary = true,
            sftpChannelOpenConsumptionReceiptSha256 = sftpChannelOpenReceipt.sftpChannelOpenConsumptionReceiptSha256,
            serverAccessBindingSha256 = sftpChannelOpenReceipt.serverAccessBindingSha256,
            serverAccessId = sftpChannelOpenReceipt.serverAccessId,
            remoteHostIdentity = sftpChannelOpenReceipt.remoteHostIdentity, remotePort = sftpChannelOpenReceipt.remotePort,
            secretReferenceType = sftpChannelOpenReceipt.secretReferenceType,
            secretReferenceSha256 = sftpChannelOpenReceipt.secretReferenceSha256,
            sftpReadOnlyProbeImplementation = SiteRemoteSftpReadOnlyPreflightProbe::class.java.name,
            targetRoot = target, stagingRoot = staging, backupRoot = backup, expectedTargetEntryNames = expected,
            requestSha256 = requestSha, authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis, authorizationExpiresAtEpochMillis = expires,
            blockers = blockers, approvalChallengeSha256 = challenge, draftSha256 = "",
        )
        return base.copy(draftSha256 = draftSha256(base)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft,
        approval: SiteProductionDeploymentSftpReadOnlyPreflightApproval,
    ): SiteProductionDeploymentSftpReadOnlyPreflightAuthorization {
        validateDraft(draft)
        require(draft.status == SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationStatus.AWAITING_READ_ONLY_PREFLIGHT_APPROVAL)
        require(approval.confirmed && approval.approvalChallengeSha256 == draft.approvalChallengeSha256)
        val base = SiteProductionDeploymentSftpReadOnlyPreflightAuthorization(
            contractVersion = draft.contractVersion,
            status = SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationStatus.AUTHORIZED_FOR_SINGLE_READ_ONLY_PREFLIGHT_HANDOFF,
            fixtureEndpointRequired = true, credentialLeaseMaterialRead = false,
            authorizesSingleReadOnlyPreflightHandoff = true, authorizesMutation = false,
            authorizesCoordinatorInvocation = false, exposesDeployUiAction = false, realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeExecution = true, requiresSeparateMutationBoundary = true,
            sftpChannelOpenConsumptionReceiptSha256 = draft.sftpChannelOpenConsumptionReceiptSha256,
            serverAccessBindingSha256 = draft.serverAccessBindingSha256, serverAccessId = draft.serverAccessId,
            remoteHostIdentity = draft.remoteHostIdentity, remotePort = draft.remotePort,
            secretReferenceType = draft.secretReferenceType, secretReferenceSha256 = draft.secretReferenceSha256,
            sftpReadOnlyProbeImplementation = draft.sftpReadOnlyProbeImplementation,
            targetRoot = draft.targetRoot, stagingRoot = draft.stagingRoot, backupRoot = draft.backupRoot,
            expectedTargetEntryNames = draft.expectedTargetEntryNames, requestSha256 = draft.requestSha256,
            authorizationAttemptId = draft.authorizationAttemptId, evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256, authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base)).also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION && draft.authorizationOnly && draft.fixtureEndpointRequired)
        require(!draft.credentialLeaseMaterialRead && !draft.authorizesSingleReadOnlyPreflightHandoff)
        require(!draft.authorizesMutation && !draft.authorizesCoordinatorInvocation && !draft.exposesDeployUiAction && !draft.realVpsAccessAllowed)
        require(draft.requiresExplicitApproval && draft.requiresDurableOneShotConsumptionBeforeExecution && draft.requiresSeparateMutationBoundary)
        require(draft.remoteHostIdentity == SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.FIXTURE_LOOPBACK_HOST)
        require(draft.remotePort in 1..65535)
        validateHashes(draft.sftpChannelOpenConsumptionReceiptSha256, draft.serverAccessBindingSha256, draft.secretReferenceSha256,
            draft.requestSha256, draft.approvalChallengeSha256, draft.draftSha256)
        require(draft.expectedTargetEntryNames == draft.expectedTargetEntryNames.sorted())
        require(draft.requestSha256 == requestSha256(draft.targetRoot, draft.stagingRoot, draft.backupRoot, draft.expectedTargetEntryNames))
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = "")))
    }

    fun validateAuthorization(a: SiteProductionDeploymentSftpReadOnlyPreflightAuthorization) {
        require(a.contractVersion == CONTRACT_VERSION)
        require(a.status == SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationStatus.AUTHORIZED_FOR_SINGLE_READ_ONLY_PREFLIGHT_HANDOFF)
        require(a.fixtureEndpointRequired && !a.credentialLeaseMaterialRead && a.authorizesSingleReadOnlyPreflightHandoff)
        require(!a.authorizesMutation && !a.authorizesCoordinatorInvocation && !a.exposesDeployUiAction && !a.realVpsAccessAllowed)
        require(a.requiresDurableOneShotConsumptionBeforeExecution && a.requiresSeparateMutationBoundary)
        require(a.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        validateHashes(a.sftpChannelOpenConsumptionReceiptSha256, a.serverAccessBindingSha256, a.secretReferenceSha256,
            a.requestSha256, a.approvalChallengeSha256, a.authorizationSha256)
        require(a.expectedTargetEntryNames == a.expectedTargetEntryNames.sorted())
        require(a.requestSha256 == requestSha256(a.targetRoot, a.stagingRoot, a.backupRoot, a.expectedTargetEntryNames))
        require(a.authorizationSha256 == authorizationSha256(a.copy(authorizationSha256 = "")))
    }

    private fun draftSha256(d: SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft) = sha256(buildString {
        append("contractVersion=").append(d.contractVersion).append('\n'); append("status=").append(d.status.name).append('\n')
        append("sftpReceipt=").append(d.sftpChannelOpenConsumptionReceiptSha256).append('\n'); append("binding=").append(d.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(d.serverAccessId).append('\n'); append("host=").append(d.remoteHostIdentity).append('\n'); append("port=").append(d.remotePort).append('\n')
        append("secretType=").append(d.secretReferenceType).append('\n'); append("secretSha=").append(d.secretReferenceSha256).append('\n')
        append("probe=").append(d.sftpReadOnlyProbeImplementation).append('\n'); append("request=").append(d.requestSha256).append('\n')
        append("attempt=").append(d.authorizationAttemptId).append('\n'); append("evaluatedAt=").append(d.evaluatedAtEpochMillis).append('\n'); append("expiresAt=").append(d.authorizationExpiresAtEpochMillis).append('\n')
        append("blockers=").append(d.blockers.joinToString("|") { "${it.code}:${it.detail}" }).append('\n'); append("challenge=").append(d.approvalChallengeSha256).append('\n')
    })
    private fun authorizationSha256(a: SiteProductionDeploymentSftpReadOnlyPreflightAuthorization) = sha256(buildString {
        append("contractVersion=").append(a.contractVersion).append('\n'); append("status=").append(a.status.name).append('\n')
        append("sftpReceipt=").append(a.sftpChannelOpenConsumptionReceiptSha256).append('\n'); append("binding=").append(a.serverAccessBindingSha256).append('\n')
        append("serverAccessId=").append(a.serverAccessId).append('\n'); append("host=").append(a.remoteHostIdentity).append('\n'); append("port=").append(a.remotePort).append('\n')
        append("secretType=").append(a.secretReferenceType).append('\n'); append("secretSha=").append(a.secretReferenceSha256).append('\n')
        append("probe=").append(a.sftpReadOnlyProbeImplementation).append('\n'); append("request=").append(a.requestSha256).append('\n')
        append("attempt=").append(a.authorizationAttemptId).append('\n'); append("evaluatedAt=").append(a.evaluatedAtEpochMillis).append('\n'); append("expiresAt=").append(a.authorizationExpiresAtEpochMillis).append('\n')
        append("challenge=").append(a.approvalChallengeSha256).append('\n'); append("authorizes=").append(a.authorizesSingleReadOnlyPreflightHandoff).append('\n')
    })

    private fun secretReferenceSha256(serverAccess: ServerAccess, type: String): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("secretReferenceType=").append(type).append('\n')
        append("secretId=").append(serverAccess.auth.secretId.value).append('\n')
    })
    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        receipt: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt,
    ): String = sha256(buildString {
        append("serverAccessId=").append(serverAccess.id.value).append('\n')
        append("serverId=").append(serverAccess.serverId.value).append('\n')
        append("host=").append(serverAccess.endpoint.host).append('\n')
        append("port=").append(serverAccess.endpoint.port).append('\n')
        append("username=").append(serverAccess.username).append('\n')
        append("secretReferenceType=").append(receipt.secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(receipt.secretReferenceSha256).append('\n')
        append("pinnedHostKey=").append(serverAccess.pinnedHostKey.value).append('\n')
    })

    private fun requestSha256(target: String, staging: String, backup: String, expected: List<String>) = sha256(buildString {
        append("target=").append(target).append('\n'); append("staging=").append(staging).append('\n'); append("backup=").append(backup).append('\n')
        expected.forEach { append("entry=").append(it).append('\n') }
    })
    private fun parent(path: String) = path.substringBeforeLast('/').ifBlank { "/" }
    private fun safeEntryName(v: String) = v.isNotBlank() && v != "." && v != ".." && '/' !in v && '\\' !in v && '\u0000' !in v && v.length <= 128
    private fun safeAdd(l: Long, r: Long) = if (Long.MAX_VALUE - l < r) Long.MAX_VALUE else l + r
    private fun validateHashes(vararg values: String) = require(values.all(sha256Pattern::matches)) { "Read-only SFTP preflight hashes must be lowercase SHA-256" }
    private fun sha256(value: String) = MessageDigest.getInstance("SHA-256").digest(value.encodeToByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

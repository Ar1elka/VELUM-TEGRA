package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPolicy
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpReadOnlyPreflightProbe
import java.security.MessageDigest

/**
 * Phase 11.36 non-network admission for a future controlled real-VPS read-only preflight.
 *
 * This boundary only freezes and hashes the exact candidate endpoint, host-key pin, deployment
 * roots and reviewed read-only operation vocabulary. It does not read credential material,
 * resolve credentials, connect SSH, open SFTP, execute the preflight, mutate remote state,
 * invoke the coordinator, expose deploy UI or contact a real VPS.
 */
internal object SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary {
    const val CONTRACT_VERSION: Int = 1

    val EXACT_READ_ONLY_OPERATION_VOCABULARY: List<String> = listOf(
        "LSTAT_TARGET_ROOT",
        "LSTAT_STAGING_ROOT",
        "LSTAT_BACKUP_ROOT",
        "LIST_TARGET_ROOT_BOUNDED",
    )

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        serverAccess: ServerAccess,
        targetRoot: String,
        stagingRoot: String,
        backupRoot: String,
        expectedTargetEntryNames: List<String>,
        admissionAttemptId: String,
        evaluatedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission {
        require(canonicalId.matches(admissionAttemptId)) {
            "Real-VPS read-only preflight admission attempt id is not canonical"
        }
        require(evaluatedAtEpochMillis >= 0L)

        val host = serverAccess.endpoint.host
        require(host.isNotBlank() && host == host.trim()) {
            "Real-VPS read-only preflight host identity must be exact and non-blank"
        }
        require(serverAccess.endpoint.port in 1..65535)
        require(serverAccess.username.isNotBlank() && serverAccess.username == serverAccess.username.trim())

        val pinnedHostKeySha256 = when (
            val parsed = CanonicalHostKeyFingerprint.parse(serverAccess.pinnedHostKey)
        ) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint.asHexSha256()
            is HostKeyFingerprintParseResult.Invalid -> error(parsed.reason)
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        val secretReferenceSha256 = secretReferenceSha256(serverAccess, secretReferenceType)

        val target = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        val staging = SiteRemoteDeployPolicy.prepareTargetRoot(stagingRoot)
        val backup = SiteRemoteDeployPolicy.prepareTargetRoot(backupRoot)
        require(setOf(target, staging, backup).size == 3) {
            "Real-VPS read-only preflight roots must be distinct"
        }
        require(parent(target) == parent(staging) && parent(target) == parent(backup)) {
            "Real-VPS read-only preflight roots must be siblings"
        }

        val expected = expectedTargetEntryNames.sorted()
        require(expected.isNotEmpty() && expected.size <= SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(expected.distinct().size == expected.size)
        require(expected.all(::safeEntryName))

        val nonLoopback = !isLoopbackHost(host)
        val blockers = buildList {
            if (!nonLoopback) {
                add(
                    SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionBlocker(
                        code = "REAL_VPS_ENDPOINT_MUST_NOT_BE_LOOPBACK",
                        detail = "Future real-VPS admission requires an exact non-loopback endpoint identity",
                    ),
                )
            }
        }

        val capabilityProfileSha256 = capabilityProfileSha256()
        val bindingSha256 = serverAccessBindingSha256(
            serverAccess = serverAccess,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            pinnedHostKeySha256 = pinnedHostKeySha256,
        )
        val requestSha256 = requestSha256(
            target = target,
            staging = staging,
            backup = backup,
            expected = expected,
        )
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus
                .ADMITTED_FOR_SEPARATE_EXPLICIT_READ_ONLY_PREFLIGHT_AUTHORIZATION
        } else {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus.BLOCKED
        }

        val base = SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
            contractVersion = CONTRACT_VERSION,
            status = status,
            admissionOnly = true,
            productionNetworkTouched = false,
            credentialLeaseMaterialRead = false,
            hostKeyPinVerifiedAgainstRemote = false,
            authorizesNetworkAccess = false,
            authorizesCredentialResolution = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesReadOnlyPreflightExecution = false,
            authorizesMutation = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitSeparateAuthorization = true,
            requiresLiveRemoteHostKeyVerification = true,
            requiresSeparateCredentialResolutionBoundary = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            requiresSeparateReadOnlyExecutionBoundary = true,
            requiresSeparateMutationBoundary = true,
            candidateEndpointIsNonLoopback = nonLoopback,
            serverAccessId = serverAccess.id.value,
            serverId = serverAccess.serverId.value,
            remoteHostIdentity = host,
            remotePort = serverAccess.endpoint.port,
            sshUsername = serverAccess.username,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            pinnedHostKeySha256 = pinnedHostKeySha256,
            serverAccessBindingSha256 = bindingSha256,
            targetRoot = target,
            stagingRoot = staging,
            backupRoot = backup,
            expectedTargetEntryNames = expected,
            approvedReadOnlyOperationVocabulary = EXACT_READ_ONLY_OPERATION_VOCABULARY,
            maxTargetEntries = SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES,
            sftpReadOnlyProbeImplementation = SiteRemoteSftpReadOnlyPreflightProbe::class.java.name,
            capabilityProfileSha256 = capabilityProfileSha256,
            requestSha256 = requestSha256,
            admissionAttemptId = admissionAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            blockers = blockers,
            admissionSha256 = "",
        )
        return base.copy(admissionSha256 = admissionSha256(base)).also(::validate)
    }

    fun validate(admission: SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission) {
        require(admission.contractVersion == CONTRACT_VERSION)
        require(admission.admissionOnly)
        require(!admission.productionNetworkTouched)
        require(!admission.credentialLeaseMaterialRead)
        require(!admission.hostKeyPinVerifiedAgainstRemote)
        require(!admission.authorizesNetworkAccess)
        require(!admission.authorizesCredentialResolution)
        require(!admission.authorizesSshSessionAcquisition)
        require(!admission.authorizesSftpChannelOpen)
        require(!admission.authorizesReadOnlyPreflightExecution)
        require(!admission.authorizesMutation)
        require(!admission.authorizesCoordinatorInvocation)
        require(!admission.exposesDeployUiAction)
        require(!admission.realVpsAccessAllowed)
        require(admission.requiresExplicitSeparateAuthorization)
        require(admission.requiresLiveRemoteHostKeyVerification)
        require(admission.requiresSeparateCredentialResolutionBoundary)
        require(admission.requiresSeparateSshSessionAcquisitionBoundary)
        require(admission.requiresSeparateSftpChannelOpenBoundary)
        require(admission.requiresSeparateReadOnlyExecutionBoundary)
        require(admission.requiresSeparateMutationBoundary)
        require(admission.remotePort in 1..65535)
        require(admission.expectedTargetEntryNames == admission.expectedTargetEntryNames.sorted())
        require(admission.expectedTargetEntryNames.isNotEmpty())
        require(admission.expectedTargetEntryNames.size <= SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(admission.expectedTargetEntryNames.all(::safeEntryName))
        require(admission.approvedReadOnlyOperationVocabulary == EXACT_READ_ONLY_OPERATION_VOCABULARY)
        require(admission.maxTargetEntries == SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES)
        require(admission.sftpReadOnlyProbeImplementation == SiteRemoteSftpReadOnlyPreflightProbe::class.java.name)
        require(admission.capabilityProfileSha256 == capabilityProfileSha256())
        require(
            admission.requestSha256 == requestSha256(
                target = admission.targetRoot,
                staging = admission.stagingRoot,
                backup = admission.backupRoot,
                expected = admission.expectedTargetEntryNames,
            ),
        )
        val expectedStatus = if (admission.blockers.isEmpty()) {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus
                .ADMITTED_FOR_SEPARATE_EXPLICIT_READ_ONLY_PREFLIGHT_AUTHORIZATION
        } else {
            SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus.BLOCKED
        }
        require(admission.status == expectedStatus)
        if (admission.status ==
            SiteProductionDeploymentRealVpsReadOnlyPreflightAdmissionStatus
                .ADMITTED_FOR_SEPARATE_EXPLICIT_READ_ONLY_PREFLIGHT_AUTHORIZATION
        ) {
            require(admission.candidateEndpointIsNonLoopback)
        }
        validateHashes(
            admission.secretReferenceSha256,
            admission.pinnedHostKeySha256,
            admission.serverAccessBindingSha256,
            admission.capabilityProfileSha256,
            admission.requestSha256,
            admission.admissionSha256,
        )
        require(admission.admissionSha256 == admissionSha256(admission.copy(admissionSha256 = "")))
    }

    private fun secretReferenceSha256(serverAccess: ServerAccess, type: String): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccess.id.value).append('\n')
            append("secretReferenceType=").append(type).append('\n')
            append("secretId=").append(serverAccess.auth.secretId.value).append('\n')
        },
    )

    private fun serverAccessBindingSha256(
        serverAccess: ServerAccess,
        secretReferenceType: String,
        secretReferenceSha256: String,
        pinnedHostKeySha256: String,
    ): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccess.id.value).append('\n')
            append("serverId=").append(serverAccess.serverId.value).append('\n')
            append("host=").append(serverAccess.endpoint.host).append('\n')
            append("port=").append(serverAccess.endpoint.port).append('\n')
            append("username=").append(serverAccess.username).append('\n')
            append("secretReferenceType=").append(secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
            append("pinnedHostKeySha256=").append(pinnedHostKeySha256).append('\n')
        },
    )

    private fun capabilityProfileSha256(): String = sha256(
        buildString {
            append("probe=").append(SiteRemoteSftpReadOnlyPreflightProbe::class.java.name).append('\n')
            append("maxTargetEntries=").append(SiteRemoteSftpReadOnlyPreflightProbe.MAX_TARGET_ENTRIES).append('\n')
            EXACT_READ_ONLY_OPERATION_VOCABULARY.forEach { append("operation=").append(it).append('\n') }
        },
    )

    private fun requestSha256(
        target: String,
        staging: String,
        backup: String,
        expected: List<String>,
    ): String = sha256(
        buildString {
            append("target=").append(target).append('\n')
            append("staging=").append(staging).append('\n')
            append("backup=").append(backup).append('\n')
            expected.forEach { append("entry=").append(it).append('\n') }
            EXACT_READ_ONLY_OPERATION_VOCABULARY.forEach { append("operation=").append(it).append('\n') }
        },
    )

    private fun admissionSha256(
        admission: SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(admission.contractVersion).append('\n')
            append("status=").append(admission.status.name).append('\n')
            append("admissionOnly=").append(admission.admissionOnly).append('\n')
            append("productionNetworkTouched=").append(admission.productionNetworkTouched).append('\n')
            append("credentialLeaseMaterialRead=").append(admission.credentialLeaseMaterialRead).append('\n')
            append("hostKeyPinVerifiedAgainstRemote=").append(admission.hostKeyPinVerifiedAgainstRemote).append('\n')
            append("authorizesNetworkAccess=").append(admission.authorizesNetworkAccess).append('\n')
            append("authorizesCredentialResolution=").append(admission.authorizesCredentialResolution).append('\n')
            append("authorizesSshSessionAcquisition=").append(admission.authorizesSshSessionAcquisition).append('\n')
            append("authorizesSftpChannelOpen=").append(admission.authorizesSftpChannelOpen).append('\n')
            append("authorizesReadOnlyPreflightExecution=").append(admission.authorizesReadOnlyPreflightExecution).append('\n')
            append("authorizesMutation=").append(admission.authorizesMutation).append('\n')
            append("authorizesCoordinatorInvocation=").append(admission.authorizesCoordinatorInvocation).append('\n')
            append("exposesDeployUiAction=").append(admission.exposesDeployUiAction).append('\n')
            append("realVpsAccessAllowed=").append(admission.realVpsAccessAllowed).append('\n')
            append("requiresExplicitSeparateAuthorization=").append(admission.requiresExplicitSeparateAuthorization).append('\n')
            append("requiresLiveRemoteHostKeyVerification=").append(admission.requiresLiveRemoteHostKeyVerification).append('\n')
            append("serverAccessBindingSha256=").append(admission.serverAccessBindingSha256).append('\n')
            append("targetRoot=").append(admission.targetRoot).append('\n')
            append("stagingRoot=").append(admission.stagingRoot).append('\n')
            append("backupRoot=").append(admission.backupRoot).append('\n')
            append("requestSha256=").append(admission.requestSha256).append('\n')
            append("admissionAttemptId=").append(admission.admissionAttemptId).append('\n')
            append("evaluatedAtEpochMillis=").append(admission.evaluatedAtEpochMillis).append('\n')
            admission.blockers.forEach { blocker ->
                append("blocker=").append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
        },
    )

    private fun isLoopbackHost(host: String): Boolean {
        val normalized = host.lowercase()
        return normalized == "localhost" ||
            normalized == "::1" ||
            normalized == "[::1]" ||
            normalized.startsWith("127.")
    }

    private fun parent(path: String): String = path.substringBeforeLast('/').ifBlank { "/" }

    private fun safeEntryName(value: String): Boolean =
        value.isNotBlank() &&
            value != "." &&
            value != ".." &&
            '/' !in value &&
            '\\' !in value &&
            '\u0000' !in value &&
            value.length <= 128

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256Pattern::matches)) {
            "Real-VPS read-only preflight admission hashes must be lowercase SHA-256"
        }
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

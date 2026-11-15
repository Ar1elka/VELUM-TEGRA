package com.velumtegra.xuimobile.sitedeployer

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import java.security.MessageDigest

/**
 * Phase 11.28 non-executing credential-resolution authorization boundary.
 *
 * It binds the exact Phase 11.27 admission to the exact ServerAccess secret reference without
 * reading credential material. Explicit approval can authorize only one future credential-resolution
 * handoff. A later phase must durably consume that handoff before any SecretStore read is permitted.
 */
internal object SiteProductionDeploymentAndroidCredentialResolutionAuthorizationBoundary {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_AUTHORIZATION_LIFETIME_MILLIS: Long = 20_000L

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val canonicalId = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")

    fun prepare(
        admission: SiteProductionDeploymentTransportAcquisitionExecutionAdmission,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentCredentialResolutionAuthorizationDraft {
        SiteProductionDeploymentAndroidTransportAcquisitionExecutionAdmissionBoundary.validate(admission)
        require(
            admission.status ==
                SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus
                    .ADMITTED_FOR_SEPARATE_TRANSPORT_ACQUISITION_EXECUTION_BOUNDARY,
        ) { "Blocked transport-acquisition execution admission cannot authorize credential resolution" }
        require(admission.requiresSeparateCredentialResolutionBoundary) {
            "Transport-acquisition execution admission does not require this credential boundary"
        }
        require(serverAccess.id.value == admission.serverAccessId) {
            "Credential-resolution authorization ServerAccess mismatch"
        }
        require(canonicalId.matches(authorizationAttemptId)) {
            "Credential-resolution authorization attempt id must be a canonical 8..128 character identifier"
        }
        require(evaluatedAtEpochMillis >= admission.evaluatedAtEpochMillis) {
            "Credential-resolution authorization cannot predate execution admission"
        }
        require(requestedAuthorizationLifetimeMillis in 1L..MAX_AUTHORIZATION_LIFETIME_MILLIS) {
            "Credential-resolution authorization lifetime must be within 1..$MAX_AUTHORIZATION_LIFETIME_MILLIS ms"
        }

        val secretReferenceType = when (serverAccess.auth) {
            is SshAuthRef.Password -> "password"
            is SshAuthRef.PrivateKey -> "private-key"
        }
        val secretReferenceSha256 = secretReferenceSha256(
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretIdValue = serverAccess.auth.secretId.value,
        )
        val credentialStoreImplementation = AndroidKeystoreSecretStore::class.java.name
        val requestedExpiry = safeAdd(evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis)
        val authorizationExpiresAt = minOf(requestedExpiry, admission.authorizationExpiresAtEpochMillis)
        val blockers = buildList {
            if (evaluatedAtEpochMillis > admission.authorizationExpiresAtEpochMillis) {
                add(
                    SiteProductionDeploymentCredentialResolutionAuthorizationBlocker(
                        code = "CREDENTIAL_RESOLUTION_ADMISSION_WINDOW_EXPIRED",
                        detail = "Transport-acquisition execution admission expired before credential authorization",
                    ),
                )
            }
            if (authorizationExpiresAt <= evaluatedAtEpochMillis) {
                add(
                    SiteProductionDeploymentCredentialResolutionAuthorizationBlocker(
                        code = "NO_SAFE_CREDENTIAL_RESOLUTION_WINDOW",
                        detail = "No positive credential-resolution authorization window remains",
                    ),
                )
            }
        }
        val status = if (blockers.isEmpty()) {
            SiteProductionDeploymentCredentialResolutionAuthorizationStatus
                .AWAITING_CREDENTIAL_RESOLUTION_APPROVAL
        } else {
            SiteProductionDeploymentCredentialResolutionAuthorizationStatus.BLOCKED
        }

        val request = SiteProductionDeploymentCredentialResolutionAuthorizationRequest(
            admission = admission,
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            credentialStoreImplementation = credentialStoreImplementation,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )
        val challenge = approvalChallengeSha256(request, authorizationExpiresAt)

        val base = SiteProductionDeploymentCredentialResolutionAuthorizationDraft(
            contractVersion = CONTRACT_VERSION,
            status = status,
            authorizationOnly = true,
            secretStoreReadPerformed = false,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesCredentialResolution = false,
            authorizesSingleCredentialResolutionHandoff = false,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresExplicitApproval = true,
            requiresDurableOneShotConsumptionBeforeCredentialResolution = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            admissionSha256 = admission.admissionSha256,
            consumptionReceiptSha256 = admission.consumptionReceiptSha256,
            serverIdentitySha256 = admission.serverIdentitySha256,
            serverAccessId = serverAccess.id.value,
            secretReferenceType = secretReferenceType,
            secretReferenceSha256 = secretReferenceSha256,
            credentialStoreImplementation = credentialStoreImplementation,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = authorizationExpiresAt,
            blockers = blockers,
            approvalChallengeSha256 = challenge,
            draftSha256 = "",
        )
        return base.copy(draftSha256 = draftSha256(base)).also(::validateDraft)
    }

    fun authorize(
        draft: SiteProductionDeploymentCredentialResolutionAuthorizationDraft,
        approval: SiteProductionDeploymentCredentialResolutionApproval,
    ): SiteProductionDeploymentCredentialResolutionAuthorization {
        validateDraft(draft)
        require(
            draft.status ==
                SiteProductionDeploymentCredentialResolutionAuthorizationStatus
                    .AWAITING_CREDENTIAL_RESOLUTION_APPROVAL,
        ) { "Blocked credential-resolution authorization draft cannot be approved" }
        require(approval.confirmed) { "Credential-resolution handoff requires explicit confirmation" }
        require(sha256.matches(approval.approvalChallengeSha256)) {
            "Credential-resolution approval challenge SHA-256 is invalid"
        }
        require(approval.approvalChallengeSha256 == draft.approvalChallengeSha256) {
            "Credential-resolution approval is stale or bound to a different draft"
        }

        val base = SiteProductionDeploymentCredentialResolutionAuthorization(
            contractVersion = CONTRACT_VERSION,
            status =
                SiteProductionDeploymentCredentialResolutionAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_CREDENTIAL_RESOLUTION_HANDOFF,
            authorizationOnly = true,
            secretStoreReadPerformed = false,
            productionTransportEnabled = false,
            authorizesTransport = false,
            authorizesCredentialResolution = false,
            authorizesSingleCredentialResolutionHandoff = true,
            authorizesSshSessionAcquisition = false,
            authorizesSftpChannelOpen = false,
            authorizesCoordinatorInvocation = false,
            exposesDeployUiAction = false,
            realVpsAccessAllowed = false,
            requiresDurableOneShotConsumptionBeforeCredentialResolution = true,
            requiresSeparateSshSessionAcquisitionBoundary = true,
            requiresSeparateSftpChannelOpenBoundary = true,
            admissionSha256 = draft.admissionSha256,
            consumptionReceiptSha256 = draft.consumptionReceiptSha256,
            serverIdentitySha256 = draft.serverIdentitySha256,
            serverAccessId = draft.serverAccessId,
            secretReferenceType = draft.secretReferenceType,
            secretReferenceSha256 = draft.secretReferenceSha256,
            credentialStoreImplementation = draft.credentialStoreImplementation,
            authorizationAttemptId = draft.authorizationAttemptId,
            evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
            authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            approvalChallengeSha256 = draft.approvalChallengeSha256,
            authorizationSha256 = "",
        )
        return base.copy(authorizationSha256 = authorizationSha256(base)).also(::validateAuthorization)
    }

    fun validateDraft(draft: SiteProductionDeploymentCredentialResolutionAuthorizationDraft) {
        require(draft.contractVersion == CONTRACT_VERSION) { "Unsupported credential-resolution authorization contract" }
        require(draft.authorizationOnly) { "Credential-resolution draft must remain authorization-only" }
        require(!draft.secretStoreReadPerformed) { "Credential-resolution draft must not read SecretStore" }
        require(!draft.productionTransportEnabled) { "Credential-resolution draft must not enable transport" }
        require(!draft.authorizesTransport) { "Credential-resolution draft must not authorize transport" }
        require(!draft.authorizesCredentialResolution) { "Credential-resolution draft must not authorize actual secret read" }
        require(!draft.authorizesSingleCredentialResolutionHandoff) {
            "Unapproved credential-resolution draft must not authorize future handoff"
        }
        require(!draft.authorizesSshSessionAcquisition) { "Credential-resolution draft must not authorize SSH" }
        require(!draft.authorizesSftpChannelOpen) { "Credential-resolution draft must not authorize SFTP" }
        require(!draft.authorizesCoordinatorInvocation) { "Credential-resolution draft must not authorize coordinator" }
        require(!draft.exposesDeployUiAction) { "Credential-resolution draft must not expose deploy UI" }
        require(!draft.realVpsAccessAllowed) { "Credential-resolution draft must not permit real VPS access" }
        require(draft.requiresExplicitApproval) { "Credential-resolution draft must require explicit approval" }
        require(draft.requiresDurableOneShotConsumptionBeforeCredentialResolution) {
            "Durable consume-once must remain mandatory before credential resolution"
        }
        require(draft.requiresSeparateSshSessionAcquisitionBoundary) {
            "Separate SSH-session boundary must remain mandatory"
        }
        require(draft.requiresSeparateSftpChannelOpenBoundary) {
            "Separate SFTP-channel boundary must remain mandatory"
        }
        require(canonicalId.matches(draft.authorizationAttemptId)) {
            "Credential-resolution authorization attempt id is invalid"
        }
        require(draft.secretReferenceType == "password" || draft.secretReferenceType == "private-key") {
            "Credential-resolution secret reference type is invalid"
        }
        require(draft.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name) {
            "Credential store implementation identity drifted"
        }
        val expectedStatus = if (draft.blockers.isEmpty()) {
            SiteProductionDeploymentCredentialResolutionAuthorizationStatus.AWAITING_CREDENTIAL_RESOLUTION_APPROVAL
        } else {
            SiteProductionDeploymentCredentialResolutionAuthorizationStatus.BLOCKED
        }
        require(draft.status == expectedStatus) { "Credential-resolution draft status does not match blockers" }
        validateHashes(
            draft.admissionSha256,
            draft.consumptionReceiptSha256,
            draft.serverIdentitySha256,
            draft.secretReferenceSha256,
            draft.approvalChallengeSha256,
            draft.draftSha256,
        )
        require(draft.draftSha256 == draftSha256(draft.copy(draftSha256 = ""))) {
            "Credential-resolution authorization draft SHA-256 mismatch"
        }
    }

    fun validateAuthorization(
        authorization: SiteProductionDeploymentCredentialResolutionAuthorization,
    ) {
        require(authorization.contractVersion == CONTRACT_VERSION) {
            "Unsupported credential-resolution authorization contract"
        }
        require(
            authorization.status ==
                SiteProductionDeploymentCredentialResolutionAuthorizationStatus
                    .AUTHORIZED_FOR_SINGLE_CREDENTIAL_RESOLUTION_HANDOFF,
        ) { "Credential-resolution authorization has invalid status" }
        require(authorization.authorizationOnly) { "Credential-resolution authorization must remain authorization-only" }
        require(!authorization.secretStoreReadPerformed) { "Credential-resolution authorization must not read SecretStore" }
        require(!authorization.productionTransportEnabled) { "Credential-resolution authorization must not enable transport" }
        require(!authorization.authorizesTransport) { "Credential-resolution authorization must not authorize transport" }
        require(!authorization.authorizesCredentialResolution) {
            "Credential-resolution authorization must not authorize actual secret read"
        }
        require(authorization.authorizesSingleCredentialResolutionHandoff) {
            "Credential-resolution authorization must authorize exactly one future resolution handoff"
        }
        require(!authorization.authorizesSshSessionAcquisition) {
            "Credential-resolution authorization must not authorize SSH acquisition"
        }
        require(!authorization.authorizesSftpChannelOpen) {
            "Credential-resolution authorization must not authorize SFTP open"
        }
        require(!authorization.authorizesCoordinatorInvocation) {
            "Credential-resolution authorization must not authorize coordinator invocation"
        }
        require(!authorization.exposesDeployUiAction) { "Credential-resolution authorization must not expose deploy UI" }
        require(!authorization.realVpsAccessAllowed) { "Credential-resolution authorization must not permit real VPS access" }
        require(authorization.requiresDurableOneShotConsumptionBeforeCredentialResolution) {
            "Credential-resolution authorization must require durable consume-once"
        }
        require(authorization.requiresSeparateSshSessionAcquisitionBoundary) {
            "Separate SSH-session boundary must remain mandatory"
        }
        require(authorization.requiresSeparateSftpChannelOpenBoundary) {
            "Separate SFTP-channel boundary must remain mandatory"
        }
        require(authorization.authorizationExpiresAtEpochMillis > authorization.evaluatedAtEpochMillis) {
            "Credential-resolution authorization has no positive validity window"
        }
        require(authorization.credentialStoreImplementation == AndroidKeystoreSecretStore::class.java.name) {
            "Credential store implementation identity drifted"
        }
        validateHashes(
            authorization.admissionSha256,
            authorization.consumptionReceiptSha256,
            authorization.serverIdentitySha256,
            authorization.secretReferenceSha256,
            authorization.approvalChallengeSha256,
            authorization.authorizationSha256,
        )
        require(
            authorization.authorizationSha256 ==
                authorizationSha256(authorization.copy(authorizationSha256 = "")),
        ) { "Credential-resolution authorization SHA-256 mismatch" }
    }

    private fun secretReferenceSha256(
        serverAccessId: String,
        secretReferenceType: String,
        secretIdValue: String,
    ): String = sha256(
        buildString {
            append("serverAccessId=").append(serverAccessId).append('\n')
            append("secretReferenceType=").append(secretReferenceType).append('\n')
            append("secretId=").append(secretIdValue).append('\n')
        },
    )

    private fun approvalChallengeSha256(
        request: SiteProductionDeploymentCredentialResolutionAuthorizationRequest,
        authorizationExpiresAtEpochMillis: Long,
    ): String = sha256(
        buildString {
            append("contractVersion=").append(CONTRACT_VERSION).append('\n')
            append("admissionSha256=").append(request.admission.admissionSha256).append('\n')
            append("consumptionReceiptSha256=").append(request.admission.consumptionReceiptSha256).append('\n')
            append("serverIdentitySha256=").append(request.admission.serverIdentitySha256).append('\n')
            append("serverAccessId=").append(request.serverAccessId).append('\n')
            append("secretReferenceType=").append(request.secretReferenceType).append('\n')
            append("secretReferenceSha256=").append(request.secretReferenceSha256).append('\n')
            append("credentialStoreImplementation=").append(request.credentialStoreImplementation).append('\n')
            append("authorizationAttemptId=").append(request.authorizationAttemptId).append('\n')
            append("evaluatedAtEpochMillis=").append(request.evaluatedAtEpochMillis).append('\n')
            append("authorizationExpiresAtEpochMillis=").append(authorizationExpiresAtEpochMillis).append('\n')
        },
    )

    private fun draftSha256(
        draft: SiteProductionDeploymentCredentialResolutionAuthorizationDraft,
    ): String = sha256(
        buildString {
            appendCommon(
                authorizationOnly = draft.authorizationOnly,
                secretStoreReadPerformed = draft.secretStoreReadPerformed,
                productionTransportEnabled = draft.productionTransportEnabled,
                authorizesTransport = draft.authorizesTransport,
                authorizesCredentialResolution = draft.authorizesCredentialResolution,
                authorizesSingleCredentialResolutionHandoff = draft.authorizesSingleCredentialResolutionHandoff,
                authorizesSshSessionAcquisition = draft.authorizesSshSessionAcquisition,
                authorizesSftpChannelOpen = draft.authorizesSftpChannelOpen,
                authorizesCoordinatorInvocation = draft.authorizesCoordinatorInvocation,
                exposesDeployUiAction = draft.exposesDeployUiAction,
                realVpsAccessAllowed = draft.realVpsAccessAllowed,
                requiresSeparateSshSessionAcquisitionBoundary = draft.requiresSeparateSshSessionAcquisitionBoundary,
                requiresSeparateSftpChannelOpenBoundary = draft.requiresSeparateSftpChannelOpenBoundary,
                admissionSha256 = draft.admissionSha256,
                consumptionReceiptSha256 = draft.consumptionReceiptSha256,
                serverIdentitySha256 = draft.serverIdentitySha256,
                serverAccessId = draft.serverAccessId,
                secretReferenceType = draft.secretReferenceType,
                secretReferenceSha256 = draft.secretReferenceSha256,
                credentialStoreImplementation = draft.credentialStoreImplementation,
                authorizationAttemptId = draft.authorizationAttemptId,
                evaluatedAtEpochMillis = draft.evaluatedAtEpochMillis,
                authorizationExpiresAtEpochMillis = draft.authorizationExpiresAtEpochMillis,
            )
            append("status=").append(draft.status.name).append('\n')
            append("requiresExplicitApproval=").append(draft.requiresExplicitApproval).append('\n')
            append("requiresDurableOneShotConsumptionBeforeCredentialResolution=")
                .append(draft.requiresDurableOneShotConsumptionBeforeCredentialResolution).append('\n')
            draft.blockers.forEach { blocker ->
                append("blocker=").append(blocker.code).append('\u0000').append(blocker.detail).append('\n')
            }
            append("approvalChallengeSha256=").append(draft.approvalChallengeSha256).append('\n')
        },
    )

    private fun authorizationSha256(
        authorization: SiteProductionDeploymentCredentialResolutionAuthorization,
    ): String = sha256(
        buildString {
            appendCommon(
                authorizationOnly = authorization.authorizationOnly,
                secretStoreReadPerformed = authorization.secretStoreReadPerformed,
                productionTransportEnabled = authorization.productionTransportEnabled,
                authorizesTransport = authorization.authorizesTransport,
                authorizesCredentialResolution = authorization.authorizesCredentialResolution,
                authorizesSingleCredentialResolutionHandoff =
                    authorization.authorizesSingleCredentialResolutionHandoff,
                authorizesSshSessionAcquisition = authorization.authorizesSshSessionAcquisition,
                authorizesSftpChannelOpen = authorization.authorizesSftpChannelOpen,
                authorizesCoordinatorInvocation = authorization.authorizesCoordinatorInvocation,
                exposesDeployUiAction = authorization.exposesDeployUiAction,
                realVpsAccessAllowed = authorization.realVpsAccessAllowed,
                requiresSeparateSshSessionAcquisitionBoundary =
                    authorization.requiresSeparateSshSessionAcquisitionBoundary,
                requiresSeparateSftpChannelOpenBoundary =
                    authorization.requiresSeparateSftpChannelOpenBoundary,
                admissionSha256 = authorization.admissionSha256,
                consumptionReceiptSha256 = authorization.consumptionReceiptSha256,
                serverIdentitySha256 = authorization.serverIdentitySha256,
                serverAccessId = authorization.serverAccessId,
                secretReferenceType = authorization.secretReferenceType,
                secretReferenceSha256 = authorization.secretReferenceSha256,
                credentialStoreImplementation = authorization.credentialStoreImplementation,
                authorizationAttemptId = authorization.authorizationAttemptId,
                evaluatedAtEpochMillis = authorization.evaluatedAtEpochMillis,
                authorizationExpiresAtEpochMillis = authorization.authorizationExpiresAtEpochMillis,
            )
            append("status=").append(authorization.status.name).append('\n')
            append("requiresDurableOneShotConsumptionBeforeCredentialResolution=")
                .append(authorization.requiresDurableOneShotConsumptionBeforeCredentialResolution).append('\n')
            append("approvalChallengeSha256=").append(authorization.approvalChallengeSha256).append('\n')
        },
    )

    private fun StringBuilder.appendCommon(
        authorizationOnly: Boolean,
        secretStoreReadPerformed: Boolean,
        productionTransportEnabled: Boolean,
        authorizesTransport: Boolean,
        authorizesCredentialResolution: Boolean,
        authorizesSingleCredentialResolutionHandoff: Boolean,
        authorizesSshSessionAcquisition: Boolean,
        authorizesSftpChannelOpen: Boolean,
        authorizesCoordinatorInvocation: Boolean,
        exposesDeployUiAction: Boolean,
        realVpsAccessAllowed: Boolean,
        requiresSeparateSshSessionAcquisitionBoundary: Boolean,
        requiresSeparateSftpChannelOpenBoundary: Boolean,
        admissionSha256: String,
        consumptionReceiptSha256: String,
        serverIdentitySha256: String,
        serverAccessId: String,
        secretReferenceType: String,
        secretReferenceSha256: String,
        credentialStoreImplementation: String,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        authorizationExpiresAtEpochMillis: Long,
    ) {
        append("contractVersion=").append(CONTRACT_VERSION).append('\n')
        append("authorizationOnly=").append(authorizationOnly).append('\n')
        append("secretStoreReadPerformed=").append(secretStoreReadPerformed).append('\n')
        append("productionTransportEnabled=").append(productionTransportEnabled).append('\n')
        append("authorizesTransport=").append(authorizesTransport).append('\n')
        append("authorizesCredentialResolution=").append(authorizesCredentialResolution).append('\n')
        append("authorizesSingleCredentialResolutionHandoff=")
            .append(authorizesSingleCredentialResolutionHandoff).append('\n')
        append("authorizesSshSessionAcquisition=").append(authorizesSshSessionAcquisition).append('\n')
        append("authorizesSftpChannelOpen=").append(authorizesSftpChannelOpen).append('\n')
        append("authorizesCoordinatorInvocation=").append(authorizesCoordinatorInvocation).append('\n')
        append("exposesDeployUiAction=").append(exposesDeployUiAction).append('\n')
        append("realVpsAccessAllowed=").append(realVpsAccessAllowed).append('\n')
        append("requiresSeparateSshSessionAcquisitionBoundary=")
            .append(requiresSeparateSshSessionAcquisitionBoundary).append('\n')
        append("requiresSeparateSftpChannelOpenBoundary=")
            .append(requiresSeparateSftpChannelOpenBoundary).append('\n')
        append("admissionSha256=").append(admissionSha256).append('\n')
        append("consumptionReceiptSha256=").append(consumptionReceiptSha256).append('\n')
        append("serverIdentitySha256=").append(serverIdentitySha256).append('\n')
        append("serverAccessId=").append(serverAccessId).append('\n')
        append("secretReferenceType=").append(secretReferenceType).append('\n')
        append("secretReferenceSha256=").append(secretReferenceSha256).append('\n')
        append("credentialStoreImplementation=").append(credentialStoreImplementation).append('\n')
        append("authorizationAttemptId=").append(authorizationAttemptId).append('\n')
        append("evaluatedAtEpochMillis=").append(evaluatedAtEpochMillis).append('\n')
        append("authorizationExpiresAtEpochMillis=").append(authorizationExpiresAtEpochMillis).append('\n')
    }

    private fun validateHashes(vararg values: String) {
        require(values.all(sha256::matches)) {
            "Credential-resolution authorization hashes must be lowercase SHA-256"
        }
    }

    private fun safeAdd(left: Long, right: Long): Long {
        require(right >= 0L) { "Credential-resolution authorization lifetime must be non-negative" }
        require(left <= Long.MAX_VALUE - right) { "Credential-resolution authorization expiry overflows Long" }
        return left + right
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.encodeToByteArray())
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
}

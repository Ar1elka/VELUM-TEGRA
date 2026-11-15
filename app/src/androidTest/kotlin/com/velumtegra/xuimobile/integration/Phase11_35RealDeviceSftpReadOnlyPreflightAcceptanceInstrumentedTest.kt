package com.velumtegra.xuimobile.integration

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.site.*
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.ssh.CanonicalHostKeyFingerprint
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpPrimitiveFactory
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSshDeploymentRuntime
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.sitedeployer.*
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Arrays
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class Phase11_35RealDeviceSftpReadOnlyPreflightAcceptanceInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val application: VelumTegraApplication
        get() = context.applicationContext as VelumTegraApplication

    @Test
    fun fixtureSftpReadOnlyPreflightUsesOnlyLstatAndListWithoutMutation() {
        runBlocking {
        val nonce = requiredRunNonce()
        val fixture = fixture(
            nonce = nonce,
            fixturePort = requiredFixturePort(),
            fixtureFingerprint = requiredFixtureFingerprint(),
        )
        val secretStore = AndroidKeystoreSecretStore(context)
        val fixtureSecretBytes = FIXTURE_PASSWORD.encodeToByteArray()
        val fixtureMaterial = SecretMaterial.fromBytes(fixtureSecretBytes)
        try {
            assertEquals(SecretCreateResult.Created, secretStore.create(fixture.secretId, fixtureMaterial))
        } finally {
            fixtureMaterial.close()
        }
        try {
        val request = SiteProductionDeploymentTransportAcquisitionAuthorizationRequest(
            readinessRequest = fixture.readinessRequest,
            readinessDescriptor = fixture.readinessDescriptor,
            authorizationAttemptId = "phase11_35_$nonce",
            evaluatedAtEpochMillis = fixture.authorizationEvaluatedAt,
            requestedAuthorizationLifetimeMillis = 30_000L,
        )
        val draft = application.siteProductionDeploymentTransportAcquisitionAuthorizationDraft(request)
        val authorization = application.siteProductionDeploymentTransportAcquisitionAuthorization(
            draft = draft,
            approval = SiteProductionDeploymentTransportAcquisitionApproval(
                approvalChallengeSha256 = draft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        val before = application.siteProductionDeploymentReplayFence.snapshot()
        val consumedAt = authorization.evaluatedAtEpochMillis + 1L
        val receipt = application.siteProductionDeploymentConsumeTransportAcquisitionHandoff(
            authorization = authorization,
            consumedAtEpochMillis = consumedAt,
        )
        SiteProductionDeploymentAndroidTransportAcquisitionHandoffConsumptionBoundary.validateReceipt(receipt)

        assertEquals(
            SiteProductionDeploymentTransportAcquisitionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_ACQUISITION_BOUNDARY,
            receipt.status,
        )
        assertTrue(receipt.singleUseConsumed)
        assertFalse(receipt.productionTransportEnabled)
        assertFalse(receipt.authorizesTransport)
        assertFalse(receipt.authorizesTransportAcquisitionExecution)
        assertFalse(receipt.authorizesCredentialResolution)
        assertFalse(receipt.authorizesSshSessionAcquisition)
        assertFalse(receipt.authorizesSftpChannelOpen)
        assertFalse(receipt.authorizesCoordinatorInvocation)
        assertFalse(receipt.exposesDeployUiAction)
        assertFalse(receipt.realVpsAccessAllowed)
        assertTrue(receipt.requiresSeparateAcquisitionExecutionBoundary)
        assertEquals(authorization.authorizationSha256, receipt.authorizationSha256)
        assertEquals(authorization.readinessSha256, receipt.readinessSha256)
        assertFalse(receipt.toString().contains(fixture.secretId.value))

        val beforeAdmission = application.siteProductionDeploymentReplayFence.snapshot()
        val admission = application.siteProductionDeploymentTransportAcquisitionExecutionAdmission(
            receipt = receipt,
            composition = fixture.composition,
            serverAccess = fixture.serverAccess,
            evaluatedAtEpochMillis = receipt.consumedAtEpochMillis + 1L,
        )
        SiteProductionDeploymentAndroidTransportAcquisitionExecutionAdmissionBoundary.validate(admission)
        assertEquals(
            SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus
                .ADMITTED_FOR_SEPARATE_TRANSPORT_ACQUISITION_EXECUTION_BOUNDARY,
            admission.status,
        )
        assertTrue(admission.admissionOnly)
        assertTrue(admission.durableHandoffConsumed)
        assertFalse(admission.productionTransportEnabled)
        assertFalse(admission.authorizesTransport)
        assertFalse(admission.authorizesTransportAcquisitionExecution)
        assertFalse(admission.authorizesCredentialResolution)
        assertFalse(admission.authorizesSshSessionAcquisition)
        assertFalse(admission.authorizesSftpChannelOpen)
        assertFalse(admission.authorizesCoordinatorInvocation)
        assertFalse(admission.exposesDeployUiAction)
        assertFalse(admission.realVpsAccessAllowed)
        assertTrue(admission.requiresSeparateCredentialResolutionBoundary)
        assertTrue(admission.requiresSeparateSshSessionAcquisitionBoundary)
        assertTrue(admission.requiresSeparateSftpChannelOpenBoundary)
        assertEquals(receipt.consumptionReceiptSha256, admission.consumptionReceiptSha256)
        assertEquals(fixture.composition.descriptorSha256, admission.compositionDescriptorSha256)
        assertEquals(fixture.composition.serverIdentitySha256, admission.serverIdentitySha256)
        assertEquals(
            OperationRuntimeCoordinator::class.java.name,
            admission.runtimeCoordinatorImplementation,
        )
        assertEquals(
            JschSshConnectionFactory::class.java.name,
            admission.sshConnectionFactoryImplementation,
        )
        assertEquals(
            ExactSessionRegistry::class.java.name,
            admission.exactSessionRegistryImplementation,
        )
        assertEquals(
            SiteRemoteSshDeploymentRuntime::class.java.name,
            admission.deploymentRuntimeImplementation,
        )
        assertEquals(
            SiteRemoteSftpPrimitiveFactory::class.java.name,
            admission.sftpPrimitiveFactoryImplementation,
        )
        assertEquals(
            SiteRemoteSftpPrimitiveFactory.CAPABILITIES.implementationId,
            admission.boundedSftpImplementationId,
        )
        assertFalse(admission.toString().contains(fixture.secretId.value))

        val afterAdmission = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(beforeAdmission, afterAdmission)

        val credentialDraft = application.siteProductionDeploymentCredentialResolutionAuthorizationDraft(
            admission = admission,
            serverAccess = fixture.serverAccess,
            authorizationAttemptId = "phase11_35_credential_$nonce",
            evaluatedAtEpochMillis = admission.evaluatedAtEpochMillis + 1L,
            requestedAuthorizationLifetimeMillis = 20_000L,
        )
        val credentialDraftAgain = application.siteProductionDeploymentCredentialResolutionAuthorizationDraft(
            admission = admission,
            serverAccess = fixture.serverAccess,
            authorizationAttemptId = "phase11_35_credential_$nonce",
            evaluatedAtEpochMillis = admission.evaluatedAtEpochMillis + 1L,
            requestedAuthorizationLifetimeMillis = 20_000L,
        )
        SiteProductionDeploymentAndroidCredentialResolutionAuthorizationBoundary.validateDraft(credentialDraft)
        assertEquals(credentialDraft, credentialDraftAgain)
        assertEquals(
            SiteProductionDeploymentCredentialResolutionAuthorizationStatus
                .AWAITING_CREDENTIAL_RESOLUTION_APPROVAL,
            credentialDraft.status,
        )
        assertTrue(credentialDraft.authorizationOnly)
        assertFalse(credentialDraft.secretStoreReadPerformed)
        assertFalse(credentialDraft.productionTransportEnabled)
        assertFalse(credentialDraft.authorizesTransport)
        assertFalse(credentialDraft.authorizesCredentialResolution)
        assertFalse(credentialDraft.authorizesSingleCredentialResolutionHandoff)
        assertFalse(credentialDraft.authorizesSshSessionAcquisition)
        assertFalse(credentialDraft.authorizesSftpChannelOpen)
        assertFalse(credentialDraft.authorizesCoordinatorInvocation)
        assertFalse(credentialDraft.exposesDeployUiAction)
        assertFalse(credentialDraft.realVpsAccessAllowed)
        assertTrue(credentialDraft.requiresExplicitApproval)
        assertTrue(credentialDraft.requiresDurableOneShotConsumptionBeforeCredentialResolution)
        assertTrue(credentialDraft.requiresSeparateSshSessionAcquisitionBoundary)
        assertTrue(credentialDraft.requiresSeparateSftpChannelOpenBoundary)
        assertEquals(admission.admissionSha256, credentialDraft.admissionSha256)
        assertEquals(admission.serverAccessId, credentialDraft.serverAccessId)
        assertEquals("password", credentialDraft.secretReferenceType)
        assertEquals(
            com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore::class.java.name,
            credentialDraft.credentialStoreImplementation,
        )
        assertFalse(credentialDraft.toString().contains(fixture.secretId.value))
        assertEquals(64, credentialDraft.secretReferenceSha256.length)

        val credentialAuthorization = application.siteProductionDeploymentCredentialResolutionAuthorization(
            draft = credentialDraft,
            approval = SiteProductionDeploymentCredentialResolutionApproval(
                approvalChallengeSha256 = credentialDraft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        SiteProductionDeploymentAndroidCredentialResolutionAuthorizationBoundary
            .validateAuthorization(credentialAuthorization)
        assertEquals(
            SiteProductionDeploymentCredentialResolutionAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_CREDENTIAL_RESOLUTION_HANDOFF,
            credentialAuthorization.status,
        )
        assertTrue(credentialAuthorization.authorizationOnly)
        assertFalse(credentialAuthorization.secretStoreReadPerformed)
        assertFalse(credentialAuthorization.authorizesCredentialResolution)
        assertTrue(credentialAuthorization.authorizesSingleCredentialResolutionHandoff)
        assertFalse(credentialAuthorization.authorizesSshSessionAcquisition)
        assertFalse(credentialAuthorization.authorizesSftpChannelOpen)
        assertFalse(credentialAuthorization.authorizesCoordinatorInvocation)
        assertFalse(credentialAuthorization.realVpsAccessAllowed)
        assertTrue(credentialAuthorization.requiresDurableOneShotConsumptionBeforeCredentialResolution)
        assertEquals(
            credentialDraft.secretReferenceSha256,
            credentialAuthorization.secretReferenceSha256,
        )
        assertFalse(credentialAuthorization.toString().contains(fixture.secretId.value))

        val beforeCredentialConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        val credentialConsumedAt = credentialAuthorization.evaluatedAtEpochMillis + 1L
        val credentialReceipt = application.siteProductionDeploymentConsumeCredentialResolutionHandoff(
            authorization = credentialAuthorization,
            consumedAtEpochMillis = credentialConsumedAt,
        )
        SiteProductionDeploymentAndroidCredentialResolutionHandoffConsumptionBoundary
            .validateReceipt(credentialReceipt)
        assertEquals(
            SiteProductionDeploymentCredentialResolutionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_CREDENTIAL_RESOLUTION_EXECUTION_BOUNDARY,
            credentialReceipt.status,
        )
        assertTrue(credentialReceipt.singleUseConsumed)
        assertTrue(credentialReceipt.credentialReferenceBound)
        assertFalse(credentialReceipt.secretStoreReadPerformed)
        assertFalse(credentialReceipt.productionTransportEnabled)
        assertFalse(credentialReceipt.authorizesTransport)
        assertFalse(credentialReceipt.authorizesCredentialResolution)
        assertFalse(credentialReceipt.authorizesSshSessionAcquisition)
        assertFalse(credentialReceipt.authorizesSftpChannelOpen)
        assertFalse(credentialReceipt.authorizesCoordinatorInvocation)
        assertFalse(credentialReceipt.exposesDeployUiAction)
        assertFalse(credentialReceipt.realVpsAccessAllowed)
        assertTrue(credentialReceipt.requiresSeparateCredentialResolutionExecutionBoundary)
        assertTrue(credentialReceipt.requiresSeparateSshSessionAcquisitionBoundary)
        assertTrue(credentialReceipt.requiresSeparateSftpChannelOpenBoundary)
        assertEquals(credentialAuthorization.authorizationSha256, credentialReceipt.authorizationSha256)
        assertEquals(credentialAuthorization.admissionSha256, credentialReceipt.admissionSha256)
        assertEquals(
            credentialAuthorization.secretReferenceSha256,
            credentialReceipt.secretReferenceSha256,
        )
        assertEquals(
            credentialAuthorization.credentialStoreImplementation,
            credentialReceipt.credentialStoreImplementation,
        )
        assertFalse(credentialReceipt.toString().contains(fixture.secretId.value))

        val afterCredentialConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            beforeCredentialConsumption.credentialResolutionHandoffAuthorizationMarkerCount + 1,
            afterCredentialConsumption.credentialResolutionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            beforeCredentialConsumption.runtimeMutationPermitMarkerCount,
            afterCredentialConsumption.runtimeMutationPermitMarkerCount,
        )
        assertEquals(
            beforeCredentialConsumption.coordinatorInvocationAuthorizationMarkerCount,
            afterCredentialConsumption.coordinatorInvocationAuthorizationMarkerCount,
        )
        assertEquals(
            beforeCredentialConsumption.transportAcquisitionHandoffAuthorizationMarkerCount,
            afterCredentialConsumption.transportAcquisitionHandoffAuthorizationMarkerCount,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                credentialAuthorization.authorizationSha256,
            ),
        )

        val reconstructedCredentialFence = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructedCredentialFence.hasConsumed(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_HANDOFF_AUTHORIZATION,
                credentialAuthorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructedCredentialFence.credentialResolutionHandoffConsumptionPort()
                .consumeOnce(credentialAuthorization.authorizationSha256),
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeCredentialResolutionHandoff(
                authorization = credentialAuthorization,
                consumedAtEpochMillis = credentialConsumedAt + 1L,
            )
        }

        val afterCredentialConsumptionReplayChecks =
            application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(afterCredentialConsumption, afterCredentialConsumptionReplayChecks)

        val beforeCredentialResolutionExecution =
            application.siteProductionDeploymentReplayFence.snapshot()
        val resolvedAt = credentialReceipt.consumedAtEpochMillis + 1L
        val resolution = application.siteProductionDeploymentResolveCredentialOnce(
            receipt = credentialReceipt,
            composition = fixture.composition,
            serverAccess = fixture.serverAccess,
            resolvedAtEpochMillis = resolvedAt,
        )
        assertTrue(resolution is SiteProductionDeploymentCredentialResolutionExecutionResult.Resolved)
        val resolved =
            resolution as SiteProductionDeploymentCredentialResolutionExecutionResult.Resolved
        SiteProductionDeploymentAndroidCredentialResolutionExecutionBoundary.validateProof(resolved.proof)
        assertEquals(
            SiteProductionDeploymentCredentialResolutionExecutionStatus.RESOLVED_TO_EPHEMERAL_LEASE,
            resolved.proof.status,
        )
        assertTrue(resolved.proof.durableHandoffConsumed)
        assertTrue(resolved.proof.executionReceiptConsumed)
        assertTrue(resolved.proof.secretStoreReadPerformed)
        assertFalse(resolved.proof.credentialMaterialPersisted)
        assertFalse(resolved.proof.productionTransportEnabled)
        assertFalse(resolved.proof.authorizesTransport)
        assertFalse(resolved.proof.authorizesSshSessionAcquisition)
        assertFalse(resolved.proof.authorizesSftpChannelOpen)
        assertFalse(resolved.proof.authorizesCoordinatorInvocation)
        assertFalse(resolved.proof.exposesDeployUiAction)
        assertFalse(resolved.proof.realVpsAccessAllowed)
        assertTrue(resolved.proof.requiresSeparateSshSessionAcquisitionBoundary)
        assertTrue(resolved.proof.requiresSeparateSftpChannelOpenBoundary)
        assertEquals(
            credentialReceipt.credentialResolutionConsumptionReceiptSha256,
            resolved.proof.credentialResolutionConsumptionReceiptSha256,
        )
        assertEquals(credentialReceipt.secretReferenceSha256, resolved.proof.secretReferenceSha256)
        assertEquals(fixture.composition.descriptorSha256, resolved.proof.compositionDescriptorSha256)
        assertEquals(AndroidKeystoreSecretStore::class.java.name, resolved.proof.credentialStoreImplementation)
        assertFalse(resolved.proof.toString().contains(fixture.secretId.value))
        assertFalse(resolved.lease.toString().contains(String(fixtureSecretBytes)))

        val beforeSshAuthorization = application.siteProductionDeploymentReplayFence.snapshot()
        val sshDraft = application.siteProductionDeploymentSshSessionAcquisitionAuthorizationDraft(
            resolutionProof = resolved.proof,
            credentialLease = resolved.lease,
            composition = fixture.composition,
            serverAccess = fixture.serverAccess,
            authorizationAttemptId = "phase11_35_ssh_$nonce",
            evaluatedAtEpochMillis = resolvedAt + 1L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        SiteProductionDeploymentAndroidSshSessionAcquisitionAuthorizationBoundary.validateDraft(sshDraft)
        assertEquals(
            SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus
                .AWAITING_SSH_SESSION_ACQUISITION_APPROVAL,
            sshDraft.status,
        )
        assertTrue(sshDraft.authorizationOnly)
        assertFalse(sshDraft.credentialLeaseMaterialRead)
        assertFalse(sshDraft.productionTransportEnabled)
        assertFalse(sshDraft.authorizesTransport)
        assertFalse(sshDraft.authorizesSshSessionAcquisition)
        assertFalse(sshDraft.authorizesSingleSshSessionAcquisitionHandoff)
        assertFalse(sshDraft.authorizesSftpChannelOpen)
        assertFalse(sshDraft.authorizesCoordinatorInvocation)
        assertFalse(sshDraft.exposesDeployUiAction)
        assertFalse(sshDraft.realVpsAccessAllowed)
        assertTrue(sshDraft.requiresExplicitApproval)
        assertTrue(sshDraft.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition)
        assertTrue(sshDraft.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        assertTrue(sshDraft.requiresSeparateSftpChannelOpenBoundary)
        assertEquals(resolved.proof.resolutionProofSha256, sshDraft.resolutionProofSha256)
        assertEquals(fixture.serverAccess.id.value, sshDraft.serverAccessId)
        assertEquals(fixture.composition.runtimeIdentity.runtimeSessionId, sshDraft.runtimeSessionId)
        assertEquals(fixture.serverAccess.endpoint.host, sshDraft.remoteHostIdentity)
        assertEquals(JschSshConnectionFactory::class.java.name, sshDraft.sshConnectionFactoryImplementation)
        assertEquals(ExactSessionRegistry::class.java.name, sshDraft.exactSessionRegistryImplementation)
        assertFalse(sshDraft.toString().contains(fixture.secretId.value))
        assertFalse(sshDraft.toString().contains(String(fixtureSecretBytes)))

        val wrongApproval = runCatching {
            application.siteProductionDeploymentSshSessionAcquisitionAuthorization(
                draft = sshDraft,
                approval = SiteProductionDeploymentSshSessionAcquisitionApproval(
                    approvalChallengeSha256 = "0".repeat(64),
                    confirmed = true,
                ),
            )
        }
        assertTrue(wrongApproval.isFailure)

        val sshAuthorization = application.siteProductionDeploymentSshSessionAcquisitionAuthorization(
            draft = sshDraft,
            approval = SiteProductionDeploymentSshSessionAcquisitionApproval(
                approvalChallengeSha256 = sshDraft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        SiteProductionDeploymentAndroidSshSessionAcquisitionAuthorizationBoundary
            .validateAuthorization(sshAuthorization)
        assertEquals(
            SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus
                .AUTHORIZED_FOR_SINGLE_SSH_SESSION_ACQUISITION_HANDOFF,
            sshAuthorization.status,
        )
        assertTrue(sshAuthorization.authorizationOnly)
        assertFalse(sshAuthorization.credentialLeaseMaterialRead)
        assertFalse(sshAuthorization.productionTransportEnabled)
        assertFalse(sshAuthorization.authorizesTransport)
        assertFalse(sshAuthorization.authorizesSshSessionAcquisition)
        assertTrue(sshAuthorization.authorizesSingleSshSessionAcquisitionHandoff)
        assertFalse(sshAuthorization.authorizesSftpChannelOpen)
        assertFalse(sshAuthorization.authorizesCoordinatorInvocation)
        assertFalse(sshAuthorization.exposesDeployUiAction)
        assertFalse(sshAuthorization.realVpsAccessAllowed)
        assertTrue(sshAuthorization.requiresDurableOneShotConsumptionBeforeSshSessionAcquisition)
        assertTrue(sshAuthorization.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        assertTrue(sshAuthorization.requiresSeparateSftpChannelOpenBoundary)
        assertEquals(resolved.proof.resolutionProofSha256, sshAuthorization.resolutionProofSha256)
        assertEquals(JschSshConnectionFactory::class.java.name, sshAuthorization.sshConnectionFactoryImplementation)
        assertEquals(ExactSessionRegistry::class.java.name, sshAuthorization.exactSessionRegistryImplementation)
        assertFalse(sshAuthorization.toString().contains(fixture.secretId.value))
        assertFalse(sshAuthorization.toString().contains(String(fixtureSecretBytes)))
        assertEquals(
            beforeSshAuthorization,
            application.siteProductionDeploymentReplayFence.snapshot(),
        )

        val beforeSshConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        val sshConsumedAt = sshAuthorization.evaluatedAtEpochMillis + 2L
        val sshReceipt = application.siteProductionDeploymentConsumeSshSessionAcquisitionHandoff(
            authorization = sshAuthorization,
            consumedAtEpochMillis = sshConsumedAt,
        )
        SiteProductionDeploymentAndroidSshSessionAcquisitionHandoffConsumptionBoundary
            .validateReceipt(sshReceipt)
        assertEquals(
            SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_SSH_SESSION_ACQUISITION_EXECUTION_BOUNDARY,
            sshReceipt.status,
        )
        assertTrue(sshReceipt.singleUseConsumed)
        assertFalse(sshReceipt.credentialLeaseMaterialRead)
        assertFalse(sshReceipt.productionTransportEnabled)
        assertFalse(sshReceipt.authorizesTransport)
        assertFalse(sshReceipt.authorizesSshSessionAcquisition)
        assertFalse(sshReceipt.authorizesSftpChannelOpen)
        assertFalse(sshReceipt.authorizesCoordinatorInvocation)
        assertFalse(sshReceipt.exposesDeployUiAction)
        assertFalse(sshReceipt.realVpsAccessAllowed)
        assertTrue(sshReceipt.requiresSeparateSshSessionAcquisitionExecutionBoundary)
        assertTrue(sshReceipt.requiresSeparateSftpChannelOpenBoundary)
        assertEquals(sshAuthorization.authorizationSha256, sshReceipt.authorizationSha256)
        assertEquals(resolved.proof.resolutionProofSha256, sshReceipt.resolutionProofSha256)
        assertEquals(fixture.serverAccess.id.value, sshReceipt.serverAccessId)
        assertEquals(JschSshConnectionFactory::class.java.name, sshReceipt.sshConnectionFactoryImplementation)
        assertEquals(ExactSessionRegistry::class.java.name, sshReceipt.exactSessionRegistryImplementation)
        assertFalse(sshReceipt.toString().contains(fixture.secretId.value))
        assertFalse(sshReceipt.toString().contains(String(fixtureSecretBytes)))

        val afterSshConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            beforeSshConsumption.sshSessionAcquisitionHandoffAuthorizationMarkerCount + 1,
            afterSshConsumption.sshSessionAcquisitionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            beforeSshConsumption.credentialResolutionExecutionReceiptMarkerCount,
            afterSshConsumption.credentialResolutionExecutionReceiptMarkerCount,
        )
        assertEquals(
            beforeSshConsumption.credentialResolutionHandoffAuthorizationMarkerCount,
            afterSshConsumption.credentialResolutionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            beforeSshConsumption.transportAcquisitionHandoffAuthorizationMarkerCount,
            afterSshConsumption.transportAcquisitionHandoffAuthorizationMarkerCount,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                sshAuthorization.authorizationSha256,
            ),
        )

        val reconstructedSshFence = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructedSshFence.hasConsumed(
                SiteProductionDeploymentReplayScope.SSH_SESSION_ACQUISITION_HANDOFF_AUTHORIZATION,
                sshAuthorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructedSshFence.sshSessionAcquisitionHandoffConsumptionPort()
                .consumeOnce(sshAuthorization.authorizationSha256),
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeSshSessionAcquisitionHandoff(
                authorization = sshAuthorization,
                consumedAtEpochMillis = sshConsumedAt + 1L,
            )
        }
        assertEquals(
            afterSshConsumption,
            application.siteProductionDeploymentReplayFence.snapshot(),
        )

        val staleSshDraft = application.siteProductionDeploymentSshSessionAcquisitionAuthorizationDraft(
            resolutionProof = resolved.proof,
            credentialLease = resolved.lease,
            composition = fixture.composition,
            serverAccess = fixture.serverAccess,
            authorizationAttemptId = "phase11_35_ssh_stale_$nonce",
            evaluatedAtEpochMillis = resolved.proof.authorizationExpiresAtEpochMillis + 1L,
            requestedAuthorizationLifetimeMillis = 10_000L,
        )
        assertEquals(
            SiteProductionDeploymentSshSessionAcquisitionAuthorizationStatus.BLOCKED,
            staleSshDraft.status,
        )
        assertTrue(
            staleSshDraft.blockers.any { it.code == "SSH_SESSION_CREDENTIAL_WINDOW_EXPIRED" },
        )
        assertFalse(staleSshDraft.authorizesSingleSshSessionAcquisitionHandoff)

        val sftpDraft = application.siteProductionDeploymentSftpChannelOpenAuthorizationDraft(
            sshReceipt = sshReceipt,
            credentialLease = resolved.lease,
            serverAccess = fixture.serverAccess,
            authorizationAttemptId = "phase11_35_sftp_auth_$nonce",
            evaluatedAtEpochMillis = sshReceipt.consumedAtEpochMillis + 1L,
            requestedAuthorizationLifetimeMillis = 8_000L,
        )
        SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.validateDraft(sftpDraft)
        assertEquals(
            SiteProductionDeploymentSftpChannelOpenAuthorizationStatus.AWAITING_SFTP_CHANNEL_OPEN_APPROVAL,
            sftpDraft.status,
        )
        assertTrue(sftpDraft.authorizationOnly)
        assertTrue(sftpDraft.fixtureEndpointRequired)
        assertFalse(sftpDraft.credentialLeaseMaterialRead)
        assertFalse(sftpDraft.authorizesSingleSftpChannelOpenHandoff)
        assertFalse(sftpDraft.authorizesCoordinatorInvocation)
        assertFalse(sftpDraft.exposesDeployUiAction)
        assertFalse(sftpDraft.realVpsAccessAllowed)
        assertTrue(sftpDraft.requiresExplicitApproval)
        assertTrue(sftpDraft.requiresDurableOneShotConsumptionBeforeExecution)
        assertTrue(sftpDraft.requiresSeparateSftpChannelOpenExecutionBoundary)
        assertTrue(sftpDraft.requiresSeparateBoundedSftpOperationsBoundary)
        assertTrue(sftpDraft.requiresSeparateCoordinatorInvocationBoundary)

        val sftpAuthorization = application.siteProductionDeploymentSftpChannelOpenAuthorization(
            draft = sftpDraft,
            approval = SiteProductionDeploymentSftpChannelOpenApproval(
                approvalChallengeSha256 = sftpDraft.approvalChallengeSha256,
                confirmed = true,
            ),
        )
        SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.validateAuthorization(sftpAuthorization)
        assertEquals(
            SiteProductionDeploymentSftpChannelOpenAuthorizationStatus.AUTHORIZED_FOR_SINGLE_SFTP_CHANNEL_OPEN_HANDOFF,
            sftpAuthorization.status,
        )
        assertTrue(sftpAuthorization.authorizesSingleSftpChannelOpenHandoff)
        assertFalse(sftpAuthorization.authorizesCoordinatorInvocation)
        assertFalse(sftpAuthorization.realVpsAccessAllowed)

        val beforeSftpConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        val sftpReceipt = application.siteProductionDeploymentConsumeSftpChannelOpenHandoff(
            authorization = sftpAuthorization,
            consumedAtEpochMillis = sftpAuthorization.evaluatedAtEpochMillis + 1L,
        )
        SiteProductionDeploymentAndroidSftpChannelOpenHandoffConsumptionBoundary.validateReceipt(sftpReceipt)
        assertEquals(
            SiteProductionDeploymentSftpChannelOpenHandoffConsumptionStatus
                .DURABLY_CONSUMED_AWAITING_SEPARATE_SFTP_CHANNEL_OPEN_EXECUTION_BOUNDARY,
            sftpReceipt.status,
        )
        assertTrue(sftpReceipt.singleUseConsumed)
        assertFalse(sftpReceipt.credentialLeaseMaterialRead)
        assertFalse(sftpReceipt.authorizesSftpChannelOpen)
        assertFalse(sftpReceipt.authorizesCoordinatorInvocation)
        assertFalse(sftpReceipt.exposesDeployUiAction)
        assertFalse(sftpReceipt.realVpsAccessAllowed)
        val afterSftpConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            beforeSftpConsumption.sftpChannelOpenHandoffAuthorizationMarkerCount + 1,
            afterSftpConsumption.sftpChannelOpenHandoffAuthorizationMarkerCount,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                sftpAuthorization.authorizationSha256,
            ),
        )
        val replaySftpConsumption = runCatching {
            application.siteProductionDeploymentConsumeSftpChannelOpenHandoff(
                authorization = sftpAuthorization,
                consumedAtEpochMillis = sftpAuthorization.evaluatedAtEpochMillis + 2L,
            )
        }
        assertTrue(replaySftpConsumption.isFailure)
        assertEquals(afterSftpConsumption, application.siteProductionDeploymentReplayFence.snapshot())

        val preflightDraft = application.siteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft(
            sftpChannelOpenReceipt = sftpReceipt,
            credentialLease = resolved.lease,
            serverAccess = fixture.serverAccess,
            targetRoot = "/phase11-35-target",
            stagingRoot = "/phase11-35-staging",
            backupRoot = "/phase11-35-backup",
            expectedTargetEntryNames = listOf("index.html", "manifest.txt"),
            authorizationAttemptId = "phase11_35_preflight_auth_$nonce",
            evaluatedAtEpochMillis = sftpReceipt.consumedAtEpochMillis + 1L,
            requestedAuthorizationLifetimeMillis = 6_000L,
        )
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightAuthorizationBoundary.validateDraft(preflightDraft)
        assertEquals(SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationStatus.AWAITING_READ_ONLY_PREFLIGHT_APPROVAL, preflightDraft.status)
        assertFalse(preflightDraft.credentialLeaseMaterialRead)
        assertFalse(preflightDraft.authorizesMutation)
        assertFalse(preflightDraft.authorizesCoordinatorInvocation)
        assertFalse(preflightDraft.realVpsAccessAllowed)

        val preflightAuthorization = application.siteProductionDeploymentSftpReadOnlyPreflightAuthorization(
            preflightDraft,
            SiteProductionDeploymentSftpReadOnlyPreflightApproval(preflightDraft.approvalChallengeSha256, true),
        )
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightAuthorizationBoundary.validateAuthorization(preflightAuthorization)
        assertTrue(preflightAuthorization.authorizesSingleReadOnlyPreflightHandoff)
        val beforePreflightConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        val preflightReceipt = application.siteProductionDeploymentConsumeSftpReadOnlyPreflightHandoff(
            preflightAuthorization,
            preflightAuthorization.evaluatedAtEpochMillis + 1L,
        )
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightHandoffConsumptionBoundary.validateReceipt(preflightReceipt)
        val afterPreflightConsumption = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            beforePreflightConsumption.sftpReadOnlyPreflightHandoffAuthorizationMarkerCount + 1,
            afterPreflightConsumption.sftpReadOnlyPreflightHandoffAuthorizationMarkerCount,
        )
        assertTrue(application.siteProductionDeploymentReplayFence.hasConsumed(
            SiteProductionDeploymentReplayScope.SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
            preflightAuthorization.authorizationSha256,
        ))
        assertTrue(runCatching {
            application.siteProductionDeploymentConsumeSftpReadOnlyPreflightHandoff(
                preflightAuthorization, preflightAuthorization.evaluatedAtEpochMillis + 2L,
            )
        }.isFailure)

        val beforePreflightExecution = application.siteProductionDeploymentReplayFence.snapshot()
        val preflightProof = application.siteProductionDeploymentObserveFixtureSftpReadOnlyPreflightOnce(
            receipt = preflightReceipt,
            credentialLease = resolved.lease,
            serverAccess = fixture.serverAccess,
            executionAttemptId = "phase11_35_preflight_exec_$nonce",
            executedAtEpochMillis = preflightReceipt.consumedAtEpochMillis + 1L,
        )
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightExecutionBoundary.validateProof(preflightProof)
        assertEquals(SiteProductionDeploymentSftpReadOnlyPreflightExecutionStatus.FIXTURE_READ_ONLY_SFTP_PREFLIGHT_VERIFIED, preflightProof.status)
        assertTrue(preflightProof.sftpChannelOpened)
        assertTrue(preflightProof.sftpChannelClosed)
        assertEquals(3, preflightProof.lstatOperationCount)
        assertEquals(1, preflightProof.listOperationCount)
        assertFalse(preflightProof.mutationOperationPerformed)
        assertFalse(preflightProof.remoteCommandDispatched)
        assertFalse(preflightProof.coordinatorInvoked)
        assertFalse(preflightProof.exposesDeployUiAction)
        assertFalse(preflightProof.realVpsAccessAllowed)
        assertEquals(SiteRemoteObservedPathType.DIRECTORY, preflightProof.targetType)
        assertEquals(SiteRemoteObservedPathType.ABSENT, preflightProof.stagingType)
        assertEquals(SiteRemoteObservedPathType.ABSENT, preflightProof.backupType)
        assertEquals(listOf("index.html", "manifest.txt"), preflightProof.targetEntryNames)
        assertEquals(beforePreflightExecution, application.siteProductionDeploymentReplayFence.snapshot())
        assertTrue(runCatching { resolved.lease.useMaterialOnce { material -> material.useBytes { it.size } } }.isFailure)

        val afterCredentialResolutionExecution =
            application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(
            beforeCredentialResolutionExecution.credentialResolutionExecutionReceiptMarkerCount + 1,
            afterCredentialResolutionExecution.credentialResolutionExecutionReceiptMarkerCount,
        )
        assertEquals(
            beforeCredentialResolutionExecution.credentialResolutionHandoffAuthorizationMarkerCount,
            afterCredentialResolutionExecution.credentialResolutionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            beforeCredentialResolutionExecution.transportAcquisitionHandoffAuthorizationMarkerCount,
            afterCredentialResolutionExecution.transportAcquisitionHandoffAuthorizationMarkerCount,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                credentialReceipt.credentialResolutionConsumptionReceiptSha256,
            ),
        )
        val reconstructedResolutionFence = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructedResolutionFence.hasConsumed(
                SiteProductionDeploymentReplayScope.CREDENTIAL_RESOLUTION_EXECUTION_RECEIPT,
                credentialReceipt.credentialResolutionConsumptionReceiptSha256,
            ),
        )
        assertFalse(
            reconstructedResolutionFence.credentialResolutionExecutionUsePort()
                .consumeOnce(credentialReceipt.credentialResolutionConsumptionReceiptSha256),
        )
        val repeatedResolution = runCatching {
            application.siteProductionDeploymentResolveCredentialOnce(
                receipt = credentialReceipt,
                composition = fixture.composition,
                serverAccess = fixture.serverAccess,
                resolvedAtEpochMillis = resolvedAt + 1L,
            )
        }
        assertTrue(repeatedResolution.isFailure)
        assertEquals(
            afterCredentialResolutionExecution,
            application.siteProductionDeploymentReplayFence.snapshot(),
        )

        val staleCredentialDraft = application.siteProductionDeploymentCredentialResolutionAuthorizationDraft(
            admission = admission,
            serverAccess = fixture.serverAccess,
            authorizationAttemptId = "phase11_35_credential_stale_$nonce",
            evaluatedAtEpochMillis = admission.authorizationExpiresAtEpochMillis + 1L,
            requestedAuthorizationLifetimeMillis = 20_000L,
        )
        assertEquals(
            SiteProductionDeploymentCredentialResolutionAuthorizationStatus.BLOCKED,
            staleCredentialDraft.status,
        )
        assertTrue(
            staleCredentialDraft.blockers.any {
                it.code == "CREDENTIAL_RESOLUTION_ADMISSION_WINDOW_EXPIRED"
            },
        )
        assertFalse(staleCredentialDraft.authorizesSingleCredentialResolutionHandoff)

        val staleAdmission = application.siteProductionDeploymentTransportAcquisitionExecutionAdmission(
            receipt = receipt,
            composition = fixture.composition,
            serverAccess = fixture.serverAccess,
            evaluatedAtEpochMillis = receipt.authorizationExpiresAtEpochMillis + 1L,
        )
        assertEquals(
            SiteProductionDeploymentTransportAcquisitionExecutionAdmissionStatus.BLOCKED,
            staleAdmission.status,
        )
        assertTrue(
            staleAdmission.blockers.any {
                it.code == "TRANSPORT_ACQUISITION_AUTHORIZATION_WINDOW_EXPIRED"
            },
        )
        assertFalse(staleAdmission.authorizesTransportAcquisitionExecution)

        val after = application.siteProductionDeploymentReplayFence.snapshot()
        assertEquals(before.runtimeMutationPermitMarkerCount, after.runtimeMutationPermitMarkerCount)
        assertEquals(
            before.coordinatorInvocationAuthorizationMarkerCount,
            after.coordinatorInvocationAuthorizationMarkerCount,
        )
        assertEquals(
            before.transportAcquisitionHandoffAuthorizationMarkerCount + 1,
            after.transportAcquisitionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            before.credentialResolutionHandoffAuthorizationMarkerCount + 1,
            after.credentialResolutionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            before.credentialResolutionExecutionReceiptMarkerCount + 1,
            after.credentialResolutionExecutionReceiptMarkerCount,
        )
        assertEquals(
            before.sshSessionAcquisitionHandoffAuthorizationMarkerCount + 1,
            after.sshSessionAcquisitionHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            before.sftpChannelOpenHandoffAuthorizationMarkerCount + 1,
            after.sftpChannelOpenHandoffAuthorizationMarkerCount,
        )
        assertEquals(
            before.sftpReadOnlyPreflightHandoffAuthorizationMarkerCount + 1,
            after.sftpReadOnlyPreflightHandoffAuthorizationMarkerCount,
        )
        assertTrue(
            application.siteProductionDeploymentReplayFence.hasConsumed(
                SiteProductionDeploymentReplayScope.TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )

        val reconstructed = SiteProductionDeploymentAndroidReplayFence.open(context)
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope.TRANSPORT_ACQUISITION_HANDOFF_AUTHORIZATION,
                authorization.authorizationSha256,
            ),
        )
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope.SFTP_CHANNEL_OPEN_HANDOFF_AUTHORIZATION,
                sftpAuthorization.authorizationSha256,
            ),
        )
        assertTrue(
            reconstructed.hasConsumed(
                SiteProductionDeploymentReplayScope.SFTP_READ_ONLY_PREFLIGHT_HANDOFF_AUTHORIZATION,
                preflightAuthorization.authorizationSha256,
            ),
        )
        assertFalse(
            reconstructed.transportAcquisitionHandoffConsumptionPort()
                .consumeOnce(authorization.authorizationSha256),
        )
        assertThrows(IllegalArgumentException::class.java) {
            application.siteProductionDeploymentConsumeTransportAcquisitionHandoff(
                authorization = authorization,
                consumedAtEpochMillis = consumedAt + 1L,
            )
        }
        } finally {
            val deleted = secretStore.delete(fixture.secretId)
            assertTrue(
                deleted == SecretDeleteResult.Deleted || deleted == SecretDeleteResult.AlreadyAbsent,
            )
            Arrays.fill(fixtureSecretBytes, 0)
        }
        }
    }

    private fun requiredRunNonce(): String {
        val nonce = InstrumentationRegistry.getArguments()
            .getString(ARG_RUN_NONCE)
            ?.trim()
            ?.lowercase()
            ?: throw AssertionError("Missing $ARG_RUN_NONCE instrumentation argument")
        require(RUN_NONCE.matches(nonce)) {
            "Phase 11.35 run nonce must be exactly 32 lowercase hex characters"
        }
        return nonce
    }

    private fun requiredFixturePort(): Int {
        val raw = InstrumentationRegistry.getArguments()
            .getString(ARG_FIXTURE_PORT)
            ?.trim()
            ?: throw AssertionError("Missing $ARG_FIXTURE_PORT instrumentation argument")
        val port = raw.toIntOrNull()
            ?: throw AssertionError("$ARG_FIXTURE_PORT is not an integer")
        require(port in 1..65535) { "Phase 11.35 fixture port is outside 1..65535" }
        return port
    }

    private fun requiredFixtureFingerprint(): String {
        val value = InstrumentationRegistry.getArguments()
            .getString(ARG_FIXTURE_FINGERPRINT)
            ?.trim()
            ?: throw AssertionError("Missing $ARG_FIXTURE_FINGERPRINT instrumentation argument")
        require(
            CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(value)) is
                com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult.Valid,
        ) { "Phase 11.35 fixture fingerprint is not canonical SHA-256" }
        return value
    }

    private data class Fixture(
        val secretId: SecretId,
        val serverAccess: ServerAccess,
        val composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        val readinessRequest: SiteProductionDeploymentTransportAcquisitionReadinessRequest,
        val readinessDescriptor: SiteProductionDeploymentTransportAcquisitionReadinessDescriptor,
        val runtimeMutationPermit: SiteProductionDeploymentRuntimeMutationPermit,
        val authorizationEvaluatedAt: Long,
    )

    private fun fixture(
        nonce: String,
        fixturePort: Int,
        fixtureFingerprint: String,
    ): Fixture {
        val canonicalHostKey = when (
            val parsed = CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(fixtureFingerprint))
        ) {
            is com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult.Valid ->
                parsed.fingerprint
            is com.velumtegra.xuimobile.core.ssh.HostKeyFingerprintParseResult.Invalid ->
                throw AssertionError("Runner supplied invalid Phase 11.35 host fingerprint")
        }
        val trustedKey = canonicalHostKey.asHexSha256()
        val secretId = SecretId("phase11_35_secret_$nonce")
        val host = "127.0.0.1"
        val serverAccess = ServerAccess(
            id = ServerAccessId("phase11_35_access"),
            serverId = ServerId("phase11_35_server"),
            endpoint = SshEndpoint(host = host, port = fixturePort),
            username = FIXTURE_USERNAME,
            auth = SshAuthRef.Password(secretId),
            pinnedHostKey = canonicalHostKey.asModel(),
        )
        val composition = application.siteProductionDeploymentCompositionDescriptor(
            serverAccess = serverAccess,
            runtimeSessionId = "phase11_35_runtime_0001",
        )

        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(DesignSeed(125L)),
                siteName = "Velum Fixture SFTP Read-Only Preflight",
                tagline = "Bounded lstat/list preflight; no mutation or remote command",
            ),
        )
        val bundle = SiteBuilder.build(SiteBuildRequest(design))
        val exportPlan = SitePreviewExportBoundary.prepare(
            bundle = bundle,
            request = SitePreviewExportRequest(format = SiteExportFormat.DIRECTORY),
        ).export
        val receipt = SiteLocalExportReceipt(
            format = SiteExportFormat.DIRECTORY,
            outputName = exportPlan.manifest.outputName,
            outputPath = Path.of("phase11_35_verified_export"),
            fileCount = exportPlan.manifest.fileCount,
            totalBytes = exportPlan.manifest.totalBytes,
            sourceTreeSha256 = exportPlan.manifest.sourceTreeSha256,
            planSha256 = exportPlan.manifest.planSha256,
            artifactSha256 = null,
            verified = true,
        )
        val domain = "site.example.com"
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = host,
            targetRoot = "/srv/www/site",
            owner = "www_data",
            group = "www_data",
            certificateReuse = SiteCertificateReuseRequest(
                mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                requestedDomain = domain,
            ),
        )
        val plan = SiteRemoteDeployBoundary.prepare(exportPlan, receipt, remoteRequest)
        val observedAt = 1_800_000_100_000L
        val readinessEvaluatedAt = observedAt + 30_000L
        val remoteObservation = SiteRemotePreflightObservation(
            server = SiteRemoteServerObservation(host, trustedKey),
            target = SiteRemoteObservedPath(plan.publish.targetRoot, SiteRemoteObservedPathType.ABSENT),
            staging = SiteRemoteObservedPath(plan.publish.stagingRoot, SiteRemoteObservedPathType.ABSENT),
            backup = null,
            availableBytes = SiteRemotePreflightPolicy.requiredAvailableBytes(plan) + 4096L,
            ownership = SiteRemoteOwnershipObservation(true, true, true, true),
            certificate = SiteRemoteCertificateObservation(
                serverKeySha256 = trustedKey,
                dnsNames = listOf(domain),
                certificateSha256 = "c".repeat(64),
                usableNow = true,
                privateKeyPresentOnServer = true,
            ),
        )
        val productionReadinessRequest = SiteProductionDeploymentReadinessRequest(
            exportPlan = exportPlan,
            localReceipt = receipt,
            remoteRequest = remoteRequest,
            trust = SiteRemotePreflightTrust(trustedKey),
            remoteObservation = remoteObservation,
            remoteObservationObservedAtEpochMillis = observedAt,
            serviceBindingIntent = SiteProductionServiceBindingIntent(domain, 443),
            serviceBindingObservation = SiteProductionServiceBindingObservation(
                remoteHostIdentity = host,
                serverKeySha256 = trustedKey,
                domain = domain,
                port = 443,
                configured = true,
                observedAtEpochMillis = observedAt,
            ),
            freshnessPolicy = SiteProductionObservationFreshnessPolicy(readinessEvaluatedAt, 300_000L),
        )
        val readinessDraft = SiteProductionDeploymentReadinessBoundary.prepare(productionReadinessRequest)
        val readyRecord = SiteProductionDeploymentReadinessBoundary.approve(
            readinessDraft,
            SiteProductionOperatorApproval(readinessDraft.operatorApprovalChallengeSha256, true),
        )
        val executionEvaluatedAt = readinessEvaluatedAt + 1_000L
        val executionRequest = SiteProductionDeploymentExecutionRequest(
            readyRecord = readyRecord,
            readinessRequest = productionReadinessRequest,
            coordinatorRequest = SiteDeploymentCoordinatorRequest(
                exportPlan = exportPlan,
                localOutputRoot = Path.of("phase11_35_coordinator_output"),
                remoteRequest = remoteRequest,
                trust = productionReadinessRequest.trust,
            ),
            transportCapabilities = SiteRemoteSftpPrimitiveFactory.CAPABILITIES,
            executionAttemptId = "phase11_35_attempt_0001",
            evaluatedAtEpochMillis = executionEvaluatedAt,
        )
        val executionDraft = SiteProductionDeploymentExecutionBoundary.prepare(executionRequest)
        val executionAuthorization = SiteProductionDeploymentExecutionBoundary.authorize(
            executionDraft,
            SiteProductionDeploymentExecutionApproval(executionDraft.executionApprovalChallengeSha256, true),
        )
        val runtimeEvaluatedAt = executionEvaluatedAt + 1_000L
        val runtimeMutationRequest = SiteProductionDeploymentRuntimeMutationRequest(
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeIdentity = composition.runtimeIdentity,
            coordinatorInvocationId = "phase11_35_invocation_0001",
            evaluatedAtEpochMillis = runtimeEvaluatedAt,
            requestedPermitLifetimeMillis = 60_000L,
        )
        val runtimeDraft = SiteProductionDeploymentRuntimeMutationBoundary.prepare(runtimeMutationRequest)
        val runtimeMutationPermit = SiteProductionDeploymentRuntimeMutationBoundary.authorize(
            runtimeDraft,
            SiteProductionDeploymentRuntimeMutationApproval(runtimeDraft.runtimeMutationApprovalChallengeSha256, true),
        )
        val transportReadinessEvaluatedAt = runtimeEvaluatedAt + 1_000L
        val transportReadinessRequest = SiteProductionDeploymentTransportAcquisitionReadinessRequest(
            composition = composition,
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeMutationPermit = runtimeMutationPermit,
            runtimeMutationRequest = runtimeMutationRequest,
            evaluatedAtEpochMillis = transportReadinessEvaluatedAt,
        )
        val transportReadinessDescriptor = application.siteProductionDeploymentTransportAcquisitionReadiness(
            composition = composition,
            executionAuthorization = executionAuthorization,
            executionRequest = executionRequest,
            runtimeMutationPermit = runtimeMutationPermit,
            runtimeMutationRequest = runtimeMutationRequest,
            evaluatedAtEpochMillis = transportReadinessEvaluatedAt,
        )
        return Fixture(
            secretId = secretId,
            serverAccess = serverAccess,
            composition = composition,
            readinessRequest = transportReadinessRequest,
            readinessDescriptor = transportReadinessDescriptor,
            runtimeMutationPermit = runtimeMutationPermit,
            authorizationEvaluatedAt = transportReadinessEvaluatedAt + 1_000L,
        )
    }
    companion object {
        private const val ARG_RUN_NONCE = "phase11_35_run_nonce"
        private const val ARG_FIXTURE_PORT = "phase11_35_fixture_port"
        private const val ARG_FIXTURE_FINGERPRINT = "phase11_35_fixture_fingerprint"
        private const val FIXTURE_USERNAME = "velum-phase1135"
        private const val FIXTURE_PASSWORD = "VELUM-phase1135-test-only-password"
        private val RUN_NONCE = Regex("^[0-9a-f]{32}$")
    }
}

package com.velumtegra.xuimobile

import android.app.Activity
import android.app.Application
import android.net.ConnectivityManager
import java.io.File
import kotlinx.coroutines.launch
import com.velumtegra.xuimobile.core.data.db.VelumDatabaseFactory
import com.velumtegra.xuimobile.core.data.repository.RoomManagementAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomManagementEnrollmentPublisher
import com.velumtegra.xuimobile.core.data.repository.RoomOperationJournal
import com.velumtegra.xuimobile.core.data.repository.RoomServerAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomCredentialReferenceWriter
import com.velumtegra.xuimobile.core.data.repository.RoomServerRepository
import com.velumtegra.xuimobile.core.data.repository.RoomWebPanelAccessRepository
import com.velumtegra.xuimobile.core.data.repository.RoomXuiInstallationRepository
import com.velumtegra.xuimobile.core.domain.CredentialTransactionService
import com.velumtegra.xuimobile.core.domain.OperationJournal
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.discovery.DiscoveryResultProjector
import com.velumtegra.xuimobile.discovery.XuiReadOnlyDiscoveryPort
import com.velumtegra.xuimobile.discovery.RepositoryXuiReadOnlyDiscoveryPort
import com.velumtegra.xuimobile.discovery.XuiVerifiedEnrollmentPort
import com.velumtegra.xuimobile.discovery.RepositoryXuiVerifiedEnrollmentPort
import com.velumtegra.xuimobile.discovery.DiscoveryResultRegistry
import com.velumtegra.xuimobile.discovery.VisibleDiscoveryOperationLauncher
import com.velumtegra.xuimobile.management.DeepDiagnosticResultProjector
import com.velumtegra.xuimobile.management.DeepDiagnosticResultRegistry
import com.velumtegra.xuimobile.management.ManagementResultProjector
import com.velumtegra.xuimobile.management.ManagementResultRegistry
import com.velumtegra.xuimobile.management.VisibleDeepDiagnosticOperationLauncher
import com.velumtegra.xuimobile.management.VisibleManagementQuickInspectOperationLauncher
import com.velumtegra.xuimobile.core.runtime.OperationRuntimeCoordinator
import com.velumtegra.xuimobile.core.runtime.android.AndroidApplicationExitInfoAdapter
import com.velumtegra.xuimobile.core.runtime.android.AndroidDefaultNetworkObserver
import com.velumtegra.xuimobile.core.secrets.AndroidKeystoreSecretStore
import com.velumtegra.xuimobile.core.secrets.ProcessCredentialMutationCoordinator
import com.velumtegra.xuimobile.core.ssh.ExactSessionRegistry
import com.velumtegra.xuimobile.core.ssh.JschSshConnectionFactory
import com.velumtegra.xuimobile.enrollment.LocalServerEnrollmentPort
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentPort
import com.velumtegra.xuimobile.enrollment.ServerHostKeyDiscoveryPort
import com.velumtegra.xuimobile.enrollment.JschServerHostKeyDiscoveryPort
import com.velumtegra.xuimobile.readiness.LiveSshConnectionPort
import com.velumtegra.xuimobile.readiness.RepositoryLiveSshConnectionPort
import com.velumtegra.xuimobile.core.ssh.SshConnectionFactory
import com.velumtegra.xuimobile.runtime.ExactOperationHostLifecycleRegistry
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentDurableReplayFence
import com.velumtegra.xuimobile.core.site.SiteDeployerLocalPreparationResult
import com.velumtegra.xuimobile.core.site.SiteDeployerStagingWritePlan
import com.velumtegra.xuimobile.core.site.SiteDeployerCommitTransactionPlan
import com.velumtegra.xuimobile.core.site.SiteDeployerPostTransactionCleanupPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingPublicationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingReadOnlyPreflightReport
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigMutationPreparation
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigStagingSyntaxExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingConfigActivationExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingNginxReloadExecutionPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingLiveHttpVerificationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingExternalHttpReachabilityVerificationPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingDomainDnsResolutionVerificationPlan
import com.velumtegra.xuimobile.core.site.SiteExisting3xUiCertificateReuseEligibilityPlan
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimePrerequisiteReport
import com.velumtegra.xuimobile.core.site.SiteWebServingRuntimeProvisioningPlan
import com.velumtegra.xuimobile.core.ssh.SiteRemoteSftpCommitFailureInjection
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCompositionDescriptor
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCompositionGate
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionAuthorization
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentExecutionRequest
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationPermit
import com.velumtegra.xuimobile.core.site.SiteProductionDeploymentRuntimeMutationRequest
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionReadinessDescriptor
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidTransportAcquisitionReadinessGate
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionReadinessRequest
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidTransportAcquisitionAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionAuthorizationRequest
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidTransportAcquisitionHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidTransportAcquisitionExecutionAdmissionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentTransportAcquisitionExecutionAdmission
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCredentialResolutionAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentCredentialResolutionAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentCredentialResolutionAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCredentialResolutionHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentCredentialResolutionExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentEphemeralCredentialLease
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSshSessionAcquisitionAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSshSessionAcquisitionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSshSessionAcquisitionAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSshSessionAcquisitionHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSshSessionAcquisitionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSshSessionAcquisitionExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpChannelOpenAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpChannelOpenApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpChannelOpenAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSftpChannelOpenHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSftpChannelOpenExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpChannelOpenExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSftpReadOnlyPreflightAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpReadOnlyPreflightApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpReadOnlyPreflightAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSftpReadOnlyPreflightHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidSftpReadOnlyPreflightExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentSftpReadOnlyPreflightExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSshSessionAcquisitionApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpChannelOpenHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpChannelOpenExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightApproval
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightHandoffConsumptionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStagingWriteExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCommitTransactionExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsPostTransactionCleanupExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsPostTransactionCleanupExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidProductionExecutionContext
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidProductionExecutionContextRegistry
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidProductionExecutionPort
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReleaseBootstrapBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReleaseContextBootstrapPort
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReleaseBootstrapPort
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentReleaseBootstrapAdmission
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentReleaseFlow
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerProductionExecutionPort
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionRequest
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsStaticFileTransactionResult
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingReadOnlyPreflightExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsWebServingReadOnlyPreflightExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingRuntimePrerequisiteExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsWebServingRuntimePrerequisiteExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingRuntimeProvisioningExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsWebServingLiveHttpVerificationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidExternalHttpReachabilityVerificationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidDomainDnsResolutionVerificationExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentDomainDnsResolutionVerificationExecutionProof
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary
import com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentRealVpsExisting3xUiCertificateReuseEligibilityExecutionProof

/**
 * Android process owner for the single production Phase 4 runtime graph.
 *
 * Activity/Service/Job components must obtain runtime machinery from this Application instance;
 * none may construct another OperationRuntimeCoordinator, session registry or connectivity observer.
 * The graph is lazy so merely creating the Android process does not open the database, query exit
 * evidence, register a network callback, open SSH, or start background work.
 */
class VelumTegraApplication : Application() {
    internal val operationHostLifecycleRegistry = ExactOperationHostLifecycleRegistry()
    internal val discoveryResultRegistry = DiscoveryResultRegistry()
    internal val managementResultRegistry = ManagementResultRegistry()
    internal val deepDiagnosticResultRegistry = DeepDiagnosticResultRegistry()
    internal val serviceLogResultRegistry = com.velumtegra.xuimobile.management.ServiceLogResultRegistry()
    internal val updatePreflightResultRegistry = com.velumtegra.xuimobile.management.UpdatePreflightResultRegistry()
    internal val installationBackupResultRegistry = com.velumtegra.xuimobile.management.InstallationBackupResultRegistry()
    internal val restoreCheckResultRegistry = com.velumtegra.xuimobile.management.RestoreCheckResultRegistry()
    internal val restoreCompatibilityResultRegistry = com.velumtegra.xuimobile.management.RestoreCompatibilityResultRegistry()
    internal val workingDatabaseRestoreResultRegistry = com.velumtegra.xuimobile.management.WorkingDatabaseRestoreResultRegistry()
    internal val restoredPanelStartResultRegistry = com.velumtegra.xuimobile.management.RestoredPanelStartResultRegistry()
    internal val databaseBackupResultRegistry = com.velumtegra.xuimobile.management.DatabaseBackupResultRegistry()
    private val updatePackagePort by lazy {
        com.velumtegra.xuimobile.management.OfficialUpdatePackagePreparationPort(
            java.io.File(cacheDir, "velum-xui-update-v1"), updatePreflightStatusPort())
    }

    private val runtimeGraph: RuntimeGraph by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        createRuntimeGraph()
    }

    private val maintenanceScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.IO,
    )

    internal val localStorageJanitor by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.maintenance.LocalStorageJanitor(
            secrets = { runtimeGraph.secretGarbageCollector },
            panels = { runtimeGraph.webPanelAccessRepository },
            pins = com.velumtegra.xuimobile.inventory.PrivatePanelCertificatePins(this),
            siteCacheRoot = File(cacheDir, "site-deployer-release-bootstrap"),
            fenceRoot = {
                com.velumtegra.xuimobile.sitedeployer.SiteProductionDeploymentAndroidReplayFence.canonicalRoot(this)
            },
        )
    }

    /** Local-only cleanup of unreferenced leftovers; safe to call any time, runs off the main thread. */
    internal fun sweepLocalStorageInBackground() {
        maintenanceScope.launch { localStorageJanitor.sweep() }
    }

    /** Removes a server and all its local records, then cleans the leftovers. VPS untouched. */
    internal suspend fun purgeServerLocally(
        serverId: com.velumtegra.xuimobile.core.model.ServerId,
        revision: com.velumtegra.xuimobile.core.domain.RecordRevision,
    ): com.velumtegra.xuimobile.core.domain.RepositoryResult<List<String>> {
        val result = runtimeGraph.serverRepository.deleteWithAllLocalRecords(serverId, revision)
        if (result is com.velumtegra.xuimobile.core.domain.RepositoryResult.Success) localStorageJanitor.sweep()
        return result
    }

    /** Instrumented dedicated-server setup only; no secret-store exposure or second graph. */
    internal data class DebugMaintenanceDependencies(
        val connections: SshConnectionFactory,
        val journal: OperationJournal,
        val coordinator: OperationRuntimeCoordinator,
    )

    internal fun debugMaintenanceDependencies(): DebugMaintenanceDependencies {
        check((applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        return DebugMaintenanceDependencies(runtimeGraph.connectionFactory, runtimeGraph.journal, runtimeGraph.coordinator)
    }

    // Phase 14.1: read-only local inventory capabilities. The one existing RuntimeGraph remains
    // the owner. Merely opening the home screen does not initialize the persistence graph.
    internal val inventoryServerRepository get() = runtimeGraph.serverRepository
    internal val serverEnrollmentPort: ServerEnrollmentPort by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        LocalServerEnrollmentPort(runtimeGraph.serverRepository, runtimeGraph.credentialTransactions)
    }
    internal val serverHostKeyDiscoveryPort: ServerHostKeyDiscoveryPort by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        JschServerHostKeyDiscoveryPort()
    }
    internal val inventoryServerAccessRepository get() = runtimeGraph.serverAccessRepository
    internal val sshPortMigration by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.sshport.SshPortMigration(
            runtimeGraph.serverRepository,
            runtimeGraph.serverAccessRepository,
            runtimeGraph.connectionFactory,
            runtimeGraph.journal,
            runtimeGraph.coordinator,
        ) { assets.open("velum-ssh-port.sh").bufferedReader().use { it.readText() } }
    }
    internal val asBlocklistManager by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.blocklist.AsBlocklistManager(
            runtimeGraph.serverAccessRepository,
            runtimeGraph.connectionFactory,
            runtimeGraph.coordinator,
            listProfiles = { sshPortMigration.profiles() },
        ) { assets.open("velum-as-blocklist.sh").bufferedReader().use { it.readText() } }
    }
    internal val liveSshConnectionPort: LiveSshConnectionPort by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        RepositoryLiveSshConnectionPort(
            runtimeGraph.serverRepository,
            runtimeGraph.serverAccessRepository,
            runtimeGraph.connectionFactory,
        )
    }
    internal val sshProfileManagementPort: com.velumtegra.xuimobile.profiles.SshProfileManagementPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.profiles.RepositorySshProfileManagementPort(
                runtimeGraph.serverRepository,
                runtimeGraph.serverAccessRepository,
                runtimeGraph.managementAccessRepository,
                runtimeGraph.webPanelAccessRepository,
                runtimeGraph.credentialTransactions::deleteServerAccess,
            )
        }
    internal val xuiReadOnlyDiscoveryPort: XuiReadOnlyDiscoveryPort by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        RepositoryXuiReadOnlyDiscoveryPort(
            runtimeGraph.serverRepository,
            runtimeGraph.serverAccessRepository,
            runtimeGraph.connectionFactory,
        )
    }
    internal val xuiVerifiedEnrollmentPort: XuiVerifiedEnrollmentPort by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        RepositoryXuiVerifiedEnrollmentPort(
            runtimeGraph.serverRepository,
            runtimeGraph.serverAccessRepository,
            runtimeGraph.connectionFactory,
            runtimeGraph.managementEnrollmentPublisher,
        )
    }
    internal val inventoryInstallationRepository get() = runtimeGraph.installationRepository
    internal val inventoryManagementRepository get() = runtimeGraph.managementAccessRepository
    internal val inventoryWebPanelRepository get() = runtimeGraph.webPanelAccessRepository
    internal val linkedWebPanelLoginCheckPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelLoginCheckPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelLoginCheckPort(
                runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,
                    runtimeGraph.serverRepository,
                    runtimeGraph.serverAccessRepository,
                ),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.secretStore,
                ),
            )
        }
    internal val linkedWebPanelInboundReadPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelInboundReadPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelInboundReadPort(
                runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,
                    runtimeGraph.serverRepository,
                    runtimeGraph.serverAccessRepository,
                ),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.secretStore,
                ),
            )
        }
    internal val linkedWebPanelServerStatusReadPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelServerStatusReadPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelServerStatusReadPort(
                runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,
                    runtimeGraph.serverRepository,
                    runtimeGraph.serverAccessRepository,
                ),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.secretStore,
                ),
            )
        }
    internal val linkedWebPanelClientCountReadPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelClientCountReadPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelClientCountReadPort(
                runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,
                    runtimeGraph.serverRepository,
                    runtimeGraph.serverAccessRepository,
                ),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.secretStore,
                ),
            )
        }
    internal val linkedWebPanelClientTrafficReadPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelClientTrafficReadPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelClientTrafficReadPort(
                runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,
                    runtimeGraph.serverRepository,
                    runtimeGraph.serverAccessRepository,
                ),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.secretStore,
                ),
            )
        }
    internal val linkedWebPanelClientQuotaExpiryReadPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelClientQuotaExpiryReadPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelClientQuotaExpiryReadPort(
                runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,
                    runtimeGraph.serverRepository,
                    runtimeGraph.serverAccessRepository,
                ),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.secretStore,
                ),
            )
        }
    internal val linkedWebPanelInboundDetailsReadPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelInboundDetailsReadPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelInboundDetailsReadPort(
                runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,
                    runtimeGraph.serverRepository,
                    runtimeGraph.serverAccessRepository,
                ),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(
                    runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.secretStore,
                ),
            )
        }
    private val browserPanelResolver by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(
            runtimeGraph.webPanelAccessRepository,
            runtimeGraph.installationRepository,
            runtimeGraph.serverRepository,
            runtimeGraph.serverAccessRepository,
        )
    }
    internal val savedWebPanelLogin by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.inventory.SavedWebPanelLogin(
            browserPanelResolver, runtimeGraph.webPanelAccessRepository, runtimeGraph.secretStore,
        )
    }
    internal val privateWebPanelSshPort: com.velumtegra.xuimobile.inventory.PrivateWebPanelSshPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryPrivateWebPanelSshPort(
                browserPanelResolver,
                runtimeGraph.serverAccessRepository,
                runtimeGraph.connectionFactory,
                savedWebPanelLogin,
            )
        }
    internal val linkedWebPanelCredentialPort: com.velumtegra.xuimobile.inventory.LinkedWebPanelCredentialPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.inventory.RepositoryLinkedWebPanelCredentialPort(
                runtimeGraph.serverRepository,
                runtimeGraph.installationRepository,
                runtimeGraph.webPanelAccessRepository,
                runtimeGraph.credentialTransactions,
                runtimeGraph.serverAccessRepository,
            )
        }

    /**
     * App-private, no-backup replay authority for Site Deployer production approval consumption.
     * Lazy construction preserves the existing rule that process creation alone performs no disk
     * mutation beyond Android/framework initialization.
     */
    internal val siteProductionDeploymentReplayFence: SiteProductionDeploymentDurableReplayFence by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            SiteProductionDeploymentAndroidReplayFence.open(applicationContext)
        }

    private val siteProductionDeploymentExecutionContextRegistry:
        SiteProductionDeploymentAndroidProductionExecutionContextRegistry by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            SiteProductionDeploymentAndroidProductionExecutionContextRegistry()
        }

    /** Phase 11.82: the one concrete Android UI -> accepted Phase 11.80 execution adapter. */
    internal val siteDeployerProductionExecutionPort: SiteDeployerProductionExecutionPort by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            SiteProductionDeploymentAndroidProductionExecutionPort(
                contextRegistry = siteProductionDeploymentExecutionContextRegistry,
                replayFence = siteProductionDeploymentReplayFence,
            )
        }

    /** Phase 11.100: explicit stored-target -> reviewed first-publication context composition. */
    internal val siteDeployerReleaseBootstrapPort: SiteDeployerReleaseBootstrapPort by
        lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            SiteProductionDeploymentAndroidReleaseContextBootstrapPort(
                application = this,
                serverRepositoryProvider = { runtimeGraph.serverRepository },
                serverAccessRepositoryProvider = { runtimeGraph.serverAccessRepository },
                cacheRoot = File(cacheDir, "site-deployer-release-bootstrap"),
                connectionFactoryProvider = { runtimeGraph.connectionFactory },
            )
        }

    /**
     * Legacy/static-only publication seam retained for Phase 11.82 regression acceptance. A
     * complete post-coordinator serving context must use the Phase 11.96 release bootstrap below
     * so first-publication readiness cannot be bypassed.
     */
    internal fun publishSiteDeployerProductionExecutionContext(
        context: SiteProductionDeploymentAndroidProductionExecutionContext,
    ) {
        require(context.postCoordinatorCredentialProvider == null) {
            "Complete serving contexts must pass the Phase 11.96 release bootstrap gate"
        }
        require(siteProductionDeploymentExecutionContextRegistry.installOnce(context)) {
            "A production Site Deployer execution context is already pending"
        }
    }

    /**
     * Phase 11.96 release publication seam for an already-reviewed first-publication context.
     * The gate revalidates the exact Phase 11.95 readiness mode, unconfigured endpoint evidence,
     * operator-approved ready record, pinned-host identity and Phase 11.94 serving capability before
     * the process-local UI context can become visible. It performs no network I/O or remote mutation.
     */
    internal fun publishReviewedFirstPublicationSiteDeployerExecutionContext(
        context: SiteProductionDeploymentAndroidProductionExecutionContext,
    ): SiteProductionDeploymentReleaseBootstrapAdmission {
        val evidence = SiteProductionDeploymentAndroidReleaseBootstrapBoundary.evidenceFrom(
            releaseFlow = SiteProductionDeploymentReleaseFlow.FIRST_PUBLICATION_POST_COORDINATOR,
            context = context,
        )
        val admission = SiteProductionDeploymentAndroidReleaseBootstrapBoundary
            .admitReviewedFirstPublication(evidence)
        require(siteProductionDeploymentExecutionContextRegistry.installOnce(context)) {
            "A production Site Deployer execution context is already pending"
        }
        return admission
    }

    internal fun publishReviewedReplacementSiteDeployerExecutionContext(
        context: SiteProductionDeploymentAndroidProductionExecutionContext,
    ): SiteProductionDeploymentReleaseBootstrapAdmission {
        val evidence = SiteProductionDeploymentAndroidReleaseBootstrapBoundary.evidenceFrom(
            releaseFlow = SiteProductionDeploymentReleaseFlow.PRECONFIGURED_ENDPOINT,
            context = context,
        )
        val admission = SiteProductionDeploymentAndroidReleaseBootstrapBoundary.admitReviewedReplacement(
            evidence = evidence,
            replacementPolicyBound = context.preparation.remoteDeployPlan.publish.existingTargetPolicy ==
                com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
            previousTargetTreeBound = context.previousTargetTree != null,
        )
        require(siteProductionDeploymentExecutionContextRegistry.installOnce(context)) {
            "A production Site Deployer execution context is already pending"
        }
        return admission
    }

    internal fun clearSiteDeployerProductionExecutionContext() {
        siteProductionDeploymentExecutionContextRegistry.clear()
    }

    /**
     * Phase 11.23 review-only production composition descriptor. This method does not touch the
     * runtime SSH graph: it binds public ServerAccess identity, the app-private replay authority and
     * the static bounded-SFTP capability profile only.
     */
    internal fun siteProductionDeploymentCompositionDescriptor(
        serverAccess: ServerAccess,
        runtimeSessionId: String,
    ): SiteProductionDeploymentAndroidCompositionDescriptor =
        SiteProductionDeploymentAndroidCompositionGate.prepare(
            context = applicationContext,
            replayFence = siteProductionDeploymentReplayFence,
            serverAccess = serverAccess,
            runtimeSessionId = runtimeSessionId,
        )


    /**
     * Phase 11.24 non-executing transport-acquisition readiness projection. This method only
     * revalidates immutable evidence; it does not resolve secrets or touch the runtime SSH graph.
     */
    internal fun siteProductionDeploymentTransportAcquisitionReadiness(
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        executionAuthorization: SiteProductionDeploymentExecutionAuthorization,
        executionRequest: SiteProductionDeploymentExecutionRequest,
        runtimeMutationPermit: SiteProductionDeploymentRuntimeMutationPermit,
        runtimeMutationRequest: SiteProductionDeploymentRuntimeMutationRequest,
        evaluatedAtEpochMillis: Long,
    ): SiteProductionDeploymentTransportAcquisitionReadinessDescriptor =
        SiteProductionDeploymentAndroidTransportAcquisitionReadinessGate.prepare(
            SiteProductionDeploymentTransportAcquisitionReadinessRequest(
                composition = composition,
                executionAuthorization = executionAuthorization,
                executionRequest = executionRequest,
                runtimeMutationPermit = runtimeMutationPermit,
                runtimeMutationRequest = runtimeMutationRequest,
                evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            ),
        )


    /**
     * Phase 11.25 non-executing transport-acquisition authorization boundary. These methods issue
     * only a short-lived handoff authorization and deliberately do not resolve secrets or touch the
     * runtime SSH graph. Durable one-shot consumption remains mandatory before any future acquisition.
     */
    internal fun siteProductionDeploymentTransportAcquisitionAuthorizationDraft(
        request: SiteProductionDeploymentTransportAcquisitionAuthorizationRequest,
    ): SiteProductionDeploymentTransportAcquisitionAuthorizationDraft =
        SiteProductionDeploymentAndroidTransportAcquisitionAuthorizationBoundary.prepare(request)

    internal fun siteProductionDeploymentTransportAcquisitionAuthorization(
        draft: SiteProductionDeploymentTransportAcquisitionAuthorizationDraft,
        approval: SiteProductionDeploymentTransportAcquisitionApproval,
    ): SiteProductionDeploymentTransportAcquisitionAuthorization =
        SiteProductionDeploymentAndroidTransportAcquisitionAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /**
     * Phase 11.26 durable one-shot handoff consumption. This burns only the exact Phase 11.25
     * authorization in the app-private replay fence; it does not resolve secrets or acquire transport.
     */
    internal fun siteProductionDeploymentConsumeTransportAcquisitionHandoff(
        authorization: SiteProductionDeploymentTransportAcquisitionAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidTransportAcquisitionHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .transportAcquisitionHandoffConsumptionPort(),
        )

    /**
     * Phase 11.27 non-executing execution admission. It validates the consumed handoff against
     * exact public ServerAccess/composition and static runtime/SSH/SFTP implementation identities.
     * It deliberately does not touch runtimeGraph and therefore cannot resolve secrets or connect.
     */
    internal fun siteProductionDeploymentTransportAcquisitionExecutionAdmission(
        receipt: SiteProductionDeploymentTransportAcquisitionHandoffConsumptionReceipt,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        serverAccess: ServerAccess,
        evaluatedAtEpochMillis: Long,
    ): SiteProductionDeploymentTransportAcquisitionExecutionAdmission =
        SiteProductionDeploymentAndroidTransportAcquisitionExecutionAdmissionBoundary.prepare(
            context = applicationContext,
            replayFence = siteProductionDeploymentReplayFence,
            receipt = receipt,
            composition = composition,
            serverAccess = serverAccess,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
        )

    /**
     * Phase 11.28 non-executing credential-resolution authorization. It binds only the hashed exact
     * SecretId reference and does not touch SecretStore or runtimeGraph.
     */
    internal fun siteProductionDeploymentCredentialResolutionAuthorizationDraft(
        admission: SiteProductionDeploymentTransportAcquisitionExecutionAdmission,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentCredentialResolutionAuthorizationDraft =
        SiteProductionDeploymentAndroidCredentialResolutionAuthorizationBoundary.prepare(
            admission = admission,
            serverAccess = serverAccess,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentCredentialResolutionAuthorization(
        draft: SiteProductionDeploymentCredentialResolutionAuthorizationDraft,
        approval: SiteProductionDeploymentCredentialResolutionApproval,
    ): SiteProductionDeploymentCredentialResolutionAuthorization =
        SiteProductionDeploymentAndroidCredentialResolutionAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /**
     * Phase 11.29 durable one-shot credential-resolution handoff consumption. This burns only the
     * exact Phase 11.28 authorization SHA-256 in the app-private replay fence. It does not touch
     * SecretStore or runtimeGraph and therefore cannot resolve credentials or acquire transport.
     */
    internal fun siteProductionDeploymentConsumeCredentialResolutionHandoff(
        authorization: SiteProductionDeploymentCredentialResolutionAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidCredentialResolutionHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .credentialResolutionHandoffConsumptionPort(),
        )

    /**
     * Phase 11.30 performs one bounded credential-resolution execution from the exact durably
     * consumed Phase 11.29 receipt. It reads only the exact app-private SecretId through the reviewed
     * AndroidKeystoreSecretStore and returns material solely in a closeable in-memory lease.
     * runtimeGraph remains untouched, so this cannot acquire SSH/SFTP or invoke the coordinator.
     */
    internal suspend fun siteProductionDeploymentResolveCredentialOnce(
        receipt: SiteProductionDeploymentCredentialResolutionHandoffConsumptionReceipt,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        serverAccess: ServerAccess,
        resolvedAtEpochMillis: Long,
    ): SiteProductionDeploymentCredentialResolutionExecutionResult =
        SiteProductionDeploymentAndroidCredentialResolutionExecutionBoundary.resolveOnce(
            context = applicationContext,
            replayFence = siteProductionDeploymentReplayFence,
            receipt = receipt,
            composition = composition,
            serverAccess = serverAccess,
            secretStore = AndroidKeystoreSecretStore(applicationContext),
            resolvedAtEpochMillis = resolvedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence
                .credentialResolutionExecutionUsePort(),
        )


    /**
     * Phase 11.31 non-network SSH-session acquisition authorization. It binds the exact successful
     * Phase 11.30 proof/ephemeral lease metadata to public ServerAccess plus reviewed JSch/registry
     * identities. It does not read lease material or touch runtimeGraph.
     */
    internal fun siteProductionDeploymentSshSessionAcquisitionAuthorizationDraft(
        resolutionProof: SiteProductionDeploymentCredentialResolutionExecutionProof,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        composition: SiteProductionDeploymentAndroidCompositionDescriptor,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft =
        SiteProductionDeploymentAndroidSshSessionAcquisitionAuthorizationBoundary.prepare(
            resolutionProof = resolutionProof,
            credentialLease = credentialLease,
            composition = composition,
            serverAccess = serverAccess,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentSshSessionAcquisitionAuthorization(
        draft: SiteProductionDeploymentSshSessionAcquisitionAuthorizationDraft,
        approval: SiteProductionDeploymentSshSessionAcquisitionApproval,
    ): SiteProductionDeploymentSshSessionAcquisitionAuthorization =
        SiteProductionDeploymentAndroidSshSessionAcquisitionAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /**
     * Phase 11.32 durable one-shot SSH-session-acquisition handoff consumption. Only the exact
     * Phase 11.31 authorization SHA-256 is burned into its dedicated app-private replay namespace.
     * The ephemeral credential lease is deliberately not accepted here and therefore remains
     * in-memory and untouched for a later separately reviewed SSH execution boundary.
     */
    internal fun siteProductionDeploymentConsumeSshSessionAcquisitionHandoff(
        authorization: SiteProductionDeploymentSshSessionAcquisitionAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidSshSessionAcquisitionHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .sshSessionAcquisitionHandoffConsumptionPort(),
        )

    /**
     * Phase 11.33 fixture-only actual SSH-session acquisition execution. This deliberately does not
     * touch runtimeGraph: the exact reviewed JSch factory + ExactSessionRegistry are exercised in a
     * bounded one-session acquire/register/lookup/remove/close path against adb-reverse loopback only.
     */
    internal suspend fun siteProductionDeploymentAcquireFixtureSshSessionOnce(
        receipt: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentSshSessionAcquisitionExecutionProof =
        SiteProductionDeploymentAndroidSshSessionAcquisitionExecutionBoundary.acquireFixtureSessionOnce(
            receipt = receipt,
            credentialLease = credentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )

    /**
     * Phase 11.34 explicit fixture-only SFTP channel-open authorization. This remains non-network
     * and does not read the credential lease.
     */
    internal fun siteProductionDeploymentSftpChannelOpenAuthorizationDraft(
        sshReceipt: SiteProductionDeploymentSshSessionAcquisitionHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentSftpChannelOpenAuthorizationDraft =
        SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.prepare(
            sshReceipt = sshReceipt,
            credentialLease = credentialLease,
            serverAccess = serverAccess,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentSftpChannelOpenAuthorization(
        draft: SiteProductionDeploymentSftpChannelOpenAuthorizationDraft,
        approval: SiteProductionDeploymentSftpChannelOpenApproval,
    ): SiteProductionDeploymentSftpChannelOpenAuthorization =
        SiteProductionDeploymentAndroidSftpChannelOpenAuthorizationBoundary.authorize(draft, approval)

    internal fun siteProductionDeploymentConsumeSftpChannelOpenHandoff(
        authorization: SiteProductionDeploymentSftpChannelOpenAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidSftpChannelOpenHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence.sftpChannelOpenHandoffConsumptionPort(),
        )

    internal suspend fun siteProductionDeploymentOpenFixtureSftpChannelOnce(
        receipt: SiteProductionDeploymentSftpChannelOpenHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentSftpChannelOpenExecutionProof =
        SiteProductionDeploymentAndroidSftpChannelOpenExecutionBoundary.openFixtureSftpChannelOnce(
            receipt = receipt,
            credentialLease = credentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )


    /** Phase 11.35 explicit fixture-only read-only SFTP deployment-root preflight authorization. */
    internal fun siteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft(
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
    ): SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft =
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightAuthorizationBoundary.prepare(
            sftpChannelOpenReceipt, credentialLease, serverAccess, targetRoot, stagingRoot, backupRoot,
            expectedTargetEntryNames, authorizationAttemptId, evaluatedAtEpochMillis, requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentSftpReadOnlyPreflightAuthorization(
        draft: SiteProductionDeploymentSftpReadOnlyPreflightAuthorizationDraft,
        approval: SiteProductionDeploymentSftpReadOnlyPreflightApproval,
    ): SiteProductionDeploymentSftpReadOnlyPreflightAuthorization =
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightAuthorizationBoundary.authorize(draft, approval)

    internal fun siteProductionDeploymentConsumeSftpReadOnlyPreflightHandoff(
        authorization: SiteProductionDeploymentSftpReadOnlyPreflightAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightHandoffConsumptionBoundary.consume(
            authorization, consumedAtEpochMillis,
            siteProductionDeploymentReplayFence.sftpReadOnlyPreflightHandoffConsumptionPort(),
        )

    internal suspend fun siteProductionDeploymentObserveFixtureSftpReadOnlyPreflightOnce(
        receipt: SiteProductionDeploymentSftpReadOnlyPreflightHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentSftpReadOnlyPreflightExecutionProof =
        SiteProductionDeploymentAndroidSftpReadOnlyPreflightExecutionBoundary.observeFixtureReadOnlyPreflightOnce(
            receipt, credentialLease, serverAccess, executionAttemptId, executedAtEpochMillis,
        )

    /** Phase 11.36 non-network admission for a future explicitly authorized real-VPS read-only preflight. */
    internal fun siteProductionDeploymentRealVpsReadOnlyPreflightAdmission(
        serverAccess: ServerAccess,
        targetRoot: String,
        stagingRoot: String,
        backupRoot: String,
        expectedTargetEntryNames: List<String>,
        admissionAttemptId: String,
        evaluatedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission =
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAdmissionBoundary.prepare(
            serverAccess = serverAccess,
            targetRoot = targetRoot,
            stagingRoot = stagingRoot,
            backupRoot = backupRoot,
            expectedTargetEntryNames = expectedTargetEntryNames,
            admissionAttemptId = admissionAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
        )

    /** Phase 11.37 non-network explicit authorization draft for one exact Phase 11.36 admission. */
    internal fun siteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft(
        admission: SiteProductionDeploymentRealVpsReadOnlyPreflightAdmission,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft =
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAuthorizationBoundary.prepare(
            admission = admission,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentRealVpsReadOnlyPreflightAuthorization(
        draft: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsReadOnlyPreflightApproval,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization =
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /** Phase 11.38 durable one-shot consumption; the replay marker is the only side effect. */
    internal fun siteProductionDeploymentConsumeRealVpsReadOnlyPreflightHandoff(
        authorization: SiteProductionDeploymentRealVpsReadOnlyPreflightAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidRealVpsReadOnlyPreflightHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .realVpsReadOnlyPreflightHandoffConsumptionPort(),
        )

    /** Phase 11.39 non-network authorization for one future credential-resolution handoff. */
    internal fun siteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft(
        receipt: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft =
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionAuthorizationBoundary.prepare(
            receipt = receipt,
            serverAccess = serverAccess,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentRealVpsCredentialResolutionAuthorization(
        draft: SiteProductionDeploymentRealVpsCredentialResolutionAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsCredentialResolutionApproval,
    ): SiteProductionDeploymentRealVpsCredentialResolutionAuthorization =
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /** Phase 11.40 durable one-shot credential-resolution handoff consumption. */
    internal fun siteProductionDeploymentConsumeRealVpsCredentialResolutionHandoff(
        authorization: SiteProductionDeploymentRealVpsCredentialResolutionAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .realVpsCredentialResolutionHandoffConsumptionPort(),
        )

    /**
     * Phase 11.41 performs exactly one app-private credential read from the exact consumed Phase 11.40
     * receipt and returns any found material only as an ephemeral lease. The production runtime graph
     * remains untouched, so no network, SSH/SFTP, coordinator invocation or remote access can occur.
     */
    internal suspend fun siteProductionDeploymentResolveRealVpsCredentialOnce(
        receipt: SiteProductionDeploymentRealVpsCredentialResolutionHandoffConsumptionReceipt,
        serverAccess: ServerAccess,
        resolvedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsCredentialResolutionExecutionResult =
        SiteProductionDeploymentAndroidRealVpsCredentialResolutionExecutionBoundary.resolveOnce(
            receipt = receipt,
            serverAccess = serverAccess,
            secretStore = AndroidKeystoreSecretStore(applicationContext),
            resolvedAtEpochMillis = resolvedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence
                .realVpsCredentialResolutionExecutionUsePort(),
        )


    /**
     * Phase 11.42 non-network authorization for one future real-VPS SSH-session-acquisition handoff.
     * It binds the exact Phase 11.41 proof and untouched lease metadata to reviewed public SSH
     * identities, but does not read lease material or touch production network/runtimeGraph.
     */
    internal fun siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft(
        resolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft =
        SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary.prepare(
            resolutionProof = resolutionProof,
            credentialLease = credentialLease,
            serverAccess = serverAccess,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization(
        draft: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsSshSessionAcquisitionApproval,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization =
        SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /** Phase 11.43 durable one-shot real-VPS SSH-session-acquisition handoff consumption. */
    internal fun siteProductionDeploymentConsumeRealVpsSshSessionAcquisitionHandoff(
        authorization: SiteProductionDeploymentRealVpsSshSessionAcquisitionAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .realVpsSshSessionAcquisitionHandoffConsumptionPort(),
        )


    /**
     * Phase 11.44 performs one durable-burned real-VPS SSH acquisition attempt. The already-resolved
     * credential lease is consumed once, the exact pinned host key is verified live, and the session
     * is registered, exact-looked-up, removed and closed without any command or SFTP operation.
     */
    internal suspend fun siteProductionDeploymentAcquireRealVpsSshSessionOnce(
        receipt: SiteProductionDeploymentRealVpsSshSessionAcquisitionHandoffConsumptionReceipt,
        credentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof =
        SiteProductionDeploymentAndroidRealVpsSshSessionAcquisitionExecutionBoundary.acquireSessionOnce(
            receipt = receipt,
            credentialLease = credentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence
                .realVpsSshSessionAcquisitionExecutionUsePort(),
        )

    /**
     * Phase 11.45 is a non-network authorization boundary for one future real-VPS SFTP
     * channel-open handoff. The prior Phase 11.44 proof is verified-and-closed evidence only; no
     * credential material or live session crosses this boundary.
     */
    internal fun siteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft(
        sshExecutionProof: SiteProductionDeploymentRealVpsSshSessionAcquisitionExecutionProof,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft =
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary.prepare(
            sshExecutionProof = sshExecutionProof,
            serverAccess = serverAccess,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentRealVpsSftpChannelOpenAuthorization(
        draft: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsSftpChannelOpenApproval,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization =
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /** Phase 11.46 durable one-shot real-VPS SFTP channel-open handoff consumption. */
    internal fun siteProductionDeploymentConsumeRealVpsSftpChannelOpenHandoff(
        authorization: SiteProductionDeploymentRealVpsSftpChannelOpenAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .realVpsSftpChannelOpenHandoffConsumptionPort(),
        )

    /**
     * Phase 11.47 durably burns the exact Phase 11.46 receipt before reading one fresh credential
     * lease or touching production network, then performs one fresh pinned SSH acquisition and one
     * SFTP channel open/close with zero SFTP path operations or remote commands.
     */
    internal suspend fun siteProductionDeploymentOpenRealVpsSftpChannelOnce(
        receipt: SiteProductionDeploymentRealVpsSftpChannelOpenHandoffConsumptionReceipt,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof =
        SiteProductionDeploymentAndroidRealVpsSftpChannelOpenExecutionBoundary.openRealVpsSftpChannelOnce(
            receipt = receipt,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence
                .realVpsSftpChannelOpenExecutionUsePort(),
        )

    /**
     * Phase 11.48 is a non-network explicit authorization boundary for one future bounded
     * real-VPS SFTP read-only preflight handoff. It binds the exact Phase 11.38 roots/vocabulary
     * to the exact successful-and-closed Phase 11.47 proof without reading credentials or network.
     */
    internal fun siteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft(
        sftpExecutionProof: SiteProductionDeploymentRealVpsSftpChannelOpenExecutionProof,
        preflightReceipt: SiteProductionDeploymentRealVpsReadOnlyPreflightHandoffConsumptionReceipt,
        serverAccess: ServerAccess,
        authorizationAttemptId: String,
        evaluatedAtEpochMillis: Long,
        requestedAuthorizationLifetimeMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft =
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary.prepare(
            sftpExecutionProof = sftpExecutionProof,
            preflightReceipt = preflightReceipt,
            serverAccess = serverAccess,
            authorizationAttemptId = authorizationAttemptId,
            evaluatedAtEpochMillis = evaluatedAtEpochMillis,
            requestedAuthorizationLifetimeMillis = requestedAuthorizationLifetimeMillis,
        )

    internal fun siteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization(
        draft: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorizationDraft,
        approval: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightApproval,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization =
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightAuthorizationBoundary.authorize(
            draft = draft,
            approval = approval,
        )

    /** Phase 11.49 durable one-shot real-VPS bounded SFTP read-only-preflight handoff consumption. */
    internal fun siteProductionDeploymentConsumeRealVpsSftpReadOnlyPreflightHandoff(
        authorization: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightAuthorization,
        consumedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt =
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightHandoffConsumptionBoundary.consume(
            authorization = authorization,
            consumedAtEpochMillis = consumedAtEpochMillis,
            consumptionPort = siteProductionDeploymentReplayFence
                .realVpsSftpReadOnlyPreflightHandoffConsumptionPort(),
        )

    /**
     * Phase 11.50 durably burns the exact Phase 11.49 receipt before consuming fresh credential
     * material or touching production network, then performs only the exact bounded read-only SFTP
     * preflight: 3 lstat operations + 1 bounded target-root list.
     */
    internal suspend fun siteProductionDeploymentObserveRealVpsSftpReadOnlyPreflightOnce(
        receipt: SiteProductionDeploymentRealVpsSftpReadOnlyPreflightHandoffConsumptionReceipt,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsSftpReadOnlyPreflightExecutionProof =
        SiteProductionDeploymentAndroidRealVpsSftpReadOnlyPreflightExecutionBoundary
            .observeRealVpsReadOnlyPreflightOnce(
                receipt = receipt,
                freshResolutionProof = freshResolutionProof,
                freshCredentialLease = freshCredentialLease,
                serverAccess = serverAccess,
                executionAttemptId = executionAttemptId,
                executedAtEpochMillis = executedAtEpochMillis,
                executionUsePort = siteProductionDeploymentReplayFence
                    .realVpsSftpReadOnlyPreflightExecutionUsePort(),
            )

    /**
     * Phase 11.52 is the first protected real-VPS write boundary. It writes and verifies only the
     * exact Phase 11.51 bundle under its exact staging root; publish/rename/delete/chmod/chown,
     * coordinator invocation and deploy UI remain unavailable.
     */
    internal suspend fun siteProductionDeploymentStageRealVpsBundleOnce(
        preparation: SiteDeployerLocalPreparationResult,
        stagingPlan: SiteDeployerStagingWritePlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsStagingWriteExecutionProof =
        SiteProductionDeploymentAndroidRealVpsStagingWriteExecutionBoundary.stageVerifiedBundleOnce(
            preparation = preparation,
            stagingPlan = stagingPlan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence.realVpsStagingWriteExecutionUsePort(),
        )


    /**
     * Phase 11.53 consumes one exact verified staging execution proof and performs only the exact
     * hash-bound SFTP renames required to commit or to restore the previous target. No upload,
     * mkdir, delete/cleanup, metadata mutation, remote shell, coordinator or deploy UI is exposed.
     */
    internal suspend fun siteProductionDeploymentCommitRealVpsStagingOnce(
        plan: SiteDeployerCommitTransactionPlan,
        stagingExecutionProof: SiteProductionDeploymentRealVpsStagingWriteExecutionProof,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
        failureInjection: SiteRemoteSftpCommitFailureInjection = SiteRemoteSftpCommitFailureInjection.NONE,
    ): SiteProductionDeploymentRealVpsCommitTransactionExecutionProof =
        SiteProductionDeploymentAndroidRealVpsCommitTransactionExecutionBoundary.commitOrRollbackOnce(
            plan = plan,
            stagingExecutionProof = stagingExecutionProof,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            failureInjection = failureInjection,
            executionUsePort = siteProductionDeploymentReplayFence.realVpsCommitTransactionExecutionUsePort(),
        )

    /**
     * Phase 11.54 consumes one exact Phase 11.53 commit/rollback proof and deletes only the
     * exact verified residual backup or rollback staging tree. The live target is verification-only.
     */
    internal suspend fun siteProductionDeploymentCleanupRealVpsTransactionResidualOnce(
        plan: SiteDeployerPostTransactionCleanupPlan,
        commitPlan: SiteDeployerCommitTransactionPlan,
        commitExecutionProof: SiteProductionDeploymentRealVpsCommitTransactionExecutionProof,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsPostTransactionCleanupExecutionProof =
        SiteProductionDeploymentAndroidRealVpsPostTransactionCleanupExecutionBoundary.cleanupOnce(
            plan = plan,
            commitPlan = commitPlan,
            commitExecutionProof = commitExecutionProof,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence.realVpsPostTransactionCleanupExecutionUsePort(),
        )


    /**
     * Phase 11.55 composes the already accepted staging -> commit/rollback -> residual-cleanup
     * boundaries into one bounded static-file transaction. Each remote step obtains one fresh
     * credential lease only when that step is reached. No automatic retry, web-server mutation,
     * coordinator invocation or Deploy UI action is introduced.
     */
    internal suspend fun siteProductionDeploymentExecuteRealVpsStaticFileTransactionOnce(
        request: SiteProductionDeploymentRealVpsStaticFileTransactionRequest,
        credentialProvider: SiteProductionDeploymentRealVpsFreshExecutionCredentialProvider,
    ): SiteProductionDeploymentRealVpsStaticFileTransactionResult =
        SiteProductionDeploymentAndroidRealVpsStaticFileTransactionBoundary.executeOnce(
            request = request,
            credentialProvider = credentialProvider,
            replayFence = siteProductionDeploymentReplayFence,
        )


    /**
     * Phase 11.57 performs one exact real-VPS read-only web-serving preflight from a deterministic
     * Phase 11.56 publication plan. Only a fixed internal command vocabulary is dispatched; no
     * config/service/DNS/firewall/package mutation, automatic retry, coordinator or Deploy UI action
     * is authorized.
     */
    internal suspend fun siteProductionDeploymentObserveRealVpsWebServingReadOnlyPreflightOnce(
        plan: SiteWebServingPublicationPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingReadOnlyPreflightExecutionProof =
        SiteProductionDeploymentAndroidRealVpsWebServingReadOnlyPreflightExecutionBoundary.observeOnce(
            plan = plan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )

    /**
     * Phase 11.59A classifies the exact missing web-serving runtime prerequisite using one fresh
     * pinned SSH session. It is read-only and cannot install packages or mutate config/services.
     */
    internal suspend fun siteProductionDeploymentObserveRealVpsWebServingRuntimePrerequisiteOnce(
        plan: SiteWebServingPublicationPlan,
        sourcePreflight: SiteWebServingReadOnlyPreflightReport,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingRuntimePrerequisiteExecutionProof =
        SiteProductionDeploymentAndroidRealVpsWebServingRuntimePrerequisiteExecutionBoundary.observeOnce(
            plan = plan,
            sourcePreflight = sourcePreflight,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )

    /**
     * Phase 11.59B performs one exact apt-based nginx provisioning attempt after 11.59A proved the
     * clean missing-runtime gap. A durable replay marker is consumed immediately before the first
     * package-manager mutation; no Site Deployer config activation, explicit service command,
     * reload, DNS/firewall mutation or automatic retry is introduced.
     */
    internal suspend fun siteProductionDeploymentExecuteRealVpsWebServingRuntimeProvisioningOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        prerequisiteReport: SiteWebServingRuntimePrerequisiteReport,
        provisioningPlan: SiteWebServingRuntimeProvisioningPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingRuntimeProvisioningExecutionProof =
        SiteProductionDeploymentAndroidRealVpsWebServingRuntimeProvisioningExecutionBoundary.executeOnce(
            publicationPlan = publicationPlan,
            prerequisiteReport = prerequisiteReport,
            provisioningPlan = provisioningPlan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence
                .realVpsWebServingRuntimeProvisioningExecutionUsePort(),
        )

    /**
     * Phase 11.59 performs one bounded real-VPS operation-owned staging/syntax-validation write.
     * Exact nginx *.conf activation and reload remain unauthorized. The durable replay fence is the
     * baseline checkpoint and is consumed immediately before the first remote write.
     */
    internal suspend fun siteProductionDeploymentExecuteRealVpsWebServingConfigStagingSyntaxOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
        mutationPreparation: SiteWebServingConfigMutationPreparation,
        executionPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionProof =
        SiteProductionDeploymentAndroidRealVpsWebServingConfigStagingSyntaxExecutionBoundary.executeOnce(
            publicationPlan = publicationPlan,
            readOnlyPreflight = readOnlyPreflight,
            mutationPreparation = mutationPreparation,
            executionPlan = executionPlan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence
                .realVpsWebServingConfigStagingSyntaxExecutionUsePort(),
        )

    /**
     * Phase 11.60 activates one exact reviewed nginx *.conf from a SHA-verified operation-owned
     * staging file after a durable preactivation checkpoint. nginx reload remains unauthorized.
     */
    internal suspend fun siteProductionDeploymentExecuteRealVpsWebServingConfigActivationOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        readOnlyPreflight: SiteWebServingReadOnlyPreflightReport,
        mutationPreparation: SiteWebServingConfigMutationPreparation,
        stagingSyntaxPlan: SiteWebServingConfigStagingSyntaxExecutionPlan,
        stagingSyntaxProof: SiteProductionDeploymentRealVpsWebServingConfigStagingSyntaxExecutionProof,
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof =
        SiteProductionDeploymentAndroidRealVpsWebServingConfigActivationExecutionBoundary.executeOnce(
            publicationPlan = publicationPlan,
            readOnlyPreflight = readOnlyPreflight,
            mutationPreparation = mutationPreparation,
            stagingSyntaxPlan = stagingSyntaxPlan,
            stagingSyntaxProof = stagingSyntaxProof,
            activationPlan = activationPlan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence
                .realVpsWebServingConfigActivationExecutionUsePort(),
        )

    /**
     * Phase 11.61 consumes one durable pre-reload fence and authorizes exactly one nginx reload
     * after a successful Phase 11.60 activation proof. It performs no config/DNS/firewall/package mutation.
     */
    internal suspend fun siteProductionDeploymentExecuteRealVpsWebServingNginxReloadOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        activationPlan: SiteWebServingConfigActivationExecutionPlan,
        activationProof: SiteProductionDeploymentRealVpsWebServingConfigActivationExecutionProof,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof =
        SiteProductionDeploymentAndroidRealVpsWebServingNginxReloadExecutionBoundary.executeOnce(
            publicationPlan = publicationPlan,
            activationPlan = activationPlan,
            activationProof = activationProof,
            reloadPlan = reloadPlan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
            executionUsePort = siteProductionDeploymentReplayFence.realVpsWebServingNginxReloadExecutionUsePort(),
        )

    /**
     * Phase 11.62 performs one bounded read-only HTTP GET over the remote loopback interface after
     * the accepted Phase 11.61 reload proof. It proves exact generated index bytes without claiming
     * external reachability and grants no config/DNS/firewall/package mutation.
     */
    internal suspend fun siteProductionDeploymentVerifyRealVpsWebServingLiveHttpOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        reloadPlan: SiteWebServingNginxReloadExecutionPlan,
        reloadProof: SiteProductionDeploymentRealVpsWebServingNginxReloadExecutionProof,
        verificationPlan: SiteWebServingLiveHttpVerificationPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof =
        SiteProductionDeploymentAndroidRealVpsWebServingLiveHttpVerificationExecutionBoundary.executeOnce(
            publicationPlan = publicationPlan,
            reloadPlan = reloadPlan,
            reloadProof = reloadProof,
            verificationPlan = verificationPlan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )

    /**
     * Phase 11.63 performs one bounded external plain-HTTP probe from this Android device to the
     * exact literal IPv4 host/port after the accepted Phase 11.62 loopback proof. It does not use
     * DNS and grants no firewall/config/package/TLS mutation authority.
     */
    internal suspend fun siteProductionDeploymentVerifyExternalHttpReachabilityOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        loopbackVerificationPlan: SiteWebServingLiveHttpVerificationPlan,
        loopbackProof: SiteProductionDeploymentRealVpsWebServingLiveHttpVerificationExecutionProof,
        verificationPlan: SiteWebServingExternalHttpReachabilityVerificationPlan,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionProof =
        SiteProductionDeploymentAndroidExternalHttpReachabilityVerificationExecutionBoundary.executeOnce(
            publicationPlan = publicationPlan,
            loopbackVerificationPlan = loopbackVerificationPlan,
            loopbackProof = loopbackProof,
            verificationPlan = verificationPlan,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )

    internal suspend fun siteProductionDeploymentVerifyDomainDnsResolutionOnce(
        publicationPlan: SiteWebServingPublicationPlan,
        loopbackVerificationPlan: SiteWebServingLiveHttpVerificationPlan,
        externalVerificationPlan: SiteWebServingExternalHttpReachabilityVerificationPlan,
        externalProof: SiteProductionDeploymentExternalHttpReachabilityVerificationExecutionProof,
        verificationPlan: SiteWebServingDomainDnsResolutionVerificationPlan,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentDomainDnsResolutionVerificationExecutionProof =
        SiteProductionDeploymentAndroidDomainDnsResolutionVerificationExecutionBoundary.executeOnce(
            publicationPlan = publicationPlan,
            loopbackVerificationPlan = loopbackVerificationPlan,
            externalVerificationPlan = externalVerificationPlan,
            externalProof = externalProof,
            verificationPlan = verificationPlan,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )

    /**
     * Phase 11.65 opens one fresh pinned SSH session and performs only the finite read-only 3x-ui
     * certificate reuse eligibility observation. Private-key bytes are never read and HTTPS is not
     * configured by this boundary.
     */
    internal suspend fun siteProductionDeploymentObserveRealVpsExisting3xUiCertificateReuseEligibilityOnce(
        plan: SiteExisting3xUiCertificateReuseEligibilityPlan,
        freshResolutionProof: SiteProductionDeploymentRealVpsCredentialResolutionExecutionProof,
        freshCredentialLease: SiteProductionDeploymentEphemeralCredentialLease,
        serverAccess: ServerAccess,
        executionAttemptId: String,
        executedAtEpochMillis: Long,
    ): SiteProductionDeploymentRealVpsExisting3xUiCertificateReuseEligibilityExecutionProof =
        SiteProductionDeploymentAndroidRealVpsExisting3xUiCertificateReuseEligibilityExecutionBoundary.observeOnce(
            plan = plan,
            freshResolutionProof = freshResolutionProof,
            freshCredentialLease = freshCredentialLease,
            serverAccess = serverAccess,
            executionAttemptId = executionAttemptId,
            executedAtEpochMillis = executedAtEpochMillis,
        )

    internal val operationRuntimeCoordinator: OperationRuntimeCoordinator
        get() = runtimeGraph.coordinator

    internal val connectivityObserver: AndroidDefaultNetworkObserver
        get() = runtimeGraph.connectivityObserver

    internal val exitInfoAdapter: AndroidApplicationExitInfoAdapter
        get() = runtimeGraph.exitInfoAdapter

    internal fun visibleDiscoveryOperationLauncher(activity: Activity): VisibleDiscoveryOperationLauncher =
        VisibleDiscoveryOperationLauncher(
            activity = activity,
            journal = runtimeGraph.journal,
            resultRegistry = discoveryResultRegistry,
        )

    internal fun discoveryResultProjector(): DiscoveryResultProjector =
        DiscoveryResultProjector(runtimeGraph.journal, discoveryResultRegistry)

    internal fun visibleManagementQuickInspectOperationLauncher(
        activity: Activity,
    ): VisibleManagementQuickInspectOperationLauncher =
        VisibleManagementQuickInspectOperationLauncher(
            activity = activity,
            journal = runtimeGraph.journal,
            installationRepository = runtimeGraph.installationRepository,
            managementAccessRepository = runtimeGraph.managementAccessRepository,
            resultRegistry = managementResultRegistry,
        )

    internal fun managementResultProjector(): ManagementResultProjector =
        ManagementResultProjector(runtimeGraph.journal, managementResultRegistry)

    internal fun managementInspectionStatusPort(): com.velumtegra.xuimobile.management.ManagementInspectionStatusPort =
        com.velumtegra.xuimobile.management.ManagementInspectionStatusReader(
            managementResultProjector(), deepDiagnosticResultProjector(), runtimeGraph.journal,
        )

    internal fun serviceLogStatusPort(): com.velumtegra.xuimobile.management.ServiceLogStatusPort =
        com.velumtegra.xuimobile.management.JournalServiceLogStatusPort(runtimeGraph.journal, serviceLogResultRegistry)
    internal fun visibleServiceLogActionPort(activity: Activity, local: com.velumtegra.xuimobile.management.ManagementLocalReviewPort):
        com.velumtegra.xuimobile.management.ServiceLogActionPort =
        com.velumtegra.xuimobile.management.ProductionServiceLogActionPort(activity, local, runtimeGraph.journal, serviceLogResultRegistry)

    internal fun updatePreflightStatusPort(): com.velumtegra.xuimobile.management.UpdatePreflightStatusPort =
        com.velumtegra.xuimobile.management.JournalUpdatePreflightStatusPort(runtimeGraph.journal, updatePreflightResultRegistry,
            runtimeGraph.installationRepository, runtimeGraph.serverAccessRepository, runtimeGraph.managementAccessRepository)
    internal fun updatePackagePreparationPort(): com.velumtegra.xuimobile.management.UpdatePackagePreparationPort = updatePackagePort
    internal fun visibleUpdatePreflightActionPort(activity: Activity, local: com.velumtegra.xuimobile.management.ManagementLocalReviewPort):
        com.velumtegra.xuimobile.management.UpdatePreflightActionPort =
        com.velumtegra.xuimobile.management.ProductionUpdatePreflightActionPort(activity, local, runtimeGraph.journal, updatePreflightResultRegistry)

    internal fun managementInspectionHistoryPort(): com.velumtegra.xuimobile.management.ManagementInspectionHistoryPort =
        com.velumtegra.xuimobile.management.JournalManagementInspectionHistoryPort(runtimeGraph.inspectionInventory)

    internal fun backupArchiveHistoryPort(): com.velumtegra.xuimobile.management.ManagementBackupArchiveHistoryPort =
        com.velumtegra.xuimobile.management.JournalBackupArchiveHistoryPort(runtimeGraph.backupArchiveInventory, managementRestartLocalPort)

    internal val managementRestartLocalPort: com.velumtegra.xuimobile.management.ManagementRestartLocalPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            com.velumtegra.xuimobile.management.RepositoryManagementRestartLocalPort(runtimeGraph.serverRepository,
                runtimeGraph.installationRepository, runtimeGraph.serverAccessRepository, runtimeGraph.managementAccessRepository)
        }
    internal val managementXuiServerMenu by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.management.ManagementXuiServerMenu(
            managementRestartLocalPort, runtimeGraph.connectionFactory, runtimeGraph.journal, runtimeGraph.coordinator,
        )
    }
    internal val managementPanelTlsReader by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.management.ManagementPanelTlsReader(
            managementRestartLocalPort, runtimeGraph.connectionFactory,
        )
    }
    internal val managementPanelAccessPort by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.management.ManagementPanelAccessPort(
            managementRestartLocalPort, runtimeGraph.connectionFactory, runtimeGraph.journal, runtimeGraph.coordinator,
            runtimeGraph.webPanelAccessRepository, runtimeGraph.credentialTransactions, linkedWebPanelCredentialPort,
            runtimeGraph.installationRepository,
            onLocalLeftovers = { sweepLocalStorageInBackground() },
        )
    }
    internal val managementPanelCredentialsReader by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        com.velumtegra.xuimobile.management.ManagementPanelCredentialsReader(
            managementRestartLocalPort, runtimeGraph.connectionFactory,
        )
    }
    internal fun databaseBackupStatusPort(): com.velumtegra.xuimobile.management.DatabaseBackupStatusPort =
        com.velumtegra.xuimobile.management.JournalDatabaseBackupStatusPort(runtimeGraph.journal, managementRestartLocalPort, databaseBackupResultRegistry, { id, profile -> runtimeGraph.coordinator.databaseBackupSlotInventory(id, profile) })
    internal fun visibleDatabaseBackupActionPort(activity: Activity): com.velumtegra.xuimobile.management.DatabaseBackupActionPort =
        com.velumtegra.xuimobile.management.ProductionDatabaseBackupActionPort(activity, managementRestartLocalPort,
            updatePreflightStatusPort(), runtimeGraph.journal, runtimeGraph.coordinator, databaseBackupResultRegistry)

    internal fun installationBackupStatusPort(): com.velumtegra.xuimobile.management.InstallationBackupStatusPort =
        com.velumtegra.xuimobile.management.JournalInstallationBackupStatusPort(runtimeGraph.journal, managementRestartLocalPort, installationBackupResultRegistry, { id, profile -> runtimeGraph.coordinator.installationBackupSlotInventory(id, profile) })
    internal fun visibleInstallationBackupActionPort(activity: Activity): com.velumtegra.xuimobile.management.InstallationBackupActionPort =
        com.velumtegra.xuimobile.management.ProductionInstallationBackupActionPort(activity, managementRestartLocalPort,
            updatePreflightStatusPort(), runtimeGraph.journal, runtimeGraph.coordinator, installationBackupResultRegistry)

    internal fun restoreCheckStatusPort(): com.velumtegra.xuimobile.management.RestoreCheckStatusPort =
        com.velumtegra.xuimobile.management.JournalRestoreCheckStatusPort(runtimeGraph.journal, managementRestartLocalPort, restoreCheckResultRegistry,
            verified = runtimeGraph.restoreCheckInventory)
    internal fun visibleRestoreCheckActionPort(activity: Activity): com.velumtegra.xuimobile.management.RestoreCheckActionPort =
        com.velumtegra.xuimobile.management.ProductionRestoreCheckActionPort(activity, managementRestartLocalPort,
            runtimeGraph.journal, runtimeGraph.coordinator, restoreCheckResultRegistry)

    internal val compensatedPanelStartPort:com.velumtegra.xuimobile.management.CompensatedPanelStartPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED){
            com.velumtegra.xuimobile.management.RepositoryCompensatedPanelStartPort(managementRestartLocalPort,runtimeGraph.journal,runtimeGraph.connectionFactory,
                {server,operation,action->runtimeGraph.coordinator.withBeforeCopyReturnLease(server,operation,action)})
        }

    internal val beforeCopyReturnPort:com.velumtegra.xuimobile.management.BeforeCopyReturnPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED){
            com.velumtegra.xuimobile.management.RepositoryBeforeCopyReturnPort(managementRestartLocalPort,runtimeGraph.journal,runtimeGraph.connectionFactory,
                {server,operation,action->runtimeGraph.coordinator.withBeforeCopyReturnLease(server,operation,action)})
        }

    internal val knownFileRestorePort:com.velumtegra.xuimobile.management.KnownFileRestorePort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED){
            com.velumtegra.xuimobile.management.RepositoryKnownFileRestorePort(managementRestartLocalPort,runtimeGraph.journal,runtimeGraph.connectionFactory,
                {server,operation,action->runtimeGraph.coordinator.withBeforeCopyReturnLease(server,operation,action)})
        }

    internal val recoveryReadinessPort:com.velumtegra.xuimobile.management.RecoveryReadinessPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED){
            com.velumtegra.xuimobile.management.RepositoryRecoveryReadinessPort(managementRestartLocalPort,runtimeGraph.journal,runtimeGraph.connectionFactory,
                {server,operation,read->runtimeGraph.coordinator.withRecoveryPanelReadLease(server,operation,read)})
        }

    internal val beforeCopyEvidencePort:com.velumtegra.xuimobile.management.BeforeCopyEvidencePort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED){
            com.velumtegra.xuimobile.management.RepositoryBeforeCopyEvidencePort(managementRestartLocalPort,runtimeGraph.journal,runtimeGraph.connectionFactory,
                {server,operation,read->runtimeGraph.coordinator.withRecoveryPanelReadLease(server,operation,read)})
        }

    internal val recoveryPanelCheckPort: com.velumtegra.xuimobile.management.RecoveryPanelCheckPort
        by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            val pins = com.velumtegra.xuimobile.inventory.PrivatePanelCertificatePins(this)
            com.velumtegra.xuimobile.management.RepositoryRecoveryPanelCheckPort(
                managementRestartLocalPort, runtimeGraph.journal, restoredPanelStartStatusPort(), runtimeGraph.webPanelAccessRepository,
                com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver(runtimeGraph.webPanelAccessRepository,
                    runtimeGraph.installationRepository,runtimeGraph.serverRepository,runtimeGraph.serverAccessRepository),
                com.velumtegra.xuimobile.core.webpanel.OkHttpWebPanelAuthenticationClient(runtimeGraph.webPanelAccessRepository,runtimeGraph.secretStore),
                runtimeGraph.connectionFactory,pins::read,
                { server, operation, read -> runtimeGraph.coordinator.withRecoveryPanelReadLease(server,operation,read) },
                compensatedSource = { server, installation, access, operation -> compensatedPanelStartPort.verifiedSource(server,installation,access,operation) },
            )
        }

    internal fun restoredPanelStartStatusPort():com.velumtegra.xuimobile.management.RestoredPanelStartStatusPort=
        com.velumtegra.xuimobile.management.JournalRestoredPanelStartStatusPort(runtimeGraph.journal,managementRestartLocalPort,restoredPanelStartResultRegistry)
    internal fun visibleRestoredPanelStartActionPort(activity:Activity):com.velumtegra.xuimobile.management.RestoredPanelStartActionPort=
        com.velumtegra.xuimobile.management.ProductionRestoredPanelStartActionPort(activity,managementRestartLocalPort,runtimeGraph.journal,
            restoredPanelStartStatusPort(),runtimeGraph.coordinator,restoredPanelStartResultRegistry)
    internal fun workingDatabaseRestoreStatusPort():com.velumtegra.xuimobile.management.WorkingDatabaseRestoreStatusPort=
        com.velumtegra.xuimobile.management.JournalWorkingDatabaseRestoreStatusPort(runtimeGraph.journal,managementRestartLocalPort,restoreCompatibilityStatusPort(),workingDatabaseRestoreResultRegistry)
    internal fun visibleWorkingDatabaseRestoreActionPort(activity:Activity):com.velumtegra.xuimobile.management.WorkingDatabaseRestoreActionPort=
        com.velumtegra.xuimobile.management.ProductionWorkingDatabaseRestoreActionPort(activity,managementRestartLocalPort,runtimeGraph.journal,
            workingDatabaseRestoreStatusPort(),runtimeGraph.coordinator,workingDatabaseRestoreResultRegistry)
    internal fun restoreCompatibilityStatusPort(): com.velumtegra.xuimobile.management.RestoreCompatibilityStatusPort =
        com.velumtegra.xuimobile.management.JournalRestoreCompatibilityStatusPort(runtimeGraph.journal, managementRestartLocalPort, restoreCompatibilityResultRegistry)
    internal fun visibleRestoreCompatibilityActionPort(activity: Activity): com.velumtegra.xuimobile.management.RestoreCompatibilityActionPort =
        com.velumtegra.xuimobile.management.ProductionRestoreCompatibilityActionPort(activity, managementRestartLocalPort,
            runtimeGraph.journal, restoreCompatibilityResultRegistry)

    internal fun visibleXuiFreshInstallActionPort(activity: Activity): com.velumtegra.xuimobile.discovery.XuiFreshInstallActionPort =
        com.velumtegra.xuimobile.discovery.ProductionXuiFreshInstallActionPort(
            runtimeGraph.serverRepository, runtimeGraph.serverAccessRepository, runtimeGraph.installationRepository,
            runtimeGraph.journal,
            object : com.velumtegra.xuimobile.discovery.XuiFreshInstallConsentRuntime {
                override fun register(consent: com.velumtegra.xuimobile.core.runtime.InstallerExplicitInstallConsent) =
                    runtimeGraph.coordinator.registerInstallerExplicitInstallConsent(consent)
                override fun discard(operationId: com.velumtegra.xuimobile.core.model.OperationId) =
                    runtimeGraph.coordinator.discardInstallerExplicitInstallConsent(operationId)
            },
            { id -> com.velumtegra.xuimobile.runtime.VisibleExactOperationHostLauncher(activity).start(id) },
        )

    internal fun managementRestartStatusPort(): com.velumtegra.xuimobile.management.ManagementRestartStatusPort =
        com.velumtegra.xuimobile.management.JournalManagementRestartStatusPort(runtimeGraph.journal)
    internal fun visibleManagementRestartActionPort(activity: Activity): com.velumtegra.xuimobile.management.ManagementRestartActionPort =
        com.velumtegra.xuimobile.management.ProductionManagementRestartActionPort(activity, managementRestartLocalPort,
            runtimeGraph.journal, runtimeGraph.coordinator)

    internal fun visibleDeepDiagnosticOperationLauncher(
        activity: Activity,
    ): VisibleDeepDiagnosticOperationLauncher =
        VisibleDeepDiagnosticOperationLauncher(
            activity = activity,
            journal = runtimeGraph.journal,
            installationRepository = runtimeGraph.installationRepository,
            managementAccessRepository = runtimeGraph.managementAccessRepository,
            resultRegistry = deepDiagnosticResultRegistry,
        )

    internal fun deepDiagnosticResultProjector(): DeepDiagnosticResultProjector =
        DeepDiagnosticResultProjector(runtimeGraph.journal, deepDiagnosticResultRegistry)

    private fun createRuntimeGraph(): RuntimeGraph {
        val appContext = applicationContext
        val database = VelumDatabaseFactory.open(appContext)
        val secretStore = AndroidKeystoreSecretStore(appContext)
        val sessionRegistry = ExactSessionRegistry()
        val connectionFactory = JschSshConnectionFactory(secretStore)
        val journal = RoomOperationJournal(database)
        val serverRepository = RoomServerRepository(database)
        val serverAccessRepository = RoomServerAccessRepository(database)
        val webPanelAccessRepository = RoomWebPanelAccessRepository(database)
        val installationRepository = RoomXuiInstallationRepository(database)
        val managementAccessRepository = RoomManagementAccessRepository(database)
        val managementEnrollmentPublisher = RoomManagementEnrollmentPublisher(database)
        val coordinator = OperationRuntimeCoordinator(
            journal = journal,
            accessRepository = serverAccessRepository,
            connectionFactory = connectionFactory,
            sessionRegistry = sessionRegistry,
            installationRepository = installationRepository,
            managementAccessRepository = managementAccessRepository,
            managementEnrollmentPublisher = managementEnrollmentPublisher,
        )
        val connectivityManager = requireNotNull(
            appContext.getSystemService(ConnectivityManager::class.java),
        ) { "ConnectivityManager is unavailable" }

        // Credential writers and the orphan-secret collector must share ONE coordinator (see GC contract).
        val credentialCoordinator = ProcessCredentialMutationCoordinator()
        return RuntimeGraph(
            coordinator = coordinator,
            connectionFactory = connectionFactory,
            secretStore = secretStore,
            credentialTransactions = CredentialTransactionService(
                secretStore = secretStore,
                serverAccessRepository = serverAccessRepository,
                webPanelAccessRepository = webPanelAccessRepository,
                credentialReferenceWriter = RoomCredentialReferenceWriter(database),
                coordinator = credentialCoordinator,
            ),
            secretGarbageCollector = com.velumtegra.xuimobile.core.domain.ReferenceProvenSecretGarbageCollector(
                secretStore,
                com.velumtegra.xuimobile.core.data.repository.RoomSecretReferenceRepository(database),
                credentialCoordinator,
            ),
            journal = journal,
            serverRepository = serverRepository,
            inspectionInventory = journal,
            backupArchiveInventory = journal,
            restoreCheckInventory = journal,
            serverAccessRepository = serverAccessRepository,
            webPanelAccessRepository = webPanelAccessRepository,
            installationRepository = installationRepository,
            managementAccessRepository = managementAccessRepository,
            managementEnrollmentPublisher = managementEnrollmentPublisher,
            connectivityObserver = AndroidDefaultNetworkObserver(
                connectivityManager = connectivityManager,
                onConnectivityChanged = coordinator::observeConnectivity,
            ),
            exitInfoAdapter = AndroidApplicationExitInfoAdapter(appContext),
        )
    }

    private data class RuntimeGraph(
        val coordinator: OperationRuntimeCoordinator,
        val connectionFactory: SshConnectionFactory,
        val secretStore: AndroidKeystoreSecretStore,
        val credentialTransactions: CredentialTransactionService,
        val secretGarbageCollector: com.velumtegra.xuimobile.core.domain.ReferenceProvenSecretGarbageCollector,
        val journal: OperationJournal,
        val inspectionInventory: com.velumtegra.xuimobile.core.domain.InstallationInspectionInventory,
        val backupArchiveInventory: com.velumtegra.xuimobile.core.domain.InstallationBackupArchiveInventory,
        val restoreCheckInventory: com.velumtegra.xuimobile.core.domain.RestoreCheckResultInventory,
        val serverRepository: RoomServerRepository,
        val serverAccessRepository: RoomServerAccessRepository,
        val webPanelAccessRepository: RoomWebPanelAccessRepository,
        val installationRepository: RoomXuiInstallationRepository,
        val managementAccessRepository: RoomManagementAccessRepository,
        val managementEnrollmentPublisher: RoomManagementEnrollmentPublisher,
        val connectivityObserver: AndroidDefaultNetworkObserver,
        val exitInfoAdapter: AndroidApplicationExitInfoAdapter,
    )
}

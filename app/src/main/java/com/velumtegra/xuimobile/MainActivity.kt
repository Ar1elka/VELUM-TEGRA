package com.velumtegra.xuimobile

import android.os.Bundle
import android.content.Context
import android.graphics.Color as AndroidColor
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModelProvider
import androidx.core.view.WindowCompat
import com.velumtegra.xuimobile.core.scanner.android.RealityScannerForegroundService
import com.velumtegra.xuimobile.feature.home.HomeScreen
import com.velumtegra.xuimobile.inventory.InventorySection
import com.velumtegra.xuimobile.inventory.WebPanelInstallationScope
import com.velumtegra.xuimobile.inventory.InventoryScreen
import com.velumtegra.xuimobile.core.domain.WebPanelScheme
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.inventory.EmbeddedHttpsWebPanelScreen
import com.velumtegra.xuimobile.inventory.SavedDirectWebPanel
import com.velumtegra.xuimobile.inventory.PrivateSshWebPanelScreen
import com.velumtegra.xuimobile.inventory.PrivateWebPanelOpenRequest
import com.velumtegra.xuimobile.enrollment.ServerEnrollmentScreen
import com.velumtegra.xuimobile.management.ManagementLocalReviewScreen
import com.velumtegra.xuimobile.management.ManagementServiceLogsScreen
import com.velumtegra.xuimobile.management.ManagementDatabaseBackupScreen
import com.velumtegra.xuimobile.management.ManagementDatabaseBackupViewModel
import com.velumtegra.xuimobile.management.ManagementDatabaseBackupViewModelFactory
import com.velumtegra.xuimobile.management.ManagementInstallationBackupScreen
import com.velumtegra.xuimobile.management.ManagementRestoreCheckScreen
import com.velumtegra.xuimobile.management.ManagementRestoreCheckViewModel
import com.velumtegra.xuimobile.management.ManagementRestoreCheckViewModelFactory
import com.velumtegra.xuimobile.management.ManagementRestoreCompatibilityScreen
import com.velumtegra.xuimobile.management.ManagementWorkingDatabaseRestoreScreen
import com.velumtegra.xuimobile.management.ManagementWorkingDatabaseRestoreViewModel
import com.velumtegra.xuimobile.management.ManagementWorkingDatabaseRestoreViewModelFactory
import com.velumtegra.xuimobile.management.ManagementRestoredPanelStartScreen
import com.velumtegra.xuimobile.management.ManagementRestoredPanelStartViewModel
import com.velumtegra.xuimobile.management.ManagementRestoredPanelStartViewModelFactory
import com.velumtegra.xuimobile.management.ManagementRestoreCompatibilityViewModel
import com.velumtegra.xuimobile.management.ManagementRestoreCompatibilityViewModelFactory
import com.velumtegra.xuimobile.management.ManagementInstallationBackupViewModel
import com.velumtegra.xuimobile.management.ManagementInstallationBackupViewModelFactory
import com.velumtegra.xuimobile.management.UpdatePreflightPointer
import com.velumtegra.xuimobile.management.ManagementUpdatePreparationScreen
import com.velumtegra.xuimobile.management.ManagementServiceLogsViewModel
import com.velumtegra.xuimobile.management.ManagementUpdatePreparationViewModel
import com.velumtegra.xuimobile.management.ManagementServiceLogsViewModelFactory
import com.velumtegra.xuimobile.management.ManagementUpdatePreparationViewModelFactory
import com.velumtegra.xuimobile.management.ManagementHomeScreen
import com.velumtegra.xuimobile.management.ManagementInspectionHistoryScreen
import com.velumtegra.xuimobile.management.ManagementInspectionHistoryViewModel
import com.velumtegra.xuimobile.management.ManagementInspectionHistoryViewModelFactory
import com.velumtegra.xuimobile.management.ManagementHomeViewModel
import com.velumtegra.xuimobile.management.ManagementHomeViewModelFactory
import com.velumtegra.xuimobile.management.ManagementRestartScreen
import com.velumtegra.xuimobile.core.model.ExistingInstallationServiceAction
import com.velumtegra.xuimobile.management.ManagementRestartViewModel
import com.velumtegra.xuimobile.management.ManagementRestartViewModelFactory
import com.velumtegra.xuimobile.management.RepositoryManagementVersionReadPort
import com.velumtegra.xuimobile.management.RepositoryManagementLocalReviewPort
import com.velumtegra.xuimobile.management.ProductionManagementInspectionsPort
import com.velumtegra.xuimobile.readiness.RepositorySshReadinessPort
import com.velumtegra.xuimobile.readiness.SshReadinessScreen
import com.velumtegra.xuimobile.readiness.LiveSshConnectionScreen
import com.velumtegra.xuimobile.profiles.SshProfileManagementScreen
import com.velumtegra.xuimobile.discovery.XuiReadOnlyDiscoveryScreen
import com.velumtegra.xuimobile.scanner.RealityScannerScreen
import com.velumtegra.xuimobile.scanner.ScannerUiProjection
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewScreen
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewViewModel
import com.velumtegra.xuimobile.sitedeployer.SiteDeployerReviewViewModelFactory
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import kotlinx.coroutines.delay

private enum class DashboardDestination(val label: String) {
    HOME("Главная"),
    SERVERS("Серверы"),
    MANAGEMENT("X-UI"),
    WEB_PANEL("Веб-панель"),
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = application as VelumTegraApplication
        if (savedInstanceState == null) app.sweepLocalStorageInBackground()
        val siteDeployerReviewViewModel = ViewModelProvider(
            this,
            SiteDeployerReviewViewModelFactory(
                app.siteDeployerProductionExecutionPort,
                app.siteDeployerReleaseBootstrapPort,
            ),
        )[SiteDeployerReviewViewModel::class.java]

        val sshReadinessPort by lazy(LazyThreadSafetyMode.NONE) { RepositorySshReadinessPort(
            app.inventoryServerRepository, app.inventoryServerAccessRepository,
        ) }
        val managementReviewPort by lazy(LazyThreadSafetyMode.NONE) { RepositoryManagementLocalReviewPort(
            app.inventoryServerRepository,
            app.inventoryInstallationRepository,
            app.inventoryManagementRepository,
            app.inventoryServerAccessRepository,
        ) }
        val managementInspections by lazy(LazyThreadSafetyMode.NONE) {
            ProductionManagementInspectionsPort(this, app, managementReviewPort)
        }
        val managementStatus by lazy(LazyThreadSafetyMode.NONE) { app.managementInspectionStatusPort() }
        val serviceLogStatuses by lazy(LazyThreadSafetyMode.NONE) { app.serviceLogStatusPort() }
        val serviceLogActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleServiceLogActionPort(this, managementReviewPort) }
        val updatePreflightStatuses by lazy(LazyThreadSafetyMode.NONE) { app.updatePreflightStatusPort() }
        val updatePreflightActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleUpdatePreflightActionPort(this, managementReviewPort) }
        val backupStatuses by lazy(LazyThreadSafetyMode.NONE) { app.databaseBackupStatusPort() }
        val backupActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleDatabaseBackupActionPort(this) }
        val installationBackupStatuses by lazy(LazyThreadSafetyMode.NONE) { app.installationBackupStatusPort() }
        val installationBackupActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleInstallationBackupActionPort(this) }
        val restoreCheckStatuses by lazy(LazyThreadSafetyMode.NONE) { app.restoreCheckStatusPort() }
        val restoreCheckActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleRestoreCheckActionPort(this) }
        val restoreCompatibilityActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleRestoreCompatibilityActionPort(this) }
        val restoreCompatibilityStatuses by lazy(LazyThreadSafetyMode.NONE) { app.restoreCompatibilityStatusPort() }
        val workingDatabaseRestoreActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleWorkingDatabaseRestoreActionPort(this) }
        val restoredPanelStartActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleRestoredPanelStartActionPort(this) }
        val restoredPanelStartStatuses by lazy(LazyThreadSafetyMode.NONE) { app.restoredPanelStartStatusPort() }
        val workingDatabaseRestoreStatuses by lazy(LazyThreadSafetyMode.NONE) { app.workingDatabaseRestoreStatusPort() }
        val inspectionHistory by lazy(LazyThreadSafetyMode.NONE) { app.managementInspectionHistoryPort() }
        val backupArchiveHistory by lazy(LazyThreadSafetyMode.NONE) { app.backupArchiveHistoryPort() }
        val restartStatuses by lazy(LazyThreadSafetyMode.NONE) { app.managementRestartStatusPort() }
        val restartActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleManagementRestartActionPort(this) }
        val freshInstallActions by lazy(LazyThreadSafetyMode.NONE) { app.visibleXuiFreshInstallActionPort(this) }
        val managementVersions by lazy(LazyThreadSafetyMode.NONE) {
            RepositoryManagementVersionReadPort(
                managementReviewPort, app.inventoryInstallationRepository, app.xuiReadOnlyDiscoveryPort,
            )
        }
        val displayPrefs = getSharedPreferences("velum_tegra_next_display", Context.MODE_PRIVATE)
        setContent {
            // First launch is dark independently of the phone's system theme.
            // Persist only this app-local preference; never alter Android's theme or server data.
            var darkTheme by remember { mutableStateOf(displayPrefs.getBoolean("dark_theme_enabled", true)) }
            SideEffect {
                // Match status/navigation bar contrast to the explicitly selected app theme.
                @Suppress("DEPRECATION")
                window.statusBarColor = if (darkTheme) AndroidColor.rgb(5, 5, 5) else AndroidColor.rgb(248, 248, 248)
                @Suppress("DEPRECATION")
                window.navigationBarColor = AndroidColor.rgb(5, 5, 5)
                WindowCompat.getInsetsController(window, window.decorView).apply {
                    isAppearanceLightStatusBars = !darkTheme
                    isAppearanceLightNavigationBars = false
                }
            }
            VelumTegraTheme(darkTheme = darkTheme) {
                var destination by rememberSaveable { mutableStateOf(DashboardDestination.HOME) }
                var scannerOpened by rememberSaveable { mutableStateOf(false) }
                var siteDeployerOpened by rememberSaveable { mutableStateOf(false) }
                var sshPortOpened by rememberSaveable { mutableStateOf(false) }
                var blocklistOpened by rememberSaveable { mutableStateOf(false) }
                var createServerOpened by rememberSaveable { mutableStateOf(false) }
                var accessServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var accessServerName by rememberSaveable { mutableStateOf<String?>(null) }
                var readinessServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var readinessServerName by rememberSaveable { mutableStateOf<String?>(null) }
                var profilesServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var profilesServerName by rememberSaveable { mutableStateOf<String?>(null) }
                var xuiDiscoveryServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var xuiDiscoveryServerName by rememberSaveable { mutableStateOf<String?>(null) }
                var liveSshServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var liveSshServerName by rememberSaveable { mutableStateOf<String?>(null) }
                var managementReviewServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var managementReviewInstallationId by rememberSaveable { mutableStateOf<String?>(null) }
                var managementDetailsOpened by rememberSaveable { mutableStateOf(false) }
                var serviceLogsAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var updatePreparationAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var backupPreparationAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var installationBackupSourceId by rememberSaveable { mutableStateOf<String?>(null) }
                var installationBackupAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var restoreCheckSourceId by rememberSaveable { mutableStateOf<String?>(null) }
                var restoreCheckAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var restoreCompatibilitySourceId by rememberSaveable { mutableStateOf<String?>(null) }
                var restoreCompatibilityAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var beforeCopyOperationId by rememberSaveable { mutableStateOf<String?>(null) }
                var beforeReturnOperationId by rememberSaveable { mutableStateOf<String?>(null) }
                var knownFileComparisonId by rememberSaveable { mutableStateOf<String?>(null) }
                var knownFileAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var knownFileNonce by rememberSaveable { mutableStateOf<String?>(null) }
                var knownFileReadiness by remember { mutableStateOf<com.velumtegra.xuimobile.core.model.RecoveryReadinessEvidence?>(null) }
                var compensatedStartOperationId by rememberSaveable { mutableStateOf<String?>(null) }
                var compensatedStartAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var beforeReturnAllowed by rememberSaveable { mutableStateOf(false) }
                var beforeReturnEvidence by remember { mutableStateOf<com.velumtegra.xuimobile.core.model.BeforeCopyEvidence?>(null) }
                var recoveryPanelOperationId by rememberSaveable { mutableStateOf<String?>(null) }
                var restoredPanelStartSourceId by rememberSaveable { mutableStateOf<String?>(null) }
                var restoredPanelStartAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var workingDatabaseRestoreSourceId by rememberSaveable { mutableStateOf<String?>(null) }
                var workingDatabaseRestoreAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var workingDatabaseRestorePinnedId by rememberSaveable { mutableStateOf<String?>(null) }
                var databaseBackupSourceId by rememberSaveable { mutableStateOf<String?>(null) }
                var databaseBackupAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var inspectionHistoryOpened by rememberSaveable { mutableStateOf(false) }
                var managementMenuAccessId by remember { mutableStateOf<String?>(null) }
                var managementRestartAccessId by rememberSaveable { mutableStateOf<String?>(null) }
                var managementServiceAction by rememberSaveable { mutableStateOf(ExistingInstallationServiceAction.RESTART) }
                fun openServiceAction(accessId: String, action: ExistingInstallationServiceAction) {
                    managementServiceAction = action
                    managementRestartAccessId = accessId
                }
                var profilesReturnServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var profilesReturnInstallationId by rememberSaveable { mutableStateOf<String?>(null) }
                var enrollmentReturnProfilesServerId by rememberSaveable { mutableStateOf<String?>(null) }
                var enrollmentReturnProfilesServerName by rememberSaveable { mutableStateOf<String?>(null) }
                // Keep the user-authorized HTTPS destination inside this Activity only.
                // No credentials are inferred, copied or inserted into a WebView URL.
                var embeddedHttpsPanelUrl by rememberSaveable { mutableStateOf<String?>(null) }
                var savedDirectPanel by remember { mutableStateOf<SavedDirectWebPanel?>(null) }
                val openSavedDirectPanel: (SavedDirectWebPanel) -> Unit = { saved ->
                    savedDirectPanel = saved
                    embeddedHttpsPanelUrl = saved.url
                }
                val openManualPanel: (String) -> Unit = { url ->
                    savedDirectPanel = null
                    embeddedHttpsPanelUrl = url
                }
                // Scoped Web Panel list opened from Management; management route state stays untouched.
                var scopedPanelOpened by rememberSaveable { mutableStateOf(false) }
                var privateWebPanelRequest by remember { mutableStateOf<PrivateWebPanelOpenRequest?>(null) }
                fun closeManagementReview() {
                    scopedPanelOpened = false
                    installationBackupSourceId = null; installationBackupAccessId = null
                    restoreCheckSourceId = null; restoreCheckAccessId = null
                    restoreCompatibilitySourceId = null; restoreCompatibilityAccessId = null
                    knownFileComparisonId=null;knownFileAccessId=null;knownFileNonce=null;knownFileReadiness=null
                                        workingDatabaseRestoreSourceId = null; workingDatabaseRestoreAccessId = null; workingDatabaseRestorePinnedId = null
                    restoredPanelStartSourceId = null; restoredPanelStartAccessId = null; recoveryPanelOperationId = null; beforeCopyOperationId = null; beforeReturnOperationId=null; beforeReturnEvidence=null; beforeReturnAllowed=false;compensatedStartOperationId=null;compensatedStartAccessId=null
                    databaseBackupSourceId = null
                    databaseBackupAccessId = null
                    serviceLogsAccessId = null
                    updatePreparationAccessId = null
                    backupPreparationAccessId = null
                    inspectionHistoryOpened = false
                    managementDetailsOpened = false
                    managementRestartAccessId = null
                    managementMenuAccessId = null
                    managementReviewServerId = null
                    managementReviewInstallationId = null
                }
                fun closeEnrollment() {
                    createServerOpened = false
                    accessServerId = null
                    accessServerName = null
                    if (enrollmentReturnProfilesServerId != null) {
                        profilesServerId = enrollmentReturnProfilesServerId
                        profilesServerName = enrollmentReturnProfilesServerName
                        enrollmentReturnProfilesServerId = null
                        enrollmentReturnProfilesServerName = null
                    }
                }
                var scannerHomeState by remember {
                    mutableStateOf(
                        ScannerUiProjection.home(
                            RealityScannerForegroundService.state(this@MainActivity),
                        ),
                    )
                }

                LaunchedEffect(Unit) {
                    RealityScannerForegroundService.ensureRunning(this@MainActivity)
                    while (true) {
                        scannerHomeState = ScannerUiProjection.home(
                            RealityScannerForegroundService.state(this@MainActivity),
                        )
                        delay(750)
                    }
                }

                BackHandler(
                    enabled = !scannerOpened && !siteDeployerOpened && !sshPortOpened && !blocklistOpened &&!createServerOpened && accessServerId == null && readinessServerId == null && liveSshServerId == null && profilesServerId == null && xuiDiscoveryServerId == null && managementReviewInstallationId == null && embeddedHttpsPanelUrl == null && privateWebPanelRequest == null && destination != DashboardDestination.HOME,
                ) { destination = DashboardDestination.HOME }

                Scaffold(
                    bottomBar = {
                        if (!scannerOpened && !siteDeployerOpened && !sshPortOpened && !blocklistOpened &&!createServerOpened && accessServerId == null && readinessServerId == null && liveSshServerId == null && profilesServerId == null && xuiDiscoveryServerId == null && managementReviewInstallationId == null && embeddedHttpsPanelUrl == null && privateWebPanelRequest == null) {
                            NavigationBar(modifier = Modifier.testTag("dashboard_navigation"),
                                containerColor = MaterialTheme.colorScheme.surface) {
                                DashboardDestination.entries.forEach { item ->
                                    NavigationBarItem(
                                        selected = destination == item,
                                        onClick = { destination = item },
                                        icon = { DashboardGlyph(item, selected = destination == item) },
                                        label = { Text(item.label) },
                                        alwaysShowLabel = true,
                                        modifier = Modifier.testTag("nav_${item.name.lowercase()}"),
                                    )
                                }
                            }
                        }
                    },
                ) { padding ->
                    // Scaffold only reports system-bar/bottom-bar insets via `padding`; consume them so
                    // screens using safeDrawingPadding() do not pad twice on edge-to-edge Android 15+.
                    // imePadding() keeps focused form fields above the keyboard (no window resize there).
                    Surface(modifier = Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()) {
                        when {
                            privateWebPanelRequest != null -> PrivateSshWebPanelScreen(
                                request = requireNotNull(privateWebPanelRequest),
                                port = app.privateWebPanelSshPort,
                                onClose = { privateWebPanelRequest = null },
                            )
                            embeddedHttpsPanelUrl != null -> EmbeddedHttpsWebPanelScreen(
                                initialUrl = requireNotNull(embeddedHttpsPanelUrl),
                                onClose = {
                                    savedDirectPanel = null
                                    embeddedHttpsPanelUrl = null
                                },
                                savedLoginScript = savedDirectPanel?.takeIf { it.url == embeddedHttpsPanelUrl }
                                    ?.let { saved ->
                                        val loadLogin: suspend (String) -> String? = { pageUrl ->
                                            app.savedWebPanelLogin.fillScript(
                                                WebPanelTargetResolutionRequest(
                                                    saved.target.webPanelAccessId, WebPanelScheme.HTTPS,
                                                ),
                                                saved.target,
                                                pageUrl,
                                            )
                                        }
                                        loadLogin
                                    },
                            )
                            scannerOpened -> RealityScannerScreen(
                                modifier = Modifier.fillMaxSize(),
                                onBack = { scannerOpened = false },
                            )
                            sshPortOpened -> com.velumtegra.xuimobile.sshport.SshPortScreen(
                                migration = app.sshPortMigration, onBack = { sshPortOpened = false },
                            )
                            blocklistOpened -> com.velumtegra.xuimobile.blocklist.AsBlocklistScreen(
                                manager = app.asBlocklistManager, onBack = { blocklistOpened = false },
                            )
                            siteDeployerOpened -> SiteDeployerReviewScreen(
                                viewModel = siteDeployerReviewViewModel,
                                onBack = { siteDeployerOpened = false },
                                modifier = Modifier.fillMaxSize(),
                            )
                            scopedPanelOpened && managementReviewServerId != null && managementReviewInstallationId != null -> InventoryScreen(
                                section = InventorySection.WEB_PANEL,
                                webPanelScope = WebPanelInstallationScope(
                                    requireNotNull(managementReviewServerId), requireNotNull(managementReviewInstallationId),
                                ),
                                onBackToManagement = { scopedPanelOpened = false },
                                linkedCredentialPort = app.linkedWebPanelCredentialPort,
                                serverRepository = app.inventoryServerRepository,
                                serverAccessRepository = app.inventoryServerAccessRepository,
                                installationRepository = app.inventoryInstallationRepository,
                                managementAccessRepository = app.inventoryManagementRepository,
                                webPanelAccessRepository = app.inventoryWebPanelRepository,
                                onOpenWebPanelInApp = openManualPanel,
                                onOpenSavedWebPanel = openSavedDirectPanel,
                                onOpenPrivateWebPanel = { request -> privateWebPanelRequest = request },
                            )
                            managementReviewInstallationId != null -> {
                                val server = managementReviewServerId.orEmpty()
                                val installation = managementReviewInstallationId.orEmpty()
                                if(knownFileComparisonId!=null && knownFileAccessId!=null && knownFileNonce!=null){
                                    val comparison=requireNotNull(knownFileComparisonId);val access=requireNotNull(knownFileAccessId);val nonce=requireNotNull(knownFileNonce)
                                    val model=remember(server,installation,access,comparison,nonce){
                                        val key=listOf(server,installation,access,comparison,nonce).joinToString(""){it.length.toString()+":"+it}
                                        ViewModelProvider(this@MainActivity,com.velumtegra.xuimobile.management.ManagementKnownFileRestoreViewModelFactory(this@MainActivity,
                                            server,installation,access,comparison,knownFileReadiness,app.knownFileRestorePort))["known-file-restore:"+key,com.velumtegra.xuimobile.management.ManagementKnownFileRestoreViewModel::class.java]
                                    }
                                    com.velumtegra.xuimobile.management.ManagementKnownFileRestoreScreen(model,onBack={knownFileComparisonId=null;knownFileAccessId=null;knownFileNonce=null;knownFileReadiness=null})
                                }else if(compensatedStartOperationId!=null && compensatedStartAccessId!=null){
                                    val operation=requireNotNull(compensatedStartOperationId);val access=requireNotNull(compensatedStartAccessId)
                                    val model=remember(server,installation,access,operation){
                                        val key=listOf(server,installation,access,operation).joinToString(""){it.length.toString()+":"+it}
                                        ViewModelProvider(this@MainActivity,com.velumtegra.xuimobile.management.ManagementCompensatedPanelStartViewModelFactory(this@MainActivity,
                                            server,installation,access,operation,app.compensatedPanelStartPort))["compensated-panel-start:"+key,com.velumtegra.xuimobile.management.ManagementCompensatedPanelStartViewModel::class.java]
                                    }
                                    if(recoveryPanelOperationId!=null){
                                        val checkModel=remember(server,installation,access,operation){
                                            val key=listOf(server,installation,access,operation).joinToString(""){it.length.toString()+":"+it}
                                            ViewModelProvider(this@MainActivity,com.velumtegra.xuimobile.management.ManagementRecoveryPanelCheckViewModelFactory(this@MainActivity,
                                                server,installation,access,operation,app.recoveryPanelCheckPort))["compensated-panel-auth:"+key,com.velumtegra.xuimobile.management.ManagementRecoveryPanelCheckViewModel::class.java]
                                        }
                                        com.velumtegra.xuimobile.management.ManagementRecoveryPanelCheckScreen(checkModel,onBack={recoveryPanelOperationId=null},onWebPanels={closeManagementReview();destination=DashboardDestination.WEB_PANEL})
                                    }else com.velumtegra.xuimobile.management.ManagementCompensatedPanelStartScreen(model,onBack={compensatedStartOperationId=null;compensatedStartAccessId=null},onCheckLogin={recoveryPanelOperationId=it})
                                }else if(restoredPanelStartSourceId!=null && restoredPanelStartAccessId!=null){
                                    val access=requireNotNull(restoredPanelStartAccessId);val source=requireNotNull(restoredPanelStartSourceId)
                                    val startModel=remember(server,installation,access,source){
                                        val key=listOf(server,installation,access,source).joinToString(""){it.length.toString()+":"+it}
                                        ViewModelProvider(this@MainActivity,ManagementRestoredPanelStartViewModelFactory(this@MainActivity,server,installation,access,source,
                                            app.managementRestartLocalPort,restoredPanelStartStatuses))["xui-restored-panel-start:"+key,ManagementRestoredPanelStartViewModel::class.java]
                                    }
                                    if(recoveryPanelOperationId!=null){
                                        val operation=requireNotNull(recoveryPanelOperationId)
                                        val checkModel=remember(server,installation,access,operation){
                                            val key=listOf(server,installation,access,operation).joinToString(""){it.length.toString()+":"+it}
                                            ViewModelProvider(this@MainActivity,com.velumtegra.xuimobile.management.ManagementRecoveryPanelCheckViewModelFactory(this@MainActivity,
                                                server,installation,access,operation,app.recoveryPanelCheckPort))["recovery-panel-check:"+key,com.velumtegra.xuimobile.management.ManagementRecoveryPanelCheckViewModel::class.java]
                                        }
                                        com.velumtegra.xuimobile.management.ManagementRecoveryPanelCheckScreen(checkModel,onBack={recoveryPanelOperationId=null},onWebPanels={closeManagementReview();destination=DashboardDestination.WEB_PANEL})
                                    }else ManagementRestoredPanelStartScreen(startModel,restoredPanelStartActions,onBack={restoredPanelStartSourceId=null;restoredPanelStartAccessId=null},onWebPanels={
                                        closeManagementReview();destination=DashboardDestination.WEB_PANEL
                                    },onCheckLogin={recoveryPanelOperationId=it})
                                }else if(workingDatabaseRestoreSourceId!=null && workingDatabaseRestoreAccessId!=null){
                                    val access=requireNotNull(workingDatabaseRestoreAccessId);val source=requireNotNull(workingDatabaseRestoreSourceId)
                                    val pinnedOperation=workingDatabaseRestorePinnedId
                                    val restoreDatabaseModel=remember(server,installation,access,source,pinnedOperation){
                                        val key = listOf(server, installation, access, source).joinToString("") { it.length.toString() + ":" + it }
                                        val modelKey = if (pinnedOperation == null) "xui-working-database-restore:" + key
                                            else "xui-working-database-restore-pinned:" + pinnedOperation.length + ":" + pinnedOperation + ":" + key
                                        ViewModelProvider(this@MainActivity, ManagementWorkingDatabaseRestoreViewModelFactory(
                                            this@MainActivity, server, installation, access, source,
                                            app.managementRestartLocalPort, workingDatabaseRestoreStatuses, pinnedOperation,
                                        ))[modelKey, ManagementWorkingDatabaseRestoreViewModel::class.java]
                                    }
                                    if(beforeCopyOperationId!=null){
                                        val operation=requireNotNull(beforeCopyOperationId)
                                        val beforeModel=remember(server,installation,access,operation){
                                            val key=listOf(server,installation,access,operation).joinToString(""){it.length.toString()+":"+it}
                                            ViewModelProvider(this@MainActivity,com.velumtegra.xuimobile.management.ManagementBeforeCopyEvidenceViewModelFactory(this@MainActivity,
                                                server,installation,access,operation,app.beforeCopyEvidencePort))["before-copy-evidence:"+key,com.velumtegra.xuimobile.management.ManagementBeforeCopyEvidenceViewModel::class.java]
                                        }
                                        if(beforeReturnOperationId!=null){
                                            val returnId=requireNotNull(beforeReturnOperationId)
                                            val returnModel=remember(server,installation,access,returnId,beforeReturnEvidence?.observedAt){
                                                val key=listOf(server,installation,access,returnId,beforeReturnEvidence?.observedAt?.toString()?:"readback").joinToString(""){it.length.toString()+":"+it}
                                                ViewModelProvider(this@MainActivity,com.velumtegra.xuimobile.management.ManagementBeforeCopyReturnViewModelFactory(this@MainActivity,
                                                    server,installation,access,returnId,beforeReturnEvidence,app.beforeCopyReturnPort))["before-copy-return:"+key,com.velumtegra.xuimobile.management.ManagementBeforeCopyReturnViewModel::class.java]
                                            }
                                            com.velumtegra.xuimobile.management.ManagementBeforeCopyReturnScreen(returnModel,onBack={beforeReturnOperationId=null;beforeReturnEvidence=null})
                                        }else com.velumtegra.xuimobile.management.ManagementBeforeCopyEvidenceScreen(beforeModel,onBack={beforeCopyOperationId=null;beforeReturnAllowed=false;compensatedStartOperationId=null;compensatedStartAccessId=null},
                                            onReturn=if(beforeReturnAllowed)({proof:com.velumtegra.xuimobile.core.model.BeforeCopyEvidence?->beforeReturnEvidence=proof;beforeReturnOperationId=operation})else null)
                                    }else ManagementWorkingDatabaseRestoreScreen(restoreDatabaseModel,workingDatabaseRestoreActions,onBack={workingDatabaseRestoreSourceId=null;workingDatabaseRestoreAccessId=null;workingDatabaseRestorePinnedId=null;beforeCopyOperationId=null},onStartService={restoredPanelStartSourceId=it;restoredPanelStartAccessId=access},onInspectBeforeCopy={beforeCopyOperationId=it;beforeReturnAllowed=restoreDatabaseModel.state.value.observation?.mayReturnBeforeCopy==true;beforeReturnOperationId=null;beforeReturnEvidence=null},onStartReturnedPanel={compensatedStartOperationId=it;compensatedStartAccessId=access;recoveryPanelOperationId=null})
                                }else if (restoreCompatibilitySourceId != null && restoreCompatibilityAccessId != null) {
                                    val access = requireNotNull(restoreCompatibilityAccessId)
                                    val source = requireNotNull(restoreCompatibilitySourceId)
                                    val compareModel = remember(server, installation, access, source) {
                                        val key = listOf(server, installation, access, source).joinToString("") { it.length.toString() + ":" + it }
                                        ViewModelProvider(this@MainActivity, ManagementRestoreCompatibilityViewModelFactory(
                                            this@MainActivity, server, installation, access, source,
                                            app.managementRestartLocalPort, restoreCompatibilityStatuses,
                                        ))["xui-restore-comparison:" + key, ManagementRestoreCompatibilityViewModel::class.java]
                                    }
                                    ManagementRestoreCompatibilityScreen(compareModel, restoreCompatibilityActions, onBack = {
                                        restoreCompatibilitySourceId = null; restoreCompatibilityAccessId = null
                    knownFileComparisonId=null;knownFileAccessId=null;knownFileNonce=null;knownFileReadiness=null
                                        workingDatabaseRestoreSourceId = null; workingDatabaseRestoreAccessId = null; workingDatabaseRestorePinnedId = null
                    restoredPanelStartSourceId = null; restoredPanelStartAccessId = null; recoveryPanelOperationId = null; beforeCopyOperationId = null; beforeReturnOperationId=null; beforeReturnEvidence=null; beforeReturnAllowed=false;compensatedStartOperationId=null;compensatedStartAccessId=null
                                    },onRestore={comparisonId->workingDatabaseRestorePinnedId=null;workingDatabaseRestoreSourceId=comparisonId;workingDatabaseRestoreAccessId=access},readiness={observation->
                                        val report=requireNotNull(observation.report)
                                        val planScope=report.scope
                                        val planModel=remember(planScope){
                                            val key=listOf(planScope.serverId.value,planScope.installationId.value,planScope.serverAccessId.value,planScope.operationId.value).joinToString(""){it.length.toString()+":"+it}
                                            ViewModelProvider(this@MainActivity,com.velumtegra.xuimobile.management.ManagementRecoveryReadinessViewModelFactory(
                                                this@MainActivity,planScope,app.recoveryReadinessPort))["recovery-readiness:"+key,com.velumtegra.xuimobile.management.ManagementRecoveryReadinessViewModel::class.java]
                                        }
                                        com.velumtegra.xuimobile.management.ManagementRecoveryReadinessSection(planModel,onRestoreFiles={proof->knownFileComparisonId=proof.scope.operationId.value;knownFileAccessId=proof.scope.serverAccessId.value;knownFileReadiness=proof;knownFileNonce=java.util.UUID.randomUUID().toString()})
                                    })
                                } else if (restoreCheckSourceId != null && restoreCheckAccessId != null) {
                                    val access = requireNotNull(restoreCheckAccessId)
                                    val source = requireNotNull(restoreCheckSourceId)
                                    val restoreModel = remember(server, installation, access, source) {
                                        val key = listOf(server, installation, access, source).joinToString("") { it.length.toString() + ":" + it }
                                        ViewModelProvider(this@MainActivity, ManagementRestoreCheckViewModelFactory(
                                            this@MainActivity, server, installation, access, source,
                                            app.managementRestartLocalPort, restoreCheckStatuses,
                                        ))["xui-restore-check:" + key, ManagementRestoreCheckViewModel::class.java]
                                    }
                                    ManagementRestoreCheckScreen(restoreModel, restoreCheckActions, onBack = {
                                        restoreCheckSourceId = null; restoreCheckAccessId = null
                                        restoreCompatibilitySourceId = null; restoreCompatibilityAccessId = null
                    knownFileComparisonId=null;knownFileAccessId=null;knownFileNonce=null;knownFileReadiness=null
                                        workingDatabaseRestoreSourceId = null; workingDatabaseRestoreAccessId = null; workingDatabaseRestorePinnedId = null
                    restoredPanelStartSourceId = null; restoredPanelStartAccessId = null; recoveryPanelOperationId = null; beforeCopyOperationId = null; beforeReturnOperationId=null; beforeReturnEvidence=null; beforeReturnAllowed=false;compensatedStartOperationId=null;compensatedStartAccessId=null
                                    }, onCompare = { sourceCheck ->
                                        restoreCompatibilitySourceId = sourceCheck; restoreCompatibilityAccessId = access
                                    })
                                } else if (installationBackupSourceId != null && installationBackupAccessId != null) {
                                    val access = requireNotNull(installationBackupAccessId)
                                    val source = requireNotNull(installationBackupSourceId)
                                    val backupModel = remember(server, installation, access, source) {
                                        val key = listOf(server, installation, access, source).joinToString("") { it.length.toString() + ":" + it }
                                        ViewModelProvider(this@MainActivity, ManagementInstallationBackupViewModelFactory(
                                            this@MainActivity, server, installation, access, UpdatePreflightPointer(source, access),
                                            app.managementRestartLocalPort, updatePreflightStatuses, installationBackupStatuses,
                                        ))["xui-installation-backup:" + key, ManagementInstallationBackupViewModel::class.java]
                                    }
                                    ManagementInstallationBackupScreen(backupModel, installationBackupActions, onBack = {
                                        installationBackupSourceId = null; installationBackupAccessId = null
                                    }, onRestoreCheck = { sourceOperation ->
                                        restoreCheckSourceId = sourceOperation; restoreCheckAccessId = access
                                    })
                                } else if (databaseBackupSourceId != null && databaseBackupAccessId != null) {
                                    val access = requireNotNull(databaseBackupAccessId)
                                    val source = requireNotNull(databaseBackupSourceId)
                                    val backupModel = remember(server, installation, access, source) {
                                        val key = listOf(server, installation, access, source).joinToString("") { it.length.toString() + ":" + it }
                                        ViewModelProvider(this@MainActivity, ManagementDatabaseBackupViewModelFactory(
                                            this@MainActivity, server, installation, access, UpdatePreflightPointer(source, access),
                                            app.managementRestartLocalPort, updatePreflightStatuses, backupStatuses,
                                        ))["xui-db-backup:" + key, ManagementDatabaseBackupViewModel::class.java]
                                    }
                                    ManagementDatabaseBackupScreen(backupModel, backupActions, onBack = {
                                        databaseBackupSourceId = null; databaseBackupAccessId = null
                                    })
                                } else if (updatePreparationAccessId != null || backupPreparationAccessId != null) {
                                    val backupMode = updatePreparationAccessId == null
                                    val access = requireNotNull(updatePreparationAccessId ?: backupPreparationAccessId)
                                    val preparationModel = remember(server, installation, access, backupMode) {
                                        ViewModelProvider(this@MainActivity, ManagementUpdatePreparationViewModelFactory(
                                            this@MainActivity, server, installation, access, managementReviewPort,
                                            updatePreflightStatuses, sshReadinessPort,
                                            packages = if (backupMode) null else app.updatePackagePreparationPort(),
                                        ))[(if (backupMode) "xui-backup-preflight:" else "xui-update-preflight:") + server.length + ":" + server + ":" + installation.length + ":" + installation + ":" + access.length + ":" + access,
                                            ManagementUpdatePreparationViewModel::class.java]
                                    }
                                    val archiveModel = if (backupMode) remember(server, installation, access) {
                                        ViewModelProvider(this@MainActivity, com.velumtegra.xuimobile.management.ManagementBackupArchiveHistoryViewModelFactory(
                                            server, installation, access, backupArchiveHistory,
                                        ))["xui-backup-archives:" + server.length + ":" + server + ":" + installation.length + ":" + installation + ":" + access.length + ":" + access,
                                            com.velumtegra.xuimobile.management.ManagementBackupArchiveHistoryViewModel::class.java]
                                    } else null
                                    val pendingModel = if (backupMode) remember(server, installation, access) {
                                        ViewModelProvider(this@MainActivity, com.velumtegra.xuimobile.management.ManagementPendingWorkingRestoreViewModelFactory(
                                            server, installation, access, workingDatabaseRestoreStatuses,
                                        ))["xui-backup-pending-restores:" + server.length + ":" + server + ":" + installation.length + ":" + installation + ":" + access.length + ":" + access,
                                            com.velumtegra.xuimobile.management.ManagementPendingWorkingRestoreViewModel::class.java]
                                    } else null
                                    ManagementUpdatePreparationScreen(preparationModel, updatePreflightActions,
                                        onBack = { updatePreparationAccessId = null; backupPreparationAccessId = null }, backupMode = backupMode, archives = archiveModel, pendingRestores = pendingModel,
                                        onPendingRestore = { operation, comparison -> workingDatabaseRestorePinnedId = operation; workingDatabaseRestoreSourceId = comparison; workingDatabaseRestoreAccessId = access },
                                        onArchive = { source -> restoreCheckSourceId = source; restoreCheckAccessId = access }, onDatabaseBackup = { pointer ->
                                            databaseBackupSourceId = pointer.operationId; databaseBackupAccessId = pointer.accessId
                                        }, onInstallationBackup = { pointer ->
                                            installationBackupSourceId = pointer.operationId; installationBackupAccessId = pointer.accessId
                                        })
                                } else if (serviceLogsAccessId != null) {
                                    val access = requireNotNull(serviceLogsAccessId)
                                    val logsModel = remember(server, installation, access) {
                                        ViewModelProvider(this@MainActivity, ManagementServiceLogsViewModelFactory(
                                            this@MainActivity, server, installation, access, managementReviewPort,
                                            serviceLogStatuses, sshReadinessPort,
                                        ))["xui-logs:" + server.length + ":" + server + ":" + installation.length + ":" + installation + ":" + access.length + ":" + access,
                                            ManagementServiceLogsViewModel::class.java]
                                    }
                                    ManagementServiceLogsScreen(logsModel, serviceLogActions, onBack = { serviceLogsAccessId = null })
                                } else if (inspectionHistoryOpened) {
                                    val historyModel = remember(server, installation) {
                                        ViewModelProvider(this@MainActivity, ManagementInspectionHistoryViewModelFactory(
                                            this@MainActivity, server, installation, managementReviewPort,
                                            inspectionHistory, managementStatus,
                                        ))["xui-history:" + server.length + ":" + server + ":" + installation.length + ":" + installation,
                                            ManagementInspectionHistoryViewModel::class.java]
                                    }
                                    ManagementInspectionHistoryScreen(historyModel, onBack = { inspectionHistoryOpened = false })
                                } else if (managementMenuAccessId != null) {
                                    com.velumtegra.xuimobile.management.ManagementXuiServerMenuScreen(
                                        server, installation, requireNotNull(managementMenuAccessId),
                                        app.managementXuiServerMenu, window,
                                        onBack = { managementMenuAccessId = null },
                                    )
                                } else if (managementRestartAccessId != null) {
                                    val access = requireNotNull(managementRestartAccessId)
                                    val model = remember(server, installation, access) {
                                        ViewModelProvider(this@MainActivity, ManagementRestartViewModelFactory(
                                            this@MainActivity, server, installation, access, app.managementRestartLocalPort, restartStatuses,
                                        ))["xui-restart:" + server + ":" + installation + ":" + access, ManagementRestartViewModel::class.java]
                                    }
                                    ManagementRestartScreen(
                                        model, restartActions, onBack = { managementRestartAccessId = null },
                                        serviceAction = managementServiceAction,
                                    )
                                } else if (managementDetailsOpened) {
                                    ManagementLocalReviewScreen(
                                        serverId = server, installationId = installation,
                                        port = managementReviewPort,
                                        onBack = { managementDetailsOpened = false },
                                        inspections = null,
                                        showOfflineDraft = false,
                                    )
                                } else {
                                    val managementHome = remember(server, installation) {
                                        ViewModelProvider(
                                            this@MainActivity,
                                            ManagementHomeViewModelFactory(
                                                this@MainActivity, server, installation, managementReviewPort,
                                                sshReadinessPort, managementStatus, managementVersions,
                                            ),
                                        )["xui-home:" + server + ":" + installation, ManagementHomeViewModel::class.java]
                                    }
                                    ManagementHomeScreen(
                                        viewModel = managementHome, launcher = managementInspections,
                                        onBack = { closeManagementReview() },
                                        onDetails = { managementDetailsOpened = true },
                                        onSshProfiles = { name ->
                                            profilesReturnServerId = server
                                            profilesReturnInstallationId = installation
                                            profilesServerId = server
                                            profilesServerName = name
                                            closeManagementReview()
                                        },
                                        onWebPanels = { scopedPanelOpened = true },
                                        onServerMenu = { managementMenuAccessId = it },
                                        onRestart = { openServiceAction(it, ExistingInstallationServiceAction.RESTART) },
                                        onStartService = { openServiceAction(it, ExistingInstallationServiceAction.START) },
                                        onStopService = { openServiceAction(it, ExistingInstallationServiceAction.STOP) },
                                        onExtraServiceAction = { access, action -> openServiceAction(access, action) },
                                        readPanelTls = { access -> app.managementPanelTlsReader.read(server, installation, access) },
                                        readPanelCredentials = { access -> app.managementPanelCredentialsReader.read(server, installation, access) },
                                        panelAccessDialog = { access, dismiss ->
                                            com.velumtegra.xuimobile.management.ManagementPanelAccessDialog(
                                                app.managementPanelAccessPort, server, installation, access, dismiss,
                                            )
                                        },
                                        onHistory = { inspectionHistoryOpened = true },
                                        onServiceLogs = { access -> serviceLogsAccessId = access },
                                        onUpdatePreparation = { access -> updatePreparationAccessId = access },
                                        onBackup = { access -> backupPreparationAccessId = access },
                                    )
                                }
                            }
                            xuiDiscoveryServerId != null -> XuiReadOnlyDiscoveryScreen(
                                serverId = requireNotNull(xuiDiscoveryServerId),
                                serverName = xuiDiscoveryServerName.orEmpty(),
                                readinessPort = sshReadinessPort,
                                discoveryPort = app.xuiReadOnlyDiscoveryPort,
                                enrollmentPort = app.xuiVerifiedEnrollmentPort,
                                installPort = freshInstallActions,
                                secureAfterInstall = { server, access ->
                                    when (val outcome = app.managementPanelAccessPort.secureFreshInstallation(server, access)) {
                                        is com.velumtegra.xuimobile.management.PanelAccessOutcome.Done -> "✓ " + outcome.message
                                        is com.velumtegra.xuimobile.management.PanelAccessOutcome.Failed -> outcome.reason
                                        is com.velumtegra.xuimobile.management.PanelAccessOutcome.NewSignIn -> outcome.message
                                    }
                                },
                                onSaved = {
                                    xuiDiscoveryServerId = null
                                    xuiDiscoveryServerName = null
                                    destination = DashboardDestination.MANAGEMENT
                                },
                                onBack = { xuiDiscoveryServerId = null; xuiDiscoveryServerName = null },
                            )
                            profilesServerId != null -> SshProfileManagementScreen(
                                serverId = requireNotNull(profilesServerId),
                                serverName = profilesServerName.orEmpty(),
                                readinessPort = sshReadinessPort,
                                profiles = app.sshProfileManagementPort,
                                onAddAccess = {
                                    enrollmentReturnProfilesServerId = profilesServerId
                                    enrollmentReturnProfilesServerName = profilesServerName
                                    accessServerId = profilesServerId
                                    accessServerName = profilesServerName
                                    profilesServerId = null
                                    profilesServerName = null
                                },
                                onBack = {
                                    profilesServerId = null
                                    profilesServerName = null
                                    if (profilesReturnInstallationId != null) {
                                        managementReviewServerId = profilesReturnServerId
                                        managementReviewInstallationId = profilesReturnInstallationId
                                    }
                                    profilesReturnServerId = null
                                    profilesReturnInstallationId = null
                                },
                            )
                            liveSshServerId != null -> LiveSshConnectionScreen(
                                serverId = requireNotNull(liveSshServerId),
                                serverName = liveSshServerName.orEmpty(),
                                readinessPort = sshReadinessPort,
                                connectionPort = app.liveSshConnectionPort,
                                onBack = {
                                    liveSshServerId = null
                                    liveSshServerName = null
                                },
                            )
                            readinessServerId != null -> SshReadinessScreen(
                                serverId = requireNotNull(readinessServerId),
                                serverName = readinessServerName.orEmpty(),
                                port = sshReadinessPort,
                                onBack = {
                                    readinessServerId = null
                                    readinessServerName = null
                                },
                            )
                            createServerOpened || accessServerId != null -> ServerEnrollmentScreen(
                                serverId = accessServerId,
                                serverName = accessServerName,
                                port = app.serverEnrollmentPort,
                                hostKeyDiscoveryPort = app.serverHostKeyDiscoveryPort,
                                onBack = { closeEnrollment() },
                                onSaved = {
                                    closeEnrollment()
                                    if (profilesServerId == null) destination = DashboardDestination.SERVERS
                                },
                                onServerCreated = { id, name ->
                                    createServerOpened = false
                                    accessServerId = id
                                    accessServerName = name
                                },
                            )
                            destination == DashboardDestination.SERVERS -> InventoryScreen(
                                section = InventorySection.SERVERS,
                                serverRepository = app.inventoryServerRepository,
                                serverAccessRepository = app.inventoryServerAccessRepository,
                                installationRepository = app.inventoryInstallationRepository,
                                managementAccessRepository = app.inventoryManagementRepository,
                                webPanelAccessRepository = app.inventoryWebPanelRepository,
                                onAddServer = { createServerOpened = true },
                                onAddSshAccess = { id, name ->
                                    accessServerId = id
                                    accessServerName = name
                                },
                                onReviewSshReadiness = { id, name ->
                                    readinessServerId = id
                                    readinessServerName = name
                                },
                                onManageSshProfiles = { id, name ->
                                    profilesServerId = id
                                    profilesServerName = name
                                },
                                onConnectSsh = { id, name ->
                                    liveSshServerId = id
                                    liveSshServerName = name
                                },
                                onDiscoverXui = { id, name ->
                                    xuiDiscoveryServerId = id
                                    xuiDiscoveryServerName = name
                                },
                                purgeServer = { id, revision -> app.purgeServerLocally(id, revision) },
                            )
                            destination == DashboardDestination.MANAGEMENT -> InventoryScreen(
                                section = InventorySection.MANAGEMENT,
                                linkedCredentialPort = app.linkedWebPanelCredentialPort,
                                serverRepository = app.inventoryServerRepository,
                                serverAccessRepository = app.inventoryServerAccessRepository,
                                installationRepository = app.inventoryInstallationRepository,
                                managementAccessRepository = app.inventoryManagementRepository,
                                webPanelAccessRepository = app.inventoryWebPanelRepository,
                                onReviewManagement = { serverId, installationId ->
                                    managementReviewServerId = serverId
                                    managementReviewInstallationId = installationId
                                },
                                onOpenWebPanelInApp = openManualPanel,
                                onOpenSavedWebPanel = openSavedDirectPanel,
                            )
                            destination == DashboardDestination.WEB_PANEL -> InventoryScreen(
                                section = InventorySection.WEB_PANEL,
                                linkedCredentialPort = app.linkedWebPanelCredentialPort,
                                linkedLoginCheckPort = app.linkedWebPanelLoginCheckPort,
                                linkedInboundReadPort = app.linkedWebPanelInboundReadPort,
                                linkedServerStatusReadPort = app.linkedWebPanelServerStatusReadPort,
                                linkedClientCountReadPort = app.linkedWebPanelClientCountReadPort,
                                linkedClientTrafficReadPort = app.linkedWebPanelClientTrafficReadPort,
                                linkedClientQuotaExpiryReadPort = app.linkedWebPanelClientQuotaExpiryReadPort,
                                linkedInboundDetailsReadPort = app.linkedWebPanelInboundDetailsReadPort,
                                serverRepository = app.inventoryServerRepository,
                                serverAccessRepository = app.inventoryServerAccessRepository,
                                installationRepository = app.inventoryInstallationRepository,
                                managementAccessRepository = app.inventoryManagementRepository,
                                webPanelAccessRepository = app.inventoryWebPanelRepository,
                                onOpenWebPanelInApp = openManualPanel,
                                onOpenSavedWebPanel = openSavedDirectPanel,
                                onOpenPrivateWebPanel = { request -> privateWebPanelRequest = request },
                            )
                            else -> HomeScreen(
                                darkTheme = darkTheme,
                                onDarkThemeChange = { enabled ->
                                    darkTheme = enabled
                                    displayPrefs.edit().putBoolean("dark_theme_enabled", enabled).apply()
                                },
                                scannerRunning = scannerHomeState.running,
                                scannerPaused = scannerHomeState.paused,
                                scannerNetworkLost = scannerHomeState.networkLost,
                                scannerCompleted = scannerHomeState.completed,
                                scannerFeasible = scannerHomeState.feasible,
                                onOpenScanner = { scannerOpened = true },
                                onStopScanner = { RealityScannerForegroundService.stop(this@MainActivity) },
                                onOpenSiteDeployer = { siteDeployerOpened = true },
                                onOpenSshPort = { sshPortOpened = true },
                                onOpenBlocklist = { blocklistOpened = true },
                                onOpenServers = { destination = DashboardDestination.SERVERS },
                                onOpenManagement = { destination = DashboardDestination.MANAGEMENT },
                                onOpenWebPanel = { destination = DashboardDestination.WEB_PANEL },
                            )
                        }
                    }
                }
            }
        }
    }
}

/** Vector bottom navigation glyphs, independent of emoji fonts and device locale. */
@androidx.compose.runtime.Composable
private fun DashboardGlyph(destination: DashboardDestination, selected: Boolean) {
    val tint = if (selected) MaterialTheme.colorScheme.onSecondaryContainer
        else MaterialTheme.colorScheme.onSurfaceVariant
    Canvas(modifier = Modifier.size(23.dp)) {
        val u = size.width / 24f
        val st = Stroke(width = 1.85f * u)
        when (destination) {
            DashboardDestination.HOME -> {
                val roof = Path().apply {
                    moveTo(3f*u, 11f*u); lineTo(12f*u, 3f*u); lineTo(21f*u, 11f*u)
                }
                drawPath(roof, tint, style = st)
                drawLine(tint, Offset(6f*u, 10f*u), Offset(6f*u, 21f*u), st.width)
                drawLine(tint, Offset(18f*u, 10f*u), Offset(18f*u, 21f*u), st.width)
                drawLine(tint, Offset(6f*u, 21f*u), Offset(18f*u, 21f*u), st.width)
                drawLine(tint, Offset(10f*u, 21f*u), Offset(10f*u, 15f*u), st.width)
                drawLine(tint, Offset(14f*u, 21f*u), Offset(14f*u, 15f*u), st.width)
                drawLine(tint, Offset(10f*u, 15f*u), Offset(14f*u, 15f*u), st.width)
            }
            DashboardDestination.SERVERS -> {
                for (y in listOf(4f, 10f, 16f)) {
                    drawRoundRect(tint, topLeft = Offset(3f*u, y*u),
                        size = androidx.compose.ui.geometry.Size(18f*u, 5f*u),
                        cornerRadius = CornerRadius(1.5f*u), style = st)
                    drawCircle(tint, radius = 0.85f*u, center = Offset(6.5f*u, (y+2.5f)*u))
                }
            }
            DashboardDestination.MANAGEMENT -> {
                drawCircle(tint, radius = 8f*u, center = center, style = st)
                drawCircle(tint, radius = 3.5f*u, center = center, style = st)
                for ((x,y) in listOf(12f to 1.5f, 12f to 22.5f, 1.5f to 12f, 22.5f to 12f)) {
                    drawCircle(tint, radius = 1f*u, center = Offset(x*u, y*u))
                }
            }
            DashboardDestination.WEB_PANEL -> {
                drawRoundRect(tint, topLeft = Offset(2f*u, 4f*u),
                    size = androidx.compose.ui.geometry.Size(20f*u, 16f*u),
                    cornerRadius = CornerRadius(2f*u), style = st)
                drawLine(tint, Offset(2f*u, 9f*u), Offset(22f*u, 9f*u), st.width)
                drawCircle(tint, radius = 0.8f*u, center = Offset(5f*u, 6.5f*u))
                drawCircle(tint, radius = 0.8f*u, center = Offset(8f*u, 6.5f*u))
            }
        }
    }
}

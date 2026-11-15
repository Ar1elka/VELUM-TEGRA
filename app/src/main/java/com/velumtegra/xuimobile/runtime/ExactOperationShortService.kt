package com.velumtegra.xuimobile.runtime

import android.annotation.TargetApi
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import com.velumtegra.xuimobile.MainActivity
import com.velumtegra.xuimobile.R
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.runtime.RetryBudget
import com.velumtegra.xuimobile.discovery.DiscoveryProcessNotice
import com.velumtegra.xuimobile.discovery.toDiscoveryProcessNotice
import com.velumtegra.xuimobile.management.DeepDiagnosticProcessNotice
import com.velumtegra.xuimobile.management.ManagementProcessNotice
import com.velumtegra.xuimobile.management.toServiceLogProcessResult
import com.velumtegra.xuimobile.management.toUpdatePreflightProcessResult
import com.velumtegra.xuimobile.management.databaseBackupResult
import com.velumtegra.xuimobile.management.installationBackupResult
import com.velumtegra.xuimobile.management.restoreCheckResult
import com.velumtegra.xuimobile.management.workingDatabaseRestoreResult
import com.velumtegra.xuimobile.management.restoredPanelStartResult
import com.velumtegra.xuimobile.management.restoreCompatibilityResult
import com.velumtegra.xuimobile.management.ServiceLogProcessResult
import com.velumtegra.xuimobile.management.UpdatePreflightProcessResult
import com.velumtegra.xuimobile.management.ServiceLogNotice
import com.velumtegra.xuimobile.management.UpdatePreflightNotice
import com.velumtegra.xuimobile.management.toDeepDiagnosticProcessNotice
import com.velumtegra.xuimobile.management.toManagementProcessNotice
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Bounded Android execution-host shell for one exact OperationId.
 *
 * One Service lifetime is bound to one exact OperationId, uses the process-wide runtime graph,
 * contributes connectivity observations while hosted, never becomes durable truth, and never asks
 * Android to restart it automatically. After cancellation-safe coordinator admission it may perform
 * only the bounded typed sequence. RESTART requires a visible one-shot confirmation, production
 * read-only preflight and core mutation barriers. Post-dispatch recovery remains read-only;
 * and a connected session is closed before the host finishes.
 *
 * The manifest declares `shortService`, so future work routed through this host must remain bounded
 * enough for that platform contract. Longer/different workloads require a separately justified
 * execution primitive/type; this service must not be generalized into a universal FGS.
 */
class ExactOperationShortService : Service() {
    private val requestGate = ExactOperationHostRequestGate()
    private val startIdTracker = ExactOperationHostStartIdTracker()
    private val runtimeBindingRegistry = ExactOperationHostRuntimeBindingRegistry()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mainHandler = Handler(Looper.getMainLooper())

    private var connectivityRegistered = false
    private var foregroundStarted = false
    private var hostedStartId: Int? = null
    private var lifecycleLease: ExactOperationHostLifecycleLease? = null
    private var runtimeAttempt: ExactOperationHostRuntimeAttempt? = null
    private var runtimeAdmissionJob: Job? = null

    private val velumApplication: VelumTegraApplication
        get() = application as VelumTegraApplication

    private val runtimeAdmissionBridge: ExactOperationHostRuntimeAdmissionBridge by lazy(
        LazyThreadSafetyMode.SYNCHRONIZED,
    ) {
        ExactOperationHostRuntimeAdmissionBridge(
            coordinator = velumApplication.operationRuntimeCoordinator,
            previousExitProvenance = velumApplication.exitInfoAdapter::previousExitProvenance,
        )
    }

    private val transportSequence: ExactOperationHostTransportSequence by lazy(
        LazyThreadSafetyMode.SYNCHRONIZED,
    ) {
        ExactOperationHostTransportSequence(
            ExactOperationHostRuntimeTransportBridge(velumApplication.operationRuntimeCoordinator),
        )
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startIdTracker.observe(startId)

        val userStopRequest = intent.toExactUserStopRequest()
        if (userStopRequest != null) {
            handleExactUserStop(userStopRequest)
            return START_NOT_STICKY
        }

        val requestedOperationId = intent.toExactOperationId()
        if (requestedOperationId == null) {
            handleInvalidStart()
            return START_NOT_STICKY
        }

        when (requestGate.tryBind(requestedOperationId)) {
            ExactOperationHostBindResult.BOUND -> {
                check(hostedStartId == null) { "Service host startId already bound" }
                val lease = velumApplication.operationHostLifecycleRegistry.begin(requestedOperationId)
                hostedStartId = startId
                lifecycleLease = lease
                try {
                    promoteToForeground(lease)
                    check(velumApplication.operationHostLifecycleRegistry.markForeground(lease)) {
                        "Fresh host lifecycle lease must remain current through foreground promotion"
                    }
                    connectivityRegistered = velumApplication.connectivityObserver.register()
                    startRuntimeAdmission(requestedOperationId)
                } catch (error: Throwable) {
                    velumApplication.operationHostLifecycleRegistry.finish(
                        lease,
                        ExactOperationHostLifecycleState.START_FAILED,
                    )
                    cleanupExact(requestedOperationId)
                    stopSelfAtLatestStart()
                    throw error
                }
            }

            ExactOperationHostBindResult.ALREADY_BOUND -> {
                // Duplicate start is intentionally idempotent. In particular, do not call
                // startForeground() again because that could extend a shortService timeout.
            }

            ExactOperationHostBindResult.REJECTED_DIFFERENT_OPERATION -> {
                // One Service lifetime never rebinds to another OperationId. A later launcher/host
                // policy may queue/reject explicitly, but this Android boundary never steals work.
            }
        }

        return START_NOT_STICKY
    }

    private fun handleInvalidStart() {
        when (requestGate.invalidStartDisposition()) {
            ExactOperationHostInvalidStartDisposition.STOP_UNBOUND_SERVICE -> stopSelfAtLatestStart()
            ExactOperationHostInvalidStartDisposition.IGNORE_ACTIVE_HOST -> Unit
        }
    }

    private fun handleExactUserStop(request: ExactOperationHostUserStopRequest) {
        when (
            ExactOperationHostUserStopGate.classify(
                request = request,
                currentOperationId = requestGate.current(),
                currentLifecycleLease = lifecycleLease,
            )
        ) {
            ExactOperationHostUserStopDisposition.STOP_EXACT_HOST ->
                stopHostedService(ExactOperationHostLifecycleState.USER_STOPPED)

            ExactOperationHostUserStopDisposition.STOP_UNBOUND_SERVICE -> stopSelfAtLatestStart()
            ExactOperationHostUserStopDisposition.IGNORE_ACTIVE_HOST -> Unit
        }
    }

    /**
     * Android 14+ shortService timeout. Timeout is a host interruption, not remote-operation truth.
     * Durable state is deliberately untouched; stop promptly to avoid the platform ANR path.
     */
    @TargetApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    override fun onTimeout(startId: Int) {
        when (
            ExactOperationHostTimeoutGate.classify(
                timeoutStartId = startId,
                hostedStartId = hostedStartId,
                currentOperationId = requestGate.current(),
                currentLifecycleLease = lifecycleLease,
            )
        ) {
            ExactOperationHostTimeoutDisposition.STOP_EXACT_HOST ->
                stopHostedService(ExactOperationHostLifecycleState.TIMED_OUT)

            // Use the callback's own startId. If Android already accepted a newer start, the stale
            // timeout is not allowed to stop that newer Service work.
            ExactOperationHostTimeoutDisposition.STOP_UNBOUND_SERVICE -> stopSelf(startId)
            ExactOperationHostTimeoutDisposition.IGNORE_ACTIVE_HOST -> Unit
        }
    }

    override fun onDestroy() {
        cancelRuntimeAdmissionAndRelease()
        lifecycleLease?.let { lease ->
            velumApplication.operationHostLifecycleRegistry.finish(
                lease,
                ExactOperationHostLifecycleState.STOPPED,
            )
            lifecycleLease = null
        }
        requestGate.current()?.let(::cleanupExact)
        serviceScope.cancel()
        super.onDestroy()
    }

    /**
     * Starts one cancellation-safe exact runtime admission and bounded typed feature sequence.
     *
     * The coordinator remains the ownership authority. This Service only keeps the returned exact
     * token while its own generation is current. The transport sequence may consume the exact
     * connected SessionId for Discovery, QUICK_INSPECT, DEEP_DIAGNOSTIC, exact RESTART or the separately gated
     * Installer runtime consumer, then closes that exact SessionId before host teardown. Installer
     * mutation authority/barriers live in core:runtime; this Service cannot invent a command or
     * make itself durable. Feature registries observe only already-typed sequence outcomes; durable
     * truth remains OperationJournal.
     */
    private fun startRuntimeAdmission(operationId: OperationId) {
        check(runtimeAttempt == null) { "Service runtime admission already started" }
        val attempt = runtimeBindingRegistry.begin(operationId)
        runtimeAttempt = attempt
        runtimeAdmissionJob = serviceScope.launch {
            try {
                when (val result = runtimeAdmissionBridge.bind(operationId)) {
                    is ExactOperationHostRuntimeBindResult.Bound -> {
                        if (runtimeBindingRegistry.adopt(attempt, result.binding)) {
                            val sequenceResult = transportSequence.run(
                                runtimeBinding = result.binding,
                                budget = HOST_TRANSPORT_RETRY_BUDGET,
                                maxConnectivityGenerations = HOST_CONNECTIVITY_GENERATION_BUDGET,
                            )
                            velumApplication.serviceLogResultRegistry.publish(operationId, sequenceResult.toServiceLogProcessResult())
                            velumApplication.updatePreflightResultRegistry.publish(operationId, sequenceResult.toUpdatePreflightProcessResult())
                            velumApplication.databaseBackupResultRegistry.publish(operationId, sequenceResult.databaseBackupResult())
                            velumApplication.installationBackupResultRegistry.publish(operationId, sequenceResult.installationBackupResult())
                            velumApplication.restoreCheckResultRegistry.publish(operationId, sequenceResult.restoreCheckResult())
                            velumApplication.workingDatabaseRestoreResultRegistry.publish(operationId, sequenceResult.workingDatabaseRestoreResult())
                            velumApplication.restoredPanelStartResultRegistry.publish(operationId, sequenceResult.restoredPanelStartResult())
                            velumApplication.restoreCompatibilityResultRegistry.publish(operationId, sequenceResult.restoreCompatibilityResult())
                            if (velumApplication.discoveryResultRegistry.isTracked(operationId)) {
                                when (sequenceResult) {
                                    is ExactOperationHostTransportSequenceResult.DiscoveryCompleted ->
                                        velumApplication.discoveryResultRegistry.publishResult(sequenceResult.result)
                                    else -> sequenceResult.toDiscoveryProcessNotice()?.let { notice ->
                                        velumApplication.discoveryResultRegistry.publishNotice(operationId, notice)
                                    }
                                }
                            }
                            if (velumApplication.managementResultRegistry.isTracked(operationId)) {
                                when (sequenceResult) {
                                    is ExactOperationHostTransportSequenceResult.ManagementCompleted ->
                                        velumApplication.managementResultRegistry.publishCompleted(
                                            operationId = operationId,
                                            snapshot = sequenceResult.snapshot,
                                            committedRevision = sequenceResult.committedRevision,
                                        )
                                    is ExactOperationHostTransportSequenceResult.ManagementEnded ->
                                        when (val management = sequenceResult.management) {
                                            is ExactOperationHostManagementResult.ReadbackFailed ->
                                                velumApplication.managementResultRegistry.publishReadbackFailure(
                                                    operationId = operationId,
                                                    kind = management.kind,
                                                    committedRevision = management.committedRevision,
                                                )
                                            else -> sequenceResult.toManagementProcessNotice()?.let { notice ->
                                                velumApplication.managementResultRegistry.publishNotice(operationId, notice)
                                            }
                                        }
                                    else -> sequenceResult.toManagementProcessNotice()?.let { notice ->
                                        velumApplication.managementResultRegistry.publishNotice(operationId, notice)
                                    }
                                }
                            }
                            if (velumApplication.deepDiagnosticResultRegistry.isTracked(operationId)) {
                                when (sequenceResult) {
                                    is ExactOperationHostTransportSequenceResult.DeepDiagnosticCompleted ->
                                        velumApplication.deepDiagnosticResultRegistry.publishCompleted(
                                            operationId = operationId,
                                            snapshot = sequenceResult.snapshot,
                                            committedRevision = sequenceResult.committedRevision,
                                        )
                                    is ExactOperationHostTransportSequenceResult.DeepDiagnosticEnded ->
                                        when (val deep = sequenceResult.deepDiagnostic) {
                                            is ExactOperationHostDeepDiagnosticResult.ReadbackFailed ->
                                                velumApplication.deepDiagnosticResultRegistry.publishReadbackFailure(
                                                    operationId = operationId,
                                                    kind = deep.kind,
                                                    committedRevision = deep.committedRevision,
                                                )
                                            else -> sequenceResult.toDeepDiagnosticProcessNotice()?.let { notice ->
                                                velumApplication.deepDiagnosticResultRegistry.publishNotice(operationId, notice)
                                            }
                                        }
                                    else -> sequenceResult.toDeepDiagnosticProcessNotice()?.let { notice ->
                                        velumApplication.deepDiagnosticResultRegistry.publishNotice(operationId, notice)
                                    }
                                }
                            }
                        } else {
                            // Destroy/timeout/user stop won before the suspend admission completed.
                            runtimeAdmissionBridge.release(result.binding)
                        }
                    }

                    else -> {
                        velumApplication.serviceLogResultRegistry.publish(operationId, ServiceLogProcessResult.Ended(ServiceLogNotice.HOST_ENDED))
                        velumApplication.updatePreflightResultRegistry.publish(operationId, UpdatePreflightProcessResult.Ended(UpdatePreflightNotice.HOST_ENDED))
                        if (velumApplication.discoveryResultRegistry.isTracked(operationId)) {
                            result.toDiscoveryProcessNotice()?.let { notice ->
                                velumApplication.discoveryResultRegistry.publishNotice(operationId, notice)
                            }
                        }
                        if (velumApplication.managementResultRegistry.isTracked(operationId)) {
                            result.toManagementProcessNotice()?.let { notice ->
                                velumApplication.managementResultRegistry.publishNotice(operationId, notice)
                            }
                        }
                        if (velumApplication.deepDiagnosticResultRegistry.isTracked(operationId)) {
                            result.toDeepDiagnosticProcessNotice()?.let { notice ->
                                velumApplication.deepDiagnosticResultRegistry.publishNotice(operationId, notice)
                            }
                        }
                    }
                }
            } catch (cancelled: CancellationException) {
                velumApplication.serviceLogResultRegistry.publish(operationId, ServiceLogProcessResult.Ended(ServiceLogNotice.INTERRUPTED))
                velumApplication.updatePreflightResultRegistry.publish(operationId, UpdatePreflightProcessResult.Ended(UpdatePreflightNotice.INTERRUPTED))
                if (velumApplication.discoveryResultRegistry.isTracked(operationId)) {
                    velumApplication.discoveryResultRegistry.publishNotice(
                        operationId,
                        DiscoveryProcessNotice.HostInterrupted,
                    )
                }
                if (velumApplication.managementResultRegistry.isTracked(operationId)) {
                    velumApplication.managementResultRegistry.publishNotice(
                        operationId,
                        ManagementProcessNotice.HostInterrupted,
                    )
                }
                if (velumApplication.deepDiagnosticResultRegistry.isTracked(operationId)) {
                    velumApplication.deepDiagnosticResultRegistry.publishNotice(
                        operationId,
                        DeepDiagnosticProcessNotice.HostInterrupted,
                    )
                }
                throw cancelled
            } finally {
                // A live Service lifetime always converges to one exact teardown after the bounded
                // admission/transport sequence. If destroy/timeout/user stop already won, runtimeAttempt was
                // cleared first and this posted callback becomes a no-op.
                postStopAfterRuntimeWork(attempt)
            }
        }
    }

    private fun postStopAfterRuntimeWork(attempt: ExactOperationHostRuntimeAttempt) {
        mainHandler.post {
            if (runtimeAttempt == attempt && requestGate.current() == attempt.operationId) {
                // Keep runtimeAttempt until stopHostedService() transfers the exact binding back to
                // the admission bridge for release. Clearing it here would leak runtime ownership.
                runtimeAdmissionJob = null
                stopHostedService(ExactOperationHostLifecycleState.STOPPED)
            }
        }
    }

    private fun cancelRuntimeAdmissionAndRelease() {
        val attempt = runtimeAttempt
        runtimeAttempt = null
        val binding = attempt?.let(runtimeBindingRegistry::cancel)

        runtimeAdmissionJob?.cancel()
        runtimeAdmissionJob = null

        if (binding != null) {
            runtimeAdmissionBridge.release(binding)
        }
    }

    private fun cleanupExact(operationId: OperationId) {
        if (!requestGate.release(operationId)) {
            return
        }
        hostedStartId = null
        if (connectivityRegistered) {
            velumApplication.connectivityObserver.unregister()
            connectivityRegistered = false
        }
        if (foregroundStarted) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            foregroundStarted = false
        }
    }

    private fun stopHostedService(terminalState: ExactOperationHostLifecycleState) {
        cancelRuntimeAdmissionAndRelease()
        lifecycleLease?.let { lease ->
            velumApplication.operationHostLifecycleRegistry.finish(lease, terminalState)
            lifecycleLease = null
        }
        requestGate.current()?.let(::cleanupExact)
        stopSelfAtLatestStart()
    }

    private fun stopSelfAtLatestStart() {
        val startId = checkNotNull(startIdTracker.latest()) {
            "Host teardown requires at least one delivered Android startId"
        }
        stopSelf(startId)
    }

    @Suppress("DEPRECATION")
    private fun promoteToForeground(lease: ExactOperationHostLifecycleLease) {
        createNotificationChannelIfNeeded()
        val notification = buildNotification(lease)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        foregroundStarted = true
    }

    private fun createNotificationChannelIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = requireNotNull(getSystemService(NotificationManager::class.java)) {
            "NotificationManager is unavailable"
        }
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "VELUM runtime operations",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "User-visible bounded VELUM//TEGRA operation hosting"
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    @Suppress("DEPRECATION")
    private fun buildNotification(lease: ExactOperationHostLifecycleLease): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopRequest = ExactOperationHostUserStopRequest(
            operationId = lease.operationId,
            hostGeneration = lease.generation,
        )
        val stopIntent = PendingIntent.getService(
            this,
            0,
            stopIntentFor(this, stopRequest),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        return builder
            .setSmallIcon(R.drawable.ic_runtime_host)
            .setContentTitle("VELUM//TEGRA")
            .setContentText("Bounded operation is active")
            .setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(contentIntent)
            .addAction(R.drawable.ic_runtime_host, "Stop", stopIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun Intent?.toExactOperationId(): OperationId? {
        if (this == null || action != ACTION_HOST_EXACT_OPERATION) {
            return null
        }
        val raw = getStringExtra(EXTRA_OPERATION_ID)?.trim().orEmpty()
        if (raw.isEmpty()) {
            return null
        }
        return OperationId(raw)
    }

    private fun Intent?.toExactUserStopRequest(): ExactOperationHostUserStopRequest? {
        if (this == null || action != ACTION_STOP_EXACT_OPERATION) {
            return null
        }
        val raw = getStringExtra(EXTRA_OPERATION_ID)?.trim().orEmpty()
        val generation = getLongExtra(EXTRA_HOST_GENERATION, Long.MIN_VALUE)
        if (raw.isEmpty() || generation <= 0L) {
            return null
        }
        val request = ExactOperationHostUserStopRequest(
            operationId = OperationId(raw),
            hostGeneration = generation,
        )
        return request.takeIf { data == stopDataFor(it) }
    }

    companion object {
        internal const val ACTION_HOST_EXACT_OPERATION =
            "com.velumtegra.xuimobile.action.HOST_EXACT_OPERATION"
        internal const val ACTION_STOP_EXACT_OPERATION =
            "com.velumtegra.xuimobile.action.STOP_EXACT_OPERATION"
        internal const val EXTRA_OPERATION_ID =
            "com.velumtegra.xuimobile.extra.OPERATION_ID"
        internal const val EXTRA_HOST_GENERATION =
            "com.velumtegra.xuimobile.extra.HOST_GENERATION"

        private const val NOTIFICATION_CHANNEL_ID = "velum_runtime_short_operation"
        private const val STOP_INTENT_SCHEME = "velum-runtime-stop"
        private const val NOTIFICATION_ID = 0x5645

        // Smallest automatic reconnect budget that exercises one coordinator-authorized retry.
        // Each SSH connect call is independently bounded by core:ssh transport timeouts.
        private val HOST_TRANSPORT_RETRY_BUDGET = RetryBudget(maxAttempts = 2)

        // Initial generation plus at most one already-observed superseding generation. Each logical
        // reconnect chain remains independently bounded by HOST_TRANSPORT_RETRY_BUDGET; therefore the
        // host has at most two finite chains, never an unbounded generation/retry product. The Service
        // never waits here for a future network callback and never requests a new FGS start.
        private const val HOST_CONNECTIVITY_GENERATION_BUDGET = 2

        /**
         * Builds an explicit exact-identity intent only. VisibleExactOperationHostLauncher remains
         * responsible for requesting the Android start and typing platform start denial.
         */
        internal fun intentFor(context: Context, operationId: OperationId): Intent {
            require(operationId.value.isNotBlank()) { "OperationId cannot be blank" }
            return Intent(context, ExactOperationShortService::class.java)
                .setAction(ACTION_HOST_EXACT_OPERATION)
                .putExtra(EXTRA_OPERATION_ID, operationId.value)
        }

        private fun stopIntentFor(
            context: Context,
            request: ExactOperationHostUserStopRequest,
        ): Intent = Intent(context, ExactOperationShortService::class.java)
            .setAction(ACTION_STOP_EXACT_OPERATION)
            .setData(stopDataFor(request))
            .putExtra(EXTRA_OPERATION_ID, request.operationId.value)
            .putExtra(EXTRA_HOST_GENERATION, request.hostGeneration)

        private fun stopDataFor(request: ExactOperationHostUserStopRequest): Uri =
            Uri.fromParts(STOP_INTENT_SCHEME, request.pendingIntentIdentity, null)
    }
}

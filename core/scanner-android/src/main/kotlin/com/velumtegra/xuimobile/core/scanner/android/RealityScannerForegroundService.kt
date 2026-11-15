package com.velumtegra.xuimobile.core.scanner.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import com.velumtegra.xuimobile.core.scanner.RealityScanProgress
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File

data class ScannerServiceState(
    val running: Boolean,
    val paused: Boolean,
    val networkLost: Boolean,
    val total: Int,
    val completed: Int,
    val feasible: Int,
    val input: String,
    val port: Int,
    val threads: Int,
    val ipv6: Boolean,
    val tls12: Boolean = false,
    /** Why the last scan stopped on its own, or empty; cleared by the next START. */
    val error: String = "",
)

/**
 * Foreground owner for one Reality Scanner session.
 *
 * START always creates a fresh session and clears current results. RESTORE never clears them and
 * only resumes an already-persisted running session. Scan lifetime belongs to this service, not to
 * Compose/navigation lifecycle.
 */
class RealityScannerForegroundService : Service() {
    companion object {
        const val ACTION_START = "com.velumtegra.xuimobile.scanner.START"
        const val ACTION_RESTORE = "com.velumtegra.xuimobile.scanner.RESTORE"
        const val ACTION_STOP = "com.velumtegra.xuimobile.scanner.STOP"
        const val ACTION_PAUSE = "com.velumtegra.xuimobile.scanner.PAUSE"
        const val ACTION_RESUME = "com.velumtegra.xuimobile.scanner.RESUME"

        private const val PREFS = "velum_reality_scanner_service"
        private const val KEY_RUNNING = "service_running"
        private const val KEY_PAUSED = "service_paused"
        private const val KEY_USER_PAUSED = "service_user_paused"
        private const val KEY_NETWORK_LOST = "service_network_lost"
        private const val KEY_INPUT = "service_input"
        private const val KEY_PORT = "service_port"
        private const val KEY_THREADS = "service_threads"
        private const val KEY_IPV6 = "service_ipv6"
        private const val KEY_TLS12 = "service_tls12"
        private const val KEY_GEO = "service_geo"
        private const val KEY_TOTAL = "service_total"
        private const val KEY_COMPLETED = "service_completed"
        private const val KEY_FEASIBLE = "service_feasible"
        private const val KEY_ERROR = "service_error"
        private const val PROGRESS_PUBLISH_INTERVAL_MS = 400L
        private const val RESUME_OVERLAP_PER_THREAD = 3

        private const val EXTRA_INPUT = "input"
        private const val EXTRA_PORT = "port"
        private const val EXTRA_THREADS = "threads"
        private const val EXTRA_IPV6 = "ipv6"
        private const val EXTRA_TLS12 = "tls12"
        private const val EXTRA_GEO = "geo"

        private const val CHANNEL_ID = "reality_scanner"
        private const val NOTIFICATION_ID = 1203
        private const val REQUEST_STOP = 1204
        private const val REQUEST_PAUSE_RESUME = 1205
        private const val REQUEST_OPEN_APP = 1206

        fun start(
            context: Context,
            input: String,
            port: Int,
            threadCount: Int,
            enableIpv6: Boolean,
            enableTls12: Boolean = false,
            geoDatabase: File? = null,
        ) {
            dispatchStartingAction(
                context,
                Intent(context, RealityScannerForegroundService::class.java)
                    .setAction(ACTION_START)
                    .putExtra(EXTRA_INPUT, input)
                    .putExtra(EXTRA_PORT, port)
                    .putExtra(EXTRA_THREADS, threadCount)
                    .putExtra(EXTRA_IPV6, enableIpv6)
                    .putExtra(EXTRA_TLS12, enableTls12)
                    .putExtra(EXTRA_GEO, geoDatabase?.absolutePath.orEmpty()),
            )
        }

        fun restore(context: Context) {
            dispatchStartingAction(
                context,
                Intent(context, RealityScannerForegroundService::class.java)
                    .setAction(ACTION_RESTORE),
            )
        }

        fun ensureRunning(context: Context) {
            val current = state(context)
            if (current.running && current.input.isNotBlank()) {
                restore(context)
            }
        }

        fun stop(context: Context) {
            dispatchCommand(context, ACTION_STOP)
        }

        fun pause(context: Context) {
            dispatchCommand(context, ACTION_PAUSE)
        }

        fun resume(context: Context) {
            dispatchCommand(context, ACTION_RESUME)
        }

        fun state(context: Context): ScannerServiceState {
            val prefs = prefs(context)
            return ScannerServiceState(
                running = prefs.getBoolean(KEY_RUNNING, false),
                paused = prefs.getBoolean(KEY_PAUSED, false),
                networkLost = prefs.getBoolean(KEY_NETWORK_LOST, false),
                total = prefs.getInt(KEY_TOTAL, 0),
                completed = prefs.getInt(KEY_COMPLETED, 0),
                feasible = prefs.getInt(KEY_FEASIBLE, 0),
                input = prefs.getString(KEY_INPUT, "").orEmpty(),
                port = prefs.getInt(KEY_PORT, 443),
                threads = prefs.getInt(KEY_THREADS, 2),
                ipv6 = prefs.getBoolean(KEY_IPV6, false),
                tls12 = prefs.getBoolean(KEY_TLS12, false),
                error = prefs.getString(KEY_ERROR, "").orEmpty(),
            )
        }

        private fun dispatchStartingAction(context: Context, intent: Intent) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        private fun dispatchCommand(context: Context, action: String) {
            val intent = Intent(context, RealityScannerForegroundService::class.java).setAction(action)
            context.startService(intent)
        }

        private fun prefs(context: Context) =
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var scanJob: Job? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startAsForeground()
        registerNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                saveConfig(intent)
                RealityScanSessionStore.clearCurrent(applicationContext)
                transition(ScannerLifecycleEvent.START)
                setProgress(total = 0, completed = 0, feasible = 0)
                startScanIfNeeded(restart = true)
            }

            ACTION_RESTORE -> {
                transition(ScannerLifecycleEvent.RESTORE)
                if (isRunning()) {
                    startScanIfNeeded()
                } else {
                    stopSelf()
                }
            }

            ACTION_STOP -> {
                stopScanningPermanently()
                stopSelf()
            }

            ACTION_PAUSE -> transition(ScannerLifecycleEvent.PAUSE)
            ACTION_RESUME -> transition(ScannerLifecycleEvent.RESUME)
        }

        if (intent == null) {
            if (isRunning()) {
                startScanIfNeeded()
            } else {
                stopSelf()
            }
        }

        updateNotification()
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (isRunning()) {
            restore(applicationContext)
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        networkCallback?.let { callback ->
            runCatching { connectivityManager?.unregisterNetworkCallback(callback) }
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** [restart] replaces a scan that is still winding down, so a new START never inherits the old plan. */
    private fun startScanIfNeeded(restart: Boolean = false) {
        if (restart) {
            scanJob?.cancel()
            scanJob = null
        }
        if (scanJob?.isActive == true || !isRunning()) return

        scanJob = serviceScope.launch(Dispatchers.IO) {
            // Workers only record the newest counters; one ticker persists them. Writing preferences and
            // rebuilding the notification for every single probed IP was pure overhead.
            val latest = AtomicReference<RealityScanProgress?>(null)
            fun publish(progress: RealityScanProgress) {
                setProgress(progress.total, progress.completed, progress.feasible)
                updateNotification()
            }
            val ticker =
                launch {
                    var written: RealityScanProgress? = null
                    while (isActive) {
                        delay(PROGRESS_PUBLISH_INTERVAL_MS)
                        val progress = latest.get()
                        if (progress != null && progress != written) {
                            publish(progress)
                            written = progress
                        }
                    }
                }
            try {
                val prefs = prefs(applicationContext)
                val input = prefs.getString(KEY_INPUT, "")?.trim().orEmpty()
                val port = prefs.getInt(KEY_PORT, 443)
                val threads = prefs.getInt(KEY_THREADS, 2)
                val ipv6 = prefs.getBoolean(KEY_IPV6, false)
                val tls12 = prefs.getBoolean(KEY_TLS12, false)
                val geoPath = prefs.getString(KEY_GEO, "")?.trim().orEmpty()

                require(input.isNotBlank()) { "Укажи IP, домен или CIDR." }

                val geoFile =
                    File(geoPath).takeIf {
                        geoPath.isNotBlank() && it.exists() && it.isFile
                    }

                // After the system killed and restarted the service the same plan is walked again. Skip what
                // was already checked instead of starting from the seed; the overlap covers probes that were
                // in flight, and the store drops their duplicates.
                val alreadyCompleted = prefs.getInt(KEY_COMPLETED, 0)
                val resumeCompleted = (alreadyCompleted - threads * RESUME_OVERLAP_PER_THREAD).coerceAtLeast(0)

                RealityScannerEngine().scan(
                    input = input,
                    port = port,
                    timeoutSeconds = 10,
                    threadCount = threads,
                    enableIpv6 = ipv6,
                    enableTls12 = tls12,
                    geoDatabase = geoFile,
                    resumeCompleted = resumeCompleted,
                    resumeFeasible = if (resumeCompleted > 0) prefs.getInt(KEY_FEASIBLE, 0) else 0,
                    isOffline = { isNetworkLost() },
                    onProgress = { progress ->
                        latest.accumulateAndGet(progress) { known, next ->
                            if (known == null || next == null || next.completed >= known.completed) next else known
                        }
                    },
                    awaitIfPaused = {
                        while (
                            isRunning() &&
                                isPaused() &&
                                !isNetworkLost() &&
                                isActive
                        ) {
                            delay(200)
                        }
                    },
                    awaitNetworkOnline = {
                        while (isRunning() && isNetworkLost() && isActive) {
                            delay(250)
                        }
                    },
                    onResult = { result ->
                        RealityScanSessionStore.appendCurrentDistinct(
                            applicationContext,
                            result,
                        )
                    },
                )

                ticker.cancel()
                latest.get()?.let(::publish)
                if (isRunning()) {
                    finishScanToHistory()
                }
            } catch (_: CancellationException) {
                // Explicit STOP/service teardown owns cancellation; partial current results remain.
            } catch (error: Exception) {
                if (isActive) {
                    // The screen used to return to "ready" without a word; keep the reason for it.
                    saveError(
                        (error as? IllegalArgumentException)?.message
                            ?: "Сканирование остановлено из-за внутренней ошибки (${error.javaClass.simpleName}).",
                    )
                    transition(ScannerLifecycleEvent.STOP)
                    updateNotification()
                    stopSelf()
                }
            } finally {
                ticker.cancel()
                if (!isRunning()) {
                    updateNotification()
                }
            }
        }
    }

    private fun finishScanToHistory() {
        RealityScanSessionStore.archiveCurrent(applicationContext)
        transition(ScannerLifecycleEvent.STOP)
        updateNotification()
        stopSelf()
    }

    private fun stopScanningPermanently() {
        // A STOP that arrives when nothing runs must not archive the same results a second time.
        if (isRunning()) RealityScanSessionStore.archiveCurrent(applicationContext)
        scanJob?.cancel()
        scanJob = null
        transition(ScannerLifecycleEvent.STOP)
        updateNotification()
    }

    private fun saveError(message: String) {
        prefs(applicationContext).edit().putString(KEY_ERROR, message).apply()
    }

    private fun saveConfig(intent: Intent) {
        prefs(applicationContext)
            .edit()
            .remove(KEY_ERROR)
            .putString(KEY_INPUT, intent.getStringExtra(EXTRA_INPUT).orEmpty())
            .putInt(KEY_PORT, intent.getIntExtra(EXTRA_PORT, 443))
            .putInt(KEY_THREADS, intent.getIntExtra(EXTRA_THREADS, 2))
            .putBoolean(KEY_IPV6, intent.getBooleanExtra(EXTRA_IPV6, false))
            .putBoolean(KEY_TLS12, intent.getBooleanExtra(EXTRA_TLS12, false))
            .putString(KEY_GEO, intent.getStringExtra(EXTRA_GEO).orEmpty())
            .apply()
    }

    private fun registerNetworkCallback() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        connectivityManager = manager

        val initialCapabilities = manager.getNetworkCapabilities(manager.activeNetwork)
        val initiallyOnline =
            initialCapabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
        transition(
            if (initiallyOnline) {
                ScannerLifecycleEvent.NETWORK_AVAILABLE
            } else {
                ScannerLifecycleEvent.NETWORK_LOST
            },
        )

        val callback =
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    transition(ScannerLifecycleEvent.NETWORK_AVAILABLE)
                    updateNotification()
                }

                override fun onLost(network: Network) {
                    val capabilities = manager.getNetworkCapabilities(manager.activeNetwork)
                    val online =
                        capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
                    if (!online) {
                        transition(ScannerLifecycleEvent.NETWORK_LOST)
                        updateNotification()
                    }
                }
            }

        networkCallback = callback
        runCatching { manager.registerDefaultNetworkCallback(callback) }
    }

    private fun transition(event: ScannerLifecycleEvent) {
        val current =
            ScannerLifecycleFlags(
                running = isRunning(),
                userPaused = isUserPaused(),
                networkLost = isNetworkLost(),
            )
        val next = RealityScannerServiceLifecyclePolicy.reduce(current, event)
        prefs(applicationContext)
            .edit()
            .putBoolean(KEY_RUNNING, next.running)
            .putBoolean(KEY_PAUSED, next.paused)
            .putBoolean(KEY_USER_PAUSED, next.userPaused)
            .putBoolean(KEY_NETWORK_LOST, next.networkLost)
            .apply()
    }

    private fun isRunning(): Boolean =
        prefs(applicationContext).getBoolean(KEY_RUNNING, false)

    private fun isPaused(): Boolean =
        prefs(applicationContext).getBoolean(KEY_PAUSED, false)

    private fun isUserPaused(): Boolean {
        val prefs = prefs(applicationContext)
        return prefs.getBoolean(
            KEY_USER_PAUSED,
            prefs.getBoolean(KEY_PAUSED, false) && !prefs.getBoolean(KEY_NETWORK_LOST, false),
        )
    }

    private fun isNetworkLost(): Boolean =
        prefs(applicationContext).getBoolean(KEY_NETWORK_LOST, false)

    private fun setProgress(total: Int, completed: Int, feasible: Int) {
        prefs(applicationContext)
            .edit()
            .putInt(KEY_TOTAL, total)
            .putInt(KEY_COMPLETED, completed)
            .putInt(KEY_FEASIBLE, feasible)
            .apply()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        "Reality Scanner",
                        NotificationManager.IMPORTANCE_LOW,
                    ),
                )
        }
    }

    private fun buildNotification(): Notification {
        val state = state(applicationContext)
        val stopIntent =
            PendingIntent.getService(
                this,
                REQUEST_STOP,
                Intent(this, javaClass).setAction(ACTION_STOP),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        val pauseResumeAction = if (state.paused) ACTION_RESUME else ACTION_PAUSE
        val pauseResumeIntent =
            PendingIntent.getService(
                this,
                REQUEST_PAUSE_RESUME,
                Intent(this, javaClass).setAction(pauseResumeAction),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val contentIntent =
            launchIntent?.let {
                PendingIntent.getActivity(
                    this,
                    REQUEST_OPEN_APP,
                    it,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )
            }

        val title =
            when {
                state.networkLost -> "Reality Scanner — нет связи"
                state.paused -> "Reality Scanner — пауза"
                state.running -> "Reality Scanner — сканирование"
                else -> "Reality Scanner"
            }

        val builder =
            NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_menu_search)
                .setContentTitle(title)
                .setContentText(
                    "Проверено: ${state.completed}" +
                        (if (state.total > 0) " из ${state.total}" else "") +
                        ", найдено: ${state.feasible}",
                )
                .setOngoing(state.running)
                .setOnlyAlertOnce(true)

        contentIntent?.let(builder::setContentIntent)

        if (state.running && !state.networkLost) {
            builder.addAction(
                if (state.paused) android.R.drawable.ic_media_play else android.R.drawable.ic_media_pause,
                if (state.paused) "Продолжить" else "Пауза",
                pauseResumeIntent,
            )
        }
        if (state.running) {
            builder.addAction(android.R.drawable.ic_delete, "Стоп", stopIntent)
        }

        return builder.build()
    }

    private fun startAsForeground() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification() {
        runCatching {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIFICATION_ID, buildNotification())
        }
    }
}

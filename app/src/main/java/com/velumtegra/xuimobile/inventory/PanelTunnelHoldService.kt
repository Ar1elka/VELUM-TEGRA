package com.velumtegra.xuimobile.inventory

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.velumtegra.xuimobile.R

/**
 * Android 15+/16 blocks network for apps in the background (netpolicy APP_BACKGROUND) and destroys their
 * sockets, so the panel's SSH tunnel died as soon as the system file picker covered the app — the upload
 * after picking a backup then failed. While a picker/save dialog opened from the panel is on screen, this
 * short foreground service keeps the process network-eligible. It holds no SSH state itself, runs at most
 * the platform shortService limit (~3 min) and stops as soon as the dialog returns.
 */
class PanelTunnelHoldService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        try {
            val notification = buildNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (error: Exception) {
            Log.w(TAG, "hold not started: ${error.javaClass.simpleName}")
            stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onTimeout(startId: Int) {
        stopSelf() // The platform limit is reached; the panel reconnects on its own when visible again.
    }

    @Suppress("DEPRECATION")
    private fun buildNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Веб-панель через SSH", NotificationManager.IMPORTANCE_LOW)
                    .apply { setShowBadge(false) },
            )
            Notification.Builder(this, CHANNEL_ID)
        } else Notification.Builder(this)
        return builder
            .setSmallIcon(R.drawable.ic_runtime_host)
            .setContentTitle("VELUM//TEGRA")
            .setContentText("SSH-туннель веб-панели удерживается, пока выбран файл")
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "VelumPanelHold"
        private const val CHANNEL_ID = "velum_panel_tunnel_hold"
        private const val NOTIFICATION_ID = 4107
        private const val ACTION_STOP = "com.velumtegra.xuimobile.panel.HOLD_STOP"

        fun start(context: Context) {
            try {
                val intent = Intent(context, PanelTunnelHoldService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent)
                else context.startService(intent)
            } catch (error: Exception) {
                Log.w(TAG, "start refused: ${error.javaClass.simpleName}")
            }
        }

        fun stop(context: Context) {
            try {
                context.stopService(Intent(context, PanelTunnelHoldService::class.java))
            } catch (_: Exception) {
            }
        }
    }
}

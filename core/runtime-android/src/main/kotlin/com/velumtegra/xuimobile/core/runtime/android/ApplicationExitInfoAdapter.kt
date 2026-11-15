package com.velumtegra.xuimobile.core.runtime.android

import android.app.ActivityManager
import android.annotation.TargetApi
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import com.velumtegra.xuimobile.core.runtime.RecoveryExitProvenance

internal data class HistoricalProcessExitRecord(
    val reason: Int,
)

internal fun interface HistoricalProcessExitRecordSource {
    fun latest(): HistoricalProcessExitRecord?
}

/**
 * Thin API-30+ bridge around ActivityManager historical process-exit records.
 *
 * The semantic mapping intentionally lives outside this bridge so it remains deterministic and
 * JVM-testable. Only the most recent record is requested because the production app is constrained
 * to one process in Phase 4.
 */
internal class ActivityManagerHistoricalProcessExitRecordSource(
    private val activityManager: ActivityManager?,
    private val packageName: String,
) : HistoricalProcessExitRecordSource {
    override fun latest(): HistoricalProcessExitRecord? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return null
        }
        return latestApi30()
    }

    @TargetApi(Build.VERSION_CODES.R)
    private fun latestApi30(): HistoricalProcessExitRecord? {
        val manager = activityManager ?: return null
        return manager
            .getHistoricalProcessExitReasons(packageName, 0, 1)
            .firstOrNull()
            ?.let { HistoricalProcessExitRecord(reason = it.reason) }
    }
}

/**
 * Conservative mapping from Android ApplicationExitInfo reason codes into the platform-neutral
 * recovery provenance consumed by ColdStartRecoveryPlanPolicy.
 *
 * Unknown/new/ambiguous reasons deliberately stay UNKNOWN. In particular, REASON_USER_REQUESTED
 * is ambiguous before API 34 because older Android versions also used it for package/component
 * changes. DEVICE_REBOOT is never inferred from ApplicationExitInfo descriptions or heuristics.
 */
internal object ApplicationExitReasonMapper {
    fun map(
        sdkInt: Int,
        reason: Int,
    ): RecoveryExitProvenance {
        if (sdkInt < Build.VERSION_CODES.R) {
            return RecoveryExitProvenance.UNKNOWN
        }

        return when (reason) {
            ApplicationExitInfo.REASON_CRASH,
            ApplicationExitInfo.REASON_CRASH_NATIVE,
            ApplicationExitInfo.REASON_ANR,
            -> RecoveryExitProvenance.PROCESS_DEATH

            ApplicationExitInfo.REASON_LOW_MEMORY,
            ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE,
            ApplicationExitInfo.REASON_DEPENDENCY_DIED,
            -> RecoveryExitProvenance.SYSTEM_STOP

            ApplicationExitInfo.REASON_USER_STOPPED -> RecoveryExitProvenance.USER_REQUESTED_STOP

            ApplicationExitInfo.REASON_USER_REQUESTED -> {
                if (sdkInt >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    RecoveryExitProvenance.USER_REQUESTED_STOP
                } else {
                    RecoveryExitProvenance.UNKNOWN
                }
            }

            ApplicationExitInfo.REASON_FREEZER -> {
                if (sdkInt >= Build.VERSION_CODES.TIRAMISU) {
                    RecoveryExitProvenance.SYSTEM_STOP
                } else {
                    RecoveryExitProvenance.UNKNOWN
                }
            }

            else -> RecoveryExitProvenance.UNKNOWN
        }
    }
}

/**
 * Android-facing cold-start exit-evidence adapter for Phase 4.3.
 *
 * This class does no recovery execution, opens no SSH connection and mutates no journal state. It
 * only normalizes the best available Android evidence. API 24-29, missing history and query errors
 * all fail closed to UNKNOWN so the platform-neutral recovery policy remains authoritative.
 */
class AndroidApplicationExitInfoAdapter internal constructor(
    private val sdkIntProvider: () -> Int,
    private val recordSource: HistoricalProcessExitRecordSource,
) {
    constructor(context: Context) : this(
        sdkIntProvider = { Build.VERSION.SDK_INT },
        recordSource = ActivityManagerHistoricalProcessExitRecordSource(
            activityManager = context.getSystemService(ActivityManager::class.java),
            packageName = context.packageName,
        ),
    )

    fun previousExitProvenance(): RecoveryExitProvenance {
        val sdkInt = sdkIntProvider()
        if (sdkInt < Build.VERSION_CODES.R) {
            return RecoveryExitProvenance.UNKNOWN
        }

        val record = try {
            recordSource.latest()
        } catch (_: SecurityException) {
            null
        } catch (_: RuntimeException) {
            null
        }

        return record?.let { ApplicationExitReasonMapper.map(sdkInt, it.reason) }
            ?: RecoveryExitProvenance.UNKNOWN
    }
}

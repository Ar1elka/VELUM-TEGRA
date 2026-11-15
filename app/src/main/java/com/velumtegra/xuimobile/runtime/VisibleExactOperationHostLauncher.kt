package com.velumtegra.xuimobile.runtime

import android.app.Activity
import android.app.ForegroundServiceStartNotAllowedException
import android.content.ComponentName
import android.os.Build
import com.velumtegra.xuimobile.core.model.OperationId

/**
 * User-visible Android entry point for requesting the exact bounded operation host.
 *
 * The launcher intentionally requires an [Activity] rather than an arbitrary Context. This keeps
 * the production API shaped around a visible/user-driven call site. Android remains authoritative:
 * if the Activity is no longer in a state from which a foreground service may be started, the
 * platform denial is returned as a typed result instead of being treated as operation truth.
 *
 * [ExactOperationHostStartResult.START_REQUEST_ACCEPTED] means only that Android accepted the
 * Service start request. It does not prove foreground promotion, runtime admission, SSH reachability
 * or any remote operation outcome.
 */
internal class VisibleExactOperationHostLauncher(
    private val platform: ExactOperationHostStartPlatform,
) {
    constructor(activity: Activity) : this(AndroidExactOperationHostStartPlatform(activity))

    fun start(operationId: OperationId): ExactOperationHostStartResult {
        if (operationId.value.isBlank()) {
            return ExactOperationHostStartResult.INVALID_OPERATION_ID
        }
        return when (platform.request(operationId)) {
            ExactOperationHostPlatformStartResult.ACCEPTED ->
                ExactOperationHostStartResult.START_REQUEST_ACCEPTED

            ExactOperationHostPlatformStartResult.NOT_ALLOWED_FROM_CURRENT_STATE ->
                ExactOperationHostStartResult.NOT_ALLOWED_FROM_CURRENT_STATE

            ExactOperationHostPlatformStartResult.SECURITY_OR_POLICY_DENIED ->
                ExactOperationHostStartResult.SECURITY_OR_POLICY_DENIED

            ExactOperationHostPlatformStartResult.SERVICE_UNAVAILABLE ->
                ExactOperationHostStartResult.SERVICE_UNAVAILABLE
        }
    }
}

internal enum class ExactOperationHostStartResult {
    START_REQUEST_ACCEPTED,
    NOT_ALLOWED_FROM_CURRENT_STATE,
    SECURITY_OR_POLICY_DENIED,
    SERVICE_UNAVAILABLE,
    INVALID_OPERATION_ID,
}

internal fun interface ExactOperationHostStartPlatform {
    fun request(operationId: OperationId): ExactOperationHostPlatformStartResult
}

internal enum class ExactOperationHostPlatformStartResult {
    ACCEPTED,
    NOT_ALLOWED_FROM_CURRENT_STATE,
    SECURITY_OR_POLICY_DENIED,
    SERVICE_UNAVAILABLE,
}

private class AndroidExactOperationHostStartPlatform(
    private val activity: Activity,
) : ExactOperationHostStartPlatform {
    override fun request(operationId: OperationId): ExactOperationHostPlatformStartResult {
        val intent = ExactOperationShortService.intentFor(activity, operationId)
        return try {
            val component = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                activity.startForegroundService(intent)
            } else {
                @Suppress("DEPRECATION")
                activity.startService(intent)
            }
            component.toPlatformResult()
        } catch (error: SecurityException) {
            ExactOperationHostPlatformStartResult.SECURITY_OR_POLICY_DENIED
        } catch (error: IllegalStateException) {
            if (isForegroundStartNotAllowed(error)) {
                ExactOperationHostPlatformStartResult.NOT_ALLOWED_FROM_CURRENT_STATE
            } else {
                // Pre-S startService() can report an invalid current app state as an
                // IllegalStateException. The request is still only host admission evidence.
                ExactOperationHostPlatformStartResult.NOT_ALLOWED_FROM_CURRENT_STATE
            }
        }
    }

    private fun ComponentName?.toPlatformResult(): ExactOperationHostPlatformStartResult =
        if (this == null) {
            ExactOperationHostPlatformStartResult.SERVICE_UNAVAILABLE
        } else {
            ExactOperationHostPlatformStartResult.ACCEPTED
        }

    private fun isForegroundStartNotAllowed(error: IllegalStateException): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            error is ForegroundServiceStartNotAllowedException
}

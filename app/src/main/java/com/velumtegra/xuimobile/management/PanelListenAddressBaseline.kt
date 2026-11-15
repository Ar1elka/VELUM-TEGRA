package com.velumtegra.xuimobile.management

import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.XuiInstallationRepository
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.ssh.XuiPanelAccessState
import kotlinx.coroutines.CancellationException

/** Persist only the application's verified listen-address change on the exact reviewed record. */
internal suspend fun rememberPanelListenAddress(
    installations: XuiInstallationRepository,
    reviewed: XuiInstallation,
    state: XuiPanelAccessState,
): Boolean = try {
    val current = (installations.get(reviewed.id) as? RepositoryResult.Success)?.value
    val saved = current?.value
    if (saved == null || saved != reviewed || saved.baseline.panelPort != state.panelPort) false
    else {
        val next = saved.copy(baseline = saved.baseline.copy(listenAddress = state.listenAddress.trim().ifEmpty { null }))
        next == saved || installations.update(next, current.revision) is RepositoryResult.Success
    }
} catch (cancel: CancellationException) {
    throw cancel
} catch (_: Exception) {
    false
}

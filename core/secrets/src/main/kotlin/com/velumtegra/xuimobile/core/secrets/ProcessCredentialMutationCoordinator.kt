package com.velumtegra.xuimobile.core.secrets

import com.velumtegra.xuimobile.core.domain.CredentialMutationCoordinator
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * One process-wide writer lane for every credential-reference mutation and orphan GC pass.
 *
 * VELUM//TEGRA currently runs in one Android process. If a future component adds android:process,
 * this implementation must be replaced by an inter-process/single-writer mechanism before that change ships.
 */
class ProcessCredentialMutationCoordinator : CredentialMutationCoordinator {
    override suspend fun <T> runExclusive(block: suspend () -> T): T = processMutex.withLock {
        block()
    }

    private companion object {
        val processMutex = Mutex()
    }
}

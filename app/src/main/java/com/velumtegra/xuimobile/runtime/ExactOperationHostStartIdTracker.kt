package com.velumtegra.xuimobile.runtime

/**
 * Service-local high-water mark for Android startId teardown safety.
 *
 * Android may accept a newer start request while an older host teardown is being processed. Every
 * stop therefore uses the newest startId already delivered to this Service instance. Android's
 * stopSelf(startId) contract then refuses to stop the Service if an even newer request was accepted
 * after that id, preventing stale teardown from killing replacement work.
 *
 * The tracker is ephemeral host state only. It carries no OperationId, never authorizes work and
 * never replaces the exact request/runtime ownership gates.
 */
internal class ExactOperationHostStartIdTracker {
    private val lock = Any()
    private var latestStartId: Int? = null

    /**
     * Records the highest delivered positive startId. A regressed/stale observation cannot lower
     * the stop token and therefore cannot weaken replacement-start protection.
     */
    fun observe(startId: Int): Int = synchronized(lock) {
        require(startId > 0) { "Android Service startId must be positive" }
        val current = latestStartId
        if (current == null || startId > current) {
            latestStartId = startId
        }
        checkNotNull(latestStartId)
    }

    fun latest(): Int? = synchronized(lock) { latestStartId }
}

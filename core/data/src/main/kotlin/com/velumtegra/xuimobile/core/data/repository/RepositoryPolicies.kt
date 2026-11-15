package com.velumtegra.xuimobile.core.data.repository

import com.velumtegra.xuimobile.core.domain.OperationRevision
import com.velumtegra.xuimobile.core.domain.RecordRevision
import com.velumtegra.xuimobile.core.model.ServerId

internal sealed interface RevisionAdvance<out T> {
    data class Success<T>(val value: T) : RevisionAdvance<T>
    data object Exhausted : RevisionAdvance<Nothing>
}

internal fun RecordRevision.nextRevision(): RevisionAdvance<RecordRevision> =
    if (value == Long.MAX_VALUE) RevisionAdvance.Exhausted
    else RevisionAdvance.Success(RecordRevision(value + 1))

internal fun OperationRevision.nextRevision(): RevisionAdvance<OperationRevision> =
    if (value == Long.MAX_VALUE) RevisionAdvance.Exhausted
    else RevisionAdvance.Success(OperationRevision(value + 1))

internal sealed interface BoundServerResolution {
    data class Success(val serverId: ServerId?) : BoundServerResolution
    data class MissingReference(val reason: String) : BoundServerResolution
    data class CrossServer(val installationServerId: ServerId, val routeServerId: ServerId) : BoundServerResolution
}

/**
 * Resolves the one server discriminator stored by WebPanelAccessEntity.
 * Null/null is the only unbound case: standalone + direct.
 */
internal fun resolveBoundServer(
    installationRequired: Boolean,
    installationServerId: ServerId?,
    routeAccessRequired: Boolean,
    routeServerId: ServerId?,
): BoundServerResolution {
    if (installationRequired && installationServerId == null) {
        return BoundServerResolution.MissingReference("Linked WebPanel installation does not exist")
    }
    if (routeAccessRequired && routeServerId == null) {
        return BoundServerResolution.MissingReference("SSH-tunnel ServerAccess does not exist")
    }
    if (installationServerId != null && routeServerId != null && installationServerId != routeServerId) {
        return BoundServerResolution.CrossServer(installationServerId, routeServerId)
    }
    return BoundServerResolution.Success(installationServerId ?: routeServerId)
}

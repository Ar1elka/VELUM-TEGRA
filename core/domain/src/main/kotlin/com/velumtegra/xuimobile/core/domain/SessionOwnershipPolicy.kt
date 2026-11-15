package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionOwner

object SessionOwnershipPolicy {
    fun matches(
        session: SessionBinding,
        requiredOwner: SessionOwner,
        requiredAccessId: ServerAccessId,
    ): Boolean = session.owner == requiredOwner && session.serverAccessId == requiredAccessId
}

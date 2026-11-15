package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.WebPanelAccessId

sealed interface LocalDeletionPlan {
    data class DeleteWebPanelAccess(val webPanelAccessId: WebPanelAccessId) : LocalDeletionPlan
}

object LocalDeletionPolicy {
    /** Deleting local web credentials never authorizes or implies a remote mutation. */
    fun webPanelAccess(webPanelAccessId: WebPanelAccessId): LocalDeletionPlan =
        LocalDeletionPlan.DeleteWebPanelAccess(webPanelAccessId)
}

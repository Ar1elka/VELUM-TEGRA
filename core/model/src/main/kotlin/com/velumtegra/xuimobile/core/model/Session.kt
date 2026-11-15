package com.velumtegra.xuimobile.core.model

sealed interface SessionOwner {
    data class Management(
        val installationId: XuiInstallationId,
        val serverAccessId: ServerAccessId,
    ) : SessionOwner

    data class WebPanel(val webPanelAccessId: WebPanelAccessId) : SessionOwner
    data class Operation(val operationId: OperationId) : SessionOwner
}

data class SessionBinding(
    val sessionId: SessionId,
    val serverAccessId: ServerAccessId,
    val owner: SessionOwner,
)

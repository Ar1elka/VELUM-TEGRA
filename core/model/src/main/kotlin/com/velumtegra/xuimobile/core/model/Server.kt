package com.velumtegra.xuimobile.core.model

import java.time.Instant

/** A real VPS known to the application. Access methods are separate objects. */
data class Server(
    val id: ServerId,
    val displayName: String,
    val createdAt: Instant,
)

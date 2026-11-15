package com.velumtegra.xuimobile.scanner

import com.velumtegra.xuimobile.core.scanner.android.ScannerServiceState

data class ScannerHomeState(
    val running: Boolean = false,
    val paused: Boolean = false,
    val networkLost: Boolean = false,
    val completed: Int = 0,
    val feasible: Int = 0,
)

object ScannerUiProjection {
    fun home(state: ScannerServiceState): ScannerHomeState =
        ScannerHomeState(
            running = state.running,
            paused = state.paused,
            networkLost = state.networkLost,
            completed = state.completed,
            feasible = state.feasible,
        )

    fun validateStart(input: String, portText: String, threadsText: String): String? {
        if (input.isBlank()) return "Укажи IP, домен или CIDR."
        val port = portText.toIntOrNull()
        val threads = threadsText.toIntOrNull()
        if (port == null || port !in 1..65535) return "Порт должен быть от 1 до 65535."
        if (threads == null || threads !in 1..32) return "Количество потоков должно быть от 1 до 32."
        return null
    }
}

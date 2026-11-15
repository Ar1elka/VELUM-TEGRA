package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.DiscoveryObservation
import com.velumtegra.xuimobile.core.model.DiscoveryPathKind
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.DiscoveryPresence
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Locale

/**
 * Typed read-only probe vocabulary. It deliberately contains no shell command string and therefore
 * cannot be used as a free-form remote execution surface.
 */
sealed interface DiscoveryProbeSpec {
    val timeout: Duration

    data class PlatformRelease(
        override val timeout: Duration = DiscoveryProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DiscoveryProbeSpec

    data class ServiceUnitPresence(
        val serviceUnit: String,
        override val timeout: Duration = DiscoveryProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DiscoveryProbeSpec

    data class InstallationPathPresence(
        val pathKind: DiscoveryPathKind,
        val path: String,
        override val timeout: Duration = DiscoveryProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DiscoveryProbeSpec

    /** A positive match is normalized only to FOREIGN_PANEL evidence by the future executor. */
    data class ForeignPanelPathMarker(
        val path: String,
        override val timeout: Duration = DiscoveryProbePlan.DEFAULT_PROBE_TIMEOUT,
    ) : DiscoveryProbeSpec
}

data class DiscoverySupportedLayout(
    val binaryPath: String,
    val rootPath: String,
    val databasePaths: Set<String>,
)

/** Finite reviewed probe surface inherited from the executable specification, without its heuristics. */
object DiscoveryProbePlan {
    val DEFAULT_PROBE_TIMEOUT: Duration = Duration.ofSeconds(5)

    val supportedServiceUnits: Set<String> = linkedSetOf("x-ui.service")

    // Launcher candidates are probed, but only canonical layout binaries below may enter proof.
    val supportedBinaryProbePaths: Set<String> = linkedSetOf(
        "/usr/local/x-ui/x-ui",
        "/usr/bin/x-ui",
        "/usr/local/bin/x-ui",
        "/opt/x-ui/x-ui",
    )

    val supportedRootProbePaths: Set<String> = linkedSetOf(
        "/usr/local/x-ui",
        "/opt/x-ui",
    )

    val supportedDatabaseProbePaths: Set<String> = linkedSetOf(
        "/etc/x-ui/x-ui.db",
        "/usr/local/x-ui/db/x-ui.db",
        "/usr/local/x-ui/x-ui.db",
        "/opt/x-ui/db/x-ui.db",
        "/opt/x-ui/x-ui.db",
    )

    val supportedLayouts: List<DiscoverySupportedLayout> = listOf(
        DiscoverySupportedLayout(
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePaths = linkedSetOf(
                "/etc/x-ui/x-ui.db",
                "/usr/local/x-ui/db/x-ui.db",
                "/usr/local/x-ui/x-ui.db",
            ),
        ),
        DiscoverySupportedLayout(
            binaryPath = "/opt/x-ui/x-ui",
            rootPath = "/opt/x-ui",
            databasePaths = linkedSetOf(
                "/etc/x-ui/x-ui.db",
                "/opt/x-ui/db/x-ui.db",
                "/opt/x-ui/x-ui.db",
            ),
        ),
    )

    /** Report-only CLI entrypoints: never installation identity or an execution target. */
    val reportOnlyLauncherPaths: Set<String> = setOf("/usr/bin/x-ui", "/usr/local/bin/x-ui")

    // Report-only hints from the old executable specification. No takeover/delete behavior exists.
    val foreignPanelPathMarkers: Set<String> = linkedSetOf(
        "/www/server/panel",
        "/usr/local/cpanel/cpanel",
    )

    val initialProbes: List<DiscoveryProbeSpec> = buildList {
        add(DiscoveryProbeSpec.PlatformRelease())
        supportedServiceUnits.forEach { add(DiscoveryProbeSpec.ServiceUnitPresence(it)) }
        supportedBinaryProbePaths.forEach {
            add(DiscoveryProbeSpec.InstallationPathPresence(DiscoveryPathKind.BINARY, it))
        }
        supportedRootProbePaths.forEach {
            add(DiscoveryProbeSpec.InstallationPathPresence(DiscoveryPathKind.ROOT, it))
        }
        supportedDatabaseProbePaths.forEach {
            add(DiscoveryProbeSpec.InstallationPathPresence(DiscoveryPathKind.DATABASE, it))
        }
        foreignPanelPathMarkers.forEach { add(DiscoveryProbeSpec.ForeignPanelPathMarker(it)) }
    }
}

sealed interface DiscoveryProbeParseResult<out T> {
    data class Parsed<T>(val value: T) : DiscoveryProbeParseResult<T>
    data object Malformed : DiscoveryProbeParseResult<Nothing>
}

/** Strict transient parsers. Raw text never becomes model evidence without normalization. */
object DiscoveryProbeParsers {
    private const val MAX_OS_RELEASE_BYTES = 4 * 1024
    private const val MAX_OS_RELEASE_LINES = 64

    fun parseOsRelease(
        raw: String,
        observedAt: Instant,
    ): DiscoveryProbeParseResult<DiscoveryObservation.Platform> {
        if (raw.toByteArray(StandardCharsets.UTF_8).size > MAX_OS_RELEASE_BYTES) {
            return DiscoveryProbeParseResult.Malformed
        }
        if ('\u0000' in raw) return DiscoveryProbeParseResult.Malformed

        val lines = raw.lineSequence().toList()
        if (lines.size > MAX_OS_RELEASE_LINES) return DiscoveryProbeParseResult.Malformed

        var id: String? = null
        var versionId: String? = null
        for (line in lines) {
            if (line.isBlank() || line.startsWith('#')) continue
            val separator = line.indexOf('=')
            if (separator <= 0) continue
            val key = line.substring(0, separator)
            val value = decodeOsReleaseValue(line.substring(separator + 1))
                ?: return DiscoveryProbeParseResult.Malformed
            when (key) {
                "ID" -> {
                    val normalized = value.lowercase(Locale.ROOT)
                    if (id != null && id != normalized) return DiscoveryProbeParseResult.Malformed
                    id = normalized
                }
                "VERSION_ID" -> {
                    if (versionId != null && versionId != value) return DiscoveryProbeParseResult.Malformed
                    versionId = value
                }
            }
        }

        val distributionId = id ?: return DiscoveryProbeParseResult.Malformed
        return try {
            DiscoveryProbeParseResult.Parsed(
                DiscoveryObservation.Platform(
                    platform = DiscoveryPlatform(distributionId, versionId),
                    observedAt = observedAt,
                ),
            )
        } catch (_: IllegalArgumentException) {
            DiscoveryProbeParseResult.Malformed
        }
    }

    /** Presence probes use a fixed predicate contract: 0 = present, 1 = absent, anything else is malformed. */
    fun parsePresenceExitCode(exitCode: Int): DiscoveryProbeParseResult<DiscoveryPresence> = when (exitCode) {
        0 -> DiscoveryProbeParseResult.Parsed(DiscoveryPresence.PRESENT)
        1 -> DiscoveryProbeParseResult.Parsed(DiscoveryPresence.ABSENT)
        else -> DiscoveryProbeParseResult.Malformed
    }

    private fun decodeOsReleaseValue(rawValue: String): String? {
        if (rawValue.length > 256) return null
        val value = rawValue.trim()
        if (value.isEmpty() || '\n' in value || '\r' in value || '\u0000' in value) return null
        if (value.first() == '"' || value.first() == '\'') {
            if (value.length < 2 || value.last() != value.first()) return null
            val inner = value.substring(1, value.length - 1)
            if ('"' in inner || '\'' in inner || '\\' in inner) return null
            return inner
        }
        if (value.any { it.isWhitespace() }) return null
        return value
    }
}

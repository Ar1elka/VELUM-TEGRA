package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.DiscoveryClassifier
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeParseResult
import com.velumtegra.xuimobile.core.domain.DiscoveryProbeParsers
import com.velumtegra.xuimobile.core.domain.DiscoveryProbePlan
import com.velumtegra.xuimobile.core.domain.ManagedInstallMarkerProtocol
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.DiscoveryClassification
import com.velumtegra.xuimobile.core.model.DiscoveryEvidence
import com.velumtegra.xuimobile.core.model.DiscoveryPlatform
import com.velumtegra.xuimobile.core.model.DiscoveryScope
import com.velumtegra.xuimobile.core.model.FreshInstallInstallerCapability
import com.velumtegra.xuimobile.core.model.FreshInstallPrivilegeCapability
import com.velumtegra.xuimobile.core.model.FreshInstallScope
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.UpdateServerArchitecture
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/**
 * Read-only observation of "is this target a clean candidate for a fresh 3x-ui install" over one
 * already-open exact operation-owned SSH session.
 *
 * Boundaries (deliberate):
 * - The adapter never connects, retries, downloads, writes, restarts or escalates privileges. It
 *   runs only the fixed reviewed commands compiled by [FreshInstallReadinessCommandCompiler].
 * - Owner/access binding and [SshSessionHandle.isOpen] are verified before the first command and the
 *   exact binding is re-verified after every command.
 * - It produces only normalized facts/reasons. It does NOT create a FreshInstallPreflightProof,
 *   register authority or start an install; wiring those is a later, separate step.
 * - A path is absent only on the fixed stat probe's explicit missing-file response after effective
 *   UID 0 was proven. Other path lookup errors, truncated/malformed output and transport uncertainty are
 *   [FreshInstallReadinessObservationResult.Indeterminate] (or a conflict plus uncertainty), never Ready.
 */
class FreshInstallReadinessSshAdapter(
    private val now: () -> Instant = Instant::now,
) {
    suspend fun observe(
        scope: FreshInstallScope,
        session: SshSessionHandle,
    ): FreshInstallReadinessObservationResult {
        val binding = session.binding
        if (binding.serverAccessId != scope.serverAccessId ||
            binding.owner != SessionOwner.Operation(scope.operationId)
        ) {
            return FreshInstallReadinessObservationResult.Rejected(
                FreshInstallReadinessRejection.ExactSessionBindingMismatch,
            )
        }
        if (!session.isOpen) {
            return FreshInstallReadinessObservationResult.Rejected(FreshInstallReadinessRejection.SessionClosed)
        }

        val observedAt = now()
        val conflicts = linkedSetOf<FreshInstallConflict>()
        val gaps = linkedSetOf<FreshInstallPrerequisiteGap>()
        val uncertainties = linkedSetOf<FreshInstallUncertainty>()
        var platform: DiscoveryPlatform? = null
        var architecture: UpdateServerArchitecture? = null

        fun conclude(): FreshInstallReadinessObservationResult {
            if (conflicts.isNotEmpty()) {
                return FreshInstallReadinessObservationResult.Conflict(
                    conflicts = conflicts.toSet(),
                    prerequisiteGaps = gaps.toSet(),
                    uncertainties = uncertainties.toSet(),
                )
            }
            if (uncertainties.isNotEmpty()) {
                return FreshInstallReadinessObservationResult.Indeterminate(
                    uncertainties = uncertainties.toSet(),
                    prerequisiteGaps = gaps.toSet(),
                )
            }
            if (gaps.isNotEmpty()) {
                return FreshInstallReadinessObservationResult.PrerequisitesUnmet(gaps.toSet())
            }
            val completePlatform = platform
            val completeArchitecture = architecture
            if (completePlatform == null || completeArchitecture == null) {
                // Defensive: no reason was recorded yet a mandatory fact is missing.
                return FreshInstallReadinessObservationResult.Indeterminate(
                    uncertainties = setOf(
                        FreshInstallUncertainty.MalformedEvidence(FreshInstallReadinessStep.PLATFORM),
                    ),
                    prerequisiteGaps = emptySet(),
                )
            }
            return FreshInstallReadinessObservationResult.Ready(
                FreshInstallReadinessFacts(
                    scope = scope,
                    platform = completePlatform,
                    architecture = completeArchitecture,
                    privilegeCapability = FreshInstallPrivilegeCapability.DIRECT_ROOT,
                    installerCapability = FreshInstallInstallerCapability.OFFICIAL_3X_UI_LINUX_V1,
                    observedAt = observedAt,
                ),
            )
        }

        // 1. Effective UID first: without proven root every later "absent" is unreliable, so stop.
        val uidText = when (val read = readStep(session, binding, FreshInstallReadinessCommandCompiler.effectiveUid)) {
            is StepRead.Text -> read.value
            is StepRead.Abort -> {
                uncertainties += read.uncertainty
                return conclude()
            }
        }
        val uid = parseUid(uidText)
        if (uid == null) {
            uncertainties += FreshInstallUncertainty.MalformedEvidence(FreshInstallReadinessStep.EFFECTIVE_UID)
            return conclude()
        }
        if (uid != 0L) {
            gaps += FreshInstallPrerequisiteGap.NotDirectRoot
            return conclude()
        }

        // 2. Kernel + architecture.
        when (val read = readStep(session, binding, FreshInstallReadinessCommandCompiler.kernelAndArchitecture)) {
            is StepRead.Abort -> {
                uncertainties += read.uncertainty
                return conclude()
            }
            is StepRead.Text -> {
                val lines = strictLines(read.value, expected = 2)
                val kernel = lines?.get(0)
                val rawArchitecture = lines?.get(1)
                if (kernel == null || rawArchitecture == null ||
                    !TOKEN.matches(kernel) || !TOKEN.matches(rawArchitecture)
                ) {
                    uncertainties += FreshInstallUncertainty.MalformedEvidence(
                        FreshInstallReadinessStep.KERNEL_AND_ARCHITECTURE,
                    )
                    return conclude()
                }
                if (kernel != "Linux") gaps += FreshInstallPrerequisiteGap.NotLinux
                architecture = when (rawArchitecture) {
                    "x86_64" -> UpdateServerArchitecture.AMD64
                    "aarch64" -> UpdateServerArchitecture.ARM64
                    else -> {
                        gaps += FreshInstallPrerequisiteGap.UnsupportedArchitecture
                        null
                    }
                }
            }
        }

        // 3. Platform via the existing strict os-release parser and existing classifier policy.
        when (val read = readStep(session, binding, FreshInstallReadinessCommandCompiler.platformRelease)) {
            is StepRead.Abort -> {
                uncertainties += read.uncertainty
                return conclude()
            }
            is StepRead.Text -> {
                when (val parsed = DiscoveryProbeParsers.parseOsRelease(read.value, observedAt)) {
                    DiscoveryProbeParseResult.Malformed -> {
                        uncertainties += FreshInstallUncertainty.MalformedEvidence(FreshInstallReadinessStep.PLATFORM)
                        return conclude()
                    }
                    is DiscoveryProbeParseResult.Parsed -> {
                        val observed = parsed.value.platform
                        val classification = DiscoveryClassifier.classify(
                            DiscoveryEvidence(
                                scope = DiscoveryScope(scope.operationId, scope.serverId, scope.serverAccessId),
                                observations = listOf(parsed.value),
                            ),
                        )
                        if (classification is DiscoveryClassification.UnsupportedPlatform) {
                            gaps += FreshInstallPrerequisiteGap.UnsupportedPlatform(observed)
                        } else {
                            platform = observed
                        }
                    }
                }
            }
        }

        // 4. systemd.
        var systemdPresent = false
        when (val read = readStep(session, binding, FreshInstallReadinessCommandCompiler.systemd)) {
            is StepRead.Abort -> {
                uncertainties += read.uncertainty
                return conclude()
            }
            is StepRead.Text -> when (strictLines(read.value, expected = 1)?.get(0)) {
                "SYSTEMD=PRESENT" -> systemdPresent = true
                "SYSTEMD=ABSENT" -> gaps += FreshInstallPrerequisiteGap.SystemdUnavailable
                else -> {
                    uncertainties += FreshInstallUncertainty.MalformedEvidence(FreshInstallReadinessStep.SYSTEMD)
                    return conclude()
                }
            }
        }

        // 5. Required tools of the existing reviewed installer compiler.
        when (val read = readStep(session, binding, FreshInstallReadinessCommandCompiler.requiredTools)) {
            is StepRead.Abort -> {
                uncertainties += read.uncertainty
                return conclude()
            }
            is StepRead.Text -> {
                val tools = FreshInstallReadinessCommandCompiler.requiredToolNames
                val lines = strictLines(read.value, expected = tools.size)
                if (lines == null) {
                    uncertainties += FreshInstallUncertainty.MalformedEvidence(FreshInstallReadinessStep.REQUIRED_TOOLS)
                    return conclude()
                }
                for ((index, tool) in tools.withIndex()) {
                    when (lines[index]) {
                        "$tool P" -> Unit
                        "$tool A" -> gaps += FreshInstallPrerequisiteGap.RequiredToolMissing(tool)
                        else -> {
                            uncertainties += FreshInstallUncertainty.MalformedEvidence(
                                FreshInstallReadinessStep.REQUIRED_TOOLS,
                            )
                            return conclude()
                        }
                    }
                }
            }
        }

        // 6. Existing x-ui service unit (only meaningful, and only run, with systemd present).
        if (systemdPresent) {
            when (val read = readStep(session, binding, FreshInstallReadinessCommandCompiler.serviceLoadState)) {
                is StepRead.Abort -> {
                    uncertainties += read.uncertainty
                    return conclude()
                }
                is StepRead.Text -> {
                    val state = strictLines(read.value, expected = 1)?.get(0)
                    when {
                        state == "not-found" -> Unit
                        state != null && state in PRESENT_LOAD_STATES -> {
                            conflicts += FreshInstallConflict.ExistingServiceUnit(
                                serviceUnit = FreshInstallReadinessCommandCompiler.SERVICE_UNIT,
                                loadState = PRESENT_LOAD_STATES.getValue(state),
                            )
                        }
                        else -> {
                            uncertainties += FreshInstallUncertainty.MalformedEvidence(
                                FreshInstallReadinessStep.SERVICE_UNIT,
                            )
                            return conclude()
                        }
                    }
                }
            }
        }

        // 7. Known files/folders/markers, symlink- and wrong-type-aware, in one fixed read-only script.
        when (val read = readStep(session, binding, FreshInstallReadinessCommandCompiler.knownPaths)) {
            is StepRead.Abort -> {
                uncertainties += read.uncertainty
                return conclude()
            }
            is StepRead.Text -> {
                val observedPaths = FreshInstallReadinessCommandCompiler.observedPaths
                val lines = strictLines(read.value, expected = observedPaths.size)
                if (lines == null) {
                    uncertainties += FreshInstallUncertainty.MalformedEvidence(FreshInstallReadinessStep.KNOWN_PATHS)
                    return conclude()
                }
                for ((index, observed) in observedPaths.withIndex()) {
                    val prefix = "$index "
                    val state = lines[index].takeIf { it.startsWith(prefix) }?.removePrefix(prefix)
                    when (state) {
                        "ABSENT" -> Unit
                        "UNREADABLE" -> uncertainties += FreshInstallUncertainty.UnreadablePath(observed.path)
                        "FILE" -> conflicts += observed.conflict(FreshInstallPathObject.REGULAR_FILE)
                        "DIR" -> conflicts += observed.conflict(FreshInstallPathObject.DIRECTORY)
                        "SYMLINK" -> conflicts += observed.conflict(FreshInstallPathObject.SYMLINK)
                        "OTHER" -> conflicts += observed.conflict(FreshInstallPathObject.OTHER)
                        else -> {
                            uncertainties += FreshInstallUncertainty.MalformedEvidence(
                                FreshInstallReadinessStep.KNOWN_PATHS,
                            )
                            return conclude()
                        }
                    }
                }
            }
        }

        return conclude()
    }

    private suspend fun readStep(
        session: SshSessionHandle,
        binding: SessionBinding,
        command: FreshInstallReadinessCommand,
    ): StepRead {
        currentCoroutineContext().ensureActive()
        if (!session.isOpen || session.binding != binding) {
            return StepRead.Abort(FreshInstallUncertainty.SessionChanged)
        }
        val result = session.execute(command.command, command.config)
        currentCoroutineContext().ensureActive()
        if (!session.isOpen || session.binding != binding) {
            return StepRead.Abort(FreshInstallUncertainty.SessionChanged)
        }
        if (result.dispatchState != CommandDispatchState.DISPATCHED) {
            return StepRead.Abort(FreshInstallUncertainty.CommandUncertain(command.step, result.dispatchState))
        }
        when (val completion = result.completion) {
            CommandCompletion.ConfirmedSuccess -> Unit
            is CommandCompletion.ConfirmedFailure -> {
                // A non-zero exit is never interpreted as "absent": every probe prints explicit states.
                return StepRead.Abort(FreshInstallUncertainty.CommandFailed(command.step, completion.exitCode))
            }
            is CommandCompletion.Unknown -> {
                return StepRead.Abort(FreshInstallUncertainty.CommandUncertain(command.step, result.dispatchState))
            }
        }
        if (result.stdout.truncated || result.stderr.truncated) {
            return StepRead.Abort(FreshInstallUncertainty.OutputTruncated(command.step))
        }
        if (result.stdout.sizeBytes > command.config.stdoutCaptureLimitBytes || result.stderr.sizeBytes != 0) {
            return StepRead.Abort(FreshInstallUncertainty.MalformedEvidence(command.step))
        }
        val bytes = result.stdout.copyBytes()
        val text = try {
            decodeUtf8Strict(bytes)
        } finally {
            Arrays.fill(bytes, 0)
        }
        return if (text == null || !text.endsWith('\n') || '\r' in text || '\u0000' in text) {
            StepRead.Abort(FreshInstallUncertainty.MalformedEvidence(command.step))
        } else {
            StepRead.Text(text)
        }
    }

    /** Exactly [expected] non-empty, newline-terminated lines without CR/NUL; otherwise null. */
    private fun strictLines(text: String, expected: Int): List<String>? {
        if (!text.endsWith("\n") || '\r' in text || '\u0000' in text) return null
        val lines = text.removeSuffix("\n").split('\n')
        if (lines.size != expected || lines.any { it.isEmpty() }) return null
        return lines
    }

    private fun parseUid(text: String): Long? {
        val value = strictLines(text, expected = 1)?.get(0) ?: return null
        if (!UID.matches(value)) return null
        val parsed = value.toLongOrNull() ?: return null
        return parsed.takeIf { it <= MAX_UID }
    }

    private fun decodeUtf8Strict(bytes: ByteArray): String? = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: java.nio.charset.CharacterCodingException) {
        null
    }

    private sealed interface StepRead {
        data class Text(val value: String) : StepRead
        data class Abort(val uncertainty: FreshInstallUncertainty) : StepRead
    }

    private companion object {
        val TOKEN = Regex("[A-Za-z0-9_.-]{1,32}")
        val UID = Regex("0|[1-9][0-9]{0,9}")
        const val MAX_UID = 4294967295L
        val PRESENT_LOAD_STATES: Map<String, FreshInstallServiceLoadState> = mapOf(
            "loaded" to FreshInstallServiceLoadState.LOADED,
            "masked" to FreshInstallServiceLoadState.MASKED,
            "error" to FreshInstallServiceLoadState.ERROR,
            "bad-setting" to FreshInstallServiceLoadState.BAD_SETTING,
            "merged" to FreshInstallServiceLoadState.MERGED,
            "stub" to FreshInstallServiceLoadState.STUB,
        )
    }
}

/** Safe, non-secret normalized facts. Not a proof and not authority: wiring is a later step. */
data class FreshInstallReadinessFacts(
    val scope: FreshInstallScope,
    val platform: DiscoveryPlatform,
    val architecture: UpdateServerArchitecture,
    val privilegeCapability: FreshInstallPrivilegeCapability,
    val installerCapability: FreshInstallInstallerCapability,
    val observedAt: Instant,
)

/**
 * Precedence: any observed [FreshInstallConflict] wins; else any [FreshInstallUncertainty] makes the
 * result Indeterminate; else unmet prerequisites; Ready only when everything was observed and clean.
 */
sealed interface FreshInstallReadinessObservationResult {
    data class Ready(val facts: FreshInstallReadinessFacts) : FreshInstallReadinessObservationResult

    /** Positive evidence of an existing/foreign/managed installation or wrong-type object. */
    data class Conflict(
        val conflicts: Set<FreshInstallConflict>,
        val prerequisiteGaps: Set<FreshInstallPrerequisiteGap>,
        val uncertainties: Set<FreshInstallUncertainty>,
    ) : FreshInstallReadinessObservationResult {
        init {
            require(conflicts.isNotEmpty())
        }
    }

    /** Fully observed target that lacks something the reviewed installer needs. */
    data class PrerequisitesUnmet(
        val prerequisiteGaps: Set<FreshInstallPrerequisiteGap>,
    ) : FreshInstallReadinessObservationResult {
        init {
            require(prerequisiteGaps.isNotEmpty())
        }
    }

    /** Error/uncertainty: absence of evidence, never confirmation that the server is clean. */
    data class Indeterminate(
        val uncertainties: Set<FreshInstallUncertainty>,
        val prerequisiteGaps: Set<FreshInstallPrerequisiteGap>,
    ) : FreshInstallReadinessObservationResult {
        init {
            require(uncertainties.isNotEmpty())
        }
    }

    /** No command was sent. */
    data class Rejected(val failure: FreshInstallReadinessRejection) : FreshInstallReadinessObservationResult
}

enum class FreshInstallReadinessRejection {
    ExactSessionBindingMismatch,
    SessionClosed,
}

enum class FreshInstallReadinessStep {
    EFFECTIVE_UID,
    KERNEL_AND_ARCHITECTURE,
    PLATFORM,
    SYSTEMD,
    REQUIRED_TOOLS,
    SERVICE_UNIT,
    KNOWN_PATHS,
}

enum class FreshInstallServiceLoadState { LOADED, MASKED, ERROR, BAD_SETTING, MERGED, STUB }

enum class FreshInstallPathObject { REGULAR_FILE, DIRECTORY, SYMLINK, OTHER }

enum class FreshInstallPathRole {
    SERVICE_DEFINITION,
    BINARY,
    LAUNCHER,
    ROOT,
    DATABASE,
    CONFIG_DIRECTORY,
    MANAGED_MARKER,
    FOREIGN_PANEL,
}

sealed interface FreshInstallConflict {
    data class ExistingServiceUnit(
        val serviceUnit: String,
        val loadState: FreshInstallServiceLoadState,
    ) : FreshInstallConflict

    /** Anything at a known path that is not absent: file, directory, symlink (even dangling) or other. */
    data class ExistingPath(
        val role: FreshInstallPathRole,
        val path: String,
        val objectKind: FreshInstallPathObject,
    ) : FreshInstallConflict
}

sealed interface FreshInstallPrerequisiteGap {
    data object NotDirectRoot : FreshInstallPrerequisiteGap
    data object NotLinux : FreshInstallPrerequisiteGap
    data object UnsupportedArchitecture : FreshInstallPrerequisiteGap
    data class UnsupportedPlatform(val platform: DiscoveryPlatform) : FreshInstallPrerequisiteGap
    data object SystemdUnavailable : FreshInstallPrerequisiteGap
    data class RequiredToolMissing(val tool: String) : FreshInstallPrerequisiteGap
}

sealed interface FreshInstallUncertainty {
    data object SessionChanged : FreshInstallUncertainty
    data class CommandUncertain(
        val step: FreshInstallReadinessStep,
        val dispatchState: CommandDispatchState,
    ) : FreshInstallUncertainty
    data class CommandFailed(val step: FreshInstallReadinessStep, val exitCode: Int?) : FreshInstallUncertainty
    data class OutputTruncated(val step: FreshInstallReadinessStep) : FreshInstallUncertainty
    data class MalformedEvidence(val step: FreshInstallReadinessStep) : FreshInstallUncertainty
    data class UnreadablePath(val path: String) : FreshInstallUncertainty
}

internal data class FreshInstallReadinessCommand(
    val step: FreshInstallReadinessStep,
    val command: RemoteCommand,
    val config: SshTransportConfig,
)

internal data class ObservedFreshInstallPath(val role: FreshInstallPathRole, val path: String) {
    fun conflict(kind: FreshInstallPathObject): FreshInstallConflict =
        FreshInstallConflict.ExistingPath(role, path, kind)
}

/** Fixed compiler. No caller-provided text can reach a remote shell; every literal is a reviewed constant. */
internal object FreshInstallReadinessCommandCompiler {
    const val SERVICE_UNIT: String = "x-ui.service"
    private const val MANAGED_MARKER_DIRECTORY = "/var/lib/velum-tegra/managed-install/v1"
    private val commandTimeout: Duration = Duration.ofSeconds(10)
    private val channelOpenTimeout: Duration = Duration.ofSeconds(5)

    val requiredToolNames: List<String> = InstallerReviewedCommandCompiler.REQUIRED_REMOTE_TOOLS

    /** Order is the wire contract: output line N describes entry N. */
    val observedPaths: List<ObservedFreshInstallPath> = buildList {
        listOf(
            "/etc/systemd/system/x-ui.service",
            "/etc/systemd/system/x-ui.service.d",
            "/usr/lib/systemd/system/x-ui.service",
            "/lib/systemd/system/x-ui.service",
        ).forEach { add(ObservedFreshInstallPath(FreshInstallPathRole.SERVICE_DEFINITION, it)) }
        DiscoveryProbePlan.supportedBinaryProbePaths.forEach {
            val role = if (it in DiscoveryProbePlan.reportOnlyLauncherPaths) {
                FreshInstallPathRole.LAUNCHER
            } else {
                FreshInstallPathRole.BINARY
            }
            add(ObservedFreshInstallPath(role, it))
        }
        DiscoveryProbePlan.supportedRootProbePaths.forEach {
            add(ObservedFreshInstallPath(FreshInstallPathRole.ROOT, it))
        }
        DiscoveryProbePlan.supportedDatabaseProbePaths.forEach {
            add(ObservedFreshInstallPath(FreshInstallPathRole.DATABASE, it))
        }
        listOf("/etc/x-ui", "/usr/local/x-ui/db", "/opt/x-ui/db").forEach {
            add(ObservedFreshInstallPath(FreshInstallPathRole.CONFIG_DIRECTORY, it))
        }
        add(ObservedFreshInstallPath(FreshInstallPathRole.MANAGED_MARKER, MANAGED_MARKER_DIRECTORY))
        add(ObservedFreshInstallPath(FreshInstallPathRole.MANAGED_MARKER, ManagedInstallMarkerProtocol.MARKER_PATH))
        DiscoveryProbePlan.foreignPanelPathMarkers.forEach {
            add(ObservedFreshInstallPath(FreshInstallPathRole.FOREIGN_PANEL, it))
        }
    }

    val effectiveUid: FreshInstallReadinessCommand = build(
        FreshInstallReadinessStep.EFFECTIVE_UID, "fresh-readiness-uid", "id -u", stdoutLimit = 32,
    )

    val kernelAndArchitecture: FreshInstallReadinessCommand = build(
        FreshInstallReadinessStep.KERNEL_AND_ARCHITECTURE,
        "fresh-readiness-kernel-arch",
        "uname -s && uname -m",
        stdoutLimit = 128,
    )

    val platformRelease: FreshInstallReadinessCommand = build(
        FreshInstallReadinessStep.PLATFORM,
        "fresh-readiness-platform",
        "cat -- /etc/os-release",
        stdoutLimit = 8 * 1024,
    )

    val systemd: FreshInstallReadinessCommand = build(
        FreshInstallReadinessStep.SYSTEMD,
        "fresh-readiness-systemd",
        "if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; " +
            "then echo SYSTEMD=PRESENT; else echo SYSTEMD=ABSENT; fi",
        stdoutLimit = 64,
    )

    val requiredTools: FreshInstallReadinessCommand = build(
        FreshInstallReadinessStep.REQUIRED_TOOLS,
        "fresh-readiness-tools",
        "for t in ${requiredToolNames.joinToString(" ") { quote(it) }}; do " +
            "if command -v \"\$t\" >/dev/null 2>&1; then printf '%s P\\n' \"\$t\"; " +
            // The installer worker installs a missing curl through apt-get before fetching.
            "elif [ \"\$t\" = 'curl' ] && command -v 'apt-get' >/dev/null 2>&1; then printf '%s P\\n' \"\$t\"; " +
            "else printf '%s A\\n' \"\$t\"; fi; done",
        stdoutLimit = 1024,
    )

    val serviceLoadState: FreshInstallReadinessCommand = build(
        FreshInstallReadinessStep.SERVICE_UNIT,
        "fresh-readiness-service",
        "systemctl show --property=LoadState --value -- ${quote(SERVICE_UNIT)} 2>/dev/null",
        stdoutLimit = 64,
    )

    /**
     * Prints "<index> <STATE>" for each fixed path. GNU stat examines the entry without following a
     * final symlink. Only the explicit missing-file diagnostic in the C locale is treated as absent
     * (GNU coreutils wording, or uutils coreutils as shipped by Ubuntu 26.04+, which appends "(os error 2)").
     */
    val knownPaths: FreshInstallReadinessCommand = build(
        FreshInstallReadinessStep.KNOWN_PATHS,
        "fresh-readiness-paths",
        """
        command -v stat >/dev/null 2>&1 || exit 69
        state() {
          if kind=${'$'}(LC_ALL=C stat -c '%F' -- "${'$'}1" 2>&1); then
            case "${'$'}kind" in
              'regular file'|'regular empty file') printf '%s\n' FILE ;;
              directory) printf '%s\n' DIR ;;
              'symbolic link') printf '%s\n' SYMLINK ;;
              fifo|socket|'block special file'|'character special file') printf '%s\n' OTHER ;;
              *) printf '%s\n' UNREADABLE ;;
            esac
          else
            case "${'$'}kind" in
              'stat: '*': No such file or directory'|'stat: '*': No such file or directory (os error 2)') printf '%s\n' ABSENT ;;
              *) printf '%s\n' UNREADABLE ;;
            esac
          fi
        }
        i=0
        for p in ${observedPaths.joinToString(" ") { quote(it.path) }}; do
          printf '%s %s\n' "${'$'}i" "${'$'}(state "${'$'}p")"
          i=${'$'}((i + 1))
        done
        """.trimIndent(),
        stdoutLimit = 2048,
    )

    val all: List<FreshInstallReadinessCommand> = listOf(
        effectiveUid, kernelAndArchitecture, platformRelease, systemd, requiredTools, serviceLoadState, knownPaths,
    )

    private fun build(
        step: FreshInstallReadinessStep,
        label: String,
        raw: String,
        stdoutLimit: Int,
    ) = FreshInstallReadinessCommand(
        step = step,
        command = RemoteCommand.create(raw, label),
        config = SshTransportConfig(
            channelOpenTimeout = channelOpenTimeout,
            commandExecutionTimeout = commandTimeout,
            stdoutCaptureLimitBytes = stdoutLimit,
            stderrCaptureLimitBytes = 512,
        ),
    )

    private fun quote(value: String): String {
        require(value.all { it.isLetterOrDigit() || it in "/._-" }) { "Unreviewed character in fixed literal" }
        return "'$value'"
    }
}

package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.ChannelSftp
import com.jcraft.jsch.SftpATTRS
import com.jcraft.jsch.SftpException
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.Session
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelRouteTarget
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.sync.Mutex
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.Arrays
import java.util.concurrent.atomic.AtomicBoolean
import java.util.UUID

/**
 * One-attempt JSch adapter for one exact ServerAccess. It owns no repository lookup and has no retry,
 * fallback, TOFU or known_hosts path.
 */
class JschSshConnectionFactory(
    private val secretStore: SecretStore,
    /**
     * Detect non-root logins with sudo right after authentication and run every command through sudo.
     * Root logins are never probed and behave exactly as before. Loopback protocol fixtures disable it.
     * (Kept before [sessionIdFactory] so existing trailing-lambda call sites keep binding to the factory.)
     */
    private val detectPrivilege: Boolean = true,
    private val sessionIdFactory: () -> SessionId = { SessionId(UUID.randomUUID().toString()) },
) : SshConnectionFactory {
    override suspend fun connect(
        access: ServerAccess,
        owner: SessionOwner,
        config: SshTransportConfig,
    ): SshConnectResult {
        validateOwner(access, owner)?.let {
            return SshConnectResult.Failed(SshConnectFailure.InvalidConfiguration(it))
        }

        val pin = when (val parsed = CanonicalHostKeyFingerprint.parse(access.pinnedHostKey)) {
            is HostKeyFingerprintParseResult.Valid -> parsed.fingerprint
            is HostKeyFingerprintParseResult.Invalid -> {
                return SshConnectResult.Failed(
                    SshConnectFailure.InvalidConfiguration(parsed.reason),
                )
            }
        }

        val secretMaterial = when (val read = secretStore.read(access.auth.secretId)) {
            is SecretReadResult.Found -> read.material
            SecretReadResult.NotFound -> {
                return SshConnectResult.Failed(
                    SshConnectFailure.SecretUnavailable("Configured SSH authentication secret was not found"),
                )
            }
            is SecretReadResult.Unavailable -> {
                return SshConnectResult.Failed(SshConnectFailure.SecretUnavailable(read.reason))
            }
            is SecretReadResult.Corrupt -> {
                return SshConnectResult.Failed(SshConnectFailure.SecretCorrupt(read.reason))
            }
            is SecretReadResult.StorageFailure -> {
                return SshConnectResult.Failed(SshConnectFailure.SecretStorageFailure(read.reason))
            }
        }

        val preparedAuth = try {
            prepareAuthentication(access.auth, secretMaterial)
        } finally {
            secretMaterial.close()
        }
        if (preparedAuth is PreparedAuthResult.Failed) {
            return SshConnectResult.Failed(preparedAuth.failure)
        }
        val auth = (preparedAuth as PreparedAuthResult.Ready).auth

        var session: Session? = null
        var jsch: JSch? = null
        var socketFactory: BoundedSocketFactory? = null
        var pinRepository: ExactPinnedHostKeyRepository? = null
        try {
            val expectedLookupHost = ExactPinnedHostKeyRepository.lookupHost(
                access.endpoint.host,
                access.endpoint.port,
            )
            val exactPinRepository = ExactPinnedHostKeyRepository(expectedLookupHost, pin)
            pinRepository = exactPinRepository
            val exactJsch = JSch().apply {
                setHostKeyRepository(exactPinRepository)
            }
            jsch = exactJsch

            if (auth is PreparedAuth.PrivateKey) {
                val loaded = runCatching {
                    auth.material.useForIdentity { privateKey, passphrase ->
                        exactJsch.addIdentity(
                            "velum-${access.id.value}",
                            privateKey,
                            null,
                            passphrase,
                        )
                    }
                }.isSuccess
                if (!loaded) {
                    return SshConnectResult.Failed(
                        SshConnectFailure.SecretCorrupt("Configured private-key secret could not be loaded"),
                    )
                }
            }

            session = exactJsch.getSession(
                access.username,
                access.endpoint.host,
                access.endpoint.port,
            )
            val boundedSocketFactory = BoundedSocketFactory(config.tcpConnectTimeout.toJschTimeoutMillis())
            socketFactory = boundedSocketFactory
            session.setSocketFactory(boundedSocketFactory)
            session.setHostKeyRepository(exactPinRepository)
            when (auth) {
                is PreparedAuth.Password -> {
                    JschPasswordSessionPolicy.applyTo(session)
                    session.setPassword(auth.password)
                }
                is PreparedAuth.PrivateKey -> {
                    JschPrivateKeySessionPolicy.applyTo(session)
                }
            }

            runInterruptible(Dispatchers.IO) {
                session.connect(config.handshakeAndAuthTimeout.toJschTimeoutMillis())
            }

            // Authentication is complete. Release credential material retained only for authentication.
            runCatching { session.setPassword(ByteArray(0)) }
            runCatching { exactJsch.removeAllIdentity() }

            if (!session.isConnected) {
                runCatching { session.disconnect() }
                return SshConnectResult.Failed(
                    SshConnectFailure.Unexpected("SSH library returned without a connected session"),
                )
            }
            // Long-lived sessions (web panel tunnel) otherwise go silent and get dropped by mobile NAT/VPN.
            // A dead peer is detected after ~1 minute instead of hanging until the next request.
            runCatching {
                session.setServerAliveInterval(SERVER_ALIVE_INTERVAL_MS)
                session.setServerAliveCountMax(SERVER_ALIVE_COUNT_MAX)
            }

            val privilege = if (detectPrivilege && access.username != "root") {
                runInterruptible(Dispatchers.IO) {
                    RemotePrivilegeContext.detect(session, (auth as? PreparedAuth.Password)?.password)
                }
            } else {
                RemotePrivilegeContext.DIRECT
            }

            val binding = SessionBinding(
                sessionId = sessionIdFactory(),
                serverAccessId = access.id,
                owner = owner,
            )
            return SshConnectResult.Connected(
                JschConnectedSessionHandle(session, binding, pin.asHexSha256(), privilege, access.username),
            )
        } catch (_: CancellationException) {
            runCatching { session?.disconnect() }
            return SshConnectResult.Failed(SshConnectFailure.Cancelled)
        } catch (failure: Throwable) {
            runCatching { session?.disconnect() }
            return SshConnectResult.Failed(
                classifyConnectFailure(
                    failure = failure,
                    tcpEstablished = socketFactory?.tcpWasEstablished() == true,
                    pinRepository = pinRepository,
                    expectedFingerprint = pin.asString(),
                ),
            )
        } finally {
            runCatching { session?.setPassword(ByteArray(0)) }
            runCatching { jsch?.removeAllIdentity() }
            auth.close()
        }
    }

    private fun prepareAuthentication(
        auth: SshAuthRef,
        secretMaterial: com.velumtegra.xuimobile.core.domain.SecretMaterial,
    ): PreparedAuthResult = when (auth) {
        is SshAuthRef.Password -> PreparedAuthResult.Ready(
            PreparedAuth.Password(secretMaterial.useBytes { it.copyOf() }),
        )
        is SshAuthRef.PrivateKey -> secretMaterial.useBytes { encoded ->
            when (val decoded = PrivateKeySecretEnvelopeCodec.decode(encoded)) {
                is PrivateKeySecretDecodeResult.Valid -> PreparedAuthResult.Ready(
                    PreparedAuth.PrivateKey(decoded.material),
                )
                is PrivateKeySecretDecodeResult.Invalid -> PreparedAuthResult.Failed(
                    SshConnectFailure.SecretCorrupt(decoded.reason),
                )
            }
        }
    }

    private sealed interface PreparedAuth : AutoCloseable {
        class Password(val password: ByteArray) : PreparedAuth {
            override fun close() {
                Arrays.fill(password, 0)
            }
        }

        class PrivateKey(val material: PrivateKeySecretMaterial) : PreparedAuth {
            override fun close() {
                material.close()
            }
        }
    }

    private sealed interface PreparedAuthResult {
        class Ready(val auth: PreparedAuth) : PreparedAuthResult
        class Failed(val failure: SshConnectFailure) : PreparedAuthResult
    }

    private fun validateOwner(access: ServerAccess, owner: SessionOwner): String? = when (owner) {
        is SessionOwner.Management -> if (owner.serverAccessId != access.id) {
            "Management SessionOwner is pinned to a different ServerAccessId"
        } else {
            null
        }
        is SessionOwner.Operation,
        is SessionOwner.WebPanel,
        -> null
    }

    private fun classifyConnectFailure(
        failure: Throwable,
        tcpEstablished: Boolean,
        pinRepository: ExactPinnedHostKeyRepository?,
        expectedFingerprint: String,
    ): SshConnectFailure {
        if (pinRepository?.didObserveMismatch() == true) {
            return SshConnectFailure.HostIdentityMismatch(
                expectedFingerprint = expectedFingerprint,
                presentedFingerprint = pinRepository.presentedFingerprintOrNull(),
            )
        }

        val chain = generateSequence(failure) { it.cause }.toList()
        if (chain.any { it is SocketTimeoutException }) {
            return SshConnectFailure.Timeout(
                if (tcpEstablished) SshTimeoutPhase.HANDSHAKE_OR_AUTH else SshTimeoutPhase.TCP_CONNECT,
            )
        }
        if (chain.any { it is UnknownHostException || it is ConnectException || it is NoRouteToHostException }) {
            return SshConnectFailure.Unreachable(chain.first().javaClass.simpleName)
        }

        val message = chain.asSequence().mapNotNull { it.message }.joinToString(" | ")
        if (AUTH_FAILURE_MARKERS.any { marker -> message.contains(marker, ignoreCase = true) }) {
            return SshConnectFailure.AuthenticationRejected
        }
        if (NEGOTIATION_FAILURE_MARKERS.any { marker -> message.contains(marker, ignoreCase = true) }) {
            return SshConnectFailure.NegotiationFailure("SSH algorithm negotiation failed")
        }
        if (failure is JSchException) {
            return SshConnectFailure.Unreachable("SSH transport connection failed")
        }
        return SshConnectFailure.Unexpected(failure.javaClass.simpleName.ifBlank { "Unexpected failure" })
    }

    private class JschConnectedSessionHandle(
        private val session: Session,
        override val binding: SessionBinding,
        override val verifiedHostKeySha256: String,
        private val privilege: RemotePrivilegeContext,
        override val remoteLoginUser: String,
    ) : WebPanelForwardingSshSessionHandle, VerifiedHostKeySshSessionHandle,
        SiteRemoteSftpCapableSessionHandle, XuiServerMenuSession, PrivilegeAwareSshSessionHandle {
        private val executeMutex = Mutex()
        private val lifecycleMonitor = Any()
        private val closeRequested = AtomicBoolean(false)
        private var activeWebPanelForward: JschWebPanelLocalForwardHandle? = null
        private var activeSiteSftpChannel: SiteRemoteSftpChannelHandle? = null

        override val privilegeMode: RemotePrivilegeMode get() = privilege.mode

        override val isOpen: Boolean
            get() = !closeRequested.get() && session.isConnected

        override suspend fun openXuiServerMenu(): XuiServerMenuChannel? {
            if (binding.owner !is SessionOwner.Management || !isOpen) return null
            val opened = session.openChannel("exec")
            if (opened !is ChannelExec) {
                opened?.disconnect()
                return null
            }
            try {
                opened.setPty(true)
                opened.setPtyType("dumb", 120, 40, 0, 0)
                opened.setCommand(
                    if (!privilege.elevates) {
                        "stty -echo || exit 1; export PAGER=cat SYSTEMD_PAGER=cat; exec /usr/bin/x-ui"
                    } else {
                        "stty -echo || exit 1; exec " +
                            privilege.wrapProgram("env PAGER=cat SYSTEMD_PAGER=cat /usr/bin/x-ui")
                    },
                )
                val input = opened.inputStream.reader(Charsets.UTF_8)
                val output = opened.outputStream
                runInterruptible(Dispatchers.IO) { opened.connect(8_000) }
                // sudo -S reads the password line from the pty before x-ui starts (echo is off).
                privilege.stdinBytes()?.let { line ->
                    try { runInterruptible(Dispatchers.IO) { output.write(line); output.flush() } } finally { line.fill(0) }
                }
                return JschXuiServerMenuChannel(opened, input, output)
            } catch (failure: Exception) {
                opened.disconnect()
                throw failure
            }
        }

        override fun openWebPanelLocalForward(
            target: ResolvedWebPanelTarget,
            config: WebPanelLocalForwardConfig,
        ): WebPanelLocalForwardOpenResult {
            val route = target.routeTarget
            if (route !is ResolvedWebPanelRouteTarget.SshTunnel) {
                return WebPanelLocalForwardOpenResult.Rejected(
                    WebPanelLocalForwardFailure.ROUTE_NOT_SSH_TUNNEL,
                )
            }

            val expectedOwner = SessionOwner.WebPanel(target.webPanelAccessId)
            if (binding.owner != expectedOwner) {
                return WebPanelLocalForwardOpenResult.Rejected(
                    WebPanelLocalForwardFailure.SESSION_OWNER_MISMATCH,
                )
            }
            if (binding.serverAccessId != route.serverAccessId) {
                return WebPanelLocalForwardOpenResult.Rejected(
                    WebPanelLocalForwardFailure.SERVER_ACCESS_MISMATCH,
                )
            }

            val remoteHost = route.remoteEndpoint.host.toSshForwardDestinationHost()
            val remotePort = route.remoteEndpoint.port

            return synchronized(lifecycleMonitor) {
                if (closeRequested.get() || !session.isConnected) {
                    return@synchronized WebPanelLocalForwardOpenResult.Rejected(
                        WebPanelLocalForwardFailure.SESSION_NOT_OPEN,
                    )
                }

                val current = activeWebPanelForward
                if (current != null) {
                    if (current.isLocallyOpen) {
                        return@synchronized if (current.target == target) {
                            WebPanelLocalForwardOpenResult.AlreadyOpen(current)
                        } else {
                            WebPanelLocalForwardOpenResult.Rejected(
                                WebPanelLocalForwardFailure.DIFFERENT_TARGET_ALREADY_FORWARDED,
                            )
                        }
                    }
                    activeWebPanelForward = null
                }

                val allocatedPort = try {
                    session.setPortForwardingL(
                        WEB_PANEL_LOOPBACK_HOST,
                        0,
                        remoteHost,
                        remotePort,
                        null,
                        config.remoteConnectTimeout.toJschTimeoutMillis(),
                    )
                } catch (_: JSchException) {
                    return@synchronized WebPanelLocalForwardOpenResult.Rejected(
                        WebPanelLocalForwardFailure.LOCAL_FORWARD_OPEN_FAILED,
                    )
                } catch (_: RuntimeException) {
                    return@synchronized WebPanelLocalForwardOpenResult.Rejected(
                        WebPanelLocalForwardFailure.LOCAL_FORWARD_OPEN_FAILED,
                    )
                }

                if (allocatedPort !in 1..65535) {
                    val released = runCatching {
                        session.delPortForwardingL(WEB_PANEL_LOOPBACK_HOST, allocatedPort)
                    }.isSuccess
                    if (!released) {
                        closeRequested.set(true)
                        runCatching { session.disconnect() }
                    }
                    return@synchronized WebPanelLocalForwardOpenResult.Rejected(
                        WebPanelLocalForwardFailure.INVALID_ALLOCATED_LOCAL_PORT,
                    )
                }

                lateinit var handle: JschWebPanelLocalForwardHandle
                handle = JschWebPanelLocalForwardHandle(
                    sessionBinding = binding,
                    target = target,
                    localEndpoint = WebPanelLoopbackEndpoint(port = allocatedPort),
                    sessionIsOpen = { isOpen },
                    onClose = { releaseWebPanelForward(handle) },
                )
                activeWebPanelForward = handle
                WebPanelLocalForwardOpenResult.Opened(handle)
            }
        }

        private fun releaseWebPanelForward(handle: JschWebPanelLocalForwardHandle) {
            var releaseFailed = false
            synchronized(lifecycleMonitor) {
                if (activeWebPanelForward !== handle) {
                    handle.markClosedByOwningSession()
                    return@synchronized
                }

                activeWebPanelForward = null
                handle.markClosedByOwningSession()
                if (!closeRequested.get() && session.isConnected) {
                    releaseFailed = runCatching {
                        session.delPortForwardingL(WEB_PANEL_LOOPBACK_HOST, handle.localEndpoint.port)
                    }.isFailure
                }
            }
            if (releaseFailed) {
                // Fail safe: if the listener cannot be removed deterministically, kill its owning exact SSH session.
                close()
            }
        }

        override fun openSiteRemoteSftpChannel(
            channelOpenTimeout: java.time.Duration,
        ): SiteRemoteSftpChannelHandle = synchronized(lifecycleMonitor) {
            require(!closeRequested.get() && session.isConnected) { "SSH session is not open" }
            require(!executeMutex.isLocked) { "Cannot open Site SFTP while an SSH exec occupies the exact session" }
            val current = activeSiteSftpChannel
            require(current == null || !current.isOpen) { "A Site SFTP channel is already open on this exact SSH session" }
            if (current != null) activeSiteSftpChannel = null

            if (privilege.elevates) {
                // SFTP would write with the login user's rights; use the sudo-backed command channel.
                lateinit var sudoHandle: SudoExecSiteFileChannelHandle
                sudoHandle = SudoExecSiteFileChannelHandle(
                    run = { command, stdin, limit ->
                        val password = privilege.stdinBytes()
                        val input = when {
                            password == null -> stdin
                            stdin == null -> password
                            else -> (password + stdin).also { password.fill(0) }
                        }
                        try {
                            JschBlockingExec.run(session, privilege.wrap(command), input, limit, 60_000)
                        } finally {
                            // Only buffers created here carry the password; never wipe the caller's payload.
                            if (password != null) input?.fill(0)
                        }
                    },
                    onClose = { synchronized(lifecycleMonitor) { if (activeSiteSftpChannel === sudoHandle) activeSiteSftpChannel = null } },
                )
                activeSiteSftpChannel = sudoHandle
                return@synchronized sudoHandle
            }

            val opened = session.openChannel("sftp")
            if (opened !is ChannelSftp) {
                runCatching { opened?.disconnect() }
                error("SSH library did not provide an SFTP channel")
            }
            try {
                opened.connect(channelOpenTimeout.toJschTimeoutMillis())
            } catch (failure: Throwable) {
                runCatching { opened.disconnect() }
                throw IllegalStateException("SFTP channel could not be opened", failure)
            }
            lateinit var handle: JschSiteRemoteSftpChannelHandle
            handle = JschSiteRemoteSftpChannelHandle(opened) { releaseSiteSftpChannel(handle) }
            activeSiteSftpChannel = handle
            handle
        }

        private fun releaseSiteSftpChannel(handle: JschSiteRemoteSftpChannelHandle) {
            synchronized(lifecycleMonitor) {
                if (activeSiteSftpChannel === handle) activeSiteSftpChannel = null
                handle.markClosedByOwningSession()
            }
            runCatching { handle.disconnectTransport() }
        }

        override suspend fun execute(
            command: RemoteCommand,
            config: SshTransportConfig,
        ): SshCommandResult {
            try {
                executeMutex.lock()
            } catch (_: CancellationException) {
                return commandResult(
                    dispatchState = CommandDispatchState.NOT_DISPATCHED,
                    completion = CommandCompletion.Unknown("SSH exec cancelled while waiting for session command slot"),
                )
            }
            return try {
                executeOnce(command, config)
            } finally {
                executeMutex.unlock()
            }
        }

        private suspend fun executeOnce(
            command: RemoteCommand,
            config: SshTransportConfig,
        ): SshCommandResult {
            val siteSftpActive = synchronized(lifecycleMonitor) { activeSiteSftpChannel?.isOpen == true }
            if (siteSftpActive) {
                return commandResult(
                    dispatchState = CommandDispatchState.NOT_DISPATCHED,
                    completion = CommandCompletion.Unknown("SSH exec is disabled while the bounded Site SFTP channel is active"),
                )
            }
            if (!isOpen) {
                return commandResult(
                    dispatchState = CommandDispatchState.NOT_DISPATCHED,
                    completion = CommandCompletion.Unknown("SSH session is not connected"),
                )
            }

            var channel: ChannelExec? = null
            var stdout: BoundedCaptureOutputStream? = null
            var stderr: BoundedCaptureOutputStream? = null
            var dispatchState = CommandDispatchState.NOT_DISPATCHED

            try {
                val opened = session.openChannel("exec")
                if (opened !is ChannelExec) {
                    runCatching { opened?.disconnect() }
                    return commandResult(
                        dispatchState = CommandDispatchState.NOT_DISPATCHED,
                        completion = CommandCompletion.Unknown("SSH exec channel is unavailable"),
                    )
                }
                val execChannel = opened
                channel = execChannel

                val stdoutSink = BoundedCaptureOutputStream(config.stdoutCaptureLimitBytes)
                val stderrSink = BoundedCaptureOutputStream(config.stderrCaptureLimitBytes)
                stdout = stdoutSink
                stderr = stderrSink

                // Configure the complete channel before the conservative dispatch boundary.
                execChannel.setInputStream(privilege.stdinBytes()?.let { java.io.ByteArrayInputStream(it) })
                execChannel.setOutputStream(stdoutSink)
                execChannel.setErrStream(stderrSink)
                execChannel.setCommand(privilege.wrap(command.rawForTransport()))

                try {
                    currentCoroutineContext().ensureActive()
                } catch (_: CancellationException) {
                    return commandResult(
                        dispatchState = CommandDispatchState.NOT_DISPATCHED,
                        completion = CommandCompletion.Unknown("SSH exec cancelled before dispatch"),
                        stdout = stdoutSink.snapshot(),
                        stderr = stderrSink.snapshot(),
                    )
                }

                // Coordinate local close/replacement with the conservative dispatch boundary.
                // If close() wins this monitor first, the command is provably NOT_DISPATCHED. If this
                // boundary wins first, any subsequent close/disconnect is conservatively DISPATCHED.
                val locallyClosedBeforeDispatch = synchronized(lifecycleMonitor) {
                    if (closeRequested.get() || !session.isConnected) {
                        true
                    } else {
                        dispatchState = CommandDispatchState.DISPATCHED
                        false
                    }
                }
                if (locallyClosedBeforeDispatch) {
                    return commandResult(
                        dispatchState = CommandDispatchState.NOT_DISPATCHED,
                        completion = CommandCompletion.Unknown("SSH session closed before exec dispatch"),
                        stdout = stdoutSink.snapshot(),
                        stderr = stderrSink.snapshot(),
                    )
                }

                // JSch Channel.connect() opens the channel and then sends the exec request. From this
                // point onward we deliberately cannot prove that the remote side did not receive it.
                try {
                    runInterruptible(Dispatchers.IO) {
                        execChannel.connect(config.channelOpenTimeout.toJschTimeoutMillis())
                    }
                } catch (_: CancellationException) {
                    runCatching { execChannel.disconnect() }
                    return commandResult(
                        dispatchState = dispatchState,
                        completion = CommandCompletion.Unknown("SSH exec cancelled after dispatch began"),
                        stdout = stdoutSink.snapshot(),
                        stderr = stderrSink.snapshot(),
                    )
                } catch (_: Exception) {
                    runCatching { execChannel.disconnect() }
                    return commandResult(
                        dispatchState = dispatchState,
                        completion = CommandCompletion.Unknown("SSH exec dispatch did not complete definitively"),
                        stdout = stdoutSink.snapshot(),
                        stderr = stderrSink.snapshot(),
                    )
                }

                val observedTerminalState: Boolean? = try {
                    withTimeoutOrNull(config.commandExecutionTimeout.toMillis().coerceAtLeast(1L)) {
                        while (!execChannel.isClosed && session.isConnected) {
                            delay(COMMAND_COMPLETION_POLL_MILLIS)
                        }
                        execChannel.isClosed
                    }
                } catch (_: CancellationException) {
                    runCatching { execChannel.disconnect() }
                    return commandResult(
                        dispatchState = dispatchState,
                        completion = CommandCompletion.Unknown("SSH exec cancelled after dispatch began"),
                        stdout = stdoutSink.snapshot(),
                        stderr = stderrSink.snapshot(),
                    )
                }

                if (observedTerminalState == null) {
                    runCatching { execChannel.disconnect() }
                    return commandResult(
                        dispatchState = dispatchState,
                        completion = CommandCompletion.Unknown("SSH command execution timed out after dispatch"),
                        stdout = stdoutSink.snapshot(),
                        stderr = stderrSink.snapshot(),
                    )
                }

                if (!observedTerminalState) {
                    runCatching { execChannel.disconnect() }
                    return commandResult(
                        dispatchState = dispatchState,
                        completion = CommandCompletion.Unknown("SSH session disconnected before command completion"),
                        stdout = stdoutSink.snapshot(),
                        stderr = stderrSink.snapshot(),
                    )
                }

                val exitStatus = execChannel.exitStatus
                val completion = when {
                    exitStatus == 0 -> CommandCompletion.ConfirmedSuccess
                    exitStatus > 0 -> CommandCompletion.ConfirmedFailure(
                        exitCode = exitStatus,
                        reason = "Remote command exited with non-zero status",
                    )
                    else -> CommandCompletion.Unknown("SSH channel closed without a trustworthy exit status")
                }
                return commandResult(
                    dispatchState = dispatchState,
                    completion = completion,
                    stdout = stdoutSink.snapshot(),
                    stderr = stderrSink.snapshot(),
                )
            } catch (_: CancellationException) {
                // This catch covers pre-dispatch setup cancellation. Post-dispatch cancellation is
                // handled next to the blocking/waiting boundary so its evidence remains DISPATCHED.
                return commandResult(
                    dispatchState = dispatchState,
                    completion = CommandCompletion.Unknown(
                        if (dispatchState == CommandDispatchState.DISPATCHED) {
                            "SSH exec cancelled after dispatch began"
                        } else {
                            "SSH exec cancelled before dispatch"
                        },
                    ),
                    stdout = stdout?.snapshot() ?: CapturedOutput.EMPTY,
                    stderr = stderr?.snapshot() ?: CapturedOutput.EMPTY,
                )
            } catch (_: Exception) {
                return commandResult(
                    dispatchState = dispatchState,
                    completion = CommandCompletion.Unknown(
                        if (dispatchState == CommandDispatchState.DISPATCHED) {
                            "SSH command completion became indeterminate after dispatch"
                        } else {
                            "SSH exec could not be prepared for dispatch"
                        },
                    ),
                    stdout = stdout?.snapshot() ?: CapturedOutput.EMPTY,
                    stderr = stderr?.snapshot() ?: CapturedOutput.EMPTY,
                )
            } finally {
                runCatching { channel?.disconnect() }
            }
        }

        private fun commandResult(
            dispatchState: CommandDispatchState,
            completion: CommandCompletion,
            stdout: CapturedOutput = CapturedOutput.EMPTY,
            stderr: CapturedOutput = CapturedOutput.EMPTY,
        ): SshCommandResult = SshCommandResult(
            dispatchState = dispatchState,
            completion = completion,
            stdout = stdout,
            stderr = stderr,
        )

        override fun close() {
            val shouldDisconnect = synchronized(lifecycleMonitor) {
                if (!closeRequested.compareAndSet(false, true)) {
                    false
                } else {
                    val forward = activeWebPanelForward
                    activeWebPanelForward = null
                    forward?.markClosedByOwningSession()
                    if (forward != null && session.isConnected) {
                        runCatching {
                            session.delPortForwardingL(WEB_PANEL_LOOPBACK_HOST, forward.localEndpoint.port)
                        }
                    }
                    val sftp = activeSiteSftpChannel
                    activeSiteSftpChannel = null
                    when (sftp) {
                        is JschSiteRemoteSftpChannelHandle -> {
                            sftp.markClosedByOwningSession()
                            runCatching { sftp.disconnectTransport() }
                        }
                        is SudoExecSiteFileChannelHandle -> sftp.markClosedByOwningSession()
                        else -> Unit
                    }
                    privilege.close()
                    true
                }
            }
            if (shouldDisconnect) {
                runCatching { session.disconnect() }
            }
        }

        private class JschSiteRemoteSftpChannelHandle(
            private val channel: ChannelSftp,
            private val onClose: () -> Unit,
        ) : SiteRemoteSftpChannelHandle {
            private val closed = AtomicBoolean(false)

            override val isOpen: Boolean
                get() = !closed.get() && channel.isConnected

            override fun lstat(path: String): SiteRemoteSftpPathObservation {
                ensureOpen()
                val attrs = try {
                    channel.lstat(path)
                } catch (failure: SftpException) {
                    if (failure.id == ChannelSftp.SSH_FX_NO_SUCH_FILE) {
                        return SiteRemoteSftpPathObservation(
                            type = com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.ABSENT,
                            sizeBytes = 0,
                            uid = -1,
                            gid = -1,
                            permissions = 0,
                        )
                    }
                    throw failure
                }
                return attrs.toObservation()
            }

            override fun mkdir(path: String) { ensureOpen(); channel.mkdir(path) }

            override fun writeFile(path: String, payload: ByteArray) {
                ensureOpen()
                ByteArrayInputStream(payload).use { input ->
                    channel.put(input, path, ChannelSftp.OVERWRITE)
                }
            }

            override fun readFile(path: String, maxBytes: Int): ByteArray {
                ensureOpen()
                require(maxBytes > 0) { "SFTP read bound must be positive" }
                channel.get(path).use { input ->
                    val output = ByteArrayOutputStream(minOf(maxBytes, 8192))
                    val buffer = ByteArray(8192)
                    var total = 0
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        require(total <= maxBytes) { "SFTP read exceeded configured bound" }
                        output.write(buffer, 0, read)
                    }
                    return output.toByteArray()
                }
            }

            override fun listDirectory(path: String, maxEntries: Int): List<SiteRemoteSftpDirectoryEntry> {
                ensureOpen()
                require(maxEntries > 0) { "SFTP directory-list bound must be positive" }
                val result = ArrayList<SiteRemoteSftpDirectoryEntry>(minOf(maxEntries, 32))
                var overflow = false
                channel.ls(path, ChannelSftp.LsEntrySelector { entry ->
                    if (result.size >= maxEntries) {
                        overflow = true
                        ChannelSftp.LsEntrySelector.BREAK
                    } else {
                        result += SiteRemoteSftpDirectoryEntry(entry.filename, entry.attrs.toObservation())
                        ChannelSftp.LsEntrySelector.CONTINUE
                    }
                })
                require(!overflow) { "SFTP directory listing exceeded configured bound" }
                return result
            }

            override fun chmod(path: String, permissions: Int) { ensureOpen(); channel.chmod(permissions, path) }
            override fun chown(path: String, uid: Int) { ensureOpen(); channel.chown(uid, path) }
            override fun chgrp(path: String, gid: Int) { ensureOpen(); channel.chgrp(gid, path) }
            override fun rename(fromPath: String, toPath: String) { ensureOpen(); channel.rename(fromPath, toPath) }
            override fun removeFile(path: String) { ensureOpen(); channel.rm(path) }
            override fun removeDirectory(path: String) { ensureOpen(); channel.rmdir(path) }

            override fun close() {
                if (closed.compareAndSet(false, true)) onClose()
            }

            fun markClosedByOwningSession() { closed.set(true) }
            fun disconnectTransport() { runCatching { channel.disconnect() } }

            private fun ensureOpen() { require(isOpen) { "SFTP channel is closed" } }

            private fun SftpATTRS.toObservation(): SiteRemoteSftpPathObservation = SiteRemoteSftpPathObservation(
                type = when {
                    isLink() -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.SYMLINK
                    isDir() -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.DIRECTORY
                    isReg() -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.FILE
                    else -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.OTHER
                },
                sizeBytes = getSize(),
                uid = getUId(),
                gid = getGId(),
                permissions = getPermissions() and 4095,
            )
        }

        private class JschWebPanelLocalForwardHandle(
            override val sessionBinding: SessionBinding,
            override val target: ResolvedWebPanelTarget,
            override val localEndpoint: WebPanelLoopbackEndpoint,
            private val sessionIsOpen: () -> Boolean,
            private val onClose: () -> Unit,
        ) : WebPanelLocalForwardHandle {
            private val closed = AtomicBoolean(false)

            val isLocallyOpen: Boolean
                get() = !closed.get()

            override val isOpen: Boolean
                get() = !closed.get() && sessionIsOpen()

            override fun close() {
                onClose()
            }

            fun markClosedByOwningSession() {
                closed.set(true)
            }
        }
    }

    private companion object {
        val AUTH_FAILURE_MARKERS = listOf(
            "auth fail",
            "auth cancel",
            "authentication failed",
            "too many authentication failures",
        )
        const val COMMAND_COMPLETION_POLL_MILLIS = 10L
        const val SERVER_ALIVE_INTERVAL_MS = 15_000
        const val SERVER_ALIVE_COUNT_MAX = 4

        val NEGOTIATION_FAILURE_MARKERS = listOf(
            "algorithm negotiation fail",
            "there are not any available",
            "verify: false",
            "key exchange failed",
        )
    }
}

internal fun java.time.Duration.toJschTimeoutMillis(): Int {
    val millis = toMillis()
    return when {
        millis <= 0L -> 1
        millis > Int.MAX_VALUE.toLong() -> Int.MAX_VALUE
        else -> millis.toInt()
    }
}

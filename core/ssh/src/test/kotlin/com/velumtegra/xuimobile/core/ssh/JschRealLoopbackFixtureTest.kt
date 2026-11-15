package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.SecretCreateResult
import com.velumtegra.xuimobile.core.domain.SecretDeleteResult
import com.velumtegra.xuimobile.core.domain.SecretListResult
import com.velumtegra.xuimobile.core.domain.SecretMaterial
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.HostKeyFingerprint
import com.velumtegra.xuimobile.core.model.SecretId
import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.model.SshAuthRef
import com.velumtegra.xuimobile.core.model.SshEndpoint
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import java.time.Duration
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.apache.sshd.common.config.keys.KeyUtils
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Real protocol fixture for Phase 3.2B/3.2C.
 *
 * This does not mock JSch: a real Apache MINA SSHD server listens only on JVM loopback, negotiates
 * SSH, presents a real RSA host key and performs password authentication. Its command factory is
 * deterministic and test-only: it recognizes fixture tokens, never invokes a system shell/process,
 * and therefore cannot mutate the host or any external machine.
 */
class JschRealLoopbackFixtureTest {
    @Test
    fun `real loopback ssh accepts exact pin and exact password then closes`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val access = fixture.access(fixture.hostFingerprint)
            val result = JschSshConnectionFactory(
                StaticPasswordSecretStore(FIXTURE_SECRET_ID, FIXTURE_PASSWORD),
                detectPrivilege = false,
            ).connect(access, ownerFor(access), TEST_CONFIG)

            assertTrue(result is SshConnectResult.Connected)
            val handle = (result as SshConnectResult.Connected).handle
            assertTrue(handle.isOpen)
            assertEquals(access.id, handle.binding.serverAccessId)
            assertEquals(ownerFor(access), handle.binding.owner)
            assertEquals(1, fixture.passwordAttempts.get())

            handle.close()
            assertFalse(handle.isOpen)
        }
    }

    @Test
    fun `real loopback ssh rejects wrong host pin before password authentication`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val wrongPin = CanonicalHostKeyFingerprint
                .fromRawHostKey("definitely-not-the-fixture-key".encodeToByteArray())
                .asString()
            val access = fixture.access(wrongPin)
            val result = JschSshConnectionFactory(
                StaticPasswordSecretStore(FIXTURE_SECRET_ID, FIXTURE_PASSWORD),
                detectPrivilege = false,
            ).connect(access, ownerFor(access), TEST_CONFIG)

            assertTrue(result is SshConnectResult.Failed)
            val failure = (result as SshConnectResult.Failed).failure
            assertTrue(failure is SshConnectFailure.HostIdentityMismatch)
            assertEquals(wrongPin, (failure as SshConnectFailure.HostIdentityMismatch).expectedFingerprint)
            assertEquals(fixture.hostFingerprint, failure.presentedFingerprint)
            assertEquals(0, fixture.passwordAttempts.get())
        }
    }

    @Test
    fun `real loopback ssh rejects wrong password with one password attempt and no fallback`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val access = fixture.access(fixture.hostFingerprint)
            val result = JschSshConnectionFactory(
                StaticPasswordSecretStore(FIXTURE_SECRET_ID, "wrong-password"),
                detectPrivilege = false,
            ).connect(access, ownerFor(access), TEST_CONFIG)

            assertTrue(result is SshConnectResult.Failed)
            assertEquals(SshConnectFailure.AuthenticationRejected, (result as SshConnectResult.Failed).failure)
            assertEquals(1, fixture.passwordAttempts.get())
        }
    }

    @Test
    fun `real loopback exec captures stdout and stderr separately and confirms exit zero`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()

            val result = handle.execute(RemoteCommand.create(FIXTURE_SUCCESS_COMMAND), TEST_CONFIG)

            assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
            assertEquals(CommandCompletion.ConfirmedSuccess, result.completion)
            assertArrayEquals(FIXTURE_STDOUT.encodeToByteArray(), result.stdout.copyBytes())
            assertArrayEquals(FIXTURE_STDERR.encodeToByteArray(), result.stderr.copyBytes())
            assertFalse(result.stdout.truncated)
            assertFalse(result.stderr.truncated)
            assertEquals(1, fixture.execRequests.get())
            assertTrue(handle.isOpen)
            handle.close()
        }
    }

    @Test
    fun `real loopback exec maps nonzero exit without using stderr as completion truth`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()

            val result = handle.execute(RemoteCommand.create(FIXTURE_FAILURE_COMMAND), TEST_CONFIG)

            assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
            assertTrue(result.completion is CommandCompletion.ConfirmedFailure)
            val completion = result.completion as CommandCompletion.ConfirmedFailure
            assertEquals(7, completion.exitCode)
            assertArrayEquals(FIXTURE_STDERR.encodeToByteArray(), result.stderr.copyBytes())
            assertEquals(1, fixture.execRequests.get())
            handle.close()
        }
    }

    @Test
    fun `real loopback exec bounds both outputs and keeps known success`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()
            val limited = TEST_CONFIG.copy(
                stdoutCaptureLimitBytes = 32,
                stderrCaptureLimitBytes = 48,
            )

            val result = handle.execute(RemoteCommand.create(FIXTURE_FLOOD_COMMAND), limited)

            assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
            assertEquals(CommandCompletion.ConfirmedSuccess, result.completion)
            assertEquals(32, result.stdout.sizeBytes)
            assertEquals(48, result.stderr.sizeBytes)
            assertTrue(result.stdout.truncated)
            assertTrue(result.stderr.truncated)
            assertEquals(1, fixture.execRequests.get())
            handle.close()
        }
    }

    @Test
    fun `real loopback exec timeout is unknown after exactly one dispatch`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()
            val short = TEST_CONFIG.copy(commandExecutionTimeout = Duration.ofMillis(150))

            val result = handle.execute(RemoteCommand.create(FIXTURE_HANG_COMMAND), short)

            assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
            assertTrue(result.completion is CommandCompletion.Unknown)
            assertEquals(1, fixture.execRequests.get())
            assertTrue(handle.isOpen)

            // Timeout cleanup is channel-scoped: the exact authenticated session remains reusable.
            val followUp = handle.execute(RemoteCommand.create(FIXTURE_SUCCESS_COMMAND), TEST_CONFIG)
            assertEquals(CommandCompletion.ConfirmedSuccess, followUp.completion)
            assertEquals(CommandDispatchState.DISPATCHED, followUp.dispatchState)
            assertEquals(2, fixture.execRequests.get())
            handle.close()
        }
    }

    @Test
    fun `channel close without exit status is unknown once and exact session stays reusable`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()

            val result = handle.execute(RemoteCommand.create(FIXTURE_NO_EXIT_COMMAND), TEST_CONFIG)

            assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
            assertTrue(result.completion is CommandCompletion.Unknown)
            assertEquals(1, fixture.execRequests.get())
            assertTrue(handle.isOpen)

            val followUp = handle.execute(RemoteCommand.create(FIXTURE_SUCCESS_COMMAND), TEST_CONFIG)
            assertEquals(CommandDispatchState.DISPATCHED, followUp.dispatchState)
            assertEquals(CommandCompletion.ConfirmedSuccess, followUp.completion)
            assertEquals(2, fixture.execRequests.get())
            handle.close()
        }
    }

    @Test
    fun `server transport loss after dispatch is unknown and never auto retries`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()

            val result = handle.execute(RemoteCommand.create(FIXTURE_DROP_SESSION_COMMAND), TEST_CONFIG)

            assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
            assertTrue(result.completion is CommandCompletion.Unknown)
            assertEquals(1, fixture.execRequests.get())

            withTimeout(2_000) {
                while (handle.isOpen) delay(10)
            }
            val followUp = handle.execute(RemoteCommand.create(FIXTURE_SUCCESS_COMMAND), TEST_CONFIG)
            assertEquals(CommandDispatchState.NOT_DISPATCHED, followUp.dispatchState)
            assertTrue(followUp.completion is CommandCompletion.Unknown)
            assertEquals(1, fixture.execRequests.get())
        }
    }

    @Test
    fun `local close after dispatch makes active command unknown and queued command not dispatched`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()
            val active = async { handle.execute(RemoteCommand.create(FIXTURE_HANG_COMMAND), TEST_CONFIG) }

            withTimeout(2_000) {
                while (fixture.execRequests.get() == 0) delay(10)
            }
            val queued = async(start = CoroutineStart.UNDISPATCHED) {
                handle.execute(RemoteCommand.create(FIXTURE_SUCCESS_COMMAND), TEST_CONFIG)
            }

            handle.close()
            handle.close() // explicit idempotency: a second close must be harmless.

            val activeResult = withTimeout(2_000) { active.await() }
            val queuedResult = withTimeout(2_000) { queued.await() }

            assertEquals(CommandDispatchState.DISPATCHED, activeResult.dispatchState)
            assertTrue(activeResult.completion is CommandCompletion.Unknown)
            assertEquals(CommandDispatchState.NOT_DISPATCHED, queuedResult.dispatchState)
            assertTrue(queuedResult.completion is CommandCompletion.Unknown)
            assertEquals(1, fixture.execRequests.get())
            assertFalse(handle.isOpen)
        }
    }

    @Test
    fun `exact registry replacement closes only prior live session and does not replay active exec`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val first = fixture.connectHandle()
            val second = fixture.connectHandle()
            val registry = ExactSessionRegistry()
            assertEquals(SessionInstallResult.Installed, registry.install(first))

            val active = async { first.execute(RemoteCommand.create(FIXTURE_HANG_COMMAND), TEST_CONFIG) }
            withTimeout(2_000) {
                while (fixture.execRequests.get() == 0) delay(10)
            }

            val installResult = registry.install(second)
            assertTrue(installResult is SessionInstallResult.Replaced)

            val activeResult = withTimeout(2_000) { active.await() }
            assertEquals(CommandDispatchState.DISPATCHED, activeResult.dispatchState)
            assertTrue(activeResult.completion is CommandCompletion.Unknown)
            assertEquals(1, fixture.execRequests.get())
            assertFalse(first.isOpen)
            assertTrue(second.isOpen)
            assertEquals(second, registry.find(second.binding.owner, second.binding.serverAccessId))

            val followUp = second.execute(RemoteCommand.create(FIXTURE_SUCCESS_COMMAND), TEST_CONFIG)
            assertEquals(CommandDispatchState.DISPATCHED, followUp.dispatchState)
            assertEquals(CommandCompletion.ConfirmedSuccess, followUp.completion)
            assertEquals(2, fixture.execRequests.get())
            registry.close()
            assertFalse(second.isOpen)
        }
    }

    @Test
    fun `coroutine cancellation after dispatch produces unknown evidence and cleans channel`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()
            val observed = AtomicReference<SshCommandResult?>(null)
            val job = launch {
                observed.set(handle.execute(RemoteCommand.create(FIXTURE_HANG_COMMAND), TEST_CONFIG))
            }

            withTimeout(2_000) {
                while (fixture.execRequests.get() == 0) delay(10)
            }
            job.cancelAndJoin()

            val result = observed.get()
            assertTrue(result != null)
            result!!
            assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
            assertTrue(result.completion is CommandCompletion.Unknown)
            assertEquals(1, fixture.execRequests.get())
            assertTrue(handle.isOpen)
            handle.close()
        }
    }

    @Test
    fun `closed session proves command was not dispatched`() = runBlocking {
        LocalSshFixture().use { fixture ->
            val handle = fixture.connectHandle()
            handle.close()

            val result = handle.execute(RemoteCommand.create(FIXTURE_SUCCESS_COMMAND), TEST_CONFIG)

            assertEquals(CommandDispatchState.NOT_DISPATCHED, result.dispatchState)
            assertTrue(result.completion is CommandCompletion.Unknown)
            assertEquals(0, fixture.execRequests.get())
        }
    }

    private fun ownerFor(access: ServerAccess): SessionOwner.Management = SessionOwner.Management(
        installationId = XuiInstallationId("fixture-installation"),
        serverAccessId = access.id,
    )

    private inner class LocalSshFixture : AutoCloseable {
        val passwordAttempts = AtomicInteger(0)
        val execRequests = AtomicInteger(0)
        private val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }.generateKeyPair()
        private val server = SshServer.setUpDefaultServer().apply {
            host = LOOPBACK_HOST
            port = 0
            keyPairProvider = KeyPairProvider.wrap(hostKey)
            userAuthFactories = listOf(UserAuthPasswordFactory.INSTANCE)
            passwordAuthenticator = org.apache.sshd.server.auth.password.PasswordAuthenticator { username, password, _ ->
                passwordAttempts.incrementAndGet()
                username == FIXTURE_USERNAME && password == FIXTURE_PASSWORD
            }
            commandFactory = CommandFactory { _, command ->
                execRequests.incrementAndGet()
                FixtureCommand(command)
            }
        }

        val hostFingerprint: String

        init {
            // Apache MINA computes the OpenSSH SHA-256 fingerprint over the SSH public-key encoding,
            // which is the same identity representation JSch passes to our pinned repository.
            hostFingerprint = KeyUtils.getFingerPrint(hostKey.public)
            require(
                CanonicalHostKeyFingerprint.parse(HostKeyFingerprint(hostFingerprint)) is
                    HostKeyFingerprintParseResult.Valid,
            ) { "Fixture host fingerprint is not canonical SHA-256: $hostFingerprint" }
            server.start()
            check(server.port in 1..65535) { "Fixture did not bind a TCP port" }
        }

        suspend fun connectHandle(): SshSessionHandle {
            val access = access(hostFingerprint)
            val result = JschSshConnectionFactory(
                StaticPasswordSecretStore(FIXTURE_SECRET_ID, FIXTURE_PASSWORD),
                detectPrivilege = false,
            ).connect(access, ownerFor(access), TEST_CONFIG)
            check(result is SshConnectResult.Connected) { "Fixture SSH connection did not succeed: $result" }
            return result.handle
        }

        fun access(pin: String): ServerAccess = ServerAccess(
            id = ServerAccessId("fixture-access-${server.port}"),
            serverId = ServerId("fixture-server"),
            endpoint = SshEndpoint(LOOPBACK_HOST, server.port),
            username = FIXTURE_USERNAME,
            auth = SshAuthRef.Password(FIXTURE_SECRET_ID),
            pinnedHostKey = HostKeyFingerprint(pin),
        )

        override fun close() {
            runCatching { server.stop() }
        }
    }

    private class FixtureCommand(
        private val command: String,
    ) : Command {
        private var input: InputStream? = null
        private var output: OutputStream? = null
        private var error: OutputStream? = null
        private var exitCallback: ExitCallback? = null
        private val worker = AtomicReference<Thread?>(null)

        override fun setInputStream(input: InputStream) {
            this.input = input
        }

        override fun setOutputStream(output: OutputStream) {
            this.output = output
        }

        override fun setErrorStream(error: OutputStream) {
            this.error = error
        }

        override fun setExitCallback(callback: ExitCallback) {
            exitCallback = callback
        }

        override fun start(channel: ChannelSession, env: Environment) {
            val thread = Thread({ runFixtureCommand(channel) }, "velum-ssh-fixture-command").apply {
                isDaemon = true
            }
            check(worker.compareAndSet(null, thread)) { "Fixture command started more than once" }
            thread.start()
        }

        override fun destroy(channel: ChannelSession) {
            worker.getAndSet(null)?.interrupt()
        }

        private fun runFixtureCommand(channel: ChannelSession) {
            try {
                when (command) {
                    FIXTURE_SUCCESS_COMMAND -> {
                        output?.write(FIXTURE_STDOUT.encodeToByteArray())
                        error?.write(FIXTURE_STDERR.encodeToByteArray())
                        output?.flush()
                        error?.flush()
                        exitCallback?.onExit(0)
                    }
                    FIXTURE_FAILURE_COMMAND -> {
                        error?.write(FIXTURE_STDERR.encodeToByteArray())
                        error?.flush()
                        exitCallback?.onExit(7)
                    }
                    FIXTURE_FLOOD_COMMAND -> {
                        output?.write(ByteArray(8 * 1024) { 0x41.toByte() })
                        error?.write(ByteArray(8 * 1024) { 0x42.toByte() })
                        output?.flush()
                        error?.flush()
                        exitCallback?.onExit(0)
                    }
                    FIXTURE_NO_EXIT_COMMAND -> {
                        // Close only this SSH channel without an exit-status callback. The client must
                        // classify completion as Unknown while preserving the healthy parent session.
                        channel.close(true)
                    }
                    FIXTURE_DROP_SESSION_COMMAND -> {
                        // Abruptly close the authenticated transport after the exec request was accepted.
                        // No exit callback is sent; the client must never auto-repeat this command.
                        channel.session.close(true)
                    }
                    FIXTURE_HANG_COMMAND -> {
                        while (!Thread.currentThread().isInterrupted) {
                            Thread.sleep(1_000)
                        }
                    }
                    else -> exitCallback?.onExit(127)
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private class StaticPasswordSecretStore(
        private val id: SecretId,
        password: String,
    ) : SecretStore {
        private val encoded = password.encodeToByteArray()

        override suspend fun create(secretId: SecretId, material: SecretMaterial): SecretCreateResult =
            SecretCreateResult.StorageFailure("Fixture store is read-only")

        override suspend fun read(secretId: SecretId): SecretReadResult = if (secretId == id) {
            SecretReadResult.Found(SecretMaterial.fromBytes(encoded))
        } else {
            SecretReadResult.NotFound
        }

        override suspend fun delete(secretId: SecretId): SecretDeleteResult =
            SecretDeleteResult.StorageFailure("Fixture store is read-only")

        override suspend fun listIds(): SecretListResult = SecretListResult.Success(setOf(id))
    }

    private companion object {
        const val LOOPBACK_HOST = "127.0.0.1"
        const val FIXTURE_SUCCESS_COMMAND = "fixture-success"
        const val FIXTURE_FAILURE_COMMAND = "fixture-failure"
        const val FIXTURE_FLOOD_COMMAND = "fixture-flood"
        const val FIXTURE_NO_EXIT_COMMAND = "fixture-no-exit"
        const val FIXTURE_DROP_SESSION_COMMAND = "fixture-drop-session"
        const val FIXTURE_HANG_COMMAND = "fixture-hang"
        const val FIXTURE_STDOUT = "fixture-stdout"
        const val FIXTURE_STDERR = "fixture-stderr"
        const val FIXTURE_USERNAME = "velum-fixture"
        const val FIXTURE_PASSWORD = "VELUM-fixture-password-only"
        val FIXTURE_SECRET_ID = SecretId("fixture-password-secret")
        val TEST_CONFIG = SshTransportConfig(
            tcpConnectTimeout = Duration.ofSeconds(5),
            handshakeAndAuthTimeout = Duration.ofSeconds(5),
            channelOpenTimeout = Duration.ofSeconds(5),
            commandExecutionTimeout = Duration.ofSeconds(5),
            stdoutCaptureLimitBytes = 4 * 1024,
            stderrCaptureLimitBytes = 4 * 1024,
        )
    }
}

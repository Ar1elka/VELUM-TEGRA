package com.velumtegra.xuimobile.core.ssh

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.Session
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Arrays

/**
 * How root-level commands reach the server for the exact SSH login.
 *
 * Many clouds (Yandex Cloud, AWS, GCP, Oracle…) disable direct root login and give a normal user
 * with sudo. Every reviewed command in this module was written for root, so for such logins the
 * transport transparently runs it as `sudo … -- bash -c '<command>'`. Root logins are unchanged.
 */
enum class RemotePrivilegeMode {
    /** Logged in as root (uid 0). Commands run exactly as written. */
    ROOT,

    /** Normal user with password-less sudo (typical cloud image). */
    SUDO_NOPASSWD,

    /** Normal user whose sudo asks for the same password that was used for the SSH login. */
    SUDO_PASSWORD,

    /** Normal user without usable sudo: root-only operations will be refused by their own checks. */
    UNPRIVILEGED,
}

/** Exposes the detected privilege of an open session (for server-profile UI and diagnostics). */
interface PrivilegeAwareSshSessionHandle : SshSessionHandle {
    val privilegeMode: RemotePrivilegeMode
    val remoteLoginUser: String
}

internal class RemotePrivilegeContext private constructor(
    val mode: RemotePrivilegeMode,
    private val shell: String,
    private var sudoPassword: ByteArray?,
) : AutoCloseable {
    val elevates: Boolean get() = mode == RemotePrivilegeMode.SUDO_NOPASSWD || mode == RemotePrivilegeMode.SUDO_PASSWORD

    /** Wraps one complete reviewed command; the command text itself is passed as a single quoted argument. */
    fun wrap(raw: String): String = when (mode) {
        RemotePrivilegeMode.ROOT, RemotePrivilegeMode.UNPRIVILEGED -> raw
        RemotePrivilegeMode.SUDO_NOPASSWD -> "sudo -n -H -- $SESSION_ENV $shell -c ${shellQuote(raw)}"
        RemotePrivilegeMode.SUDO_PASSWORD -> "sudo -S -p '' -H -- $SESSION_ENV $shell -c ${shellQuote(raw)}"
    }

    /** Wraps the interactive x-ui menu program (pty session). */
    fun wrapProgram(program: String): String = when (mode) {
        RemotePrivilegeMode.ROOT, RemotePrivilegeMode.UNPRIVILEGED -> program
        RemotePrivilegeMode.SUDO_NOPASSWD -> "sudo -n -H -- $program"
        RemotePrivilegeMode.SUDO_PASSWORD -> "sudo -S -p '' -H -- $program"
    }

    /** stdin for an exec channel: the sudo password line, or nothing. A fresh copy each time. */
    fun stdinBytes(): ByteArray? = sudoPassword?.let { it.copyOf() + '\n'.code.toByte() }

    override fun close() {
        sudoPassword?.let { Arrays.fill(it, 0) }
        sudoPassword = null
    }

    companion object {
        val DIRECT = RemotePrivilegeContext(RemotePrivilegeMode.ROOT, "/bin/sh", null)

        fun shellQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

        /**
         * sudo's env_reset drops SSH_CONNECTION, but reviewed scripts (SSH port change) read it to learn
         * which local port this exact session arrived on. The login shell expands the value set by sshd
         * for this session and passes it through `env`; nothing else from the login environment is kept.
         */
        internal const val SESSION_ENV: String = "env SSH_CONNECTION=\"\${SSH_CONNECTION:-}\""

        internal const val PROBE_COMMAND: String =
            "u=$(id -u 2>/dev/null); printf 'UID=%s\\n' \"\$u\"; " +
                "if command -v bash >/dev/null 2>&1; then printf 'BASH=1\\n'; fi; " +
                "if [ \"\$u\" != 0 ] && command -v sudo >/dev/null 2>&1; then " +
                "if sudo -n true >/dev/null 2>&1; then printf 'SUDO=NOPASSWD\\n'; else printf 'SUDO=ASKS\\n'; fi; " +
                "else printf 'SUDO=NONE\\n'; fi"

        /**
         * One short probe right after authentication. Any failure degrades to the previous behaviour
         * (commands run as the login user), never to something more privileged.
         */
        fun detect(session: Session, loginPassword: ByteArray?): RemotePrivilegeContext {
            val probe = JschBlockingExec.run(session, PROBE_COMMAND, null, 4096, 8_000) ?: return unprivileged()
            if (probe.exitStatus != 0) return unprivileged()
            val lines = probe.stdout.decodeToString().lines().associate { it.substringBefore('=') to it.substringAfter('=', "") }
            val uid = lines["UID"]?.trim()?.toLongOrNull() ?: return unprivileged()
            if (uid == 0L) return DIRECT
            val shell = if (lines["BASH"] == "1") "bash" else "sh"
            return when (lines["SUDO"]?.trim()) {
                "NOPASSWD" -> RemotePrivilegeContext(RemotePrivilegeMode.SUDO_NOPASSWD, shell, null)
                "ASKS" -> {
                    if (loginPassword == null || loginPassword.isEmpty()) return unprivileged(shell)
                    val password = loginPassword.copyOf()
                    val line = password + '\n'.code.toByte()
                    val check = try {
                        JschBlockingExec.run(session, "sudo -S -p '' -v >/dev/null 2>&1 && printf OK", line, 64, 8_000)
                    } finally {
                        Arrays.fill(line, 0)
                    }
                    if (check?.exitStatus == 0 && check.stdout.decodeToString() == "OK") {
                        RemotePrivilegeContext(RemotePrivilegeMode.SUDO_PASSWORD, shell, password)
                    } else {
                        Arrays.fill(password, 0)
                        unprivileged(shell)
                    }
                }
                else -> unprivileged(shell)
            }
        }

        private fun unprivileged(shell: String = "sh") = RemotePrivilegeContext(RemotePrivilegeMode.UNPRIVILEGED, shell, null)
    }
}

/** Minimal synchronous exec used only for the privilege probe and the sudo-backed file channel. */
internal object JschBlockingExec {
    class Result(val exitStatus: Int, val stdout: ByteArray, val stderr: ByteArray, val truncated: Boolean)

    fun run(session: Session, command: String, stdin: ByteArray?, stdoutLimit: Int, timeoutMillis: Long): Result? {
        val channel = runCatching { session.openChannel("exec") as? ChannelExec }.getOrNull() ?: return null
        val out = BoundedBuffer(stdoutLimit)
        val err = BoundedBuffer(8192)
        return try {
            channel.setCommand(command)
            channel.setInputStream(stdin?.let { ByteArrayInputStream(it) })
            channel.setOutputStream(out)
            channel.setErrStream(err)
            channel.connect(5_000)
            val deadline = System.currentTimeMillis() + timeoutMillis
            while (!channel.isClosed && session.isConnected && System.currentTimeMillis() < deadline) Thread.sleep(20)
            if (!channel.isClosed) return null
            Result(channel.exitStatus, out.toByteArray(), err.toByteArray(), out.overflowed)
        } catch (_: Exception) {
            null
        } finally {
            // stdin may be the caller's own payload: wiping secrets is the caller's job.
            runCatching { channel.disconnect() }
        }
    }

    private class BoundedBuffer(private val limit: Int) : ByteArrayOutputStream() {
        var overflowed = false
            private set

        @Synchronized
        override fun write(b: Int) {
            if (count >= limit) { overflowed = true; return }
            super.write(b)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            val room = limit - count
            if (len > room) overflowed = true
            if (room > 0) super.write(b, off, minOf(len, room))
        }
    }
}

/**
 * Site file channel for sudo logins. SFTP always runs with the login user's rights and cannot write
 * to /var/www or /etc/nginx, so each primitive is executed as one fixed command under sudo instead.
 * Same contract and the same observable results as the SFTP implementation.
 */
internal class SudoExecSiteFileChannelHandle(
    private val run: (command: String, stdin: ByteArray?, stdoutLimit: Int) -> JschBlockingExec.Result?,
    private val onClose: () -> Unit,
) : SiteRemoteSftpChannelHandle {
    @Volatile private var closed = false

    override val isOpen: Boolean get() = !closed

    override fun lstat(path: String): SiteRemoteSftpPathObservation {
        val q = q(path)
        val text = text("if [ -e $q ] || [ -L $q ]; then LC_ALL=C stat -c '%F|%s|%u|%g|%a' -- $q; else printf 'ABSENT\\n'; fi", 4096)
            .trim()
        if (text == "ABSENT") return observation(com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.ABSENT, 0, -1, -1, 0)
        val parts = text.split('|')
        require(parts.size == 5) { "Unexpected stat output" }
        return observation(type(parts[0]), parts[1].toLong(), parts[2].toInt(), parts[3].toInt(), parts[4].toInt(8))
    }

    override fun mkdir(path: String) { ok("mkdir -- ${q(path)}") }

    override fun writeFile(path: String, payload: ByteArray) {
        // The password line (if any) is consumed by sudo first; the rest of stdin is the file body.
        ok("cat > ${q(path)}", payload)
    }

    override fun readFile(path: String, maxBytes: Int): ByteArray {
        require(maxBytes > 0) { "SFTP read bound must be positive" }
        val result = exec("cat -- ${q(path)}", null, maxBytes)
        require(!result.truncated) { "SFTP read exceeded configured bound" }
        return result.stdout
    }

    override fun listDirectory(path: String, maxEntries: Int): List<SiteRemoteSftpDirectoryEntry> {
        require(maxEntries > 0) { "SFTP directory-list bound must be positive" }
        val raw = exec("LC_ALL=C find ${q(path)} -mindepth 1 -maxdepth 1 -printf '%y/%s/%U/%G/%m/%f\\0'", null, 256 * 1024)
        require(!raw.truncated) { "Directory listing too large" }
        val records = raw.stdout.decodeToString().split('\u0000').filter { it.isNotEmpty() }
        require(records.size <= maxEntries) { "SFTP directory listing exceeded configured bound" }
        return records.map { record ->
            val parts = record.split('/', limit = 6)
            require(parts.size == 6) { "Unexpected find output" }
            val type = when (parts[0]) {
                "f" -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.FILE
                "d" -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.DIRECTORY
                "l" -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.SYMLINK
                else -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.OTHER
            }
            SiteRemoteSftpDirectoryEntry(parts[5], observation(type, parts[1].toLong(), parts[2].toInt(), parts[3].toInt(), parts[4].toInt(8)))
        }
    }

    override fun chmod(path: String, permissions: Int) { ok("chmod ${Integer.toOctalString(permissions and 4095)} -- ${q(path)}") }
    override fun chown(path: String, uid: Int) { ok("chown -h $uid -- ${q(path)}") }
    override fun chgrp(path: String, gid: Int) { ok("chgrp -h $gid -- ${q(path)}") }
    // SFTPv3 rename never replaces an existing target; keep that guarantee.
    override fun rename(fromPath: String, toPath: String) {
        val to = q(toPath)
        ok("[ ! -e $to ] && [ ! -L $to ] && mv -T -- ${q(fromPath)} $to")
    }
    override fun removeFile(path: String) { ok("rm -- ${q(path)}") }
    override fun removeDirectory(path: String) { ok("rmdir -- ${q(path)}") }

    override fun close() {
        if (!closed) { closed = true; onClose() }
    }

    /** The owning SSH session closed: no callback, the session already forgot this channel. */
    fun markClosedByOwningSession() { closed = true }

    private fun q(path: String): String {
        require(path.startsWith("/") && '\u0000' !in path && '\n' !in path) { "Unsafe remote path" }
        return RemotePrivilegeContext.shellQuote(path)
    }

    private fun exec(command: String, stdin: ByteArray?, limit: Int): JschBlockingExec.Result {
        require(isOpen) { "SFTP channel is closed" }
        val result = run(command, stdin, limit) ?: error("Remote file command did not complete")
        require(result.exitStatus == 0) { "Remote file command failed (exit ${result.exitStatus})" }
        return result
    }

    private fun ok(command: String, stdin: ByteArray? = null) { exec(command, stdin, 4096) }
    private fun text(command: String, limit: Int): String = exec(command, null, limit).stdout.decodeToString()

    private fun type(value: String) = when (value) {
        "regular file", "regular empty file" -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.FILE
        "directory" -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.DIRECTORY
        "symbolic link" -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.SYMLINK
        else -> com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType.OTHER
    }

    private fun observation(
        type: com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType,
        size: Long, uid: Int, gid: Int, permissions: Int,
    ) = SiteRemoteSftpPathObservation(type = type, sizeBytes = size, uid = uid, gid = gid, permissions = permissions and 4095)
}

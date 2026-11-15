package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RemotePrivilegeWrapTest {
    // Exercise the internal value without an SSH server, credentials or privilege escalation.
    private fun context(mode: RemotePrivilegeMode, password: ByteArray? = null): RemotePrivilegeContext =
        RemotePrivilegeContext::class.java.getDeclaredConstructor(
            RemotePrivilegeMode::class.java, String::class.java, ByteArray::class.java,
        ).also { it.isAccessible = true }.newInstance(mode, "/bin/sh", password)

    @Test fun `both sudo modes preserve only the exact SSH connection before the quoted command`() {
        val raw = "printf '%s' \"\${SSH_CONNECTION}\"; echo 'quoted'"
        for ((mode, prefix) in listOf(
            RemotePrivilegeMode.SUDO_NOPASSWD to "sudo -n -H -- ",
            RemotePrivilegeMode.SUDO_PASSWORD to "sudo -S -p '' -H -- ",
        )) {
            context(mode).use { value ->
                assertEquals(prefix + "env SSH_CONNECTION=\"\${SSH_CONNECTION:-}\" /bin/sh -c " +
                    RemotePrivilegeContext.shellQuote(raw), value.wrap(raw))
                assertFalse(value.wrap(raw).contains("sudo -E"))
                assertTrue(value.elevates)
            }
        }
    }

    @Test fun `unprivileged mode does not acquire sudo or rewrite commands`() {
        context(RemotePrivilegeMode.UNPRIVILEGED).use {
            assertEquals("echo untouched", it.wrap("echo untouched"))
            assertEquals("/usr/bin/x-ui", it.wrapProgram("/usr/bin/x-ui"))
            assertFalse(it.elevates)
            assertNull(it.stdinBytes())
        }
    }

    @Test fun `sudo password uses independent stdin buffers and is erased on close`() {
        val ownedPassword = "fixture-only".toByteArray()
        val value = context(RemotePrivilegeMode.SUDO_PASSWORD, ownedPassword)
        val first = requireNotNull(value.stdinBytes())
        first.fill(0)
        assertArrayEquals("fixture-only\n".toByteArray(), value.stdinBytes())
        assertFalse(value.wrap("echo ok").contains("fixture-only"))
        value.close()
        assertArrayEquals(ByteArray(ownedPassword.size), ownedPassword)
        assertNull(value.stdinBytes())
        value.close()
    }

    @Test fun `interactive menu does not insert env arguments into the program`() {
        context(RemotePrivilegeMode.SUDO_NOPASSWD).use {
            assertEquals("sudo -n -H -- /usr/bin/x-ui", it.wrapProgram("/usr/bin/x-ui"))
        }
        context(RemotePrivilegeMode.SUDO_PASSWORD).use {
            assertEquals("sudo -S -p '' -H -- /usr/bin/x-ui", it.wrapProgram("/usr/bin/x-ui"))
        }
    }

    @Test fun `root context leaves every command byte-identical`() {
        val raw = "set -eu\nprintf '%s\\n' \"it's\"; exit 3"
        assertEquals(raw, RemotePrivilegeContext.DIRECT.wrap(raw))
        assertEquals(null, RemotePrivilegeContext.DIRECT.stdinBytes())
    }

    @Test fun `shell quoting survives single quotes and newlines`() {
        val raw = "printf '%s\\n' \"it's\"\necho done"
        val quoted = RemotePrivilegeContext.shellQuote(raw)
        assertTrue(quoted.startsWith("'") && quoted.endsWith("'"))
        assertEquals("'a'\"'\"'b'", RemotePrivilegeContext.shellQuote("a'b"))
    }

    @Test fun `probe command reports uid bash and sudo state in fixed keys`() {
        val probe = RemotePrivilegeContext.PROBE_COMMAND
        listOf("UID=", "BASH=1", "SUDO=NOPASSWD", "SUDO=ASKS", "SUDO=NONE", "sudo -n true").forEach {
            assertTrue(it, probe.contains(it))
        }
    }
}

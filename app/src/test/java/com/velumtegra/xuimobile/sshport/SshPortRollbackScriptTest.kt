package com.velumtegra.xuimobile.sshport

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Ordering is a safety contract for systemd 247; never executes the server script. */
class SshPortRollbackScriptTest {
    private val script = generateSequence(File(requireNotNull(System.getProperty("user.dir")))) { it.parentFile }
        .map { File(it, "app/src/main/assets/velum-ssh-port.sh") }.first { it.isFile }.readText()

    @Test fun `prepare reloads before arming rollback and persist cleans it only after enablement`() {
        val stage = script.substringAfter("    prepare)").substringBefore("    persist)")
        val reload = stage.indexOf("systemctl daemon-reload ||")
        val timer = stage.indexOf("systemd-run --quiet --unit=\"\$stage_timer\"")
        assertTrue(reload >= 0 && timer > reload)
        val persist = script.substringAfter("    persist)").substringBefore("    close)")
        val enabled = persist.indexOf("systemctl enable --quiet \"\$unit\"")
        val stop = persist.indexOf("systemctl stop \"\$stage_timer.timer\"")
        val reset = persist.indexOf("systemctl reset-failed \"\$stage_timer.timer\"")
        assertTrue(enabled >= 0 && stop > enabled && reset > stop)
    }

    @Test fun `finish keeps rollback armed through disable and state removal`() {
        val finish = script.substringAfter("    finish)")
        val disables = finish.lineSequence().filter { "systemctl disable " in it }.toList()
        assertTrue(disables.size == 2)
        assertTrue(disables.all { "--no-reload" in it && "|| fail CLOSE_PENDING" in it })
        val commit = finish.indexOf("rm \"\$close_state\" || fail CLOSE_PENDING")
        val stop = finish.indexOf("systemctl stop \"\$restore_timer.timer\"")
        val reload = finish.indexOf("systemctl daemon-reload")
        assertTrue(commit > finish.indexOf(disables.last().trim()))
        assertTrue(stop > commit && reload > stop)
        assertFalse(finish.substringBefore("rm \"\$close_state\"").contains("systemctl daemon-reload"))
        assertTrue(finish.contains("systemctl reset-failed \"\$restore_timer.timer\""))
    }
}

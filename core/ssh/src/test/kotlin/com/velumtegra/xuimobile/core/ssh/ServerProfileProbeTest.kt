package com.velumtegra.xuimobile.core.ssh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerProfileProbeTest {
    @Test fun `yandex cloud ubuntu with sudo user can install and is warned about security groups`() {
        val p = ServerProfileProbe.parse(
            """
            OS=Ubuntu 24.04.1 LTS
            OS_ID=ubuntu
            OS_VER=24.04
            ARCH=x86_64
            PM=apt-get
            SYSTEMD=1
            VENDOR=Yandex
            PRODUCT=xeon-gold-6338
            CLOUD=
            VIRT=kvm
            MEM_KB=2014000
            DISK_KB=15000000
            """.trimIndent(),
            "yc-user", RemotePrivilegeMode.SUDO_NOPASSWD,
        )
        assertEquals("Yandex Cloud", p.provider)
        assertEquals("apt", p.packageManager)
        assertTrue(p.blockers.isEmpty())
        assertTrue(p.notes.any { "группе безопасности" in it })
        assertTrue(p.notes.any { "sudo" in it })
    }

    @Test fun `unprivileged centos user gets clear blockers`() {
        val p = ServerProfileProbe.parse(
            "OS=CentOS Stream 9\nOS_ID=centos\nARCH=x86_64\nPM=dnf\nSYSTEMD=1\nDISK_KB=500000\n",
            "admin", RemotePrivilegeMode.UNPRIVILEGED,
        )
        assertEquals(3, p.blockers.size)
        assertTrue(p.blockers.any { "root" in it })
        assertTrue(p.blockers.any { "Ubuntu или Debian" in it })
        assertTrue(p.blockers.any { "места" in it })
    }

    @Test fun `debian is supported`() {
        val p = ServerProfileProbe.parse("OS_ID=debian\nARCH=aarch64\nPM=apt-get\nSYSTEMD=1\n", "root", RemotePrivilegeMode.ROOT)
        assertTrue(p.blockers.isEmpty())
    }
}

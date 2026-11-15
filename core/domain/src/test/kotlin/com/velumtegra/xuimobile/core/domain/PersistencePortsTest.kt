package com.velumtegra.xuimobile.core.domain

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistencePortsTest {
    @Test
    fun `server access repository cannot create or mutate credential references directly`() {
        val methodNames = ServerAccessRepository::class.java.methods.map { it.name.lowercase() }
        val forbidden = setOf("create", "update", "replace", "save", "upsert", "write")
        assertFalse(methodNames.any { it in forbidden })
    }

    @Test
    fun `web panel repository cannot create or swap secret references directly`() {
        val methodNames = WebPanelAccessRepository::class.java.methods.map { it.name.lowercase() }
        assertFalse(methodNames.any { it == "create" || "secret" in it || "password" in it })
        assertTrue(methodNames.any { it.startsWith("updatemetadata") })
    }

    @Test
    fun `credential reference writer is a narrow explicit capability`() {
        val methodNames = CredentialReferenceWriter::class.java.methods.map { it.name }.toSet()
        assertTrue(methodNames.any { it.startsWith("createServerAccess") })
        assertTrue(methodNames.any { it.startsWith("createWebPanelAccess") })
        assertTrue(methodNames.any { it.startsWith("swapWebPanelCredential") })
        assertTrue(methodNames.size == 3)
    }

    @Test
    fun `repository ports do not expose fallback lookup names`() {
        val forbidden = listOf("active", "latest", "first", "current", "selected", "anysession")
        val interfaces = listOf(
            ServerRepository::class.java,
            ServerAccessRepository::class.java,
            XuiInstallationRepository::class.java,
            ManagementAccessRepository::class.java,
            WebPanelAccessRepository::class.java,
            OperationJournal::class.java,
        )

        val names = interfaces.flatMap { type -> type.methods.map { it.name.lowercase() } }
        assertTrue(names.none { method -> forbidden.any { token -> token in method } })
    }

    @Test
    fun `negative record revision is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            RecordRevision(-1)
        }
    }
}

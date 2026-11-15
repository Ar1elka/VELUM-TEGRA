package com.velumtegra.xuimobile.core.runtime

import com.velumtegra.xuimobile.core.model.BackupSlotInventory
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test

class BackupSlotInventoryRegistryTest {
    private val t0 = Instant.parse("2026-11-03T10:00:00Z")
    private val s = ServerId("s")
    private fun profile(server: ServerId = s, host: String = "203.0.113.1", port: Int = 22, key: String = "SHA256:KEY-A", id: String = "acc") =
        ServerAccess(ServerAccessId(id), server, SshEndpoint(host, port), "root", SshAuthRef.PrivateKey(SecretId("sec")), HostKeyFingerprint(key))
    private val a = profile()
    @Test fun unknownServerHasNoObservation() { assertNull(BackupSlotInventoryRegistry().latest(s, a)) }
    @Test fun newerObservationReplacesOlder() {
        val r = BackupSlotInventoryRegistry()
        r.record(s, a, BackupSlotInventory.Known(1, 4, t0)); r.record(s, a, BackupSlotInventory.Known(2, 4, t0.plusSeconds(1)))
        assertEquals(2, (r.latest(s, a) as BackupSlotInventory.Known).used)
    }
    @Test fun olderObservationNeverOverwritesNewer() {
        val r = BackupSlotInventoryRegistry()
        r.record(s, a, BackupSlotInventory.Known(4, 4, t0.plusSeconds(5))); r.record(s, a, BackupSlotInventory.Known(0, 4, t0))
        assertEquals(4, (r.latest(s, a) as BackupSlotInventory.Known).used)
    }
    @Test fun failedReadReplacesKnownAsUnavailableNotFree() {
        val r = BackupSlotInventoryRegistry()
        r.record(s, a, BackupSlotInventory.Known(4, 4, t0)); r.record(s, a, BackupSlotInventory.Unavailable(t0.plusSeconds(1)))
        assertTrue(r.latest(s, a) is BackupSlotInventory.Unavailable)
    }
    @Test fun memoryIsBoundedAndOldestServerIsDropped() {
        val r = BackupSlotInventoryRegistry(maxServers = 2)
        r.record(ServerId("a"), profile(ServerId("a")), BackupSlotInventory.Unavailable(t0)); r.record(ServerId("b"), profile(ServerId("b")), BackupSlotInventory.Unavailable(t0))
        r.record(ServerId("c"), profile(ServerId("c")), BackupSlotInventory.Unavailable(t0))
        assertNull(r.latest(ServerId("a"), profile(ServerId("a")))); assertNotNull(r.latest(ServerId("b"), profile(ServerId("b")))); assertNotNull(r.latest(ServerId("c"), profile(ServerId("c"))))
    }
    @Test fun serversAreIndependent() {
        val r = BackupSlotInventoryRegistry()
        r.record(ServerId("a"), profile(ServerId("a")), BackupSlotInventory.Known(4, 4, t0))
        assertNull(r.latest(ServerId("b"), profile(ServerId("b"))))
    }
    @Test fun twoProfilesOfOneServerNeverShareAnObservation() {
        val r = BackupSlotInventoryRegistry()
        r.record(s, a, BackupSlotInventory.Known(4, 4, t0))
        assertNotNull(r.latest(s, a))
        assertNull(r.latest(s, profile(host = "203.0.113.2")))
        assertNull(r.latest(s, profile(port = 2222)))
        assertNull(r.latest(s, profile(key = "SHA256:KEY-B")))
        assertNull(r.latest(s, profile(id = "other")))
        r.record(s, profile(host = "203.0.113.2"), BackupSlotInventory.Known(1, 4, t0.plusSeconds(1)))
        assertNull(r.latest(s, a))
        assertEquals(1, (r.latest(s, profile(host = "203.0.113.2")) as BackupSlotInventory.Known).used)
    }
    @Test fun profileOfAnotherServerIsIgnored() {
        val r = BackupSlotInventoryRegistry()
        r.record(s, profile(ServerId("x")), BackupSlotInventory.Known(4, 4, t0))
        assertNull(r.latest(s, a)); assertNull(r.latest(s, profile(ServerId("x"))))
    }
}

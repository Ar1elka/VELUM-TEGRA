package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class WorkingDatabaseRestoreSshAdapterTest {
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))
    private val reader=WorkingDatabaseRestoreSshAdapter({at})
    private fun proof()="FORMAT=VELUM_WORKING_DB_V1\nSCOPE=${binding.digest}\nSOURCE_DB_SHA256=${source.databaseSha256}\nRESTORED_LOGICAL_SHA256=${"1".repeat(64)}\nPREVIOUS_DB_SHA256=${"2".repeat(64)}\nPREVIOUS_LOGICAL_SHA256=${"3".repeat(64)}\nPREVIOUS_BYTES=4096\nSERVICE=INACTIVE\nSTATE=VERIFIED\n"
    private fun parse(s:String)=reader.parse(scope,binding,s,at)
    @Test fun exactProofReturnsActualPreviousCopyFacts(){val r=requireNotNull(parse(proof()));assertEquals(4096L,r.previousBytes);assertEquals("2".repeat(64),r.previousDatabaseSha256);assertEquals(binding,r.binding)}
    @Test fun wrongSourceAndOperationCannotBecomeSuccess(){assertNull(parse(proof().replace(binding.digest,"0".repeat(64))));assertNull(parse(proof().replace(source.databaseSha256,"0".repeat(64))))}
    @Test fun serviceMustStillBeStopped(){assertNull(parse(proof().replace("SERVICE=INACTIVE","SERVICE=ACTIVE")))}
    @Test fun partialStateCannotBecomeVerified(){assertNull(parse(proof().replace("STATE=VERIFIED","STATE=PARTIAL")))}
    @Test fun duplicateMissingExtraAndUnterminatedFieldsReject(){for(s in listOf(proof().dropLast(1),proof()+"PRIVATE=x\n",proof().replace("PREVIOUS_BYTES=4096\n",""),proof().replace("PREVIOUS_BYTES=4096","SERVICE=INACTIVE")))assertNull(parse(s))}
    @Test fun malformedOrOversizedCountsReject(){for(s in listOf("0","-1","+1","01","134217729","999999999999999999"))assertNull(parse(proof().replace("PREVIOUS_BYTES=4096","PREVIOUS_BYTES=$s")))}
    @Test fun nonHexDigestRejects(){assertNull(parse(proof().replace("RESTORED_LOGICAL_SHA256=${"1".repeat(64)}","RESTORED_LOGICAL_SHA256=private")))}
    @Test fun writeAndReadCommandsAreClosedDifferentModes(){assertTrue(WorkingDatabaseRestoreCommands.command("write",binding).endsWith(" write ${binding.digest} ${binding.endpointSha256} ${source.digest} ${source.source.digest} 3.10.0 AMD64 ${source.archiveSha256} ${source.databaseSha256} ${source.inventorySha256} 4096 3"));assertTrue(WorkingDatabaseRestoreCommands.command("read",binding).contains(" read ${binding.digest} "))}
    @Test fun unknownModeCannotCompile(){try{WorkingDatabaseRestoreCommands.command("start",binding);fail("not allowed")}catch(_:IllegalArgumentException){}}
    @Test fun workerNeverStartsAServiceOrDeletesWalFiles(){assertFalse(WorkingDatabaseRestoreWorker.source.contains("systemctl start"));assertFalse(WorkingDatabaseRestoreWorker.source.contains("os.unlink(DATABASE"));assertTrue(WorkingDatabaseRestoreWorker.source.contains("source.backup(target"))}
}

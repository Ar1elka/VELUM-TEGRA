package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class RestoredPanelStartSshAdapterTest{
    private val at=Instant.parse("2026-10-18T19:00:00Z")
    private val scope=ManagementScope(OperationId("start"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val restored=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))
    private val binding=RestoredPanelStartBinding(OperationId("restore"),5,restored,"7".repeat(64))
    private val reader=RestoredPanelStartSshAdapter({at})
    private fun proof()="FORMAT=VELUM_RESTORED_PANEL_START_V1\nSCOPE=${binding.digest}\nSOURCE_RESTORE=${restored.digest}\nVERSION=3.10.0\nARCH=AMD64\nSCHEMA=${"1".repeat(64)}\nINBOUNDS=1\nSERVICE=ACTIVE\n"
    private fun parse(raw:String)=reader.parse(scope,binding,raw,at)
    @Test fun exactReadbackReturnsMomentaryServiceEvidence(){val r=requireNotNull(parse(proof()));assertEquals(1,r.inbounds);assertEquals(at,r.observedAt);assertEquals(binding,r.binding)}
    @Test fun wrongSourceAndOperationReject(){assertNull(parse(proof().replace(binding.digest,"0".repeat(64))));assertNull(parse(proof().replace(restored.digest,"0".repeat(64))))}
    @Test fun inactiveServiceCannotBeSuccess(){assertNull(parse(proof().replace("SERVICE=ACTIVE","SERVICE=INACTIVE")))}
    @Test fun changedReleaseOrArchitectureCannotBeVerified(){assertNull(parse(proof().replace("VERSION=3.10.0","VERSION=3.10.2")));assertNull(parse(proof().replace("ARCH=AMD64","ARCH=ARM64")))}
    @Test fun duplicateMissingExtraAndUnterminatedFieldsReject(){for(raw in listOf(proof().dropLast(1),proof()+"COOKIE=secret\n",proof().replace("INBOUNDS=1\n",""),proof().replace("INBOUNDS=1","SERVICE=ACTIVE")))assertNull(parse(raw))}
    @Test fun malformedCountsReject(){for(n in listOf("-1","+1","01","257","999999999999999"))assertNull(parse(proof().replace("INBOUNDS=1","INBOUNDS=$n")))}
    @Test fun unknownSchemaCannotPass(){assertNull(parse(proof().replace("SCHEMA=${"1".repeat(64)}","SCHEMA=unknown")))}
    @Test fun commandModesAndSourceArgumentsAreClosed(){assertTrue(RestoredPanelStartCommands.command("write",binding).endsWith(" write ${binding.digest} ${restored.digest} ${restored.endpointSha256} ${source.digest} ${source.source.digest} 3.10.0 AMD64 ${source.archiveSha256} ${source.databaseSha256} ${source.inventorySha256} 4096 3"));assertTrue(RestoredPanelStartCommands.command("read",binding).contains(" read ${binding.digest} "))}
    @Test fun arbitraryCommandsCannotCompile(){try{RestoredPanelStartCommands.command("restart",binding);fail("closed modes")}catch(_:IllegalArgumentException){}}
    @Test fun preflightAndWriteFitSeparateShortServiceBudget(){assertTrue(RestoredPanelStartCommands.command("preflight",binding).startsWith("timeout --kill-after=2s 10s "));assertTrue(RestoredPanelStartCommands.command("write",binding).startsWith("timeout --kill-after=2s 140s "));assertTrue(RestoredPanelStartWorker.source.contains("START_DISPATCHED=True"))}
}

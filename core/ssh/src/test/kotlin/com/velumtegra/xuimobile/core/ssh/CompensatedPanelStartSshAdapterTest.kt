package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class CompensatedPanelStartSshAdapterTest {
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))

    private val returned=BeforeCopyReturnBinding(binding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),5,"1".repeat(64),"2".repeat(64),4096,"3".repeat(64))
    private val started=CompensatedPanelStartBinding(returned,7,"5".repeat(64))
    private val reader=CompensatedPanelStartSshAdapter({at})
    private fun proof()="FORMAT=VELUM_COMPENSATED_PANEL_START_V1\nSCOPE=${started.digest}\nRETURN=${returned.digest}\nVERSION=3.10.0\nARCH=AMD64\nSCHEMA=${"4".repeat(64)}\nINBOUNDS=2\nSERVICE=ACTIVE\nSTATE=STRUCTURAL_READBACK\n"
    private fun parse(s:String)=reader.parse(scope,started,s,at)
    @Test fun exactActiveStructuralReadbackAccepted(){assertEquals(2,parse(proof())!!.inbounds)}
    @Test fun wrongStartScopeRejected(){assertNull(parse(proof().replace(started.digest,"f".repeat(64))))}
    @Test fun wrongReturnScopeRejected(){assertNull(parse(proof().replace(returned.digest,"f".repeat(64))))}
    @Test fun wrongVersionRejected(){assertNull(parse(proof().replace("3.10.0","3.10.1")))}
    @Test fun wrongArchitectureRejected(){assertNull(parse(proof().replace("AMD64","ARM64")))}
    @Test fun malformedSchemaRejected(){assertNull(parse(proof().replace("4".repeat(64),"PRIVATE")))}
    @Test fun countCanonicalAndBounded(){for(n in listOf("-1","01","257","9999"))assertNull(parse(proof().replace("INBOUNDS=2","INBOUNDS=$n")))}
    @Test fun stoppedServiceCannotClaimActive(){assertNull(parse(proof().replace("SERVICE=ACTIVE","SERVICE=INACTIVE")))}
    @Test fun genericSuccessIsNotStructuralReadback(){assertNull(parse(proof().replace("STATE=STRUCTURAL_READBACK","STATE=SUCCESS")))}
    @Test fun duplicateFieldRejected(){assertNull(parse(proof().replace("SERVICE=ACTIVE","STATE=STRUCTURAL_READBACK")))}
    @Test fun missingFieldRejected(){assertNull(parse(proof().replace("SERVICE=ACTIVE\n","")))}
    @Test fun extraSecretFieldRejected(){assertNull(parse(proof()+"SECRET=never\n"))}
    @Test fun noTrailingNewlineRejected(){assertNull(parse(proof().dropLast(1)))}
    @Test fun oversizeAndInvalidFormatRejected(){assertNull(parse("x".repeat(1025)));assertNull(parse(proof().replace("VELUM_COMPENSATED_PANEL_START_V1","OTHER")))}
    @Test fun closedModesRejectStopAndShell(){for(m in listOf("stop","restart","read; start"))assertTrue(runCatching{CompensatedPanelStartCommands.command(m,started)}.isFailure)}
    @Test fun readEntryCannotStartCopyOrCreateStorage(){val s=CompensatedPanelStartWorker.source.substringAfter("def compensated_read():").substringBefore("def compensated_main():");assertFalse(s.contains("'start'"));assertFalse(s.contains("working_apply("));assertFalse(s.contains("os.mkdir("));assertFalse(s.contains("returning_store("))}
}

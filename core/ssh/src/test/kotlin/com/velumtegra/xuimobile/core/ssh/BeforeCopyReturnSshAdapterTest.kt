package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class BeforeCopyReturnSshAdapterTest {
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))

    private val returned=BeforeCopyReturnBinding(binding.phaseName(WorkingDatabaseRestorePhase.UNCERTAIN),5,"1".repeat(64),"2".repeat(64),4096,"3".repeat(64))
    private val reader=BeforeCopyReturnSshAdapter({at})
    private fun proof()="FORMAT=VELUM_BEFORE_RETURN_V1\nSCOPE=${returned.digest}\nRESTORE=${binding.digest}\nBEFORE_SHA256=${returned.beforeDatabaseSha256}\nBEFORE_LOGICAL=${returned.beforeLogicalSha256}\nDISPLACED_SHA256=${"4".repeat(64)}\nDISPLACED_BYTES=4096\nSERVICE=INACTIVE\nSTATE=VERIFIED_STOPPED\n"
    private fun parse(s:String)=reader.parse(scope,returned,s,at)
    @Test fun exactStoppedReadbackAccepted(){assertEquals(4096L,parse(proof())!!.displacedBytes)}
    @Test fun wrongReturnScopeRejected(){assertNull(parse(proof().replace(returned.digest,"f".repeat(64))))}
    @Test fun wrongOriginalScopeRejected(){assertNull(parse(proof().replace(binding.digest,"f".repeat(64))))}
    @Test fun wrongBeforeByteDigestRejected(){assertNull(parse(proof().replace(returned.beforeDatabaseSha256,"f".repeat(64))))}
    @Test fun wrongBeforeLogicalDigestRejected(){assertNull(parse(proof().replace(returned.beforeLogicalSha256,"f".repeat(64))))}
    @Test fun malformedDisplacedHashRejected(){assertNull(parse(proof().replace("4".repeat(64),"SECRET")))}
    @Test fun displacedCountIsCanonicalAndBounded(){for(n in listOf("0","-1","01","134217729","999999999999"))assertNull(parse(proof().replace("DISPLACED_BYTES=4096","DISPLACED_BYTES=$n")))}
    @Test fun activeServiceCannotClaimStoppedReturn(){assertNull(parse(proof().replace("SERVICE=INACTIVE","SERVICE=ACTIVE")))}
    @Test fun genericSuccessCannotClaimReturn(){assertNull(parse(proof().replace("STATE=VERIFIED_STOPPED","STATE=SUCCESS")))}
    @Test fun duplicateFieldRejected(){assertNull(parse(proof().replace("SERVICE=INACTIVE","STATE=VERIFIED_STOPPED")))}
    @Test fun missingFieldRejected(){assertNull(parse(proof().replace("SERVICE=INACTIVE\n","")))}
    @Test fun extraRawSecretFieldRejected(){assertNull(parse(proof()+"SECRET=never\n"))}
    @Test fun noTrailingNewlineRejected(){assertNull(parse(proof().dropLast(1)))}
    @Test fun oversizeOrInvalidFormatRejected(){assertNull(parse("x".repeat(1025)));assertNull(parse(proof().replace("VELUM_BEFORE_RETURN_V1","OLD")))}
    @Test fun closedModesRejectArbitraryCommands(){assertTrue(runCatching{BeforeCopyReturnCommands.command("stop",returned)}.isFailure);assertTrue(BeforeCopyReturnCommands.command("read",returned).endsWith(" ${source.inventorySha256} 4096 3"))}
    @Test fun readEntryCannotCopyOrCreateStorage(){val f=BeforeCopyReturnWorker.source.substringAfter("def returning_read():").substringBefore("def returning_main():");assertFalse(f.contains("working_apply("));assertFalse(f.contains("os.mkdir("));assertFalse(f.contains("returning_store("));assertTrue(f.contains("returning_lock(False)"))}
}

package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class BeforeCopyEvidenceSshAdapterTest {
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val comparison=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val binding=WorkingDatabaseRestoreBinding(OperationId("compare"),4,comparison,"9".repeat(64),"8".repeat(64))
    private val reader=BeforeCopyEvidenceSshAdapter({at})
    private fun proof()="FORMAT=VELUM_BEFORE_COPY_V1\nSCOPE=${binding.digest}\nBEFORE_DB_SHA256=${"2".repeat(64)}\nBEFORE_LOGICAL_SHA256=${"3".repeat(64)}\nBEFORE_BYTES=4096\nSERVICE=INACTIVE\nCURRENT_DB=DIFFERENT\nSTRUCTURE=MATCH\nCOPY_STATE=PARTIAL\nSTATE=OBSERVED\n"
    private fun parse(s:String)=reader.parse(scope,binding,s,at)
    @Test fun exactPartialCopyEvidenceDoesNotRequireRestoredManifest(){val p=requireNotNull(parse(proof()));assertEquals(BeforeCopyCompletion.PARTIAL,p.completion);assertEquals(4096L,p.bytes);assertEquals(binding,p.binding)}
    @Test fun activeServiceCannotClaimStableCurrentDb(){assertNull(parse(proof().replace("SERVICE=INACTIVE","SERVICE=ACTIVE")))}
    @Test fun activeServiceMayObserveOnlyPriorCopy(){val p=parse(proof().replace("SERVICE=INACTIVE","SERVICE=ACTIVE").replace("CURRENT_DB=DIFFERENT","CURRENT_DB=UNAVAILABLE"));assertNotNull(p)}
    @Test fun equalCurrentDbIsOnlyAnObservation(){assertEquals(BeforeCopyCurrent.SAME,parse(proof().replace("CURRENT_DB=DIFFERENT","CURRENT_DB=SAME"))!!.current)}
    @Test fun completeManifestDoesNotBecomeWorkingRecovery(){assertEquals(BeforeCopyCompletion.COMPLETE,parse(proof().replace("COPY_STATE=PARTIAL","COPY_STATE=COMPLETE"))!!.completion)}
    @Test fun unavailableCurrentAndStructureRemainFinite(){assertNotNull(parse(proof().replace("CURRENT_DB=DIFFERENT","CURRENT_DB=UNAVAILABLE").replace("STRUCTURE=MATCH","STRUCTURE=UNAVAILABLE")))}
    @Test fun structuralDifferenceIsNotReadFailure(){assertEquals(BeforeCopyStructure.DIFFERENT,parse(proof().replace("STRUCTURE=MATCH","STRUCTURE=DIFFERENT"))!!.structure)}
    @Test fun foreignScopeRejects(){assertNull(parse(proof().replace(binding.digest,"0".repeat(64))))}
    @Test fun missingFieldRejects(){assertNull(parse(proof().replace("COPY_STATE=PARTIAL\n","")))}
    @Test fun duplicateFieldRejects(){assertNull(parse(proof().replace("COPY_STATE=PARTIAL","SERVICE=INACTIVE")))}
    @Test fun extraRawFieldRejects(){assertNull(parse(proof()+"RAW_SECRET=never\n"))}
    @Test fun noFinalNewlineRejects(){assertNull(parse(proof().dropLast(1)))}
    @Test fun countMustBeBoundedAndCanonical(){for(n in listOf("0","-1","+1","01","134217729","999999999999"))assertNull(parse(proof().replace("BEFORE_BYTES=4096","BEFORE_BYTES=$n")))}
    @Test fun digestMustBeExactLowerHex(){for(n in listOf("secret","A".repeat(64),"0".repeat(63)))assertNull(parse(proof().replace("2".repeat(64),n)))}
    @Test fun unknownServiceAndCurrentReject(){assertNull(parse(proof().replace("SERVICE=INACTIVE","SERVICE=FAILED")));assertNull(parse(proof().replace("CURRENT_DB=DIFFERENT","CURRENT_DB=RESTORED")))}
    @Test fun unknownStructureAndCompletionReject(){assertNull(parse(proof().replace("STRUCTURE=MATCH","STRUCTURE=READY")));assertNull(parse(proof().replace("COPY_STATE=PARTIAL","COPY_STATE=ROLLBACK")))}
    @Test fun stateNeverClaimsRestoreAuthority(){assertNull(parse(proof().replace("STATE=OBSERVED","STATE=VERIFIED")))}
    @Test fun hugeOrMultilineRawResponseRejects(){assertNull(parse("x".repeat(2049)));assertNull(parse(proof().replace("BEFORE_BYTES=4096","BEFORE_BYTES=4096\nRAW=x")))}
    @Test fun fixedCommandHasOnlySpaceBindingArguments(){assertTrue(BeforeCopyEvidenceCommands.command(binding).endsWith(" space ${binding.digest} ${binding.endpointSha256} ${source.digest} ${source.source.digest} 3.10.0 AMD64 ${source.archiveSha256} ${source.databaseSha256} ${source.inventorySha256} 4096 3"))}
    @Test fun newEntrypointCannotCallWriterOrCreateLock(){val entry=BeforeCopyEvidenceWorker.source.substringAfter("def before_main():");assertFalse(entry.contains("working_write("));assertFalse(entry.contains("working_apply("));assertFalse(entry.contains("os.mkdir("));assertFalse(entry.contains("working_lock(True)"));assertTrue(entry.contains("working_lock(False)"))}
}

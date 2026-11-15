package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class RecoveryReadinessSshReaderTest {

    private val at=Instant.parse("2026-10-21T17:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val binding=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private fun groups()=RecoveryFileGroup.values().associateWith{when(it){RecoveryFileGroup.RUNTIME->RecoveryGroupDifference(2,2,0,0,0);RecoveryFileGroup.SERVICE->RecoveryGroupDifference(1,1,0,0,0);else->RecoveryGroupDifference(0,0,0,0,0)}}
    private fun evidence()=RecoveryReadinessEvidence(scope,binding,4,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),groups(),3,3,0,0,0,1024,1024,true,true,RecoveryJournalMode.WAL,RecoveryWalPresence.PRESENT,RecoveryQuiescence.STOPPED,"2".repeat(64),at)

    private fun proof():String {
        val p=evidence()
        return "FORMAT=VELUM_RECOVERY_READINESS_V1\nSCOPE=${binding.digest}\nREVISION=4\nARCHIVE=${source.archiveSha256}\nDATABASE=${source.databaseSha256}\nINVENTORY=${source.inventorySha256}\nCURRENT_VERSION=3.10.0\nCURRENT_ARCH=AMD64\nSOURCE_SCHEMA=${p.sourceSchema}\nCURRENT_SCHEMA=${p.currentSchema}\nTOTAL=3,3,0,0,0\nSOURCE_BYTES=1024\nCURRENT_BYTES=1024\nENDPOINT=MATCH\nPAGE_SIZE=MATCH\nJOURNAL=WAL\nWAL=PRESENT\nQUIESCENCE=STOPPED\nCURRENT_SET=${p.currentSetSha256}\nMIGRATION=UNVERIFIED\nRUNTIME=2,2,0,0,0\nSERVICE=1,1,0,0,0\nPANEL_TLS=0,0,0,0,0\nXRAY_TLS=0,0,0,0,0\nXRAY_DATA=0,0,0,0,0\n"
    }
    private fun parse(raw:String)=RecoveryReadinessSshReader().parse(scope,binding,4,raw,at)
    @Test fun strictFiniteProofHasExactGroupsAndScope(){assertEquals(evidence(),parse(proof()))}
    @Test fun wrongScopeArchiveDatabaseOrInventoryReject(){for(v in listOf(binding.digest,source.archiveSha256,source.databaseSha256,source.inventorySha256))assertNull(parse(proof().replace(v,"9".repeat(64))))}
    @Test fun wrongOrNoncanonicalRevisionReject(){for(v in listOf("3","04","+4","-1","999999999999999999999"))assertNull(parse(proof().replace("REVISION=4","REVISION=$v")))}
    @Test fun missingExtraDuplicateAndUnterminatedRowsReject(){for(v in listOf(proof().replace("XRAY_DATA=0,0,0,0,0\n",""),proof()+"PRIVATE=value\n",proof().replace("XRAY_DATA=","XRAY_TLS="),proof().dropLast(1)))assertNull(parse(v))}
    @Test fun malformedNumbersAndOutOfBoundsGroupsReject(){for(v in listOf("97,97,0,0,0","2,2,3,0,0","02,2,0,0,0","2,2,0,3,3","2,2,0,0"))assertNull(parse(proof().replace("RUNTIME=2,2,0,0,0","RUNTIME=$v")))}
    @Test fun absentGroupCannotInventCoverage(){assertNull(parse(proof().replace("RUNTIME=2,2,0,0,0","RUNTIME=0,0,0,0,0")))}
    @Test fun sourceMembershipCountMustMatchArchive(){assertNull(parse(proof().replace("TOTAL=3,3,0,0,0","TOTAL=4,4,0,0,0")))}
    @Test fun unknownModesAndHashesReject(){for(v in listOf(proof().replace("JOURNAL=WAL","JOURNAL=MEMORY"),proof().replace("QUIESCENCE=STOPPED","QUIESCENCE=ASSUMED"),proof().replace("ENDPOINT=MATCH","ENDPOINT=MAYBE"),proof().replace("CURRENT_SET=${"2".repeat(64)}","CURRENT_SET=/root/private")))assertNull(parse(v))}
    @Test fun falseMigrationAuthorityCannotEnterModel(){assertNull(parse(proof().replace("MIGRATION=UNVERIFIED","MIGRATION=VERIFIED")))}
    @Test fun deleteModeCannotCoexistWithNonemptyWalClaim(){assertNull(parse(proof().replace("JOURNAL=WAL","JOURNAL=DELETE")))}
    @Test fun sourceBytesAreFiniteAndCanonical(){for(v in listOf("536870913","-1","01","+2","999999999999999"))assertNull(parse(proof().replace("SOURCE_BYTES=1024","SOURCE_BYTES=$v")))}
    @Test fun versionDifferenceIsEvidenceOnly(){val p=requireNotNull(parse(proof().replace("CURRENT_VERSION=3.10.0","CURRENT_VERSION=3.10.2")));assertEquals("3.10.2",p.currentVersion)}
    @Test fun commandHasClosedReadOnlyEntrypointAndExactArguments(){val c=RecoveryReadinessCommands.read(binding,4);assertTrue(c.startsWith("timeout --kill-after=2s 140s python3 -I -c "));assertTrue(c.endsWith(" ${binding.digest} 4 ${source.digest} ${source.source.digest} 3.10.0 AMD64 ${source.archiveSha256} ${source.databaseSha256} ${source.inventorySha256} 4096 3"));val entry=RecoveryReadinessWorker.source.substringAfter("def readiness_main():");assertFalse(entry.contains("restore_copy("));assertFalse(entry.contains("systemctl','stop"));assertFalse(entry.contains("os.mkdir("))}
    @Test fun invalidRevisionCannotCompileCommand(){assertTrue(runCatching{RecoveryReadinessCommands.read(binding,-1)}.isFailure)}
}

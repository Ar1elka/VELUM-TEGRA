package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class RestoreCompatibilitySshReaderTest {
    private val at=Instant.parse("2026-10-18T06:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val binding=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val facts=ManagementLiveSnapshot(scope,ManagementIdentityStatus.Matched,ManagementServiceState.ACTIVE,ManagementBaselineStatus.Matched,null,at)
    private val reader=RestoreCompatibilitySshReader({at})
    private fun proof()="FORMAT=VELUM_RESTORE_COMPARISON_V1\nSCOPE=${binding.digest}\nSOURCE_RESTORE=${source.digest}\nSOURCE_ARCHIVE=${source.archiveSha256}\nSOURCE_DB=${source.databaseSha256}\nSOURCE_INVENTORY=${source.inventorySha256}\nCURRENT_VERSION=3.10.0\nCURRENT_ARCH=AMD64\nSOURCE_SCHEMA=${"1".repeat(64)}\nCURRENT_SCHEMA=${"1".repeat(64)}\nFILE_SET=MATCH\nCHANGED_FILES=0\nSOURCE_INBOUNDS=1\nCURRENT_INBOUNDS=2\n"
    private fun ok(s:String)=SshCommandResult(CommandDispatchState.DISPATCHED,CommandCompletion.ConfirmedSuccess,CapturedOutput.of(s.toByteArray(),false),CapturedOutput.EMPTY)
    private fun parse(s:String)=reader.parse(scope,binding,ok(s),facts,at)
    @Test fun finiteProofReturnsCountsAndSchemaHashesOnly(){val r=requireNotNull(parse(proof()));assertEquals(1,r.sourceInbounds);assertEquals(2,r.currentInbounds);assertTrue(r.sameSchema);assertEquals(binding,r.binding)}
    @Test fun wrongOperationAndSourceHashesCannotPublish(){for(v in listOf(binding.digest,source.digest,source.archiveSha256,source.databaseSha256,source.inventorySha256))assertNull(parse(proof().replace(v,"0".repeat(64))))}
    @Test fun extraMissingDuplicateAndUnterminatedFieldsReject(){for(v in listOf(proof()+"PRIVATE=value\n",proof().replace("CURRENT_INBOUNDS=2\n",""),proof().replace("CURRENT_INBOUNDS=2","SOURCE_INBOUNDS=2"),proof().dropLast(1)))assertNull(parse(v))}
    @Test fun unknownFiniteFieldsReject(){for(v in listOf(proof().replace("AMD64","OTHER"),proof().replace("FILE_SET=MATCH","FILE_SET=ASSUMED"),proof().replace("3.10.0","latest")))assertNull(parse(v))}
    @Test fun malformedOverflowOrNoncanonicalCountsReject(){for(v in listOf("-1","257","+2","02","999999999999999"))assertNull(parse(proof().replace("CURRENT_INBOUNDS=2","CURRENT_INBOUNDS=$v")))}
    @Test fun unavailableFieldsCannotInventMatch(){assertNull(parse(proof().replace("CHANGED_FILES=0","CHANGED_FILES=-")));val r=requireNotNull(parse(proof().replace("CURRENT_SCHEMA=${"1".repeat(64)}","CURRENT_SCHEMA=-").replace("CURRENT_INBOUNDS=2","CURRENT_INBOUNDS=-")));assertFalse(r.sameSchema);assertFalse(r.prerequisitesMatch)}
    @Test fun unknownTransportStderrTruncationAndInvalidUtf8Reject(){val values=listOf(ok(proof()).copy(completion=CommandCompletion.Unknown("private")),ok(proof()).copy(stderr=CapturedOutput.of("private".toByteArray(),false)),ok(proof()).copy(stdout=CapturedOutput.of(proof().toByteArray(),true)),ok(proof()).copy(stdout=CapturedOutput.of(byteArrayOf(0xc3.toByte(),0x28),false)));for(v in values)assertNull(reader.parse(scope,binding,v,facts,at))}
    @Test fun futureOrForeignManagementEvidenceReject(){assertNull(reader.parse(scope,binding,ok(proof()),facts.copy(scope=scope.copy(serverId=ServerId("other"))),at));assertNull(reader.parse(scope,binding,ok(proof()),facts.copy(observedAt=at.plusSeconds(1)),at))}
    @Test fun observedVersionDifferenceDoesNotBecomeCompatibility(){val r=requireNotNull(parse(proof().replace("CURRENT_VERSION=3.10.0","CURRENT_VERSION=3.10.2")));assertFalse(r.sameVersion);assertFalse(r.prerequisitesMatch)}
    @Test fun fixedReadCommandContainsOnlyValidatedProofArguments(){val c=RestoreCompatibilityCommands.read(binding);assertTrue(c.startsWith("timeout --kill-after=2s 120s python3 -I -c "));assertTrue(c.endsWith(" ${binding.digest} ${source.digest} ${source.source.digest} 3.10.0 AMD64 ${source.archiveSha256} ${source.databaseSha256} ${source.inventorySha256} 4096 3"));assertFalse(RestoreCompatibilityWorker.source.contains("extractall("));assertFalse(RestoreCompatibilityWorker.source.contains("systemctl stop"))}
}

package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
class KnownFileRestoreSshAdapterTest{
    @Test fun closedForeignSessionOrTargetCannotEvenProbe()=runBlocking{
        val i=XuiInstallation(XuiInstallationId("install"),ServerId("server"),InstallationOwnership.ADOPTED,InstallationIdentity("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",null),InstallationBaseline("x-ui.service","/usr/local/x-ui/x-ui","/usr/local/x-ui","/etc/x-ui/x-ui.db",2053,"/panel/",null,at))
        var commands=0
        fun session(owner:SessionOwner,access:ServerAccessId,open:Boolean)=object:SshSessionHandle{
            override val binding=SessionBinding(SessionId("fixture"),access,owner);override val isOpen=open
            override suspend fun execute(command:RemoteCommand,config:SshTransportConfig):SshCommandResult{commands++;error("No probe authorized")}
            override fun close(){}
        }
        assertNull(adapter.prepare(scope,binding,i,session(SessionOwner.Operation(OperationId("foreign")),scope.serverAccessId,true)))
        assertNull(adapter.inspect(scope,binding,i,session(SessionOwner.Operation(scope.operationId),ServerAccessId("foreign"),true)))
        assertNull(adapter.prepare(scope,binding,i,session(SessionOwner.Operation(scope.operationId),scope.serverAccessId,false)))
        assertNull(adapter.prepare(scope,binding,i.copy(id=XuiInstallationId("foreign")),session(SessionOwner.Operation(scope.operationId),scope.serverAccessId,true)))
        assertEquals(0,commands)
    }
    private val at=Instant.parse("2026-10-21T17:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val parent=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private val binding=KnownFileRestoreBinding(OperationId("compare"),4,parent,"2".repeat(64),2,"3".repeat(64))
    private val adapter=KnownFileRestoreSshAdapter()
    private fun prepared()="FORMAT=VELUM_KNOWN_FILE_PREPARED_V1\nSCOPE=${binding.digest}\nDATABASE_LOGICAL=${"4".repeat(64)}\nCHANGED=2\n"
    private fun inspection()="FORMAT=VELUM_KNOWN_FILE_READ_V1\nSCOPE=${binding.digest}\nMANIFEST=${"5".repeat(64)}\nDATABASE_LOGICAL=${"4".repeat(64)}\nDESIRED=1\nPREVIOUS=1\nFILES=2\n"
    private fun parse(s:String)=adapter.parseInspection(scope,binding,s,at)
    @Test fun finitePreparedProofHasExactScopeAndCount(){val p=adapter.parsePrepared(scope,binding,prepared(),at)!!;assertEquals(scope,p.scope);assertEquals(binding,p.binding);assertEquals("4".repeat(64),p.databaseLogicalSha256)}
    @Test fun mixedReadbackDoesNotInventCompleteness(){val p=parse(inspection())!!;assertFalse(p.desiredComplete);assertFalse(p.previousComplete);assertEquals(2,p.desiredFiles+p.previousFiles)}
    @Test fun preparedCountCannotBeNoncanonicalOrForeign(){for(c in listOf("1","02","+2","97"))assertNull(adapter.parsePrepared(scope,binding,prepared().replace("CHANGED=2","CHANGED=$c"),at))}
    @Test fun wrongScopeAndUnknownPreparedRowsReject(){assertNull(adapter.parsePrepared(scope,binding,prepared().replace(binding.digest,"9".repeat(64)),at));assertNull(adapter.parsePrepared(scope,binding,prepared()+"PATH=/root/private\n",at))}
    @Test fun missingDuplicateExtraAndUnterminatedRowsReject(){for(s in listOf(inspection().replace("PREVIOUS=1\n",""),inspection().replace("PREVIOUS=1","DESIRED=1"),inspection()+"KEY=secret\n",inspection().dropLast(1)))assertNull(parse(s))}
    @Test fun negativeNoncanonicalOverflowAndUnboundedCountsReject(){for(c in listOf("-1","01","+1","97","99999999999999999"))assertNull(parse(inspection().replace("DESIRED=1","DESIRED=$c")))}
    @Test fun countsMustCoverExactChangedSet(){assertNull(parse(inspection().replace("PREVIOUS=1","PREVIOUS=0")));assertNull(parse(inspection().replace("FILES=2","FILES=1")))}
    @Test fun badHashesAndForeignScopeReject(){for(h in listOf(binding.digest,"4".repeat(64),"5".repeat(64)))assertNull(parse(inspection().replace(h,"private path")))}
    @Test fun completeDesiredAndPreviousRemainDistinct(){assertTrue(parse(inspection().replace("DESIRED=1","DESIRED=2").replace("PREVIOUS=1","PREVIOUS=0"))!!.desiredComplete);assertTrue(parse(inspection().replace("DESIRED=1","DESIRED=0").replace("PREVIOUS=1","PREVIOUS=2"))!!.previousComplete)}
    @Test fun writerArgumentsAreClosedAndExact(){val c=KnownFileRestoreCommands.command(KnownFileCommandMode.APPLY,binding);assertTrue(c.startsWith("timeout --kill-after=2s 180s python3 -I -c "));assertTrue(c.endsWith(" apply ${binding.digest} ${binding.currentSetSha256} 2 ${source.digest} ${source.source.digest} 3.10.0 AMD64 ${source.archiveSha256} ${source.databaseSha256} ${source.inventorySha256} 4096 3 ${"0".repeat(64)}"))}
    @Test fun returnOnlyUsesFiniteManifestHash(){assertTrue(KnownFileRestoreCommands.command(KnownFileCommandMode.RETURN,binding,"6".repeat(64)).endsWith(" ${"6".repeat(64)}"));assertTrue(runCatching{KnownFileRestoreCommands.command(KnownFileCommandMode.RETURN,binding,";id")}.isFailure)}
    @Test fun entryNeverCallsDatabaseOrServiceWriters(){val s=KnownFileRestoreWorker.source.substringAfter("def file_main():");assertFalse(s.contains("working_restore("));assertFalse(s.contains("restore_copy("));assertFalse(s.contains("systemctl"));assertFalse(s.contains("backup_to("))}
}

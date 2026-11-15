package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*
import java.time.Instant
import java.time.Duration
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

enum class RestoredPanelStartCopyResult { FINISHED, NOT_STARTED, FAILED, UNCERTAIN, REJECTED }
class RestoredPanelStartSshAdapter(private val now:()->Instant=Instant::now){
    suspend fun preflight(scope:ManagementScope,b:RestoredPanelStartBinding,session:SshSessionHandle):RestoredPanelStartReady?{
        if(!exact(scope,session))return null;val identity=session.binding
        val raw=text(execute(session,RestoredPanelStartCommands.command("preflight",b),"restored-start-preflight",64,12),64)?:return null
        if(raw!="READY\n" || !exact(scope,session) || session.binding!=identity)return null
        return RestoredPanelStartReady(scope,b,now())
    }
    suspend fun copy(dispatch:VerifiedRestoredPanelStartDispatch,current:VersionedOperationSnapshot,session:SshSessionHandle):RestoredPanelStartCopyResult{
        val s=current.snapshot;val t=s.target as? OperationTarget.InstallationTarget?:return RestoredPanelStartCopyResult.REJECTED
        if(!exact(dispatch.scope,session) || s.type!=OperationType.RESTORED_PANEL_START || s.operationId!=dispatch.scope.operationId ||
            t.serverId!=dispatch.scope.serverId || t.installationId!=dispatch.scope.installationId || t.serverAccessId!=dispatch.scope.serverAccessId ||
            s.status!=OperationStatus.RUNNING || s.checkpoint.semantics!=CheckpointSemantics.MUTATION_IN_FLIGHT ||
            s.checkpoint.phaseName!=dispatch.binding.phaseName(RestoredPanelStartPhase.STARTING) ||
            !dispatch.consumeOnce(current.revision,now()))return RestoredPanelStartCopyResult.REJECTED
        val identity=session.binding
        val result=execute(session,RestoredPanelStartCommands.command("write",dispatch.binding),"restored-start-once",64,145)
        if(!exact(dispatch.scope,session) || session.binding!=identity || result.dispatchState!=CommandDispatchState.DISPATCHED)return RestoredPanelStartCopyResult.UNCERTAIN
        if(text(result,64,allowRejected=true)=="NOT_STARTED\n" && (result.completion as? CommandCompletion.ConfirmedFailure)?.exitCode==81)return RestoredPanelStartCopyResult.NOT_STARTED
        return if(result.completion==CommandCompletion.ConfirmedSuccess && text(result,64)=="SERVICE_START_REQUESTED\n")RestoredPanelStartCopyResult.FINISHED else RestoredPanelStartCopyResult.UNCERTAIN
    }
    suspend fun verify(scope:ManagementScope,b:RestoredPanelStartBinding,session:SshSessionHandle):RestoredPanelStartReceipt?{
        if(!exact(scope,session))return null;val identity=session.binding
        val raw=text(execute(session,RestoredPanelStartCommands.command("read",b),"restored-start-readback",1024,145),1024)?:return null
        if(!exact(scope,session) || session.binding!=identity)return null
        return parse(scope,b,raw,now())
    }
    internal fun parse(scope:ManagementScope,b:RestoredPanelStartBinding,raw:String,at:Instant):RestoredPanelStartReceipt?{
        if(!raw.endsWith('\n'))return null;val rows=raw.dropLast(1).split('\n');if(rows.size!=8)return null
        val values=linkedMapOf<String,String>();for(row in rows){val parts=row.split('=');if(parts.size!=2 || values.put(parts[0],parts[1])!=null)return null}
        if(values.keys!=setOf("FORMAT","SCOPE","SOURCE_RESTORE","VERSION","ARCH","SCHEMA","INBOUNDS","SERVICE") ||
            values["FORMAT"]!="VELUM_RESTORED_PANEL_START_V1" || values["SCOPE"]!=b.digest || values["SOURCE_RESTORE"]!=b.restored.digest || values["SERVICE"]!="ACTIVE")return null
        val count=values["INBOUNDS"]?.takeIf{Regex("0|[1-9][0-9]{0,2}").matches(it)}?.toIntOrNull()?:return null
        return try{RestoredPanelStartReceipt(scope,b,values["VERSION"]?:return null,UpdateServerArchitecture.valueOf(values["ARCH"]?:return null),values["SCHEMA"]?:return null,count,at)}catch(_:IllegalArgumentException){null}
    }
    private suspend fun execute(session:SshSessionHandle,command:String,label:String,limit:Int,seconds:Long):SshCommandResult{
        currentCoroutineContext().ensureActive();val result=session.execute(RemoteCommand.create(command,label),SshTransportConfig(channelOpenTimeout=Duration.ofSeconds(5),commandExecutionTimeout=Duration.ofSeconds(seconds),stdoutCaptureLimitBytes=limit,stderrCaptureLimitBytes=512));currentCoroutineContext().ensureActive();return result
    }
    private fun exact(scope:ManagementScope,s:SshSessionHandle)=s.isOpen && s.binding.owner==SessionOwner.Operation(scope.operationId) && s.binding.serverAccessId==scope.serverAccessId
    private fun text(r:SshCommandResult,limit:Int,allowRejected:Boolean=false):String?{
        if(r.dispatchState!=CommandDispatchState.DISPATCHED || (r.completion!=CommandCompletion.ConfirmedSuccess && !(allowRejected && (r.completion as? CommandCompletion.ConfirmedFailure)?.exitCode==81)) || r.stdout.truncated || r.stderr.truncated || r.stderr.sizeBytes!=0 || r.stdout.sizeBytes>limit)return null
        val bytes=r.stdout.copyBytes();return try{StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()}catch(_:Exception){null}finally{Arrays.fill(bytes,0)}
    }
}
internal object RestoredPanelStartCommands{
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun command(mode:String,b:RestoredPanelStartBinding):String{
        require(mode in setOf("preflight","write","read"));val r=b.restored;val s=r.source
        val seconds=if(mode=="preflight")10 else 140
        return "timeout --kill-after=2s ${seconds}s python3 -I -c "+quote(RestoredPanelStartWorker.source)+
            " $mode ${b.digest} ${r.digest} ${r.endpointSha256} ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name}"+
            " ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount}"
    }
}

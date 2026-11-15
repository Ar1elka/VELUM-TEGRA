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

enum class WorkingDatabaseRestoreCopyResult { FINISHED, NOT_STARTED, FAILED, UNCERTAIN, REJECTED }
class WorkingDatabaseRestoreSshAdapter(private val now:()->Instant=Instant::now){
    suspend fun storage(scope:ManagementScope,b:WorkingDatabaseRestoreBinding,session:SshSessionHandle):InstallationBackupStorageObservation?{
        if(!exact(scope,session))return null;val identity=session.binding
        val raw=text(execute(session,WorkingDatabaseRestoreCommands.command("space",b),"working-db-storage",128,12),128)?:return null
        if(!exact(scope,session) || session.binding!=identity)return null
        val parts=raw.removeSuffix("\n").split('\n');if(parts.size!=2 || !Regex("[0-4]").matches(parts[0]) || !Regex("0|[1-9][0-9]{0,18}").matches(parts[1]))return null
        val available=parts[1].toLongOrNull()?:return null
        return InstallationBackupStorageObservation(scope,true,true,parts[0].toInt(),available,now())
    }
    suspend fun copy(dispatch:VerifiedWorkingDatabaseRestoreDispatch,current:VersionedOperationSnapshot,session:SshSessionHandle):WorkingDatabaseRestoreCopyResult{
        val s=current.snapshot;val t=s.target as? OperationTarget.InstallationTarget?:return WorkingDatabaseRestoreCopyResult.REJECTED
        if(!exact(dispatch.scope,session) || s.type!=OperationType.WORKING_DATABASE_RESTORE || s.operationId!=dispatch.scope.operationId ||
            t.serverId!=dispatch.scope.serverId || t.installationId!=dispatch.scope.installationId || t.serverAccessId!=dispatch.scope.serverAccessId ||
            s.status!=OperationStatus.RUNNING || s.checkpoint.semantics!=CheckpointSemantics.MUTATION_IN_FLIGHT ||
            s.checkpoint.phaseName!=dispatch.binding.phaseName(WorkingDatabaseRestorePhase.RESTORING) ||
            !dispatch.consumeOnce(current.revision,now()))return WorkingDatabaseRestoreCopyResult.REJECTED
        val identity=session.binding
        val result=execute(session,WorkingDatabaseRestoreCommands.command("write",dispatch.binding),"working-db-restore-once",64,145)
        if(!exact(dispatch.scope,session) || session.binding!=identity || result.dispatchState!=CommandDispatchState.DISPATCHED)return WorkingDatabaseRestoreCopyResult.UNCERTAIN
        if(text(result,64,allowRejected=true)=="NOT_STARTED\n" && (result.completion as? CommandCompletion.ConfirmedFailure)?.exitCode==81)return WorkingDatabaseRestoreCopyResult.NOT_STARTED
        return if(result.completion==CommandCompletion.ConfirmedSuccess && text(result,64)=="DATABASE_RESTORED\n")WorkingDatabaseRestoreCopyResult.FINISHED else WorkingDatabaseRestoreCopyResult.UNCERTAIN
    }
    suspend fun verify(scope:ManagementScope,b:WorkingDatabaseRestoreBinding,session:SshSessionHandle):WorkingDatabaseRestoreReceipt?{
        if(!exact(scope,session))return null;val identity=session.binding
        val raw=text(execute(session,WorkingDatabaseRestoreCommands.command("read",b),"working-db-readback-only",1024,145),1024)?:return null
        if(!exact(scope,session) || session.binding!=identity)return null
        return parse(scope,b,raw,now())
    }
    internal fun parse(scope:ManagementScope,b:WorkingDatabaseRestoreBinding,raw:String,at:Instant):WorkingDatabaseRestoreReceipt?{
        if(!raw.endsWith('\n'))return null;val rows=raw.dropLast(1).split('\n');if(rows.size!=9)return null
        val values=linkedMapOf<String,String>();for(row in rows){val parts=row.split('=');if(parts.size!=2 || values.put(parts[0],parts[1])!=null)return null}
        if(values.keys!=setOf("FORMAT","SCOPE","SOURCE_DB_SHA256","RESTORED_LOGICAL_SHA256","PREVIOUS_DB_SHA256","PREVIOUS_LOGICAL_SHA256","PREVIOUS_BYTES","SERVICE","STATE") ||
            values["FORMAT"]!="VELUM_WORKING_DB_V1" || values["SCOPE"]!=b.digest || values["SOURCE_DB_SHA256"]!=b.source.databaseSha256 ||
            values["SERVICE"]!="INACTIVE" || values["STATE"]!="VERIFIED")return null
        val size=values["PREVIOUS_BYTES"]?.takeIf{Regex("[1-9][0-9]{0,9}").matches(it)}?.toLongOrNull()?:return null
        return try{WorkingDatabaseRestoreReceipt(scope,b,values["RESTORED_LOGICAL_SHA256"]?:return null,values["PREVIOUS_DB_SHA256"]?:return null,
            values["PREVIOUS_LOGICAL_SHA256"]?:return null,size,at)}catch(_:IllegalArgumentException){null}
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
internal object WorkingDatabaseRestoreCommands{
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun command(mode:String,b:WorkingDatabaseRestoreBinding):String{
        require(mode in setOf("space","write","read"));val s=b.source;val seconds=if(mode=="space")10 else 140
        return "timeout --kill-after=2s ${seconds}s python3 -I -c "+quote(WorkingDatabaseRestoreWorker.source)+
            " $mode ${b.digest} ${b.endpointSha256} ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name}"+
            " ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount}"
    }
}

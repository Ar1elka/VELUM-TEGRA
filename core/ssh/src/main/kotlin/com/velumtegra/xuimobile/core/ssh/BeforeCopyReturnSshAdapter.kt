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
/** No service command. Read mode cannot reach the write entrypoint. */
class BeforeCopyReturnSshAdapter(private val now:()->Instant=Instant::now){
    suspend fun copy(d:VerifiedBeforeCopyReturnDispatch,c:VersionedOperationSnapshot,s:SshSessionHandle):Boolean{
        if(!exact(d.scope,s) || !d.consumeOnce(c,now()))return false
        val identity=s.binding;val raw=text(execute(s,BeforeCopyReturnCommands.command("write",d.binding),"before-db-return-once"),64)
        return exact(d.scope,s) && s.binding==identity && raw=="BEFORE_DATABASE_RETURNED\n"
    }
    suspend fun verify(scope:ManagementScope,b:BeforeCopyReturnBinding,s:SshSessionHandle):BeforeCopyReturnReceipt?{
        if(!exact(scope,s))return null;val identity=s.binding
        val raw=text(execute(s,BeforeCopyReturnCommands.command("read",b),"before-db-return-readback"),1024)?:return null
        if(!exact(scope,s) || s.binding!=identity)return null
        return parse(scope,b,raw,now())
    }
    internal fun parse(scope:ManagementScope,b:BeforeCopyReturnBinding,raw:String,at:Instant):BeforeCopyReturnReceipt?{
        if(raw.length>1024 || !raw.endsWith('\n'))return null
        val lines=raw.dropLast(1).split('\n');if(lines.size!=9)return null
        val values=linkedMapOf<String,String>();for(line in lines){val p=line.split('=');if(p.size!=2 || values.put(p[0],p[1])!=null)return null}
        if(values.keys!=setOf("FORMAT","SCOPE","RESTORE","BEFORE_SHA256","BEFORE_LOGICAL","DISPLACED_SHA256","DISPLACED_BYTES","SERVICE","STATE") ||
            values["FORMAT"]!="VELUM_BEFORE_RETURN_V1" || values["SCOPE"]!=b.digest || values["RESTORE"]!=b.original.digest || values["BEFORE_SHA256"]!=b.beforeDatabaseSha256 ||
            values["BEFORE_LOGICAL"]!=b.beforeLogicalSha256 || values["SERVICE"]!="INACTIVE" || values["STATE"]!="VERIFIED_STOPPED")return null
        val count=values["DISPLACED_BYTES"]?.takeIf{Regex("[1-9][0-9]{0,9}").matches(it)}?.toLongOrNull()?:return null
        return try{BeforeCopyReturnReceipt(scope,b,values.getValue("DISPLACED_SHA256"),count,at)}catch(_:IllegalArgumentException){null}
    }
    private fun exact(scope:ManagementScope,s:SshSessionHandle)=s.isOpen && s.binding.owner==SessionOwner.Operation(scope.operationId) && s.binding.serverAccessId==scope.serverAccessId
    private suspend fun execute(s:SshSessionHandle,command:String,label:String):SshCommandResult{
        currentCoroutineContext().ensureActive();val r=s.execute(RemoteCommand.create(command,label),SshTransportConfig(channelOpenTimeout=Duration.ofSeconds(5),commandExecutionTimeout=Duration.ofSeconds(145),stdoutCaptureLimitBytes=1024,stderrCaptureLimitBytes=512));currentCoroutineContext().ensureActive();return r
    }
    private fun text(r:SshCommandResult,limit:Int):String?{
        if(r.dispatchState!=CommandDispatchState.DISPATCHED || r.completion!=CommandCompletion.ConfirmedSuccess || r.stdout.truncated || r.stderr.truncated || r.stderr.sizeBytes!=0 || r.stdout.sizeBytes>limit)return null
        val bytes=r.stdout.copyBytes();return try{StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()}catch(_:Exception){null}finally{Arrays.fill(bytes,0)}
    }
}
internal object BeforeCopyReturnCommands{
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun command(mode:String,b:BeforeCopyReturnBinding):String{
        require(mode in setOf("write","read"));val o=b.original;val s=o.source
        return "timeout --kill-after=2s 140s python3 -I -c "+quote(BeforeCopyReturnWorker.source)+
            " $mode ${b.digest} ${b.beforeDatabaseSha256} ${b.beforeLogicalSha256} ${b.beforeBytes} ${o.digest} ${o.endpointSha256}"+
            " ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name} ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount}"
    }
}

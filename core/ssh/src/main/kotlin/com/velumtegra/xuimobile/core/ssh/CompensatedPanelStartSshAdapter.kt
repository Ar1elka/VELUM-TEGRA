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
/** One consumed service-start dispatch. Read mode cannot start or copy a database. */
class CompensatedPanelStartSshAdapter(private val now:()->Instant=Instant::now){
    suspend fun start(d:VerifiedCompensatedPanelStartDispatch,c:VersionedOperationSnapshot,s:SshSessionHandle):Boolean{
        if(!exact(d.scope,s) || !d.consumeOnce(c,now()))return false
        val identity=s.binding;val raw=text(execute(s,CompensatedPanelStartCommands.command("write",d.binding),"compensated-panel-start-once"),64)
        return exact(d.scope,s) && s.binding==identity && raw=="COMPENSATED_START_REQUESTED\n"
    }
    suspend fun verify(scope:ManagementScope,b:CompensatedPanelStartBinding,s:SshSessionHandle):CompensatedPanelStartReceipt?{
        if(!exact(scope,s))return null;val identity=s.binding
        val raw=text(execute(s,CompensatedPanelStartCommands.command("read",b),"compensated-panel-start-readback"),1024)?:return null
        if(!exact(scope,s) || s.binding!=identity)return null
        return parse(scope,b,raw,now())
    }
    internal fun parse(scope:ManagementScope,b:CompensatedPanelStartBinding,raw:String,at:Instant):CompensatedPanelStartReceipt?{
        if(raw.length>1024 || !raw.endsWith('\n'))return null
        val lines=raw.dropLast(1).split('\n');if(lines.size!=9)return null
        val values=linkedMapOf<String,String>();for(line in lines){val p=line.split('=');if(p.size!=2 || values.put(p[0],p[1])!=null)return null}
        val source=b.returned.original.source.source
        if(values.keys!=setOf("FORMAT","SCOPE","RETURN","VERSION","ARCH","SCHEMA","INBOUNDS","SERVICE","STATE") ||
            values["FORMAT"]!="VELUM_COMPENSATED_PANEL_START_V1" || values["SCOPE"]!=b.digest || values["RETURN"]!=b.returned.digest ||
            values["VERSION"]!=source.version || values["ARCH"]!=source.architecture.name || values["SERVICE"]!="ACTIVE" || values["STATE"]!="STRUCTURAL_READBACK")return null
        val count=values["INBOUNDS"]?.takeIf{Regex("0|[1-9][0-9]{0,2}").matches(it)}?.toIntOrNull()?:return null
        return try{CompensatedPanelStartReceipt(scope,b,values.getValue("SCHEMA"),count,at)}catch(_:IllegalArgumentException){null}
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
internal object CompensatedPanelStartCommands{
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun command(mode:String,b:CompensatedPanelStartBinding):String{
        require(mode in setOf("write","read"));val r=b.returned;val o=r.original;val s=o.source
        return "timeout --kill-after=2s 140s python3 -I -c "+quote(CompensatedPanelStartWorker.source)+
            " $mode ${b.digest} ${r.digest} ${r.beforeDatabaseSha256} ${r.beforeLogicalSha256} ${r.beforeBytes} ${o.digest} ${o.endpointSha256}"+
            " ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name} ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount}"
    }
}

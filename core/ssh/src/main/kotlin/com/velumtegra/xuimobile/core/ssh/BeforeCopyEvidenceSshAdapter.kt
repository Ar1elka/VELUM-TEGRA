package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import java.time.Duration
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Arrays
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

class BeforeCopyEvidenceSshAdapter(private val now:()->Instant=Instant::now){
    suspend fun read(scope:ManagementScope,b:WorkingDatabaseRestoreBinding,session:SshSessionHandle):BeforeCopyEvidence?{
        if(!exact(scope,session))return null
        val identity=session.binding
        currentCoroutineContext().ensureActive()
        val result=session.execute(RemoteCommand.create(BeforeCopyEvidenceCommands.command(b),"before-copy-evidence-read-only"),
            SshTransportConfig(channelOpenTimeout=Duration.ofSeconds(5),commandExecutionTimeout=Duration.ofSeconds(145),stdoutCaptureLimitBytes=2048,stderrCaptureLimitBytes=512))
        currentCoroutineContext().ensureActive()
        if(!exact(scope,session) || session.binding!=identity || result.dispatchState!=CommandDispatchState.DISPATCHED ||
            result.completion!=CommandCompletion.ConfirmedSuccess || result.stdout.truncated || result.stderr.truncated || result.stderr.sizeBytes!=0 || result.stdout.sizeBytes>2048)return null
        val bytes=result.stdout.copyBytes()
        return try{val raw=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();parse(scope,b,raw,now())}
        catch(_:Exception){null}finally{Arrays.fill(bytes,0)}
    }
    internal fun parse(scope:ManagementScope,b:WorkingDatabaseRestoreBinding,raw:String,at:Instant):BeforeCopyEvidence?{
        if(raw.length>2048 || !raw.endsWith("\n"))return null
        val rows=raw.dropLast(1).split('\n');if(rows.size!=10)return null
        val v=linkedMapOf<String,String>()
        for(row in rows){val pair=row.split('=');if(pair.size!=2 || v.put(pair[0],pair[1])!=null)return null}
        if(v.keys!=setOf("FORMAT","SCOPE","BEFORE_DB_SHA256","BEFORE_LOGICAL_SHA256","BEFORE_BYTES","SERVICE","CURRENT_DB","STRUCTURE","COPY_STATE","STATE") ||
            v["FORMAT"]!="VELUM_BEFORE_COPY_V1" || v["SCOPE"]!=b.digest || v["STATE"]!="OBSERVED")return null
        val count=v["BEFORE_BYTES"]?.takeIf{Regex("[1-9][0-9]{0,9}").matches(it)}?.toLongOrNull()?:return null
        return try{BeforeCopyEvidence(scope,b,v.getValue("BEFORE_DB_SHA256"),v.getValue("BEFORE_LOGICAL_SHA256"),count,
            BeforeCopyService.valueOf(v.getValue("SERVICE")),BeforeCopyCurrent.valueOf(v.getValue("CURRENT_DB")),BeforeCopyStructure.valueOf(v.getValue("STRUCTURE")),BeforeCopyCompletion.valueOf(v.getValue("COPY_STATE")),at)
            .takeIf{it.service!=BeforeCopyService.ACTIVE || it.current==BeforeCopyCurrent.UNAVAILABLE}}
        catch(_:IllegalArgumentException){null}
    }
    private fun exact(scope:ManagementScope,s:SshSessionHandle)=s.isOpen && s.binding.owner==SessionOwner.Operation(scope.operationId) && s.binding.serverAccessId==scope.serverAccessId
}
internal object BeforeCopyEvidenceCommands{
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun command(b:WorkingDatabaseRestoreBinding):String{
        val s=b.source
        return "timeout --kill-after=2s 140s python3 -I -c "+quote(BeforeCopyEvidenceWorker.source)+
            " space ${b.digest} ${b.endpointSha256} ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name}"+
            " ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount}"
    }
}

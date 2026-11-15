package com.velumtegra.xuimobile.core.ssh
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.domain.*
import java.time.Instant
import java.time.Duration
import java.util.UUID
import java.util.Arrays
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.charset.CodingErrorAction
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

class KnownFileRestoreSshAdapter(private val now:()->Instant=Instant::now,private val probe:ManagementSshProbeExecutor=ManagementSshProbeExecutor()){
    suspend fun prepare(scope:ManagementScope,b:KnownFileRestoreBinding,i:XuiInstallation,s:SshSessionHandle):KnownFileRestorePrepared?{
        val raw=execute(scope,b,i,s,KnownFileCommandMode.PLAN)?:return null
        return parsePrepared(scope,b,raw,now())
    }
    suspend fun inspect(scope:ManagementScope,b:KnownFileRestoreBinding,i:XuiInstallation,s:SshSessionHandle):KnownFileRestoreInspection?{
        val raw=execute(scope,b,i,s,KnownFileCommandMode.READ)?:return null
        return parseInspection(scope,b,raw,now())
    }
    suspend fun write(d:VerifiedKnownFileRestoreDispatch,c:VersionedOperationSnapshot,i:XuiInstallation,s:SshSessionHandle):Boolean{
        val mode=if(d.action==KnownFileRestoreWrite.APPLY)KnownFileCommandMode.APPLY else KnownFileCommandMode.RETURN
        val raw=execute(d.scope,d.binding,i,s,mode,d,c)?:return false
        return raw==if(d.action==KnownFileRestoreWrite.APPLY)"FILES_WRITTEN\n" else "FILES_RETURNED\n"
    }
    private suspend fun execute(scope:ManagementScope,b:KnownFileRestoreBinding,i:XuiInstallation,s:SshSessionHandle,mode:KnownFileCommandMode,
        dispatch:VerifiedKnownFileRestoreDispatch?=null,current:VersionedOperationSnapshot?=null):String?{
        if(!exact(scope,s) || i.id!=scope.installationId || i.serverId!=scope.serverId)return null
        val layout=i.identity
        if(layout.serviceUnit!="x-ui.service" || layout.binaryPath!="/usr/local/x-ui/x-ui" || layout.rootPath!="/usr/local/x-ui" || layout.databasePath!="/etc/x-ui/x-ui.db")return null
        val identity=s.binding
        suspend fun quick():ManagementLiveSnapshot?{
            val r=probe.executeQuickInspect(scope,i,s);currentCoroutineContext().ensureActive()
            if(!exact(scope,s) || s.binding!=identity)return null
            val e=(r as? ManagementSshProbeRunResult.Completed)?.evidence?:return null
            return ManagementReadbackPolicy.quickInspect(i,e,TargetProofId(UUID.randomUUID().toString()),now()).takeIf{
                it.identityStatus==ManagementIdentityStatus.Matched && it.baselineStatus==ManagementBaselineStatus.Matched && it.serviceState==ManagementServiceState.INACTIVE}
        }
        quick()?:return null
        val writing=mode in setOf(KnownFileCommandMode.APPLY,KnownFileCommandMode.RETURN)
        if(writing && (dispatch==null || current==null || dispatch.scope!=scope || dispatch.binding!=b || !dispatch.consumeOnce(current,now())))return null
        val command=KnownFileRestoreCommands.command(mode,b,dispatch?.beforeManifestSha256?:"0".repeat(64))
        val result=s.execute(RemoteCommand.create(command,"known-file-restore-"+mode.name.lowercase()),SshTransportConfig(channelOpenTimeout=Duration.ofSeconds(5),
            commandExecutionTimeout=Duration.ofSeconds(190),stdoutCaptureLimitBytes=2048,stderrCaptureLimitBytes=512))
        currentCoroutineContext().ensureActive()
        if(!exact(scope,s) || s.binding!=identity || result.dispatchState!=CommandDispatchState.DISPATCHED || result.completion!=CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stdout.sizeBytes>2048 || result.stderr.truncated || result.stderr.sizeBytes!=0)return null
        quick()?:return null
        val bytes=result.stdout.copyBytes()
        return try{StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()}
            catch(_:Exception){null}finally{Arrays.fill(bytes,0)}
    }
    private fun fields(raw:String,n:Int,scope:String,format:String):Map<String,String>?{
        if(raw.length>2048 || !raw.endsWith('\n'))return null
        val rows=raw.dropLast(1).split('\n');if(rows.size!=n)return null
        val v=linkedMapOf<String,String>();for(row in rows){val p=row.split('=');if(p.size!=2 || v.put(p[0],p[1])!=null)return null}
        return v.takeIf{it["FORMAT"]==format && it["SCOPE"]==scope}
    }
    internal fun parsePrepared(scope:ManagementScope,b:KnownFileRestoreBinding,raw:String,at:Instant):KnownFileRestorePrepared?{
        val v=fields(raw,4,b.digest,"VELUM_KNOWN_FILE_PREPARED_V1")?:return null
        if(v.keys!=setOf("FORMAT","SCOPE","DATABASE_LOGICAL","CHANGED") || v["CHANGED"]!=b.changedFiles.toString())return null
        return try{KnownFileRestorePrepared(scope,b,v.getValue("DATABASE_LOGICAL"),at)}catch(_:IllegalArgumentException){null}
    }
    internal fun parseInspection(scope:ManagementScope,b:KnownFileRestoreBinding,raw:String,at:Instant):KnownFileRestoreInspection?{
        val v=fields(raw,7,b.digest,"VELUM_KNOWN_FILE_READ_V1")?:return null
        if(v.keys!=setOf("FORMAT","SCOPE","MANIFEST","DATABASE_LOGICAL","DESIRED","PREVIOUS","FILES") || v["FILES"]!=b.changedFiles.toString())return null
        fun count(k:String)=v[k]?.takeIf{Regex("0|[1-9][0-9]?").matches(it)}?.toIntOrNull()
        return try{KnownFileRestoreInspection(scope,b,v.getValue("MANIFEST"),v.getValue("DATABASE_LOGICAL"),count("DESIRED")?:return null,count("PREVIOUS")?:return null,at)}catch(_:IllegalArgumentException){null}
    }
    private fun exact(scope:ManagementScope,s:SshSessionHandle)=s.isOpen && s.binding.owner==SessionOwner.Operation(scope.operationId) && s.binding.serverAccessId==scope.serverAccessId
}
internal enum class KnownFileCommandMode { PLAN, APPLY, READ, RETURN }
internal object KnownFileRestoreCommands{
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun command(mode:KnownFileCommandMode,b:KnownFileRestoreBinding,manifest:String="0".repeat(64)):String{
        require(Regex("[0-9a-f]{64}").matches(manifest));val s=b.comparison.source
        return "timeout --kill-after=2s 180s python3 -I -c "+quote(KnownFileRestoreWorker.source)+
            " ${mode.name.lowercase()} ${b.digest} ${b.currentSetSha256} ${b.changedFiles} ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name}"+
            " ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount} $manifest"
    }
}

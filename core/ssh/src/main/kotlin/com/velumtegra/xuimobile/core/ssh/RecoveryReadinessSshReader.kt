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

class RecoveryReadinessSshReader(private val now:()->Instant=Instant::now,private val probe:ManagementSshProbeExecutor=ManagementSshProbeExecutor()){
    suspend fun read(scope:ManagementScope,b:RestoreCompatibilityBinding,revision:Long,installation:XuiInstallation,session:SshSessionHandle):RecoveryReadinessEvidence?{
        if(revision<0 || !exact(scope,session) || installation.id!=scope.installationId || installation.serverId!=scope.serverId)return null
        val i=installation.identity
        if(i.serviceUnit!="x-ui.service" || i.binaryPath!="/usr/local/x-ui/x-ui" || i.rootPath!="/usr/local/x-ui" || i.databasePath!="/etc/x-ui/x-ui.db")return null
        val identity=session.binding
        suspend fun quick():ManagementLiveSnapshot?{
            val r=probe.executeQuickInspect(scope,installation,session)
            currentCoroutineContext().ensureActive()
            if(!exact(scope,session) || session.binding!=identity)return null
            val e=(r as? ManagementSshProbeRunResult.Completed)?.evidence?:return null
            return ManagementReadbackPolicy.quickInspect(installation,e,TargetProofId(UUID.randomUUID().toString()),now())
                .takeIf{it.identityStatus==ManagementIdentityStatus.Matched && it.baselineStatus==ManagementBaselineStatus.Matched}
        }
        val before=quick()?:return null
        val result=session.execute(RemoteCommand.create(RecoveryReadinessCommands.read(b,revision),"recovery-readiness-read-only"),
            SshTransportConfig(channelOpenTimeout=Duration.ofSeconds(5),commandExecutionTimeout=Duration.ofSeconds(145),stdoutCaptureLimitBytes=4096,stderrCaptureLimitBytes=512))
        currentCoroutineContext().ensureActive()
        if(!exact(scope,session) || session.binding!=identity || result.dispatchState!=CommandDispatchState.DISPATCHED ||
            result.completion!=CommandCompletion.ConfirmedSuccess || result.stdout.truncated || result.stdout.sizeBytes>4096 || result.stderr.truncated || result.stderr.sizeBytes!=0)return null
        val after=quick()?:return null
        if(after.serviceState!=before.serviceState || after.baselineStatus!=before.baselineStatus)return null
        val bytes=result.stdout.copyBytes()
        val raw=try{StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()}
            catch(_:Exception){return null}finally{Arrays.fill(bytes,0)}
        val proof=parse(scope,b,revision,raw,now())?:return null
        if(proof.quiescence==RecoveryQuiescence.STOPPED && after.serviceState!=ManagementServiceState.INACTIVE ||
            proof.quiescence==RecoveryQuiescence.REQUIRED && after.serviceState!=ManagementServiceState.ACTIVE)return null
        return proof
    }
    internal fun parse(scope:ManagementScope,b:RestoreCompatibilityBinding,revision:Long,raw:String,at:Instant):RecoveryReadinessEvidence?{
        if(raw.length>4096 || !raw.endsWith('\n') || revision<0)return null
        val rows=raw.dropLast(1).split('\n');if(rows.size!=25)return null
        val v=linkedMapOf<String,String>();for(row in rows){val p=row.split('=');if(p.size!=2 || v.put(p[0],p[1])!=null)return null}
        val groups=RecoveryFileGroup.values()
        if(v.keys!=setOf("FORMAT","SCOPE","REVISION","ARCHIVE","DATABASE","INVENTORY","CURRENT_VERSION","CURRENT_ARCH","SOURCE_SCHEMA","CURRENT_SCHEMA",
            "TOTAL","SOURCE_BYTES","CURRENT_BYTES","ENDPOINT","PAGE_SIZE","JOURNAL","WAL","QUIESCENCE","CURRENT_SET","MIGRATION")+groups.map{it.name} ||
            v["FORMAT"]!="VELUM_RECOVERY_READINESS_V1" || v["SCOPE"]!=b.digest || v["REVISION"]!=revision.toString() || v["ARCHIVE"]!=b.source.archiveSha256 ||
            v["DATABASE"]!=b.source.databaseSha256 || v["INVENTORY"]!=b.source.inventorySha256 || v["MIGRATION"]!="UNVERIFIED")return null
        fun number(value:String?):Long?=value?.takeIf{Regex("0|[1-9][0-9]{0,9}").matches(it)}?.toLongOrNull()
        fun difference(key:String):RecoveryGroupDifference?{
            val p=v[key]?.split(',')?:return null;if(p.size!=5)return null
            val n=p.map{number(it)?.takeIf{it<=96}?.toInt()?:return null}
            return try{RecoveryGroupDifference(n[0],n[1],n[2],n[3],n[4])}catch(_:IllegalArgumentException){null}
        }
        fun match(key:String):Boolean?=when(v[key]){"MATCH"->true;"DIFFERENT"->false;else->null}
        val total=difference("TOTAL")?:return null;val grouped=groups.associateWith{difference(it.name)?:return null}
        return try{RecoveryReadinessEvidence(scope,b,revision,v.getValue("CURRENT_VERSION"),UpdateServerArchitecture.valueOf(v.getValue("CURRENT_ARCH")),
            v.getValue("SOURCE_SCHEMA"),v.getValue("CURRENT_SCHEMA"),grouped,total.sourceFiles,total.currentFiles,total.changedCommon,total.added,total.missing,
            number(v["SOURCE_BYTES"])?:return null,number(v["CURRENT_BYTES"])?:return null,match("ENDPOINT")?:return null,match("PAGE_SIZE")?:return null,
            RecoveryJournalMode.valueOf(v.getValue("JOURNAL")),RecoveryWalPresence.valueOf(v.getValue("WAL")),RecoveryQuiescence.valueOf(v.getValue("QUIESCENCE")),
            v.getValue("CURRENT_SET"),at)}catch(_:IllegalArgumentException){null}
    }
    private fun exact(scope:ManagementScope,s:SshSessionHandle)=s.isOpen && s.binding.owner==SessionOwner.Operation(scope.operationId) && s.binding.serverAccessId==scope.serverAccessId
}
internal object RecoveryReadinessCommands{
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun read(b:RestoreCompatibilityBinding,revision:Long):String{
        require(revision>=0);val s=b.source
        return "timeout --kill-after=2s 140s python3 -I -c "+quote(RecoveryReadinessWorker.source)+
            " ${b.digest} $revision ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name}"+
            " ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount}"
    }
}

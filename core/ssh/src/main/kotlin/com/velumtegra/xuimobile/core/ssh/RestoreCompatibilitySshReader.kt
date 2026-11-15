package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import java.util.Arrays
import java.util.UUID
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

class RestoreCompatibilitySshReader(private val now: () -> Instant = Instant::now,
    private val management: ManagementSshProbeExecutor = ManagementSshProbeExecutor()) {
    suspend fun read(scope: ManagementScope, b: RestoreCompatibilityBinding, installation: XuiInstallation,
        session: SshSessionHandle): RestoreCompatibilityReport? {
        if(!exact(scope,session) || installation.id!=scope.installationId || installation.serverId!=scope.serverId)return null
        val before=session.binding
        val result=management.executeQuickInspect(scope,installation,session)
        currentCoroutineContext().ensureActive()
        if(!exact(scope,session) || session.binding!=before)return null
        val evidence=(result as? ManagementSshProbeRunResult.Completed)?.evidence?:return null
        val facts=ManagementReadbackPolicy.quickInspect(installation,evidence,TargetProofId(UUID.randomUUID().toString()),now())
        if(facts.identityStatus!=ManagementIdentityStatus.Matched)return null
        val i=installation.identity
        if(i.serviceUnit!="x-ui.service" || i.binaryPath!="/usr/local/x-ui/x-ui" || i.rootPath!="/usr/local/x-ui" || i.databasePath!="/etc/x-ui/x-ui.db")return null
        val raw=session.execute(RemoteCommand.create(RestoreCompatibilityCommands.read(b),"restore-compatibility-read"),
            SshTransportConfig(channelOpenTimeout=Duration.ofSeconds(5),commandExecutionTimeout=Duration.ofSeconds(125),
                stdoutCaptureLimitBytes=2048,stderrCaptureLimitBytes=512))
        currentCoroutineContext().ensureActive()
        if(!exact(scope,session) || session.binding!=before)return null
        val afterResult=management.executeQuickInspect(scope,installation,session)
        currentCoroutineContext().ensureActive()
        if(!exact(scope,session) || session.binding!=before)return null
        val afterEvidence=(afterResult as? ManagementSshProbeRunResult.Completed)?.evidence?:return null
        val afterFacts=ManagementReadbackPolicy.quickInspect(installation,afterEvidence,TargetProofId(UUID.randomUUID().toString()),now())
        if(afterFacts.identityStatus!=ManagementIdentityStatus.Matched || afterFacts.serviceState!=facts.serviceState ||
            afterFacts.baselineStatus!=facts.baselineStatus)return null
        return parse(scope,b,raw,afterFacts,now())
    }
    internal fun parse(scope: ManagementScope,b: RestoreCompatibilityBinding,result: SshCommandResult,
        facts: ManagementLiveSnapshot,at: Instant): RestoreCompatibilityReport? {
        if(facts.scope!=scope || facts.identityStatus!=ManagementIdentityStatus.Matched || facts.observedAt.isAfter(at) ||
            result.dispatchState!=CommandDispatchState.DISPATCHED || result.completion!=CommandCompletion.ConfirmedSuccess ||
            result.stdout.truncated || result.stdout.sizeBytes>2048 || result.stderr.truncated || result.stderr.sizeBytes!=0)return null
        val bytes=result.stdout.copyBytes()
        val raw=try { StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString() }
            catch(_:Exception){return null} finally {Arrays.fill(bytes,0)}
        if(!raw.endsWith('\n'))return null
        val values=linkedMapOf<String,String>();val lines=raw.dropLast(1).split('\n');if(lines.size!=14)return null
        for(line in lines){val p=line.split('=');if(p.size!=2 || values.put(p[0],p[1])!=null)return null}
        if(values.keys!=setOf("FORMAT","SCOPE","SOURCE_RESTORE","SOURCE_ARCHIVE","SOURCE_DB","SOURCE_INVENTORY",
            "CURRENT_VERSION","CURRENT_ARCH","SOURCE_SCHEMA","CURRENT_SCHEMA","FILE_SET","CHANGED_FILES","SOURCE_INBOUNDS","CURRENT_INBOUNDS") ||
            values["FORMAT"]!="VELUM_RESTORE_COMPARISON_V1" || values["SCOPE"]!=b.digest || values["SOURCE_RESTORE"]!=b.source.digest ||
            values["SOURCE_ARCHIVE"]!=b.source.archiveSha256 || values["SOURCE_DB"]!=b.source.databaseSha256 || values["SOURCE_INVENTORY"]!=b.source.inventorySha256)return null
        fun hash(k:String)=values[k]?.takeIf{Regex("[0-9a-f]{64}").matches(it)}
        fun count(k:String,max:Int):Int?=values[k]?.takeIf{Regex("0|[1-9][0-9]{0,2}").matches(it)}?.toIntOrNull()?.takeIf{it in 0..max}
        val sourceHash=hash("SOURCE_SCHEMA")?:return null
        val targetHash=if(values["CURRENT_SCHEMA"]=="-")null else hash("CURRENT_SCHEMA")?:return null
        val sourceCount=count("SOURCE_INBOUNDS",256)?:return null
        val targetCount=if(values["CURRENT_INBOUNDS"]=="-")null else count("CURRENT_INBOUNDS",256)?:return null
        val changed=if(values["CHANGED_FILES"]=="-")null else count("CHANGED_FILES",RecoveryFileInventory.MAX_FILES)?:return null
        val fileSet=RestoreFileSetComparison.values().singleOrNull{it.name==values["FILE_SET"]}?:return null
        val arch=UpdateServerArchitecture.values().singleOrNull{it.name==values["CURRENT_ARCH"]}?:return null
        return try {RestoreCompatibilityReport(scope,b,values["CURRENT_VERSION"]?:return null,arch,sourceHash,targetHash,fileSet,
            changed,sourceCount,targetCount,facts.serviceState,facts.baselineStatus,at)}catch(_:IllegalArgumentException){null}
    }
    private fun exact(scope:ManagementScope,s:SshSessionHandle)=s.isOpen && s.binding.owner==SessionOwner.Operation(scope.operationId) && s.binding.serverAccessId==scope.serverAccessId
}
internal object RestoreCompatibilityCommands {
    private fun quote(s:String)="'"+s.replace("'","'\"'\"'")+"'"
    fun read(b:RestoreCompatibilityBinding):String {
        val s=b.source
        return "timeout --kill-after=2s 120s python3 -I -c "+quote(RestoreCompatibilityWorker.source)+
            " ${b.digest} ${s.digest} ${s.source.digest} ${s.source.version} ${s.source.architecture.name}"+
            " ${s.archiveSha256} ${s.databaseSha256} ${s.inventorySha256} ${s.archiveBytes} ${s.fileCount}"
    }
}

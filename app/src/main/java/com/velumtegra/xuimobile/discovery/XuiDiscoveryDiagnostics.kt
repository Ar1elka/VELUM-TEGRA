package com.velumtegra.xuimobile.discovery
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*

enum class XuiDiagnosticStage { COMPLETE, PARTIAL }
enum class XuiDiagnosticClass { SUPPORTED_CANDIDATE, NO_SUPPORTED_INSTALLATION, UNSUPPORTED_PLATFORM, FOREIGN_PANEL, AMBIGUOUS, INSUFFICIENT, PARTIAL }
enum class XuiDiagnosticPlatform { UBUNTU, DEBIAN, OTHER, NONE, CONFLICT }
enum class XuiDiagnosticError { NONE, SESSION_BINDING, SESSION_CLOSED, PROBE_POLICY, DISPATCH_UNCERTAIN, REMOTE_EXIT, TRUNCATED, MALFORMED }
/** Finite transient facts only. Missing mask bits are UNKNOWN on a partial plan, never inferred absence. */
data class XuiDiscoveryDiagnostics(val stage:XuiDiagnosticStage,val classification:XuiDiagnosticClass,val platform:XuiDiagnosticPlatform,
    val failedProbeIndex:Int,val error:XuiDiagnosticError,val exitCode:Int,val observationCount:Int,val conflictMask:Int,val gapMask:Int,
    val servicePresent:Int,val serviceAbsent:Int,val binaryPresent:Int,val binaryAbsent:Int,val rootPresent:Int,val rootAbsent:Int,val databasePresent:Int,val databaseAbsent:Int,val foreignPanel:Boolean){
    init{require(failedProbeIndex in -1 until DiscoveryProbePlan.initialProbes.size && exitCode in -1..255 && observationCount in 0..32)
        require(conflictMask in 0..31 && gapMask in 0..15 && servicePresent in 0..1 && serviceAbsent in 0..1 && binaryPresent in 0..15 && binaryAbsent in 0..15 && rootPresent in 0..3 && rootAbsent in 0..3 && databasePresent in 0..31 && databaseAbsent in 0..31)
        require((stage==XuiDiagnosticStage.COMPLETE)==(error==XuiDiagnosticError.NONE));require(stage!=XuiDiagnosticStage.PARTIAL || classification==XuiDiagnosticClass.PARTIAL)}
    fun summary()="stage=${stage.name};class=${classification.name};os=${platform.name};probe=$failedProbeIndex;error=${error.name};exit=$exitCode;observed=$observationCount;conflict=$conflictMask;gap=$gapMask;service=$servicePresent/$serviceAbsent;binary=$binaryPresent/$binaryAbsent;root=$rootPresent/$rootAbsent;database=$databasePresent/$databaseAbsent;foreign=$foreignPanel"
}
internal object XuiDiscoveryDiagnosticsProjector{
    fun completed(e:DiscoveryEvidence):XuiDiscoveryDiagnostics{
        val c=DiscoveryClassifier.classify(e)
        val code=when(c){is DiscoveryClassification.SupportedCandidate->XuiDiagnosticClass.SUPPORTED_CANDIDATE;DiscoveryClassification.NoSupportedInstallation->XuiDiagnosticClass.NO_SUPPORTED_INSTALLATION;is DiscoveryClassification.UnsupportedPlatform->XuiDiagnosticClass.UNSUPPORTED_PLATFORM;DiscoveryClassification.ForeignPanel->XuiDiagnosticClass.FOREIGN_PANEL;is DiscoveryClassification.Ambiguous->XuiDiagnosticClass.AMBIGUOUS;is DiscoveryClassification.InsufficientEvidence->XuiDiagnosticClass.INSUFFICIENT}
        val conflict=(c as? DiscoveryClassification.Ambiguous)?.conflicts?.fold(0){m,v->m or (1 shl v.ordinal)}?:0
        val gap=(c as? DiscoveryClassification.InsufficientEvidence)?.gaps?.fold(0){m,v->m or (1 shl v.ordinal)}?:0
        return project(e.observations,XuiDiagnosticStage.COMPLETE,code,-1,XuiDiagnosticError.NONE,-1,conflict,gap)
    }
    fun failed(r:DiscoverySshProbeRunResult.Failed):XuiDiscoveryDiagnostics{
        val error=when(r.failure){DiscoverySshProbeExecutionFailure.ExactSessionBindingMismatch->XuiDiagnosticError.SESSION_BINDING;DiscoverySshProbeExecutionFailure.SessionClosed->XuiDiagnosticError.SESSION_CLOSED;DiscoverySshProbeExecutionFailure.ProbeOutsideApprovedPolicy->XuiDiagnosticError.PROBE_POLICY;is DiscoverySshProbeExecutionFailure.CommandUncertain->XuiDiagnosticError.DISPATCH_UNCERTAIN;is DiscoverySshProbeExecutionFailure.CommandFailed->XuiDiagnosticError.REMOTE_EXIT;DiscoverySshProbeExecutionFailure.OutputTruncated->XuiDiagnosticError.TRUNCATED;DiscoverySshProbeExecutionFailure.MalformedProbeEvidence->XuiDiagnosticError.MALFORMED}
        val exit=(r.failure as? DiscoverySshProbeExecutionFailure.CommandFailed)?.exitCode?.takeIf{it in 0..255}?:-1
        val index=r.failedProbe?.let{DiscoveryProbePlan.initialProbes.indexOf(it)}?:-1
        return project(r.observations,XuiDiagnosticStage.PARTIAL,XuiDiagnosticClass.PARTIAL,index,error,exit,0,0)
    }
    private fun project(o:List<DiscoveryObservation>,stage:XuiDiagnosticStage,code:XuiDiagnosticClass,index:Int,error:XuiDiagnosticError,exit:Int,conflict:Int,gap:Int):XuiDiscoveryDiagnostics{
        require(o.size<=32)
        val platforms=o.filterIsInstance<DiscoveryObservation.Platform>().map{it.platform.distributionId}.distinct()
        val os=if(platforms.size>1)XuiDiagnosticPlatform.CONFLICT else when(platforms.singleOrNull()){null->XuiDiagnosticPlatform.NONE;"ubuntu"->XuiDiagnosticPlatform.UBUNTU;"debian"->XuiDiagnosticPlatform.DEBIAN;else->XuiDiagnosticPlatform.OTHER}
        fun paths(kind:DiscoveryPathKind,approved:Set<String>,presence:DiscoveryPresence):Int=approved.withIndex().fold(0){m,v->if(o.filterIsInstance<DiscoveryObservation.InstallationPath>().any{it.pathKind==kind && it.path==v.value && it.presence==presence})m or (1 shl v.index)else m}
        fun services(p:DiscoveryPresence)=if(o.filterIsInstance<DiscoveryObservation.ServiceUnit>().any{it.serviceUnit=="x-ui.service" && it.presence==p})1 else 0
        return XuiDiscoveryDiagnostics(stage,code,os,index,error,exit,o.size,conflict,gap,services(DiscoveryPresence.PRESENT),services(DiscoveryPresence.ABSENT),paths(DiscoveryPathKind.BINARY,DiscoveryProbePlan.supportedBinaryProbePaths,DiscoveryPresence.PRESENT),paths(DiscoveryPathKind.BINARY,DiscoveryProbePlan.supportedBinaryProbePaths,DiscoveryPresence.ABSENT),paths(DiscoveryPathKind.ROOT,DiscoveryProbePlan.supportedRootProbePaths,DiscoveryPresence.PRESENT),paths(DiscoveryPathKind.ROOT,DiscoveryProbePlan.supportedRootProbePaths,DiscoveryPresence.ABSENT),paths(DiscoveryPathKind.DATABASE,DiscoveryProbePlan.supportedDatabaseProbePaths,DiscoveryPresence.PRESENT),paths(DiscoveryPathKind.DATABASE,DiscoveryProbePlan.supportedDatabaseProbePaths,DiscoveryPresence.ABSENT),o.filterIsInstance<DiscoveryObservation.PanelFamily>().any{it.family==DiscoveryPanelFamily.FOREIGN_PANEL})
    }
}

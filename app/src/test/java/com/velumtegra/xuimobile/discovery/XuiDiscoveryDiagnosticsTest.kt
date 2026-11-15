package com.velumtegra.xuimobile.discovery
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class XuiDiscoveryDiagnosticsTest{
    private val at=Instant.EPOCH
    private val scope=DiscoveryScope(OperationId("diag"),ServerId("server"),ServerAccessId("access"))
    private fun platform(id:String="ubuntu")=DiscoveryObservation.Platform(DiscoveryPlatform(id,"24.04"),at)
    private fun path(k:DiscoveryPathKind,p:String,present:Boolean=true)=DiscoveryObservation.InstallationPath(k,p,if(present)DiscoveryPresence.PRESENT else DiscoveryPresence.ABSENT,at)
    private fun complete(o:List<DiscoveryObservation>)=XuiDiscoveryDiagnosticsProjector.completed(DiscoveryEvidence(scope,o))
    private fun failed(o:List<DiscoveryObservation>,f:DiscoverySshProbeExecutionFailure=DiscoverySshProbeExecutionFailure.MalformedProbeEvidence,p:DiscoveryProbeSpec?=DiscoveryProbeSpec.ServiceUnitPresence("x-ui.service"))=XuiDiscoveryDiagnosticsProjector.failed(DiscoverySshProbeRunResult.Failed(scope,p,f,o))
    @Test fun completeSupportedCandidateRemainsDistinctFromProof(){val p=complete(listOf(platform(),DiscoveryObservation.ServiceUnit("x-ui.service",DiscoveryPresence.PRESENT,at),path(DiscoveryPathKind.BINARY,"/usr/local/x-ui/x-ui"),path(DiscoveryPathKind.ROOT,"/usr/local/x-ui"),path(DiscoveryPathKind.DATABASE,"/etc/x-ui/x-ui.db")));assertEquals(XuiDiagnosticClass.SUPPORTED_CANDIDATE,p.classification);assertEquals(1,p.binaryPresent);assertEquals(1,p.rootPresent);assertEquals(1,p.databasePresent);assertEquals(0,p.conflictMask)}
    @Test fun observedLauncherRemainsVisibleWithoutCreatingSecondInstallation(){val p=complete(listOf(platform(),path(DiscoveryPathKind.BINARY,"/usr/local/x-ui/x-ui"),path(DiscoveryPathKind.BINARY,"/usr/bin/x-ui")));assertEquals(XuiDiagnosticClass.SUPPORTED_CANDIDATE,p.classification);assertEquals(3,p.binaryPresent);assertEquals(0,p.conflictMask)}
    @Test fun partialPlatformReadCannotInventPanelAbsence(){val p=failed(listOf(platform()));assertEquals(XuiDiagnosticStage.PARTIAL,p.stage);assertEquals(XuiDiagnosticClass.PARTIAL,p.classification);assertEquals(1,p.failedProbeIndex);assertEquals(0,p.binaryPresent);assertEquals(0,p.binaryAbsent);assertEquals(XuiDiagnosticError.MALFORMED,p.error)}
    @Test fun explicitAbsenceAndUnknownAreDifferentMasks(){val p=failed(listOf(platform(),path(DiscoveryPathKind.BINARY,"/usr/bin/x-ui",false)));assertEquals(2,p.binaryAbsent);assertEquals(0,p.binaryPresent)}
    @Test fun unsupportedPlatformIsReportedAsSuch(){val p=complete(listOf(platform("alpine")));assertEquals(XuiDiagnosticClass.UNSUPPORTED_PLATFORM,p.classification);assertEquals(XuiDiagnosticPlatform.OTHER,p.platform)}
    @Test fun remoteFailureExitAndUnknownExitAreFinite(){assertEquals(2,failed(emptyList(),DiscoverySshProbeExecutionFailure.CommandFailed(2)).exitCode);assertEquals(-1,failed(emptyList(),DiscoverySshProbeExecutionFailure.CommandFailed(null)).exitCode);assertEquals(-1,failed(emptyList(),DiscoverySshProbeExecutionFailure.CommandFailed(999)).exitCode)}
    @Test fun foreignOrMissingProbeIndexCannotExposeArbitraryPath(){val p=failed(listOf(platform()),p=DiscoveryProbeSpec.InstallationPathPresence(DiscoveryPathKind.DATABASE,"/root/private-not-in-probe-plan"));assertEquals(-1,p.failedProbeIndex);assertFalse(p.summary().contains("/root"))}
    @Test fun pathsOutsideAllowListDoNotEnterDiagnostic(){val p=complete(listOf(platform(),path(DiscoveryPathKind.DATABASE,"/root/private.db")));assertEquals(0,p.databasePresent);assertFalse(p.summary().contains("private"));assertFalse(p.summary().contains("/"+"root"))}
    @Test fun contradictoryPresenceRetainsBothBitsAndConflict(){val p=complete(listOf(platform(),path(DiscoveryPathKind.BINARY,"/usr/local/x-ui/x-ui"),path(DiscoveryPathKind.BINARY,"/usr/local/x-ui/x-ui",false)));assertEquals(1,p.binaryPresent);assertEquals(1,p.binaryAbsent);assertEquals(XuiDiagnosticClass.AMBIGUOUS,p.classification)}
    @Test fun legacyObservationKeepsNoDiagnosticByDefault(){assertNull(XuiReadOnlyDiscoveryResult.Observation("label","detail").diagnostics)}
    @Test fun oversizedObservationSetFailsClosed(){assertTrue(runCatching{complete(List(33){platform()})}.isFailure)}
}

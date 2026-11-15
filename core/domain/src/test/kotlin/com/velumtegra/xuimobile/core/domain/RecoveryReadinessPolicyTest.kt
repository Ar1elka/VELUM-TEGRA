package com.velumtegra.xuimobile.core.domain
import com.velumtegra.xuimobile.core.model.*
import java.time.Instant
import org.junit.Assert.*
import org.junit.Test
class RecoveryReadinessPolicyTest {

    private val at=Instant.parse("2026-10-21T17:00:00Z")
    private val scope=ManagementScope(OperationId("compare"),ServerId("server"),ServerAccessId("ssh"),XuiInstallationId("install"))
    private val source=RestoreCheckBinding(OperationId("backup"),2,InstallationBackupBinding("3.10.0",UpdateServerArchitecture.AMD64,"a".repeat(64)),"e".repeat(64),"b".repeat(64),"c".repeat(64),"d".repeat(64),4096,3)
    private val binding=RestoreCompatibilityBinding(OperationId("check"),3,source,"f".repeat(64))
    private fun groups()=RecoveryFileGroup.values().associateWith{when(it){RecoveryFileGroup.RUNTIME->RecoveryGroupDifference(2,2,0,0,0);RecoveryFileGroup.SERVICE->RecoveryGroupDifference(1,1,0,0,0);else->RecoveryGroupDifference(0,0,0,0,0)}}
    private fun evidence()=RecoveryReadinessEvidence(scope,binding,4,"3.10.0",UpdateServerArchitecture.AMD64,"1".repeat(64),"1".repeat(64),groups(),3,3,0,0,0,1024,1024,true,true,RecoveryJournalMode.WAL,RecoveryWalPresence.PRESENT,RecoveryQuiescence.STOPPED,"2".repeat(64),at)

    private fun blocks(p:RecoveryReadinessEvidence)=RecoveryReadinessPolicy.blockers(p)
    @Test fun matchingStructureStillHasMigrationAndWriterBlockers(){assertEquals(setOf(RecoveryReadinessBlocker.MIGRATION_UNVERIFIED,RecoveryReadinessBlocker.FILE_WRITE_PROTOCOL_UNVERIFIED),blocks(evidence()))}
    @Test fun numericReleaseDifferenceCannotBeCalledUpgradeCompatibility(){assertTrue(RecoveryReadinessBlocker.VERSION in blocks(evidence().copy(currentVersion="3.10.1")))}
    @Test fun architectureDifferenceBlocks(){assertTrue(RecoveryReadinessBlocker.ARCHITECTURE in blocks(evidence().copy(currentArchitecture=UpdateServerArchitecture.ARM64)))}
    @Test fun literalSchemaDifferenceBlocks(){assertTrue(RecoveryReadinessBlocker.DATABASE_SCHEMA in blocks(evidence().copy(currentSchema="3".repeat(64))))}
    @Test fun endpointDifferenceBlocks(){assertTrue(RecoveryReadinessBlocker.ENDPOINT in blocks(evidence().copy(endpointsMatch=false)))}
    @Test fun pageSizeDifferenceBlocks(){assertTrue(RecoveryReadinessBlocker.PAGE_SIZE in blocks(evidence().copy(pageSizesMatch=false)))}
    @Test fun roleMembershipDriftBlocksEvenWhenUniquePathsMatch(){val g=groups()+(RecoveryFileGroup.RUNTIME to RecoveryGroupDifference(2,2,0,1,1));assertTrue(RecoveryReadinessBlocker.FILE_MEMBERSHIP in blocks(evidence().copy(groups=g)))}
    @Test fun changedKnownBytesRemainSeparateFromMembership(){val g=groups()+(RecoveryFileGroup.RUNTIME to RecoveryGroupDifference(2,2,1,0,0));val p=evidence().copy(groups=g,changedCommon=1);assertFalse(RecoveryReadinessBlocker.FILE_MEMBERSHIP in blocks(p));assertTrue(RecoveryReadinessBlocker.FILE_WRITE_PROTOCOL_UNVERIFIED in blocks(p))}
    @Test fun liveServiceRequiresSeparateStop(){assertTrue(RecoveryReadinessBlocker.SERVICE_RUNNING in blocks(evidence().copy(quiescence=RecoveryQuiescence.REQUIRED)))}
    @Test fun unknownJobOrProcessStateCannotBecomeStopped(){assertTrue(RecoveryReadinessBlocker.SERVICE_UNVERIFIED in blocks(evidence().copy(quiescence=RecoveryQuiescence.UNAVAILABLE)))}
    @Test fun freshnessHasExactNinetySecondBoundary(){val p=evidence();assertTrue(RecoveryReadinessPolicy.fresh(p,at));assertTrue(RecoveryReadinessPolicy.fresh(p,at.plusSeconds(89)));assertFalse(RecoveryReadinessPolicy.fresh(p,at.plusSeconds(90)));assertFalse(RecoveryReadinessPolicy.fresh(p,at.minusSeconds(1)))}
    @Test fun groupCountsCannotInventNegativeCommonMembership(){assertTrue(runCatching{RecoveryGroupDifference(2,2,0,3,3)}.isFailure)}
    @Test fun byteChangeCountCannotExceedCommonFiles(){assertTrue(runCatching{RecoveryGroupDifference(2,2,2,1,1)}.isFailure)}
    @Test fun missingGroupCannotBeInterpretedAsZero(){assertTrue(runCatching{evidence().copy(groups=groups()-RecoveryFileGroup.XRAY_DATA)}.isFailure)}
    @Test fun malformedHashesAndOversizeSourcesReject(){assertTrue(runCatching{evidence().copy(currentSetSha256="private path")}.isFailure);assertTrue(runCatching{evidence().copy(sourceBytes=536870913)}.isFailure)}
    @Test fun sourceCountMustMatchExactVerifiedArchive(){assertTrue(runCatching{evidence().copy(sourceFiles=4,currentFiles=4,groups=groups()+(RecoveryFileGroup.RUNTIME to RecoveryGroupDifference(3,3,0,0,0)))}.isFailure)}
}

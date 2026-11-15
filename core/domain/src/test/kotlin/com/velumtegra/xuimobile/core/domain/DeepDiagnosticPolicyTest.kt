package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.DeepDiagnosticBinaryVersionStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticCertificateReferences
import com.velumtegra.xuimobile.core.model.DeepDiagnosticDatabaseIntegrityStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticDatabaseSchemaStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticEvidence
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFilePresence
import com.velumtegra.xuimobile.core.model.DeepDiagnosticFindingCode
import com.velumtegra.xuimobile.core.model.DeepDiagnosticObservation
import com.velumtegra.xuimobile.core.model.DeepDiagnosticOverallStatus
import com.velumtegra.xuimobile.core.model.DeepDiagnosticScope
import com.velumtegra.xuimobile.core.model.DeepDiagnosticServiceDefinitionStatus
import com.velumtegra.xuimobile.core.model.InstallationBaseline
import com.velumtegra.xuimobile.core.model.InstallationIdentity
import com.velumtegra.xuimobile.core.model.InstallationOwnership
import com.velumtegra.xuimobile.core.model.ManagementBaselineStatus
import com.velumtegra.xuimobile.core.model.ManagementIdentityStatus
import com.velumtegra.xuimobile.core.model.ManagementLiveSnapshot
import com.velumtegra.xuimobile.core.model.ManagementScope
import com.velumtegra.xuimobile.core.model.ManagementServiceState
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.ServerId
import com.velumtegra.xuimobile.core.model.XuiInstallation
import com.velumtegra.xuimobile.core.model.XuiInstallationId
import java.time.Duration
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DeepDiagnosticPolicyTest {
    private val now = Instant.parse("2026-09-06T12:00:00Z")
    private val operationId = OperationId("op-deep-1")
    private val serverId = ServerId("server-deep-1")
    private val accessId = ServerAccessId("access-deep-1")
    private val installationId = XuiInstallationId("install-deep-1")

    private val installation = XuiInstallation(
        id = installationId,
        serverId = serverId,
        ownership = InstallationOwnership.ADOPTED,
        identity = InstallationIdentity(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            managedInstallId = null,
        ),
        baseline = InstallationBaseline(
            serviceUnit = "x-ui.service",
            binaryPath = "/usr/local/x-ui/x-ui",
            rootPath = "/usr/local/x-ui",
            databasePath = "/etc/x-ui/x-ui.db",
            panelPort = 2053,
            webBasePath = "/panel/",
            listenAddress = null,
            capturedAt = now.minusSeconds(60),
        ),
    )

    @Test
    fun `plan is finite and reuses exact lightweight prelude without arbitrary shell`() {
        val plan = DeepDiagnosticProbePlan.forInstallation(installation)
        assertEquals(7, plan.managementPrelude.size)
        assertEquals(5, plan.primaryProbes.size)
        assertTrue(plan.managementPrelude.size + plan.primaryProbes.size <= DeepDiagnosticProbePlan.MAX_PRIMARY_TOTAL_PROBES)
        assertTrue(plan.primaryProbes[0] is DeepDiagnosticProbeSpec.ServiceDefinitionReadback)
        assertTrue(plan.primaryProbes[1] is DeepDiagnosticProbeSpec.BinaryVersionReadback)
        assertTrue(plan.primaryProbes[2] is DeepDiagnosticProbeSpec.DatabaseQuickCheck)
        assertTrue(plan.primaryProbes[3] is DeepDiagnosticProbeSpec.DatabaseSchemaReadback)
        assertTrue(plan.primaryProbes[4] is DeepDiagnosticProbeSpec.CertificateReferencesReadback)
    }

    @Test
    fun `certificate probes are derived only from validated exact references and capped at two`() {
        val references = DeepDiagnosticCertificateReferences(
            certificatePath = "/etc/ssl/x-ui/fullchain.pem",
            privateKeyPath = "/etc/ssl/x-ui/privkey.pem",
        )
        val derived = DeepDiagnosticProbePlan.derivedCertificateProbes(references)
        assertEquals(2, derived.size)
        assertTrue(derived.size <= DeepDiagnosticProbePlan.MAX_DERIVED_RESOURCE_PROBES)

        assertThrows(IllegalArgumentException::class.java) {
            DeepDiagnosticCertificateReferences("relative.pem", null)
        }
    }


    @Test
    fun `probe constructors reject invalid path and unbounded timeout`() {
        assertThrows(IllegalArgumentException::class.java) {
            DeepDiagnosticProbeSpec.BinaryVersionReadback("relative/path")
        }
        assertThrows(IllegalArgumentException::class.java) {
            DeepDiagnosticProbeSpec.DatabaseQuickCheck(
                databasePath = installation.identity.databasePath,
                timeout = Duration.ofSeconds(31),
            )
        }
    }

    @Test
    fun `healthy normalized evidence produces healthy process local snapshot`() {
        val snapshot = DeepDiagnosticPolicy.evaluate(
            scope = deepScope(),
            managementSnapshot = managementSnapshot(),
            evidence = healthyEvidence(),
            now = now,
        )
        assertEquals(DeepDiagnosticOverallStatus.HEALTHY, snapshot.overallStatus)
        assertTrue(snapshot.findings.isEmpty())
    }

    @Test
    fun `database integrity failure is critical`() {
        val evidence = healthyEvidence().copy(
            observations = healthyEvidence().observations.map {
                if (it is DeepDiagnosticObservation.DatabaseIntegrity) {
                    it.copy(status = DeepDiagnosticDatabaseIntegrityStatus.FAILED)
                } else it
            },
        )
        val snapshot = DeepDiagnosticPolicy.evaluate(deepScope(), managementSnapshot(), evidence, now)
        assertEquals(DeepDiagnosticOverallStatus.CRITICAL, snapshot.overallStatus)
        assertTrue(snapshot.findings.any { it.code == DeepDiagnosticFindingCode.DATABASE_INTEGRITY_FAILED })
    }

    @Test
    fun `expired certificate is critical while private key contents remain unrepresented`() {
        val references = DeepDiagnosticCertificateReferences(
            certificatePath = "/etc/ssl/x-ui/fullchain.pem",
            privateKeyPath = "/etc/ssl/x-ui/privkey.pem",
        )
        val evidence = healthyEvidence(references).copy(
            observations = healthyEvidence(references).observations.map {
                if (it is DeepDiagnosticObservation.CertificateFile) {
                    it.copy(notAfter = now.minusSeconds(1))
                } else it
            },
        )
        val snapshot = DeepDiagnosticPolicy.evaluate(deepScope(), managementSnapshot(), evidence, now)
        assertEquals(DeepDiagnosticOverallStatus.CRITICAL, snapshot.overallStatus)
        assertTrue(snapshot.findings.any { it.code == DeepDiagnosticFindingCode.CERTIFICATE_EXPIRED })
        val keyObservation = evidence.observations.filterIsInstance<DeepDiagnosticObservation.PrivateKeyFile>().single()
        assertEquals("/etc/ssl/x-ui/privkey.pem", keyObservation.path)
        assertEquals(DeepDiagnosticFilePresence.PRESENT, keyObservation.presence)
    }

    @Test
    fun `missing deep observation is insufficient instead of fabricated healthy`() {
        val evidence = healthyEvidence().copy(
            observations = healthyEvidence().observations.filterNot { it is DeepDiagnosticObservation.DatabaseSchema },
        )
        val snapshot = DeepDiagnosticPolicy.evaluate(deepScope(), managementSnapshot(), evidence, now)
        assertEquals(DeepDiagnosticOverallStatus.INSUFFICIENT, snapshot.overallStatus)
        assertTrue(snapshot.findings.any { it.code == DeepDiagnosticFindingCode.INSUFFICIENT_EVIDENCE })
    }

    private fun deepScope() = DeepDiagnosticScope(operationId, serverId, accessId, installationId)

    private fun managementSnapshot() = ManagementLiveSnapshot(
        scope = ManagementScope(operationId, serverId, accessId, installationId),
        identityStatus = ManagementIdentityStatus.Matched,
        serviceState = ManagementServiceState.ACTIVE,
        baselineStatus = ManagementBaselineStatus.Matched,
        freshProof = null,
        observedAt = now.minusSeconds(2),
    )

    private fun healthyEvidence(
        references: DeepDiagnosticCertificateReferences = DeepDiagnosticCertificateReferences(null, null),
    ): DeepDiagnosticEvidence {
        val observations = mutableListOf<DeepDiagnosticObservation>(
            DeepDiagnosticObservation.ServiceDefinition(
                serviceUnit = installation.identity.serviceUnit,
                expectedBinaryPath = installation.identity.binaryPath,
                status = DeepDiagnosticServiceDefinitionStatus.CONSISTENT,
                observedAt = now.minusSeconds(1),
            ),
            DeepDiagnosticObservation.BinaryVersion(
                binaryPath = installation.identity.binaryPath,
                status = DeepDiagnosticBinaryVersionStatus.AVAILABLE,
                normalizedVersion = "2.8.24",
                observedAt = now.minusSeconds(1),
            ),
            DeepDiagnosticObservation.DatabaseIntegrity(
                databasePath = installation.identity.databasePath,
                status = DeepDiagnosticDatabaseIntegrityStatus.OK,
                observedAt = now.minusSeconds(1),
            ),
            DeepDiagnosticObservation.DatabaseSchema(
                databasePath = installation.identity.databasePath,
                status = DeepDiagnosticDatabaseSchemaStatus.SUPPORTED,
                observedAt = now.minusSeconds(1),
            ),
            DeepDiagnosticObservation.CertificateReferences(
                databasePath = installation.identity.databasePath,
                references = references,
                observedAt = now.minusSeconds(1),
            ),
        )
        references.certificatePath?.let {
            observations += DeepDiagnosticObservation.CertificateFile(
                path = it,
                presence = DeepDiagnosticFilePresence.PRESENT,
                notBefore = now.minusSeconds(3600),
                notAfter = now.plusSeconds(3600),
                observedAt = now,
            )
        }
        references.privateKeyPath?.let {
            observations += DeepDiagnosticObservation.PrivateKeyFile(
                path = it,
                presence = DeepDiagnosticFilePresence.PRESENT,
                observedAt = now,
            )
        }
        return DeepDiagnosticEvidence(deepScope(), observations)
    }
}

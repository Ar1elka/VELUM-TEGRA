package com.velumtegra.xuimobile.core.site

object SiteRemotePreflightPolicy {
    const val CONTRACT_VERSION: Int = 1
    const val CAPACITY_RESERVE_BYTES: Long = 1024L * 1024L

    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun validateTrust(trust: SiteRemotePreflightTrust) {
        require(sha256.matches(trust.expectedServerKeySha256)) { "Expected server key SHA-256 is invalid" }
    }

    fun validateObservation(plan: SiteRemoteDeployPlan, observation: SiteRemotePreflightObservation) {
        SiteRemoteDeployPolicy.validatePlan(plan)
        require(observation.server.remoteHostIdentity.isNotBlank()) { "Observed remote host identity must not be blank" }
        require(sha256.matches(observation.server.serverKeySha256)) { "Observed server key SHA-256 is invalid" }
        validateObservedPath(observation.target)
        validateObservedPath(observation.staging)
        observation.backup?.let(::validateObservedPath)
        require(observation.availableBytes >= 0L) { "Observed available capacity must not be negative" }
        observation.certificate?.let(::validateCertificateObservation)
    }

    fun requiredAvailableBytes(plan: SiteRemoteDeployPlan): Long {
        SiteRemoteDeployPolicy.validatePlan(plan)
        return Math.addExact(plan.totalBytes, CAPACITY_RESERVE_BYTES)
    }

    fun validateReport(report: SiteRemotePreflightReport) {
        require(report.contractVersion == CONTRACT_VERSION) { "Unsupported remote preflight contract version" }
        require(sha256.matches(report.deploymentPlanSha256)) { "Preflight deployment plan SHA-256 is invalid" }
        require(sha256.matches(report.observationSha256)) { "Preflight observation SHA-256 is invalid" }
        require(report.requiredAvailableBytes >= CAPACITY_RESERVE_BYTES) { "Preflight required capacity is invalid" }
        require(report.checks.isNotEmpty()) { "Remote preflight report must contain checks" }
        require(report.checks.map { it.code }.distinct().size == report.checks.size) { "Remote preflight report contains duplicate checks" }
        require(report.checks.all { it.detail.isNotBlank() }) { "Remote preflight check detail must not be blank" }
        val expectedStatus = if (report.checks.all { it.passed }) SiteRemotePreflightStatus.READY else SiteRemotePreflightStatus.BLOCKED
        require(report.status == expectedStatus) { "Remote preflight status does not match checks" }
        require(sha256.matches(report.preflightSha256)) { "Remote preflight SHA-256 is invalid" }
        require(report.preflightSha256 == SiteRemotePreflightDigest.reportSha256(report.copy(preflightSha256 = ""))) {
            "Remote preflight SHA-256 mismatch"
        }
    }

    internal fun observationSha256(observation: SiteRemotePreflightObservation): String =
        SiteRemotePreflightDigest.observationSha256(observation)

    private fun validateObservedPath(path: SiteRemoteObservedPath) {
        SiteRemoteDeployPolicy.prepareTargetRoot(path.path)
        require(path.byteSize >= 0L) { "Observed remote path byte size must not be negative" }
        if (path.type == SiteRemoteObservedPathType.ABSENT) {
            require(path.byteSize == 0L) { "Absent remote path must report zero bytes" }
        }
    }

    private fun validateCertificateObservation(certificate: SiteRemoteCertificateObservation) {
        require(sha256.matches(certificate.serverKeySha256)) { "Observed certificate server key SHA-256 is invalid" }
        require(sha256.matches(certificate.certificateSha256)) { "Observed certificate SHA-256 is invalid" }
        require(certificate.dnsNames.isNotEmpty()) { "Observed certificate DNS names must not be empty" }
        val normalized = certificate.dnsNames.map(SiteRemoteDeployPolicy::normalizeDomain)
        require(normalized == normalized.distinct().sorted()) { "Observed certificate DNS names must be normalized, unique, and sorted" }
    }
}

internal object SiteRemotePreflightDigest {
    fun observationSha256(observation: SiteRemotePreflightObservation): String {
        val certificate = observation.certificate
        val canonical = buildString {
            append("host=").append(observation.server.remoteHostIdentity).append('\n')
            append("serverKey=").append(observation.server.serverKeySha256).append('\n')
            appendPath("target", observation.target)
            appendPath("staging", observation.staging)
            observation.backup?.let { appendPath("backup", it) } ?: append("backup=<none>\n")
            append("availableBytes=").append(observation.availableBytes).append('\n')
            append("ownerExists=").append(observation.ownership.ownerExists).append('\n')
            append("groupExists=").append(observation.ownership.groupExists).append('\n')
            append("ownershipChangeApplicable=").append(observation.ownership.ownershipChangeApplicable).append('\n')
            append("modeChangeApplicable=").append(observation.ownership.modeChangeApplicable).append('\n')
            if (certificate == null) {
                append("certificate=<none>\n")
            } else {
                append("certificateServerKey=").append(certificate.serverKeySha256).append('\n')
                append("certificateSha256=").append(certificate.certificateSha256).append('\n')
                append("certificateUsableNow=").append(certificate.usableNow).append('\n')
                append("certificatePrivateKeyPresent=").append(certificate.privateKeyPresentOnServer).append('\n')
                certificate.dnsNames.forEach { append("certificateDns=").append(it).append('\n') }
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    fun reportSha256(reportWithoutSha: SiteRemotePreflightReport): String {
        val canonical = buildString {
            append("contractVersion=").append(reportWithoutSha.contractVersion).append('\n')
            append("deploymentPlanSha256=").append(reportWithoutSha.deploymentPlanSha256).append('\n')
            append("observationSha256=").append(reportWithoutSha.observationSha256).append('\n')
            append("requiredAvailableBytes=").append(reportWithoutSha.requiredAvailableBytes).append('\n')
            append("status=").append(reportWithoutSha.status.name).append('\n')
            reportWithoutSha.checks.forEach { check ->
                append(check.code.name).append('\u0000')
                append(check.passed).append('\u0000')
                append(check.detail).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }

    private fun StringBuilder.appendPath(label: String, path: SiteRemoteObservedPath) {
        append(label).append("Path=").append(path.path).append('\n')
        append(label).append("Type=").append(path.type.name).append('\n')
        append(label).append("Bytes=").append(path.byteSize).append('\n')
    }
}

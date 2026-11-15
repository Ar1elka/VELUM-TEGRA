package com.velumtegra.xuimobile.core.site

import java.net.IDN
import java.util.Locale

object SiteRemoteDeployPolicy {
    const val CONTRACT_VERSION: Int = 1
    const val MAX_REMOTE_ROOT_LENGTH: Int = 220
    const val MAX_HOST_IDENTITY_LENGTH: Int = 255

    private val hostIdentity = Regex("^[A-Za-z0-9._:-]{1,$MAX_HOST_IDENTITY_LENGTH}$")
    private val accountName = Regex("^[a-z_][a-z0-9_-]{0,31}$")
    private val pathSegment = Regex("^[A-Za-z0-9._-]+$")
    private val allowedDirectoryModes = setOf("0700", "0750", "0755")
    private val allowedFileModes = setOf("0600", "0640", "0644")
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val safeOutputBaseName = Regex("^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

    fun prepareTargetRoot(value: String): String {
        require(value.isNotBlank()) { "Remote target root must not be blank" }
        require(value.length <= MAX_REMOTE_ROOT_LENGTH) { "Remote target root is too long" }
        require(value == value.trim()) { "Remote target root must not contain surrounding whitespace" }
        require(value.startsWith('/')) { "Remote target root must be an absolute POSIX path" }
        require(value != "/") { "Remote filesystem root cannot be used as deployment target" }
        require('\\' !in value && '\u0000' !in value) { "Remote target root contains forbidden characters" }
        require(!value.endsWith('/')) { "Remote target root must not end with a slash" }
        require("//" !in value) { "Remote target root must be canonical" }
        val segments = value.split('/').drop(1)
        require(segments.isNotEmpty() && segments.none { it.isBlank() || it == "." || it == ".." }) {
            "Remote target root contains unsafe path segments"
        }
        require(segments.all(pathSegment::matches)) { "Remote target root contains unsupported path characters" }
        return value
    }

    fun validateRequest(request: SiteRemoteDeployRequest) {
        require(hostIdentity.matches(request.remoteHostIdentity)) { "Remote host identity is not canonical/safe" }
        prepareTargetRoot(request.targetRoot)
        require(accountName.matches(request.owner)) { "Remote owner is not canonical/safe" }
        require(accountName.matches(request.group)) { "Remote group is not canonical/safe" }
        require(request.directoryMode in allowedDirectoryModes) { "Unsupported remote directory mode" }
        require(request.fileMode in allowedFileModes) { "Unsupported remote file mode" }
        validateCertificateRequest(request.certificateReuse)
    }

    fun validatePlan(plan: SiteRemoteDeployPlan) {
        require(plan.contractVersion == CONTRACT_VERSION) { "Unsupported remote deploy contract version" }
        require(hostIdentity.matches(plan.remoteHostIdentity)) { "Remote host identity is not canonical/safe" }
        require(plan.sourceTreeSha256.matches(sha256)) { "Remote source tree SHA-256 is invalid" }
        require(plan.sourcePlanSha256.matches(sha256)) { "Remote source plan SHA-256 is invalid" }
        when (plan.sourceFormat) {
            SiteExportFormat.DIRECTORY -> {
                require(plan.sourceArtifactSha256 == null) { "Directory source must not claim a single artifact SHA-256" }
                require(safeOutputBaseName.matches(plan.sourceOutputName)) { "Directory source output name is not canonical/safe" }
            }
            SiteExportFormat.ZIP -> {
                require(plan.sourceArtifactSha256?.matches(sha256) == true) { "ZIP source artifact SHA-256 is invalid" }
                require(plan.sourceOutputName.endsWith(".zip")) { "ZIP source output name must end with .zip" }
                require(safeOutputBaseName.matches(plan.sourceOutputName.removeSuffix(".zip"))) {
                    "ZIP source output name is not canonical/safe"
                }
            }
        }
        require(plan.entries.isNotEmpty()) { "Remote deploy plan must contain entries" }
        require(plan.entries.size <= SiteBuildPolicy.MAX_DOCUMENTS) { "Remote deploy plan contains too many entries" }
        require(plan.entries.map(SiteRemoteDeployEntry::path) == plan.entries.map(SiteRemoteDeployEntry::path).sorted()) {
            "Remote deploy entries must be sorted by path"
        }
        require(plan.entries.map(SiteRemoteDeployEntry::path).distinct().size == plan.entries.size) {
            "Remote deploy plan contains duplicate paths"
        }
        require(plan.fileCount == plan.entries.size) { "Remote deploy file count mismatch" }
        require(plan.totalBytes == plan.entries.sumOf { it.byteSize.toLong() }) { "Remote deploy total bytes mismatch" }
        require(plan.totalBytes <= SiteBuildPolicy.MAX_TOTAL_BYTES) { "Remote deploy plan exceeds total size limit" }
        plan.entries.forEach { entry ->
            SiteBuildPolicy.validatePath(entry.path)
            require(entry.byteSize in 0..SiteBuildPolicy.MAX_DOCUMENT_BYTES) { "Remote deploy entry exceeds size limit: ${entry.path}" }
            require(entry.sha256.matches(sha256)) { "Remote deploy entry SHA-256 is invalid: ${entry.path}" }
        }
        validatePublishContract(plan.publish, plan.sourceTreeSha256)
        validateCertificateRequirement(plan.certificate)
        require(plan.deploymentPlanSha256 == SiteRemoteDeployDigest.planSha256(plan.copy(deploymentPlanSha256 = ""))) {
            "Remote deployment plan SHA-256 mismatch"
        }
    }

    internal fun buildStagingRoot(targetRoot: String, treeSha256: String): String {
        require(treeSha256.matches(sha256)) { "Source tree SHA-256 is invalid" }
        return siblingRoot(targetRoot, ".velum-stage-${treeSha256.take(12)}")
    }

    internal fun buildBackupRoot(
        targetRoot: String,
        treeSha256: String,
        policy: SiteRemoteExistingTargetPolicy,
    ): String? = when (policy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> null
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> siblingRoot(targetRoot, ".velum-backup-${treeSha256.take(12)}")
    }

    internal fun normalizeDomain(value: String): String {
        require(value.isNotBlank()) { "Certificate domain must not be blank" }
        require(value == value.trim()) { "Certificate domain must not contain surrounding whitespace" }
        require(value.length <= 253) { "Certificate domain is too long" }
        require(value.none(Char::isISOControl)) { "Certificate domain contains control characters" }
        require('*' !in value) { "Wildcard certificate reuse is outside this contract" }
        val ascii = IDN.toASCII(value.lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
        require(ascii.length <= 253 && '.' in ascii) { "Certificate domain must be a fully qualified DNS name" }
        require(ascii.split('.').all { label ->
            label.length in 1..63 && label.firstOrNull()?.isLetterOrDigit() == true &&
                label.lastOrNull()?.isLetterOrDigit() == true &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }) { "Certificate domain is not canonical/safe" }
        return ascii
    }

    private fun validateCertificateRequest(request: SiteCertificateReuseRequest) {
        when (request.mode) {
            SiteCertificateReuseMode.NONE -> require(request.requestedDomain == null) {
                "Certificate domain must be absent when reuse is disabled"
            }
            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> {
                val domain = requireNotNull(request.requestedDomain) {
                    "Certificate domain is required for 3x-ui certificate reuse"
                }
                normalizeDomain(domain)
            }
        }
    }

    private fun validateCertificateRequirement(requirement: SiteCertificateReuseRequirement) {
        require(requirement.privateKeyHandling == SitePrivateKeyHandling.REMAIN_ON_SERVER) {
            "Private key must remain on the remote server"
        }
        when (requirement.mode) {
            SiteCertificateReuseMode.NONE -> {
                require(requirement.requiredDomain == null) { "Certificate domain must be absent when reuse is disabled" }
                require(!requirement.sameServerRequired) { "Same-server proof must be disabled when certificate reuse is disabled" }
            }
            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> {
                require(requirement.requiredDomain != null) { "Certificate reuse requires an exact domain" }
                require(normalizeDomain(requirement.requiredDomain) == requirement.requiredDomain) {
                    "Certificate reuse domain must already be normalized"
                }
                require(requirement.sameServerRequired) { "3x-ui certificate reuse requires same-server proof" }
            }
        }
    }

    private fun validatePublishContract(contract: SiteRemotePublishContract, sourceTreeSha256: String) {
        val target = prepareTargetRoot(contract.targetRoot)
        require(contract.stagingRoot == buildStagingRoot(target, sourceTreeSha256)) { "Remote staging root mismatch" }
        require(contract.backupRoot == buildBackupRoot(target, sourceTreeSha256, contract.existingTargetPolicy)) {
            "Remote backup root mismatch"
        }
        require(accountName.matches(contract.owner)) { "Remote owner is not canonical/safe" }
        require(accountName.matches(contract.group)) { "Remote group is not canonical/safe" }
        require(contract.directoryMode in allowedDirectoryModes) { "Unsupported remote directory mode" }
        require(contract.fileMode in allowedFileModes) { "Unsupported remote file mode" }
        require(contract.requireStagingAbsent) { "Remote staging root must be required absent before transfer" }
        require(contract.verifyBeforePublish) { "Remote stage must be verified before publish" }
        require(contract.verifyAfterPublish) { "Remote target must be verified after publish" }
        when (contract.existingTargetPolicy) {
            SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> {
                require(contract.backupRoot == null) { "Absent-target policy must not allocate a backup root" }
                require(!contract.requireBackupAbsent) { "Absent-target policy must not require a backup root" }
                require(!contract.rollbackOnFailure) { "Absent-target policy has no previous target to roll back" }
            }
            SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> {
                require(contract.backupRoot != null) { "Replace policy requires a backup root" }
                require(contract.requireBackupAbsent) { "Replace policy must require backup root absence" }
                require(contract.rollbackOnFailure) { "Replace policy must require rollback on failure" }
            }
        }
    }

    private fun siblingRoot(targetRoot: String, suffix: String): String {
        val lastSlash = targetRoot.lastIndexOf('/')
        val parent = if (lastSlash == 0) "" else targetRoot.substring(0, lastSlash)
        val name = targetRoot.substring(lastSlash + 1)
        val result = "$parent/.$name$suffix"
        require(result.length <= MAX_REMOTE_ROOT_LENGTH) { "Derived remote staging/backup root is too long" }
        return result
    }
}

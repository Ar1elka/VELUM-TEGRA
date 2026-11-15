package com.velumtegra.xuimobile.core.site

object SiteRemoteDeployBoundary {
    fun prepare(
        exportPlan: SiteExportPlan,
        localReceipt: SiteLocalExportReceipt,
        request: SiteRemoteDeployRequest,
    ): SiteRemoteDeployPlan {
        SiteLocalExportPolicy.validatePlan(exportPlan)
        SiteRemoteDeployPolicy.validateRequest(request)
        validateVerifiedLocalSource(exportPlan, localReceipt)

        val targetRoot = SiteRemoteDeployPolicy.prepareTargetRoot(request.targetRoot)
        val sourceTreeSha = exportPlan.manifest.sourceTreeSha256
        val certificate = when (request.certificateReuse.mode) {
            SiteCertificateReuseMode.NONE -> SiteCertificateReuseRequirement(
                mode = SiteCertificateReuseMode.NONE,
                requiredDomain = null,
                sameServerRequired = false,
                privateKeyHandling = SitePrivateKeyHandling.REMAIN_ON_SERVER,
            )
            SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> SiteCertificateReuseRequirement(
                mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                requiredDomain = SiteRemoteDeployPolicy.normalizeDomain(requireNotNull(request.certificateReuse.requestedDomain)),
                sameServerRequired = true,
                privateKeyHandling = SitePrivateKeyHandling.REMAIN_ON_SERVER,
            )
        }
        val publish = SiteRemotePublishContract(
            targetRoot = targetRoot,
            stagingRoot = SiteRemoteDeployPolicy.buildStagingRoot(targetRoot, sourceTreeSha),
            backupRoot = SiteRemoteDeployPolicy.buildBackupRoot(targetRoot, sourceTreeSha, request.existingTargetPolicy),
            existingTargetPolicy = request.existingTargetPolicy,
            owner = request.owner,
            group = request.group,
            directoryMode = request.directoryMode,
            fileMode = request.fileMode,
            requireStagingAbsent = true,
            requireBackupAbsent = request.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
            verifyBeforePublish = true,
            verifyAfterPublish = true,
            rollbackOnFailure = request.existingTargetPolicy == SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
        )
        val base = SiteRemoteDeployPlan(
            contractVersion = SiteRemoteDeployPolicy.CONTRACT_VERSION,
            remoteHostIdentity = request.remoteHostIdentity,
            sourceOutputName = localReceipt.outputName,
            sourceFormat = localReceipt.format,
            sourceTreeSha256 = sourceTreeSha,
            sourcePlanSha256 = exportPlan.manifest.planSha256,
            sourceArtifactSha256 = localReceipt.artifactSha256,
            fileCount = exportPlan.entries.size,
            totalBytes = exportPlan.manifest.totalBytes,
            entries = exportPlan.entries.map { entry ->
                SiteRemoteDeployEntry(
                    path = entry.path,
                    mediaType = entry.mediaType,
                    byteSize = entry.byteSize,
                    sha256 = entry.sha256,
                )
            },
            publish = publish,
            certificate = certificate,
            deploymentPlanSha256 = "",
        )
        return base.copy(
            deploymentPlanSha256 = SiteRemoteDeployDigest.planSha256(base),
        ).also(SiteRemoteDeployPolicy::validatePlan)
    }

    private fun validateVerifiedLocalSource(plan: SiteExportPlan, receipt: SiteLocalExportReceipt) {
        require(receipt.verified) { "Remote deployment requires a verified local export receipt" }
        require(receipt.format == plan.manifest.format) { "Local export format does not match export plan" }
        require(receipt.outputName == plan.manifest.outputName) { "Local export output name does not match export plan" }
        require(receipt.fileCount == plan.manifest.fileCount) { "Local export file count does not match export plan" }
        require(receipt.totalBytes == plan.manifest.totalBytes) { "Local export byte count does not match export plan" }
        require(receipt.sourceTreeSha256 == plan.manifest.sourceTreeSha256) { "Local export tree SHA-256 does not match export plan" }
        require(receipt.planSha256 == plan.manifest.planSha256) { "Local export plan SHA-256 does not match export plan" }
        when (receipt.format) {
            SiteExportFormat.DIRECTORY -> require(receipt.artifactSha256 == null) {
                "Directory export receipt must not claim a single artifact SHA-256"
            }
            SiteExportFormat.ZIP -> require(receipt.artifactSha256?.matches(Regex("^[0-9a-f]{64}$")) == true) {
                "ZIP export receipt must contain a verified artifact SHA-256"
            }
        }
    }
}

internal object SiteRemoteDeployDigest {
    fun planSha256(planWithoutSha: SiteRemoteDeployPlan): String {
        val p = planWithoutSha.publish
        val c = planWithoutSha.certificate
        val canonical = buildString {
            append("contractVersion=").append(planWithoutSha.contractVersion).append('\n')
            append("remoteHostIdentity=").append(planWithoutSha.remoteHostIdentity).append('\n')
            append("sourceOutputName=").append(planWithoutSha.sourceOutputName).append('\n')
            append("sourceFormat=").append(planWithoutSha.sourceFormat.name).append('\n')
            append("sourceTreeSha256=").append(planWithoutSha.sourceTreeSha256).append('\n')
            append("sourcePlanSha256=").append(planWithoutSha.sourcePlanSha256).append('\n')
            append("sourceArtifactSha256=").append(planWithoutSha.sourceArtifactSha256 ?: "").append('\n')
            append("fileCount=").append(planWithoutSha.fileCount).append('\n')
            append("totalBytes=").append(planWithoutSha.totalBytes).append('\n')
            append("targetRoot=").append(p.targetRoot).append('\n')
            append("stagingRoot=").append(p.stagingRoot).append('\n')
            append("backupRoot=").append(p.backupRoot ?: "").append('\n')
            append("existingTargetPolicy=").append(p.existingTargetPolicy.name).append('\n')
            append("owner=").append(p.owner).append('\n')
            append("group=").append(p.group).append('\n')
            append("directoryMode=").append(p.directoryMode).append('\n')
            append("fileMode=").append(p.fileMode).append('\n')
            append("requireStagingAbsent=").append(p.requireStagingAbsent).append('\n')
            append("requireBackupAbsent=").append(p.requireBackupAbsent).append('\n')
            append("verifyBeforePublish=").append(p.verifyBeforePublish).append('\n')
            append("verifyAfterPublish=").append(p.verifyAfterPublish).append('\n')
            append("rollbackOnFailure=").append(p.rollbackOnFailure).append('\n')
            append("certificateMode=").append(c.mode.name).append('\n')
            append("certificateDomain=").append(c.requiredDomain ?: "").append('\n')
            append("certificateSameServerRequired=").append(c.sameServerRequired).append('\n')
            append("privateKeyHandling=").append(c.privateKeyHandling.name).append('\n')
            planWithoutSha.entries.forEach { entry ->
                append(entry.path).append('\u0000')
                append(entry.mediaType).append('\u0000')
                append(entry.byteSize).append('\u0000')
                append(entry.sha256).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}

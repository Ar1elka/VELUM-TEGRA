package com.velumtegra.xuimobile.core.site

import java.nio.file.Path

/**
 * Large non-remote Site Deployer preparation block.
 *
 * This boundary turns one deterministic constructor request into a verified local artifact and an
 * exact hash-bound remote deployment plan. It is deliberately unable to open a network session,
 * authorize transport, invoke the deployment coordinator, or mutate a remote server.
 */
object SiteDeployerLocalPreparationBoundary {
    const val BOUNDARY_VERSION: Int = 1

    fun prepare(
        request: SiteDeployerLocalPreparationRequest,
        localOutputRoot: Path,
    ): SiteDeployerLocalPreparationResult {
        require(request.servicePort in 1..65535) { "Service port must be inside 1..65535" }
        val normalizedDomain = SiteRemoteDeployPolicy.normalizeDomain(request.domain)

        val design = SiteDesignGenerator.generate(
            SiteDesignRequest(
                seeds = SiteDesignSeeds.fromRoot(request.rootSeed),
                siteName = request.siteName,
                tagline = request.tagline,
                themeFamily = request.themeFamily,
                backgroundFamily = request.backgroundFamily,
                typographyProfile = request.typographyProfile,
                componentStyle = request.componentStyle,
            ),
        )
        val bundle = SiteBuilder.build(SiteBuildRequest(design = design))
        val previewExport = SitePreviewExportBoundary.prepare(
            bundle = bundle,
            request = SitePreviewExportRequest(
                format = request.exportFormat,
                requestedBaseName = request.requestedOutputBaseName,
            ),
        )

        // The only side effect in this boundary is a verified LOCAL export. The adapter writes to a
        // caller-selected safe local root, verifies every output byte, and atomically publishes it.
        val receipt = SiteLocalExportAdapter.export(previewExport.export, localOutputRoot)
        val remoteRequest = SiteRemoteDeployRequest(
            remoteHostIdentity = request.remoteHostIdentity,
            targetRoot = request.targetRoot,
            owner = request.owner,
            group = request.group,
            existingTargetPolicy = request.existingTargetPolicy,
            certificateReuse = if (request.reuseExisting3xUiCertificate) {
                SiteCertificateReuseRequest(
                    mode = SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN,
                    requestedDomain = normalizedDomain,
                )
            } else {
                SiteCertificateReuseRequest()
            },
        )
        val remotePlan = SiteRemoteDeployBoundary.prepare(
            exportPlan = previewExport.export,
            localReceipt = receipt,
            request = remoteRequest,
        )
        val serviceBinding = SiteDeployerLocalServiceBinding(
            domain = normalizedDomain,
            port = request.servicePort,
            // Current bounded static-file deploy contract intentionally does not edit nginx/3x-ui
            // listeners. The endpoint is bound into the preparation identity for later composition.
            appliedByCurrentDeployContract = false,
        )

        val resultWithoutSha = SiteDeployerLocalPreparationResult(
            design = design,
            bundle = bundle,
            previewExport = previewExport,
            localExportReceipt = receipt,
            remoteDeployPlan = remotePlan,
            serviceBinding = serviceBinding,
            preparationSha256 = "",
            productionNetworkTouched = false,
            remoteMutationPerformed = false,
            coordinatorInvoked = false,
            transportAuthorized = false,
        )
        return resultWithoutSha.copy(
            preparationSha256 = digest(request.rootSeed, resultWithoutSha),
        ).also(::validate)
    }

    fun validate(result: SiteDeployerLocalPreparationResult) {
        SiteBuildPolicy.validate(result.bundle)
        SitePreviewExportPolicy.validate(result.previewExport)
        SiteLocalExportPolicy.validatePlan(result.previewExport.export)
        SiteRemoteDeployPolicy.validatePlan(result.remoteDeployPlan)

        val export = result.previewExport.export
        val receipt = result.localExportReceipt
        val remote = result.remoteDeployPlan
        require(receipt.verified) { "Local preparation requires a verified export receipt" }
        require(receipt.outputName == export.manifest.outputName) { "Local output name is not bound to export plan" }
        require(receipt.sourceTreeSha256 == export.manifest.sourceTreeSha256) { "Local tree digest is not bound to export plan" }
        require(receipt.planSha256 == export.manifest.planSha256) { "Local export-plan digest is not bound" }
        require(remote.sourceTreeSha256 == export.manifest.sourceTreeSha256) { "Remote plan tree digest is not bound" }
        require(remote.sourcePlanSha256 == export.manifest.planSha256) { "Remote plan export digest is not bound" }
        require(remote.sourceArtifactSha256 == receipt.artifactSha256) { "Remote plan artifact digest is not bound" }
        require(remote.fileCount == result.bundle.manifest.fileCount) { "Remote plan file count mismatch" }
        require(remote.totalBytes == result.bundle.manifest.totalBytes) { "Remote plan byte count mismatch" }
        require(!result.serviceBinding.appliedByCurrentDeployContract) {
            "Local preparation must not claim that the static-file contract changes service listeners"
        }
        require(!result.productionNetworkTouched) { "Local preparation must not touch production network" }
        require(!result.remoteMutationPerformed) { "Local preparation must not mutate the remote server" }
        require(!result.coordinatorInvoked) { "Local preparation must not invoke deployment coordinator" }
        require(!result.transportAuthorized) { "Local preparation must not authorize remote transport" }
        require(result.preparationSha256 == digest(result.design.seeds.root, result.copy(preparationSha256 = ""))) {
            "Local preparation SHA-256 mismatch"
        }
    }

    private fun digest(rootSeed: DesignSeed, resultWithoutSha: SiteDeployerLocalPreparationResult): String {
        val design = resultWithoutSha.design
        val export = resultWithoutSha.previewExport.export.manifest
        val receipt = resultWithoutSha.localExportReceipt
        val remote = resultWithoutSha.remoteDeployPlan
        val binding = resultWithoutSha.serviceBinding
        val canonical = buildString {
            append("boundaryVersion=").append(BOUNDARY_VERSION).append('\n')
            append("rootSeed=").append(rootSeed.value).append('\n')
            append("designGeneratorVersion=").append(design.generatorVersion).append('\n')
            append("builderVersion=").append(resultWithoutSha.bundle.manifest.builderVersion).append('\n')
            append("siteName=").append(design.identity.name).append('\n')
            append("tagline=").append(design.identity.tagline ?: "").append('\n')
            append("themeFamily=").append(design.palette.family.name).append('\n')
            append("backgroundFamily=").append(design.background.family.name).append('\n')
            append("typography=").append(design.typography.name).append('\n')
            append("componentStyle=").append(design.componentStyle.name).append('\n')
            append("brandInitials=").append(design.brand.initials).append('\n')
            append("brandShape=").append(design.brand.shape.name).append('\n')
            append("domain=").append(binding.domain).append('\n')
            append("servicePort=").append(binding.port).append('\n')
            append("servicePortApplied=").append(binding.appliedByCurrentDeployContract).append('\n')
            append("exportFormat=").append(export.format.name).append('\n')
            append("outputName=").append(export.outputName).append('\n')
            append("sourceTreeSha256=").append(export.sourceTreeSha256).append('\n')
            append("exportPlanSha256=").append(export.planSha256).append('\n')
            append("artifactSha256=").append(receipt.artifactSha256 ?: "").append('\n')
            append("fileCount=").append(export.fileCount).append('\n')
            append("totalBytes=").append(export.totalBytes).append('\n')
            append("deploymentPlanSha256=").append(remote.deploymentPlanSha256).append('\n')
            append("targetRoot=").append(remote.publish.targetRoot).append('\n')
            append("stagingRoot=").append(remote.publish.stagingRoot).append('\n')
            append("backupRoot=").append(remote.publish.backupRoot ?: "").append('\n')
            append("certificateMode=").append(remote.certificate.mode.name).append('\n')
            append("certificateDomain=").append(remote.certificate.requiredDomain ?: "").append('\n')
            append("productionNetworkTouched=false\n")
            append("remoteMutationPerformed=false\n")
            append("coordinatorInvoked=false\n")
            append("transportAuthorized=false\n")
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}

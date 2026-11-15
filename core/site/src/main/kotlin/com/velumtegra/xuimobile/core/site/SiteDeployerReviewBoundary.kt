package com.velumtegra.xuimobile.core.site

object SiteDeployerReviewBoundary {
    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val targetCodes = setOf(
        SiteRemotePreflightCheckCode.TARGET_STATE,
        SiteRemotePreflightCheckCode.STAGING_STATE,
        SiteRemotePreflightCheckCode.BACKUP_STATE,
    )
    private val certificateCodes = setOf(
        SiteRemotePreflightCheckCode.CERTIFICATE_PRESENT,
        SiteRemotePreflightCheckCode.CERTIFICATE_SERVER_IDENTITY,
        SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN,
        SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW,
        SiteRemotePreflightCheckCode.CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT,
    )

    fun prepare(request: SiteDeployerReviewRequest): SiteDeployerReviewState {
        require(request.servicePort in 1..65535) { "Service port must be inside 1..65535" }
        val normalizedDomain = SiteRemoteDeployPolicy.normalizeDomain(request.domain)
        val trust = SiteRemotePreflightTrust(request.trustedServerKeySha256)
        SiteRemotePreflightPolicy.validateTrust(trust)

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
        SiteRemoteDeployPolicy.validateRequest(remoteRequest)

        val targetRoot = SiteRemoteDeployPolicy.prepareTargetRoot(remoteRequest.targetRoot)
        val treeSha256 = previewExport.preview.treeSha256
        val stagingRoot = SiteRemoteDeployPolicy.buildStagingRoot(targetRoot, treeSha256)
        val backupRoot = SiteRemoteDeployPolicy.buildBackupRoot(
            targetRoot,
            treeSha256,
            remoteRequest.existingTargetPolicy,
        )
        val requiredAvailableBytes = Math.addExact(
            previewExport.export.manifest.totalBytes,
            SiteRemotePreflightPolicy.CAPACITY_RESERVE_BYTES,
        )
        val checks = request.observation?.let { observation ->
            evaluateObservation(
                remoteRequest = remoteRequest,
                trust = trust,
                normalizedDomain = normalizedDomain,
                targetRoot = targetRoot,
                stagingRoot = stagingRoot,
                backupRoot = backupRoot,
                requiredAvailableBytes = requiredAvailableBytes,
                observation = observation,
            )
        }.orEmpty()
        val preflightState = when {
            request.observation == null -> SiteDeployerPreflightState.NOT_OBSERVED
            checks.all(SiteRemotePreflightCheck::passed) -> SiteDeployerPreflightState.READY
            else -> SiteDeployerPreflightState.BLOCKED
        }
        val blockers = checks.filterNot(SiteRemotePreflightCheck::passed).map {
            SiteDeployerPreflightBlocker(it.code, it.detail)
        }
        val targetReadiness = readiness(checks, request.observation != null, targetCodes)
        val certificateReadiness = if (!request.reuseExisting3xUiCertificate) {
            SiteDeployerReadiness.NOT_REQUESTED
        } else {
            readiness(checks, request.observation != null, certificateCodes)
        }

        val stateWithoutSha = SiteDeployerReviewState(
            executionMode = SiteDeployerExecutionMode.DRY_RUN_ONLY,
            realServerMutationEnabled = false,
            fixtureDeploymentOnly = true,
            design = SiteDeployerDesignReview(
                siteName = design.identity.name,
                tagline = design.identity.tagline,
                themeFamily = design.palette.family,
                backgroundFamily = design.background.family,
                typographyProfile = design.typography,
                componentStyle = design.componentStyle,
                brandInitials = design.brand.initials,
                brandShape = design.brand.shape,
                accentHex = design.palette.accentPrimary.hex,
                backgroundHex = design.palette.backgroundPrimary.hex,
            ),
            serviceBinding = SiteDeployerServiceBindingReview(
                domain = normalizedDomain,
                port = request.servicePort,
                // Phase 11.13 only reviews the serving endpoint. The current bounded deploy contract
                // moves verified static files and does not mutate nginx/3x-ui listeners.
                appliedByCurrentDeployContract = false,
            ),
            preview = previewExport.preview,
            exportManifest = previewExport.export.manifest,
            remoteTarget = SiteDeployerRemoteTargetReview(
                remoteHostIdentity = remoteRequest.remoteHostIdentity,
                targetRoot = targetRoot,
                stagingRoot = stagingRoot,
                backupRoot = backupRoot,
                existingTargetPolicy = remoteRequest.existingTargetPolicy,
                readiness = targetReadiness,
            ),
            certificate = SiteDeployerCertificateReview(
                requested = request.reuseExisting3xUiCertificate,
                domain = if (request.reuseExisting3xUiCertificate) normalizedDomain else null,
                readiness = certificateReadiness,
                privateKeyHandling = SitePrivateKeyHandling.REMAIN_ON_SERVER,
            ),
            preflight = SiteDeployerDryRunPreflightReview(
                state = preflightState,
                requiredAvailableBytes = requiredAvailableBytes,
                checks = checks,
                // This review deliberately cannot be passed to transport authorization. The real
                // coordinator must materialize and verify the local export first, then create a
                // hash-bound SiteRemoteDeployPlan and authoritative preflight report.
                authorizesTransport = false,
            ),
            preflightBlockers = blockers,
            reviewSha256 = "",
        )
        return stateWithoutSha.copy(reviewSha256 = digest(stateWithoutSha))
    }

    private fun evaluateObservation(
        remoteRequest: SiteRemoteDeployRequest,
        trust: SiteRemotePreflightTrust,
        normalizedDomain: String,
        targetRoot: String,
        stagingRoot: String,
        backupRoot: String?,
        requiredAvailableBytes: Long,
        observation: SiteRemotePreflightObservation,
    ): List<SiteRemotePreflightCheck> {
        validateObservationShape(targetRoot, stagingRoot, backupRoot, observation)
        return buildList {
            add(check(
                SiteRemotePreflightCheckCode.SERVER_HOST_IDENTITY,
                observation.server.remoteHostIdentity == remoteRequest.remoteHostIdentity,
                "Observed host identity must exactly match the deployment plan",
            ))
            add(check(
                SiteRemotePreflightCheckCode.SERVER_KEY_FINGERPRINT,
                observation.server.serverKeySha256 == trust.expectedServerKeySha256,
                "Observed server key fingerprint must exactly match trusted fingerprint",
            ))
            add(check(
                SiteRemotePreflightCheckCode.TARGET_STATE,
                targetStateReady(remoteRequest.existingTargetPolicy, observation.target),
                targetStateDetail(remoteRequest.existingTargetPolicy),
            ))
            add(check(
                SiteRemotePreflightCheckCode.STAGING_STATE,
                observation.staging.type == SiteRemoteObservedPathType.ABSENT,
                "Staging root must be absent before transfer",
            ))
            add(check(
                SiteRemotePreflightCheckCode.BACKUP_STATE,
                backupStateReady(remoteRequest.existingTargetPolicy, observation.backup),
                backupStateDetail(remoteRequest.existingTargetPolicy),
            ))
            add(check(
                SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY,
                observation.availableBytes >= requiredAvailableBytes,
                "Available capacity must cover source bytes plus preflight reserve",
            ))
            add(check(
                SiteRemotePreflightCheckCode.OWNER_ACCOUNT,
                observation.ownership.ownerExists,
                "Requested owner account must exist on the remote server",
            ))
            add(check(
                SiteRemotePreflightCheckCode.GROUP_ACCOUNT,
                observation.ownership.groupExists,
                "Requested group account must exist on the remote server",
            ))
            add(check(
                SiteRemotePreflightCheckCode.OWNERSHIP_APPLICABLE,
                observation.ownership.ownershipChangeApplicable,
                "Deployment identity must be able to apply requested owner/group metadata",
            ))
            add(check(
                SiteRemotePreflightCheckCode.MODE_APPLICABLE,
                observation.ownership.modeChangeApplicable,
                "Deployment identity must be able to apply requested file/directory modes",
            ))
            if (remoteRequest.certificateReuse.mode == SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN) {
                val certificate = observation.certificate
                add(check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_PRESENT,
                    certificate != null,
                    "Existing 3x-ui certificate metadata must be observed before reuse",
                ))
                add(check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_SERVER_IDENTITY,
                    certificate?.serverKeySha256 == trust.expectedServerKeySha256,
                    "Certificate metadata must come from the same trusted server",
                ))
                add(check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN,
                    certificate?.dnsNames?.contains(normalizedDomain) == true,
                    "Certificate DNS names must contain the exact requested domain",
                ))
                add(check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW,
                    certificate?.usableNow == true,
                    "Existing certificate must be currently usable",
                ))
                add(check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT,
                    certificate?.privateKeyPresentOnServer == true,
                    "Matching private key must remain present on the same server",
                ))
            }
        }
    }

    private fun validateObservationShape(
        targetRoot: String,
        stagingRoot: String,
        backupRoot: String?,
        observation: SiteRemotePreflightObservation,
    ) {
        require(observation.server.remoteHostIdentity.isNotBlank()) { "Observed remote host identity must not be blank" }
        require(sha256.matches(observation.server.serverKeySha256)) { "Observed server key SHA-256 is invalid" }
        require(observation.target.path == targetRoot) { "Observed target path does not match dry-run target" }
        require(observation.staging.path == stagingRoot) { "Observed staging path does not match dry-run staging root" }
        require(observation.backup?.path == backupRoot) { "Observed backup path does not match dry-run backup root" }
        validateObservedPath(observation.target)
        validateObservedPath(observation.staging)
        observation.backup?.let(::validateObservedPath)
        require(observation.availableBytes >= 0L) { "Observed available capacity must not be negative" }
        observation.certificate?.let { certificate ->
            require(sha256.matches(certificate.serverKeySha256)) { "Observed certificate server key SHA-256 is invalid" }
            require(sha256.matches(certificate.certificateSha256)) { "Observed certificate SHA-256 is invalid" }
            require(certificate.dnsNames.isNotEmpty()) { "Observed certificate DNS names must not be empty" }
            val normalized = certificate.dnsNames.map(SiteRemoteDeployPolicy::normalizeDomain)
            require(normalized == normalized.distinct().sorted()) {
                "Observed certificate DNS names must be normalized, unique, and sorted"
            }
        }
    }

    private fun validateObservedPath(path: SiteRemoteObservedPath) {
        SiteRemoteDeployPolicy.prepareTargetRoot(path.path)
        require(path.byteSize >= 0L) { "Observed remote path byte size must not be negative" }
        if (path.type == SiteRemoteObservedPathType.ABSENT) {
            require(path.byteSize == 0L) { "Absent remote path must report zero bytes" }
        }
    }

    private fun targetStateReady(
        policy: SiteRemoteExistingTargetPolicy,
        target: SiteRemoteObservedPath,
    ): Boolean = when (policy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> target.type == SiteRemoteObservedPathType.ABSENT
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> target.type == SiteRemoteObservedPathType.DIRECTORY
    }

    private fun targetStateDetail(policy: SiteRemoteExistingTargetPolicy): String = when (policy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> "Target root must be absent for REQUIRE_ABSENT"
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> "Target root must be an existing non-symlink directory for BACKUP_AND_REPLACE"
    }

    private fun backupStateReady(
        policy: SiteRemoteExistingTargetPolicy,
        backup: SiteRemoteObservedPath?,
    ): Boolean = when (policy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> backup == null
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> backup?.type == SiteRemoteObservedPathType.ABSENT
    }

    private fun backupStateDetail(policy: SiteRemoteExistingTargetPolicy): String = when (policy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> "Absent-target policy must not allocate or probe a backup root"
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> "Backup root must be absent before staged replacement"
    }

    private fun readiness(
        checks: List<SiteRemotePreflightCheck>,
        observed: Boolean,
        codes: Set<SiteRemotePreflightCheckCode>,
    ): SiteDeployerReadiness {
        if (!observed) return SiteDeployerReadiness.UNKNOWN
        val relevant = checks.filter { it.code in codes }
        require(relevant.isNotEmpty()) { "Dry-run preflight is missing required readiness checks" }
        return if (relevant.all(SiteRemotePreflightCheck::passed)) {
            SiteDeployerReadiness.READY
        } else {
            SiteDeployerReadiness.BLOCKED
        }
    }

    private fun check(code: SiteRemotePreflightCheckCode, passed: Boolean, detail: String) =
        SiteRemotePreflightCheck(code = code, passed = passed, detail = detail)

    private fun digest(state: SiteDeployerReviewState): String {
        val canonical = buildString {
            append("executionMode=").append(state.executionMode.name).append('\n')
            append("realServerMutationEnabled=").append(state.realServerMutationEnabled).append('\n')
            append("fixtureDeploymentOnly=").append(state.fixtureDeploymentOnly).append('\n')
            append("siteName=").append(state.design.siteName).append('\n')
            append("tagline=").append(state.design.tagline ?: "").append('\n')
            append("themeFamily=").append(state.design.themeFamily.name).append('\n')
            append("backgroundFamily=").append(state.design.backgroundFamily.name).append('\n')
            append("typographyProfile=").append(state.design.typographyProfile.name).append('\n')
            append("componentStyle=").append(state.design.componentStyle.name).append('\n')
            append("brandInitials=").append(state.design.brandInitials).append('\n')
            append("brandShape=").append(state.design.brandShape.name).append('\n')
            append("accentHex=").append(state.design.accentHex).append('\n')
            append("backgroundHex=").append(state.design.backgroundHex).append('\n')
            append("domain=").append(state.serviceBinding.domain).append('\n')
            append("port=").append(state.serviceBinding.port).append('\n')
            append("bindingApplied=").append(state.serviceBinding.appliedByCurrentDeployContract).append('\n')
            append("treeSha256=").append(state.preview.treeSha256).append('\n')
            append("exportPlanSha256=").append(state.exportManifest.planSha256).append('\n')
            append("targetRoot=").append(state.remoteTarget.targetRoot).append('\n')
            append("stagingRoot=").append(state.remoteTarget.stagingRoot).append('\n')
            append("backupRoot=").append(state.remoteTarget.backupRoot ?: "").append('\n')
            append("targetReadiness=").append(state.remoteTarget.readiness.name).append('\n')
            append("certificateRequested=").append(state.certificate.requested).append('\n')
            append("certificateDomain=").append(state.certificate.domain ?: "").append('\n')
            append("certificateReadiness=").append(state.certificate.readiness.name).append('\n')
            append("preflightState=").append(state.preflight.state.name).append('\n')
            append("requiredAvailableBytes=").append(state.preflight.requiredAvailableBytes).append('\n')
            append("authorizesTransport=").append(state.preflight.authorizesTransport).append('\n')
            state.preflight.checks.forEach { check ->
                append("check=").append(check.code.name).append('\u0000')
                append(check.passed).append('\u0000').append(check.detail).append('\n')
            }
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}

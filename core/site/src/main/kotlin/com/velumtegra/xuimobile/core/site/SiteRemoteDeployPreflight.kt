package com.velumtegra.xuimobile.core.site

object SiteRemoteDeployPreflight {
    fun evaluate(
        plan: SiteRemoteDeployPlan,
        trust: SiteRemotePreflightTrust,
        observation: SiteRemotePreflightObservation,
    ): SiteRemotePreflightReport {
        SiteRemoteDeployPolicy.validatePlan(plan)
        SiteRemotePreflightPolicy.validateTrust(trust)
        SiteRemotePreflightPolicy.validateObservation(plan, observation)

        require(observation.target.path == plan.publish.targetRoot) { "Observed target path does not match deployment plan" }
        require(observation.staging.path == plan.publish.stagingRoot) { "Observed staging path does not match deployment plan" }
        require(observation.backup?.path == plan.publish.backupRoot) { "Observed backup path does not match deployment plan" }

        val requiredCapacity = SiteRemotePreflightPolicy.requiredAvailableBytes(plan)
        val checks = buildList {
            add(check(
                SiteRemotePreflightCheckCode.SERVER_HOST_IDENTITY,
                observation.server.remoteHostIdentity == plan.remoteHostIdentity,
                "Observed host identity must exactly match the deployment plan",
            ))
            add(check(
                SiteRemotePreflightCheckCode.SERVER_KEY_FINGERPRINT,
                observation.server.serverKeySha256 == trust.expectedServerKeySha256,
                "Observed server key fingerprint must exactly match trusted fingerprint",
            ))
            add(check(
                SiteRemotePreflightCheckCode.TARGET_STATE,
                targetStateReady(plan, observation.target),
                targetStateDetail(plan),
            ))
            add(check(
                SiteRemotePreflightCheckCode.STAGING_STATE,
                observation.staging.type == SiteRemoteObservedPathType.ABSENT,
                "Staging root must be absent before transfer",
            ))
            add(check(
                SiteRemotePreflightCheckCode.BACKUP_STATE,
                backupStateReady(plan, observation.backup),
                backupStateDetail(plan),
            ))
            add(check(
                SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY,
                observation.availableBytes >= requiredCapacity,
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
            addAll(certificateChecks(plan, trust, observation.certificate))
        }
        val base = SiteRemotePreflightReport(
            contractVersion = SiteRemotePreflightPolicy.CONTRACT_VERSION,
            deploymentPlanSha256 = plan.deploymentPlanSha256,
            observationSha256 = SiteRemotePreflightPolicy.observationSha256(observation),
            requiredAvailableBytes = requiredCapacity,
            checks = checks,
            status = if (checks.all { it.passed }) SiteRemotePreflightStatus.READY else SiteRemotePreflightStatus.BLOCKED,
            preflightSha256 = "",
        )
        return base.copy(
            preflightSha256 = SiteRemotePreflightDigest.reportSha256(base),
        ).also(SiteRemotePreflightPolicy::validateReport)
    }

    private fun targetStateReady(plan: SiteRemoteDeployPlan, target: SiteRemoteObservedPath): Boolean = when (plan.publish.existingTargetPolicy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> target.type == SiteRemoteObservedPathType.ABSENT
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> target.type == SiteRemoteObservedPathType.DIRECTORY
    }

    private fun targetStateDetail(plan: SiteRemoteDeployPlan): String = when (plan.publish.existingTargetPolicy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> "Target root must be absent for REQUIRE_ABSENT"
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> "Target root must be an existing non-symlink directory for BACKUP_AND_REPLACE"
    }

    private fun backupStateReady(plan: SiteRemoteDeployPlan, backup: SiteRemoteObservedPath?): Boolean = when (plan.publish.existingTargetPolicy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> backup == null
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> backup?.type == SiteRemoteObservedPathType.ABSENT
    }

    private fun backupStateDetail(plan: SiteRemoteDeployPlan): String = when (plan.publish.existingTargetPolicy) {
        SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT -> "Absent-target policy must not allocate or probe a backup root"
        SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE -> "Backup root must be absent before staged replacement"
    }

    private fun certificateChecks(
        plan: SiteRemoteDeployPlan,
        trust: SiteRemotePreflightTrust,
        certificate: SiteRemoteCertificateObservation?,
    ): List<SiteRemotePreflightCheck> = when (plan.certificate.mode) {
        SiteCertificateReuseMode.NONE -> emptyList()
        SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> {
            val requiredDomain = requireNotNull(plan.certificate.requiredDomain)
            listOf(
                check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_PRESENT,
                    certificate != null,
                    "Existing 3x-ui certificate metadata must be observed before reuse",
                ),
                check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_SERVER_IDENTITY,
                    certificate?.serverKeySha256 == trust.expectedServerKeySha256,
                    "Certificate metadata must come from the same trusted server",
                ),
                check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN,
                    certificate?.dnsNames?.contains(requiredDomain) == true,
                    "Certificate DNS names must contain the exact requested domain",
                ),
                check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW,
                    certificate?.usableNow == true,
                    "Existing certificate must be currently usable",
                ),
                check(
                    SiteRemotePreflightCheckCode.CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT,
                    certificate?.privateKeyPresentOnServer == true,
                    "Matching private key must remain present on the same server",
                ),
            )
        }
    }

    private fun check(code: SiteRemotePreflightCheckCode, passed: Boolean, detail: String) =
        SiteRemotePreflightCheck(code = code, passed = passed, detail = detail)
}

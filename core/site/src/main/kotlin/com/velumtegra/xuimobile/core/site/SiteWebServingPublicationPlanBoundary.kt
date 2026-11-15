package com.velumtegra.xuimobile.core.site

object SiteWebServingPublicationPlanBoundary {
    const val CONTRACT_VERSION: Int = 1

    private val sha256 = Regex("^[0-9a-f]{64}$")

    fun prepare(request: SiteWebServingPublicationPlanRequest): SiteWebServingPublicationPlan {
        val preparation = request.preparation
        SiteDeployerLocalPreparationBoundary.validate(preparation)
        SiteRemoteDeployPolicy.validatePlan(preparation.remoteDeployPlan)

        val evidence = request.staticPublicationEvidence
        require(sha256.matches(evidence.preparationSha256)) { "Static publication preparation SHA-256 is invalid" }
        require(evidence.preparationSha256 == preparation.preparationSha256) {
            "Static publication evidence is bound to a different local preparation"
        }
        require(evidence.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity) {
            "Static publication evidence host differs from the deployment plan"
        }
        require(evidence.targetRoot == preparation.remoteDeployPlan.publish.targetRoot) {
            "Static publication evidence target differs from the deployment plan"
        }
        require(evidence.finalTargetTreeSha256 == preparation.remoteDeployPlan.sourceTreeSha256) {
            "Static publication evidence does not prove the prepared tree is live"
        }
        require(evidence.committedClean) { "Web-serving publication plan requires a clean committed static target" }
        require(evidence.remoteResidualStateClean) { "Web-serving publication plan requires clean remote residual state" }
        require(!preparation.serviceBinding.appliedByCurrentDeployContract) {
            "Service binding must still be unapplied before web-serving publication planning"
        }

        val domain = SiteRemoteDeployPolicy.normalizeDomain(preparation.serviceBinding.domain)
        val port = preparation.serviceBinding.port
        require(port in 1..65535) { "Web-serving port must be inside 1..65535" }

        val certificate = validateCertificateBinding(preparation, request.certificateReference, domain)
        val protocol = if (certificate == null) {
            SiteWebServingProtocol.HTTP
        } else {
            SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE
        }
        val configPath = when (request.strategy) {
            SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1 -> exactNginxConfigPath(
                remoteHostIdentity = evidence.remoteHostIdentity,
                targetRoot = evidence.targetRoot,
                domain = domain,
                port = port,
            )
        }
        val config = when (request.strategy) {
            SiteWebServingStrategy.NGINX_CONF_D_STATIC_V1 -> renderNginxConfig(
                targetRoot = evidence.targetRoot,
                domain = domain,
                port = port,
                certificate = certificate,
            )
        }
        val configSha256 = SiteBundleDigest.sha256(config.encodeToByteArray())
        val base = SiteWebServingPublicationPlan(
            contractVersion = CONTRACT_VERSION,
            preparationSha256 = preparation.preparationSha256,
            remoteHostIdentity = evidence.remoteHostIdentity,
            sourceTreeSha256 = evidence.finalTargetTreeSha256,
            targetRoot = evidence.targetRoot,
            domain = domain,
            port = port,
            strategy = request.strategy,
            protocol = protocol,
            configPath = configPath,
            desiredConfigUtf8 = config,
            desiredConfigSha256 = configSha256,
            certificateSha256 = certificate?.certificateSha256,
            certificatePath = certificate?.certificatePath,
            privateKeyPath = certificate?.privateKeyPath,
            requiresReadOnlyServerPreflight = true,
            requiresLivePortConflictProof = true,
            requiresConfigSyntaxValidationBeforeActivation = true,
            requiresDurableRollbackCheckpoint = true,
            requiresPostServeVerification = true,
            configMutationAuthorized = false,
            webServerReloadAuthorized = false,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            certificatePrivateKeyTransferRequired = false,
            publicationPlanSha256 = "",
        )
        return base.copy(
            publicationPlanSha256 = publicationPlanSha256(base),
        ).also(::validate)
    }

    fun validate(plan: SiteWebServingPublicationPlan) {
        require(plan.contractVersion == CONTRACT_VERSION) { "Unsupported web-serving publication-plan version" }
        require(sha256.matches(plan.preparationSha256)) { "Publication preparation SHA-256 is invalid" }
        require(sha256.matches(plan.sourceTreeSha256)) { "Publication source tree SHA-256 is invalid" }
        require(sha256.matches(plan.desiredConfigSha256)) { "Desired config SHA-256 is invalid" }
        require(plan.domain == SiteRemoteDeployPolicy.normalizeDomain(plan.domain)) { "Publication domain is not normalized" }
        require(plan.port in 1..65535) { "Publication port is invalid" }
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.targetRoot) == plan.targetRoot) { "Publication target root is not canonical" }
        require(SiteRemoteDeployPolicy.prepareTargetRoot(plan.configPath) == plan.configPath) { "Publication config path is not canonical" }
        require(plan.configPath.startsWith("/etc/nginx/conf.d/") && plan.configPath.endsWith(".conf")) {
            "Nginx publication config must remain inside /etc/nginx/conf.d"
        }
        require(plan.desiredConfigUtf8.isNotBlank()) { "Desired web-server config must not be blank" }
        require(plan.desiredConfigSha256 == SiteBundleDigest.sha256(plan.desiredConfigUtf8.encodeToByteArray())) {
            "Desired web-server config SHA-256 mismatch"
        }
        require(plan.requiresReadOnlyServerPreflight)
        require(plan.requiresLivePortConflictProof)
        require(plan.requiresConfigSyntaxValidationBeforeActivation)
        require(plan.requiresDurableRollbackCheckpoint)
        require(plan.requiresPostServeVerification)
        require(!plan.configMutationAuthorized)
        require(!plan.webServerReloadAuthorized)
        require(!plan.dnsMutationAuthorized)
        require(!plan.firewallMutationAuthorized)
        require(!plan.packageInstallAuthorized)
        require(!plan.certificatePrivateKeyTransferRequired)
        when (plan.protocol) {
            SiteWebServingProtocol.HTTP -> {
                require(plan.certificateSha256 == null)
                require(plan.certificatePath == null)
                require(plan.privateKeyPath == null)
                require(" ssl" !in plan.desiredConfigUtf8.substringBefore(';'))
            }
            SiteWebServingProtocol.HTTPS_EXISTING_SERVER_CERTIFICATE -> {
                require(plan.certificateSha256?.matches(sha256) == true)
                require(plan.certificatePath != null)
                require(plan.privateKeyPath != null)
                require(plan.certificatePath != plan.privateKeyPath)
                SiteRemoteDeployPolicy.prepareTargetRoot(plan.certificatePath)
                SiteRemoteDeployPolicy.prepareTargetRoot(plan.privateKeyPath)
                require("ssl_certificate ${plan.certificatePath};" in plan.desiredConfigUtf8)
                require("ssl_certificate_key ${plan.privateKeyPath};" in plan.desiredConfigUtf8)
            }
        }
        require(plan.publicationPlanSha256 == publicationPlanSha256(plan.copy(publicationPlanSha256 = ""))) {
            "Web-serving publication-plan SHA-256 mismatch"
        }
    }

    private fun validateCertificateBinding(
        preparation: SiteDeployerLocalPreparationResult,
        reference: SiteServerCertificateFileReference?,
        domain: String,
    ): SiteServerCertificateFileReference? = when (preparation.remoteDeployPlan.certificate.mode) {
        SiteCertificateReuseMode.NONE -> {
            require(reference == null) { "Certificate file reference must be absent when certificate reuse is disabled" }
            null
        }
        SiteCertificateReuseMode.REUSE_EXISTING_3X_UI_IF_PROVEN -> {
            val ref = requireNotNull(reference) { "Exact server-side certificate file reference is required for HTTPS planning" }
            require(ref.remoteHostIdentity == preparation.remoteDeployPlan.remoteHostIdentity) {
                "Certificate file reference belongs to a different remote host"
            }
            require(sha256.matches(ref.certificateSha256)) { "Certificate SHA-256 is invalid" }
            require(ref.dnsNames.isNotEmpty()) { "Certificate DNS names must not be empty" }
            val normalizedNames = ref.dnsNames.map(SiteRemoteDeployPolicy::normalizeDomain)
            require(normalizedNames == normalizedNames.distinct().sorted()) {
                "Certificate DNS names must be normalized, unique and sorted"
            }
            require(domain in normalizedNames) { "Certificate DNS names do not contain the exact publication domain" }
            require(ref.usableNow) { "Certificate must be currently usable" }
            require(ref.privateKeyPresentOnServer) { "Matching private key must remain present on the server" }
            val certificatePath = SiteRemoteDeployPolicy.prepareTargetRoot(ref.certificatePath)
            val privateKeyPath = SiteRemoteDeployPolicy.prepareTargetRoot(ref.privateKeyPath)
            require(certificatePath != privateKeyPath) { "Certificate and private-key paths must differ" }
            require(preparation.remoteDeployPlan.certificate.requiredDomain == domain) {
                "Prepared certificate requirement differs from publication domain"
            }
            ref.copy(certificatePath = certificatePath, privateKeyPath = privateKeyPath, dnsNames = normalizedNames)
        }
    }

    /**
     * Pure deterministic projection of the exact nginx config path that Phase 11.56 will use after
     * static publication. Phase 11.100 exposes this projection so first-publication readiness can
     * prove that the future exact endpoint is still unconfigured without fabricating a committed
     * static-publication receipt. It performs no I/O and grants no config-mutation authority.
     */
    fun exactNginxConfigPath(
        remoteHostIdentity: String,
        targetRoot: String,
        domain: String,
        port: Int,
    ): String {
        require(remoteHostIdentity.isNotBlank() && remoteHostIdentity == remoteHostIdentity.trim()) {
            "Web-serving remote host identity must be exact and non-blank"
        }
        require(remoteHostIdentity.none { it == '\n' || it == '\r' || it == '\u0000' }) {
            "Web-serving remote host identity contains an unsafe control character"
        }
        val canonicalTarget = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        val canonicalDomain = SiteRemoteDeployPolicy.normalizeDomain(domain)
        require(port in 1..65535) { "Web-serving port must be inside 1..65535" }
        val identity = buildString {
            append(remoteHostIdentity).append('\n')
            append(canonicalTarget).append('\n')
            append(canonicalDomain).append('\n')
            append(port).append('\n')
        }
        val suffix = SiteBundleDigest.sha256(identity.encodeToByteArray()).take(16)
        return "/etc/nginx/conf.d/velum-tegra-$suffix.conf"
    }

    private fun renderNginxConfig(
        targetRoot: String,
        domain: String,
        port: Int,
        certificate: SiteServerCertificateFileReference?,
    ): String = buildString {
        append("server {\n")
        append("    listen ").append(port)
        if (certificate != null) append(" ssl")
        append(";\n")
        append("    server_name ").append(domain).append(";\n")
        append("    root ").append(targetRoot).append(";\n")
        append("    index index.html;\n")
        if (certificate != null) {
            append("    ssl_certificate ").append(certificate.certificatePath).append(";\n")
            append("    ssl_certificate_key ").append(certificate.privateKeyPath).append(";\n")
        }
        append("    location / {\n")
        append("        try_files \$uri \$uri/ =404;\n")
        append("    }\n")
        append("}\n")
    }

    private fun publicationPlanSha256(planWithoutSha: SiteWebServingPublicationPlan): String {
        val canonical = buildString {
            append("contractVersion=").append(planWithoutSha.contractVersion).append('\n')
            append("preparationSha256=").append(planWithoutSha.preparationSha256).append('\n')
            append("remoteHostIdentity=").append(planWithoutSha.remoteHostIdentity).append('\n')
            append("sourceTreeSha256=").append(planWithoutSha.sourceTreeSha256).append('\n')
            append("targetRoot=").append(planWithoutSha.targetRoot).append('\n')
            append("domain=").append(planWithoutSha.domain).append('\n')
            append("port=").append(planWithoutSha.port).append('\n')
            append("strategy=").append(planWithoutSha.strategy.name).append('\n')
            append("protocol=").append(planWithoutSha.protocol.name).append('\n')
            append("configPath=").append(planWithoutSha.configPath).append('\n')
            append("desiredConfigSha256=").append(planWithoutSha.desiredConfigSha256).append('\n')
            append("certificateSha256=").append(planWithoutSha.certificateSha256 ?: "").append('\n')
            append("certificatePath=").append(planWithoutSha.certificatePath ?: "").append('\n')
            append("privateKeyPath=").append(planWithoutSha.privateKeyPath ?: "").append('\n')
            append("requiresReadOnlyServerPreflight=").append(planWithoutSha.requiresReadOnlyServerPreflight).append('\n')
            append("requiresLivePortConflictProof=").append(planWithoutSha.requiresLivePortConflictProof).append('\n')
            append("requiresConfigSyntaxValidationBeforeActivation=").append(planWithoutSha.requiresConfigSyntaxValidationBeforeActivation).append('\n')
            append("requiresDurableRollbackCheckpoint=").append(planWithoutSha.requiresDurableRollbackCheckpoint).append('\n')
            append("requiresPostServeVerification=").append(planWithoutSha.requiresPostServeVerification).append('\n')
            append("configMutationAuthorized=").append(planWithoutSha.configMutationAuthorized).append('\n')
            append("webServerReloadAuthorized=").append(planWithoutSha.webServerReloadAuthorized).append('\n')
            append("dnsMutationAuthorized=").append(planWithoutSha.dnsMutationAuthorized).append('\n')
            append("firewallMutationAuthorized=").append(planWithoutSha.firewallMutationAuthorized).append('\n')
            append("packageInstallAuthorized=").append(planWithoutSha.packageInstallAuthorized).append('\n')
            append("certificatePrivateKeyTransferRequired=").append(planWithoutSha.certificatePrivateKeyTransferRequired).append('\n')
        }
        return SiteBundleDigest.sha256(canonical.encodeToByteArray())
    }
}

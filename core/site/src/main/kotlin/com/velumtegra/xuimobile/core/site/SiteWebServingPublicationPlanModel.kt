package com.velumtegra.xuimobile.core.site

enum class SiteWebServingStrategy {
    NGINX_CONF_D_STATIC_V1,
}

enum class SiteWebServingProtocol {
    HTTP,
    HTTPS_EXISTING_SERVER_CERTIFICATE,
}

data class SiteStaticPublicationEvidence(
    val preparationSha256: String,
    val remoteHostIdentity: String,
    val targetRoot: String,
    val finalTargetTreeSha256: String,
    val committedClean: Boolean,
    val remoteResidualStateClean: Boolean,
)

data class SiteServerCertificateFileReference(
    val remoteHostIdentity: String,
    val certificateSha256: String,
    val dnsNames: List<String>,
    val certificatePath: String,
    val privateKeyPath: String,
    val usableNow: Boolean,
    val privateKeyPresentOnServer: Boolean,
)

data class SiteWebServingPublicationPlanRequest(
    val preparation: SiteDeployerLocalPreparationResult,
    val staticPublicationEvidence: SiteStaticPublicationEvidence,
    val strategy: SiteWebServingStrategy,
    val certificateReference: SiteServerCertificateFileReference? = null,
)

data class SiteWebServingPublicationPlan(
    val contractVersion: Int,
    val preparationSha256: String,
    val remoteHostIdentity: String,
    val sourceTreeSha256: String,
    val targetRoot: String,
    val domain: String,
    val port: Int,
    val strategy: SiteWebServingStrategy,
    val protocol: SiteWebServingProtocol,
    val configPath: String,
    val desiredConfigUtf8: String,
    val desiredConfigSha256: String,
    val certificateSha256: String?,
    val certificatePath: String?,
    val privateKeyPath: String?,
    val requiresReadOnlyServerPreflight: Boolean,
    val requiresLivePortConflictProof: Boolean,
    val requiresConfigSyntaxValidationBeforeActivation: Boolean,
    val requiresDurableRollbackCheckpoint: Boolean,
    val requiresPostServeVerification: Boolean,
    val configMutationAuthorized: Boolean,
    val webServerReloadAuthorized: Boolean,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val certificatePrivateKeyTransferRequired: Boolean,
    val publicationPlanSha256: String,
)

package com.velumtegra.xuimobile.sitedeployer

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.velumtegra.xuimobile.core.site.DesignSeed
import com.velumtegra.xuimobile.core.site.SiteDeployerReviewBoundary
import com.velumtegra.xuimobile.core.site.SiteDeployerReviewRequest
import com.velumtegra.xuimobile.core.site.SiteDeployerReviewState
import com.velumtegra.xuimobile.core.site.SiteExistingSiteMode
import com.velumtegra.xuimobile.core.site.SiteExistingSiteReport
import com.velumtegra.xuimobile.core.site.SiteServingBackend
import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import com.velumtegra.xuimobile.core.site.SiteRemoteExistingTargetPolicy
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.ThemeFamily
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Site Deployer Android presentation state holder.
 *
 * Phase 11.100 adds an explicit production-bootstrap seam. Persisted targets may be listed, but the
 * ViewModel never auto-selects one. Only an exact operator-selected ServerId + ServerAccessId can
 * request fresh read-only evidence and publication of a reviewed first-publication context. Editing
 * any target-defining input clears that pending context before another deployment can be admitted.
 */
class SiteDeployerReviewViewModel @JvmOverloads constructor(
    private val productionExecutionPort: SiteDeployerProductionExecutionPort =
        DisabledSiteDeployerProductionExecutionPort,
    private val releaseBootstrapPort: SiteDeployerReleaseBootstrapPort =
        DisabledSiteDeployerReleaseBootstrapPort,
) : ViewModel() {
    private var observation: SiteRemotePreflightObservation? = null
    private var productionTargetConfirmed: Boolean = false
    private var productionMutationConfirmed: Boolean = false
    private var productionNoRetryConfirmed: Boolean = false
    private var productionAttemptConsumed: Boolean = false
    private var productionAttemptSnapshot: SiteDeployerReviewUiState? = null
    private var productionExecutionInProgress: Boolean = false
    private var productionExecutionReceipt: SiteProductionDeploymentUiExecutionReceipt? = null
    private var productionExecutionError: String? = null

    private var releaseTargets: List<SiteDeployerReleaseTargetOption> = emptyList()
    private var selectedReleaseServerId: String? = null
    private var selectedReleaseServerAccessId: String? = null
    private var releaseTargetsLoading: Boolean = false
    private var releaseBootstrapInProgress: Boolean = false
    private var releaseBootstrapError: String? = null
    private var releaseBootstrapAdmissionSha256: String? = null
    private var releaseBootstrapPermitExpiresAtEpochMillis: Long? = null
    private var existingSiteConflict: SiteExistingSiteReport? = null
    private var replacesExistingSite: Boolean = false
    private var servingBackend: SiteServingBackend? = null
    private var plannedUrl: String? = null
    private var releaseBootstrapBlockedCategory: SiteServingFailureCategory? = null
    private var webServerInstallInProgress: Boolean = false
    private var webServerInstallMessage: String? = null

    /** Explicit, separately confirmed nginx installation offered only for the exact "no web server" block. */
    fun installWebServer() {
        val serverId = selectedReleaseServerId ?: return
        val accessId = selectedReleaseServerAccessId ?: return
        if (webServerInstallInProgress || releaseBootstrapInProgress) return
        webServerInstallInProgress = true
        webServerInstallMessage = null
        refreshCurrentForm()
        viewModelScope.launch {
            try {
                webServerInstallMessage = releaseBootstrapPort.installWebServer(serverId, accessId)
                releaseBootstrapError = null
                releaseBootstrapBlockedCategory = null
            } catch (cancel: kotlinx.coroutines.CancellationException) {
                throw cancel
            } catch (error: Throwable) {
                android.util.Log.w("VelumSiteDeployer", "nginx install failed", error)
                webServerInstallMessage = error.message ?: "Установка nginx не завершилась."
            } finally {
                webServerInstallInProgress = false
                refreshCurrentForm()
            }
        }
    }

    private val _uiState = MutableStateFlow(buildState(SiteDeployerReviewForm()))
    val uiState: StateFlow<SiteDeployerReviewUiState> = _uiState.asStateFlow()

    fun onSiteNameChanged(value: String) = updateForm { copy(siteName = value) }

    fun onTaglineChanged(value: String) = updateForm { copy(tagline = value) }

    fun onDomainChanged(value: String) = updateForm { copy(domain = value, existingSiteMode = SiteExistingSiteMode.DETECT_ONLY) }

    fun onPortChanged(value: String) = updateForm { copy(port = value, existingSiteMode = SiteExistingSiteMode.DETECT_ONLY) }

    fun onTargetRootChanged(value: String) = updateForm {
        copy(targetRoot = value, existingSiteMode = SiteExistingSiteMode.DETECT_ONLY)
    }

    /**
     * Existing site found: publish next to it on the suggested free port (and, when the folder is
     * taken, in a sibling folder). Runs the same read-only preparation again for the new address.
     */
    fun publishOnSuggestedPort() {
        val report = existingSiteConflict ?: return
        val port = report.suggestedPort ?: return
        updateForm {
            copy(
                port = port.toString(),
                targetRoot = report.suggestedTargetRoot,
                existingSiteMode = SiteExistingSiteMode.DETECT_ONLY,
            )
        }
        prepareProductionContext()
    }

    /**
     * Existing site found: explicitly replace it in the same folder. The previous files are kept in
     * a backup folder until the new files are verified, and restored automatically on failure.
     */
    fun replaceExistingSite() {
        val report = existingSiteConflict ?: return
        if (!report.replaceAvailable) return
        updateForm {
            copy(
                existingSiteMode = SiteExistingSiteMode.REPLACE_EXISTING,
                existingSiteServedOverHttps = report.replaceKeepsExistingWebServerConfig && reuseExisting3xUiCertificate,
                reuseExisting3xUiCertificate = if (report.replaceKeepsExistingWebServerConfig) {
                    false
                } else {
                    reuseExisting3xUiCertificate
                },
            )
        }
        prepareProductionContext()
    }

    fun dismissExistingSiteConflict() {
        existingSiteConflict = null
        refreshCurrentForm()
    }

    fun onSeedChanged(value: String) = updateForm { copy(seed = value) }

    fun onCertificateReuseChanged(value: Boolean) = updateForm {
        copy(reuseExisting3xUiCertificate = value, existingSiteServedOverHttps = false)
    }

    fun generateNextVariant() {
        updateForm {
            val parsed = seed.toLongOrNull() ?: 0L
            val next = if (parsed == Long.MAX_VALUE) Long.MIN_VALUE else parsed + 1L
            copy(seed = next.toString())
        }
    }

    fun cycleThemeOverride() {
        updateForm {
            val values = ThemeFamily.values()
            val next = when (val current = themeFamily) {
                null -> values.first()
                else -> {
                    val index = values.indexOf(current)
                    if (index == values.lastIndex) null else values[index + 1]
                }
            }
            copy(themeFamily = next)
        }
    }

    /** Local persistence read only. Results never imply a selection, even when there is one entry. */
    fun loadProductionTargets() {
        if (releaseTargetsLoading || releaseBootstrapInProgress || productionExecutionInProgress) return
        releaseTargetsLoading = true
        releaseBootstrapError = null
        refreshCurrentForm()
        viewModelScope.launch {
            try {
                val loaded = releaseBootstrapPort.loadTargets()
                releaseTargets = loaded
                val stillPresent = loaded.any {
                    it.serverId == selectedReleaseServerId && it.serverAccessId == selectedReleaseServerAccessId
                }
                if (!stillPresent) {
                    selectedReleaseServerId = null
                    selectedReleaseServerAccessId = null
                    clearPreparedProductionContext()
                }
            } catch (error: Throwable) {
                releaseTargets = emptyList()
                selectedReleaseServerId = null
                selectedReleaseServerAccessId = null
                clearPreparedProductionContext()
                releaseBootstrapError = error.message ?: "Не удалось прочитать сохранённые production-цели."
            } finally {
                releaseTargetsLoading = false
                refreshCurrentForm()
            }
        }
    }

    fun selectProductionTarget(serverId: String, serverAccessId: String) {
        if (releaseBootstrapInProgress || productionExecutionInProgress || productionAttemptConsumed) return
        val exact = releaseTargets.singleOrNull {
            it.serverId == serverId && it.serverAccessId == serverAccessId
        } ?: return
        if (selectedReleaseServerId == exact.serverId && selectedReleaseServerAccessId == exact.serverAccessId) return
        selectedReleaseServerId = exact.serverId
        selectedReleaseServerAccessId = exact.serverAccessId
        clearPreparedProductionContext()
        releaseBootstrapError = null
        refreshCurrentForm()
    }

    /**
     * Explicit read-only bootstrap + context composition. The action itself does not execute the
     * deployment; the existing three production confirmations remain mandatory afterward.
     */
    fun prepareProductionContext() {
        if (releaseBootstrapInProgress || productionExecutionInProgress || productionAttemptConsumed) return
        val current = _uiState.value
        val form = current.form
        val serverId = selectedReleaseServerId ?: run {
            releaseBootstrapError = "Сначала явно выберите ServerId + ServerAccessId."
            refreshCurrentForm()
            return
        }
        val accessId = selectedReleaseServerAccessId ?: run {
            releaseBootstrapError = "Сначала явно выберите ServerId + ServerAccessId."
            refreshCurrentForm()
            return
        }
        val seed = form.seed.toLongOrNull() ?: run {
            releaseBootstrapError = "Seed должен быть целым 64-битным числом."
            refreshCurrentForm()
            return
        }
        val port = form.port.toIntOrNull()?.takeIf { it in 1..65535 } ?: run {
            releaseBootstrapError = "Порт должен быть числом от 1 до 65535."
            refreshCurrentForm()
            return
        }
        if (form.targetRoot.isBlank()) {
            releaseBootstrapError = "Укажите точную целевую папку на VPS."
            refreshCurrentForm()
            return
        }

        clearPreparedProductionContext(forceRegistryClear = true)
        existingSiteConflict = null
        releaseBootstrapBlockedCategory = null
        releaseBootstrapInProgress = true
        releaseBootstrapError = null
        refreshCurrentForm()
        viewModelScope.launch {
            try {
                val result = releaseBootstrapPort.prepareReviewedFirstPublicationContext(
                    SiteDeployerReleaseBootstrapRequest(
                        serverId = serverId,
                        serverAccessId = accessId,
                        rootSeed = seed,
                        siteName = form.siteName.trim().ifEmpty { null },
                        tagline = form.tagline.trim().ifEmpty { null },
                        themeFamily = form.themeFamily,
                        domain = form.domain,
                        servicePort = port,
                        targetRoot = form.targetRoot,
                        reuseExisting3xUiCertificate = form.reuseExisting3xUiCertificate,
                        existingSiteMode = form.existingSiteMode,
                        existingSiteServedOverHttps = form.existingSiteMode == SiteExistingSiteMode.REPLACE_EXISTING &&
                            form.existingSiteServedOverHttps,
                    ),
                )
                require(result.serverId == serverId && result.serverAccessId == accessId) {
                    "Prepared production context returned a different exact target"
                }
                observation = result.remoteObservation
                releaseBootstrapAdmissionSha256 = result.releaseBootstrapAdmissionSha256
                releaseBootstrapPermitExpiresAtEpochMillis = result.coordinatorPermitExpiresAtEpochMillis
                replacesExistingSite = result.replacesExistingSite
                servingBackend = result.servingBackend
                plannedUrl = result.plannedUrl
                invalidateProductionUiAttempt()
            } catch (conflict: SiteDeployerExistingSiteConflictException) {
                clearPreparedProductionContext(forceRegistryClear = true)
                existingSiteConflict = conflict.report
            } catch (blocked: SiteDeployerServingBlockedException) {
                clearPreparedProductionContext(forceRegistryClear = true)
                releaseBootstrapBlockedCategory = blocked.category
                releaseBootstrapError = blocked.message
            } catch (error: Throwable) {
                if (error is kotlinx.coroutines.CancellationException) throw error
                clearPreparedProductionContext(forceRegistryClear = true)
                android.util.Log.w("VelumSiteDeployer", "Server check failed", error)
                releaseBootstrapError = error.message?.takeIf { it.isNotBlank() }
                    ?: ("Проверка сервера не завершилась (внутренняя ошибка " +
                        (error::class.simpleName ?: "без названия") + "). Сервер не изменялся.")
            } finally {
                releaseBootstrapInProgress = false
                refreshCurrentForm()
            }
        }
    }

    /** Called when leaving the screen; a short-lived unconsumed mutation permit is not kept hidden. */
    fun clearPendingProductionContext() {
        if (productionExecutionInProgress) return
        clearPreparedProductionContext(forceRegistryClear = true)
        refreshCurrentForm()
    }

    /**
     * Read-only integration seam retained for previously accepted tests/providers. Replacing evidence
     * invalidates every production UI confirmation because readiness/review identity may have changed.
     */
    fun replaceReadOnlyObservation(value: SiteRemotePreflightObservation?) {
        observation = value
        invalidateProductionUiAttempt()
        _uiState.value = buildState(_uiState.value.form)
    }

    fun onProductionTargetConfirmed(value: Boolean) {
        if (productionAttemptConsumed) return
        productionTargetConfirmed = value
        refreshCurrentForm()
    }

    fun onProductionMutationConfirmed(value: Boolean) {
        if (productionAttemptConsumed) return
        productionMutationConfirmed = value
        refreshCurrentForm()
    }

    fun onProductionNoRetryConfirmed(value: Boolean) {
        if (productionAttemptConsumed) return
        productionNoRetryConfirmed = value
        refreshCurrentForm()
    }

    /**
     * Consumes the local UI attempt before launching suspend work. A second tap therefore cannot
     * issue another call. Process-loss/restart safety remains enforced by the durable replay fence.
     */
    fun executeProductionDeployOnce() {
        val snapshot = _uiState.value
        val admission = snapshot.productionAdmission ?: return
        if (!snapshot.productionDeployEnabled || productionAttemptConsumed || productionExecutionInProgress) return

        val authorization = try {
            SiteProductionDeploymentAndroidUiExecutionBoundary.authorize(
                admission = admission,
                approval = SiteProductionDeploymentUiApproval(
                    operatorApprovalChallengeSha256 = admission.operatorApprovalChallengeSha256,
                    exactTargetConfirmed = productionTargetConfirmed,
                    realServerMutationConfirmed = productionMutationConfirmed,
                    singleAttemptNoRetryConfirmed = productionNoRetryConfirmed,
                ),
                approvedAtEpochMillis = System.currentTimeMillis(),
            )
        } catch (error: IllegalArgumentException) {
            // The runtime permit is deliberately capped at 60 s (SiteProductionDeploymentRuntimeMutationBoundary).
            productionExecutionError = if (error.message?.contains("permit expired", ignoreCase = true) == true) {
                "Проверка сервера устарела: после неё прошло больше минуты. Нажмите «Проверить сервер» " +
                    "ещё раз и опубликуйте в течение минуты. Сервер не изменялся."
            } else {
                error.message ?: "Публикация не подтверждена. Сервер не изменялся."
            }
            refreshCurrentForm()
            return
        }

        productionAttemptSnapshot = snapshot
        productionAttemptConsumed = true
        productionExecutionInProgress = true
        productionExecutionReceipt = null
        productionExecutionError = null
        refreshCurrentForm()

        viewModelScope.launch {
            try {
                val receipt = productionExecutionPort.executeOnce(authorization)
                SiteProductionDeploymentAndroidUiExecutionBoundary.validateReceipt(receipt, authorization)
                productionExecutionReceipt = receipt
            } catch (error: Throwable) {
                productionExecutionError = error.message
                    ?: "Production deployment failed; this exact UI attempt will not be retried automatically."
            } finally {
                productionExecutionInProgress = false
                refreshCurrentForm()
            }
        }
    }

    private fun updateForm(transform: SiteDeployerReviewForm.() -> SiteDeployerReviewForm) {
        if (productionExecutionInProgress) return
        val next = _uiState.value.form.transform()
        clearPreparedProductionContext()
        releaseBootstrapError = null
        releaseBootstrapBlockedCategory = null
        existingSiteConflict = null
        _uiState.value = buildState(next)
    }

    private fun clearPreparedProductionContext(forceRegistryClear: Boolean = false) {
        val bootstrapOwnsPendingContext = releaseBootstrapAdmissionSha256 != null
        if (forceRegistryClear || bootstrapOwnsPendingContext) {
            releaseBootstrapPort.clearPendingContext()
        }
        observation = null
        releaseBootstrapAdmissionSha256 = null
        releaseBootstrapPermitExpiresAtEpochMillis = null
        replacesExistingSite = false
        servingBackend = null
        plannedUrl = null
        invalidateProductionUiAttempt()
    }

    private fun invalidateProductionUiAttempt() {
        productionTargetConfirmed = false
        productionMutationConfirmed = false
        productionNoRetryConfirmed = false
        productionAttemptConsumed = false
        productionAttemptSnapshot = null
        productionExecutionInProgress = false
        productionExecutionReceipt = null
        productionExecutionError = null
    }

    private fun refreshCurrentForm() {
        _uiState.value = buildState(_uiState.value.form)
    }

    private fun buildState(form: SiteDeployerReviewForm): SiteDeployerReviewUiState {
        // The execution port consumes the registry entry before remote work. Preserve the
        // approved review while showing progress or the outcome of that same one-shot attempt.
        productionAttemptSnapshot?.let { attempt ->
            return commonState(
                form = form,
                review = attempt.review,
                validationMessage = null,
                realServerMutationEnabled = productionExecutionInProgress,
                productionAdmission = attempt.productionAdmission,
                productionDeployEnabled = false,
            )
        }
        val seed = form.seed.toLongOrNull()
            ?: return invalid(form, "Seed должен быть целым 64-битным числом.")
        val port = form.port.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: return invalid(form, "Порт должен быть числом от 1 до 65535.")

        return try {
            val targetBinding = runCatching {
                productionExecutionPort.currentTargetBinding()
            }.getOrNull()
            val review = SiteDeployerReviewBoundary.prepare(
                SiteDeployerReviewRequest(
                    rootSeed = DesignSeed(seed),
                    siteName = form.siteName.trim().ifEmpty { null },
                    tagline = form.tagline.trim().ifEmpty { null },
                    themeFamily = form.themeFamily,
                    domain = form.domain,
                    servicePort = port,
                    remoteHostIdentity = targetBinding?.remoteHostIdentity ?: FIXTURE_REMOTE_HOST,
                    targetRoot = targetBinding?.targetRoot ?: FIXTURE_TARGET_ROOT,
                    owner = targetBinding?.owner ?: FIXTURE_OWNER,
                    group = targetBinding?.group ?: FIXTURE_GROUP,
                    existingTargetPolicy = targetBinding?.existingTargetPolicy
                        ?: SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT,
                    reuseExisting3xUiCertificate = form.reuseExisting3xUiCertificate,
                    trustedServerKeySha256 = targetBinding?.trustedServerKeySha256 ?: FIXTURE_SERVER_KEY_SHA256,
                    observation = observation,
                ),
            )
            val productionAdmission = runCatching {
                productionExecutionPort.currentAdmission(review)
            }.getOrNull()?.let { candidate ->
                runCatching {
                    SiteProductionDeploymentAndroidUiExecutionBoundary.validateForReview(candidate, review)
                    candidate
                }.getOrNull()
            }
            val productionDeployEnabled = productionAdmission != null &&
                productionTargetConfirmed &&
                productionMutationConfirmed &&
                productionNoRetryConfirmed &&
                !productionAttemptConsumed &&
                !productionExecutionInProgress

            commonState(
                form = form,
                review = review,
                validationMessage = null,
                writeActionsEnabled = productionDeployEnabled,
                realServerMutationEnabled = productionDeployEnabled || productionExecutionInProgress,
                productionAdmission = productionAdmission,
                productionDeployEnabled = productionDeployEnabled,
            )
        } catch (_: IllegalArgumentException) {
            invalid(form, "Параметры конструктора не прошли проверку. Проверьте домен и введённые значения.")
        }
    }

    private fun invalid(form: SiteDeployerReviewForm, message: String) = commonState(
        form = form,
        review = null,
        validationMessage = message,
        productionAdmission = null,
        productionDeployEnabled = false,
    )

    private fun commonState(
        form: SiteDeployerReviewForm,
        review: SiteDeployerReviewState?,
        validationMessage: String?,
        writeActionsEnabled: Boolean = false,
        realServerMutationEnabled: Boolean = false,
        productionAdmission: SiteProductionDeploymentUiAdmission?,
        productionDeployEnabled: Boolean,
    ) = SiteDeployerReviewUiState(
        form = form,
        review = review,
        validationMessage = validationMessage,
        writeActionsEnabled = writeActionsEnabled,
        realServerMutationEnabled = realServerMutationEnabled,
        productionAdmission = productionAdmission,
        productionTargetConfirmed = productionTargetConfirmed,
        productionMutationConfirmed = productionMutationConfirmed,
        productionNoRetryConfirmed = productionNoRetryConfirmed,
        productionDeployEnabled = productionDeployEnabled,
        productionExecutionInProgress = productionExecutionInProgress,
        productionAttemptConsumed = productionAttemptConsumed,
        productionExecutionReceipt = productionExecutionReceipt,
        productionExecutionError = productionExecutionError,
        releaseTargets = releaseTargets,
        selectedReleaseServerId = selectedReleaseServerId,
        selectedReleaseServerAccessId = selectedReleaseServerAccessId,
        releaseTargetsLoading = releaseTargetsLoading,
        releaseBootstrapInProgress = releaseBootstrapInProgress,
        releaseBootstrapError = releaseBootstrapError,
        releaseBootstrapAdmissionSha256 = releaseBootstrapAdmissionSha256,
        releaseBootstrapPermitExpiresAtEpochMillis = releaseBootstrapPermitExpiresAtEpochMillis,
        existingSiteConflict = existingSiteConflict,
        replacesExistingSite = replacesExistingSite,
        servingBackend = servingBackend,
        plannedUrl = plannedUrl,
        releaseBootstrapBlockedCategory = releaseBootstrapBlockedCategory,
        webServerInstallOffered = releaseBootstrapError == com.velumtegra.xuimobile.core.site.SITE_NO_WEB_SERVER_REASON,
        webServerInstallInProgress = webServerInstallInProgress,
        webServerInstallMessage = webServerInstallMessage,
    )

    companion object {
        internal const val FIXTURE_REMOTE_HOST = "fixture.review.local"
        internal const val FIXTURE_TARGET_ROOT = "/srv/www/site"
        internal const val FIXTURE_OWNER = "www_data"
        internal const val FIXTURE_GROUP = "www_data"
        internal val FIXTURE_SERVER_KEY_SHA256: String = "a".repeat(64)
    }
}

data class SiteDeployerReviewForm(
    val seed: String = "114",
    val siteName: String = "",
    val tagline: String = "",
    val themeFamily: ThemeFamily? = null,
    val domain: String = "site.example.com",
    val port: String = "443",
    val targetRoot: String = "/var/www/velum-site",
    val reuseExisting3xUiCertificate: Boolean = false,
    val existingSiteMode: SiteExistingSiteMode = SiteExistingSiteMode.DETECT_ONLY,
    /** Files-only replacement of a site published with the 3x-ui certificate: verify over https. */
    val existingSiteServedOverHttps: Boolean = false,
)

data class SiteDeployerReviewUiState(
    val form: SiteDeployerReviewForm,
    val review: SiteDeployerReviewState?,
    val validationMessage: String?,
    val writeActionsEnabled: Boolean = false,
    val realServerMutationEnabled: Boolean = false,
    val productionAdmission: SiteProductionDeploymentUiAdmission? = null,
    val productionTargetConfirmed: Boolean = false,
    val productionMutationConfirmed: Boolean = false,
    val productionNoRetryConfirmed: Boolean = false,
    val productionDeployEnabled: Boolean = false,
    val productionExecutionInProgress: Boolean = false,
    val productionAttemptConsumed: Boolean = false,
    val productionExecutionReceipt: SiteProductionDeploymentUiExecutionReceipt? = null,
    val productionExecutionError: String? = null,
    val releaseTargets: List<SiteDeployerReleaseTargetOption> = emptyList(),
    val selectedReleaseServerId: String? = null,
    val selectedReleaseServerAccessId: String? = null,
    val releaseTargetsLoading: Boolean = false,
    val releaseBootstrapInProgress: Boolean = false,
    val releaseBootstrapError: String? = null,
    val releaseBootstrapAdmissionSha256: String? = null,
    val releaseBootstrapPermitExpiresAtEpochMillis: Long? = null,
    /** Read-only probe found an existing site / busy port; the operator must choose what to do. */
    val existingSiteConflict: SiteExistingSiteReport? = null,
    /** The prepared publication replaces the existing site in the same folder. */
    val replacesExistingSite: Boolean = false,
    /** Web server detected on the server that will serve the site. */
    val servingBackend: SiteServingBackend? = null,
    /** Address that will be checked from this device after publication. */
    val plannedUrl: String? = null,
    /** Why preparation was blocked (incompatible web server, DNS, firewall…), if it was. */
    val releaseBootstrapBlockedCategory: SiteServingFailureCategory? = null,
    /** The server has no Caddy/nginx at all: offer a separately confirmed nginx install. */
    val webServerInstallOffered: Boolean = false,
    val webServerInstallInProgress: Boolean = false,
    val webServerInstallMessage: String? = null,
)

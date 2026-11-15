package com.velumtegra.xuimobile.sitedeployer

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider

/** Explicit Activity composition: production builds no longer obtain the disabled default port. */
internal class SiteDeployerReviewViewModelFactory(
    private val productionExecutionPort: SiteDeployerProductionExecutionPort,
    private val releaseBootstrapPort: SiteDeployerReleaseBootstrapPort,
) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        require(modelClass.isAssignableFrom(SiteDeployerReviewViewModel::class.java))
        return SiteDeployerReviewViewModel(productionExecutionPort, releaseBootstrapPort) as T
    }
}

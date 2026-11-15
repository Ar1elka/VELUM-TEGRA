package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.ServerAccess
import com.velumtegra.xuimobile.core.site.SiteDeploymentRemoteRuntime
import com.velumtegra.xuimobile.core.site.SiteRemoteDeployPlan
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightObservation
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportAuthorization
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportCapabilities
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportExecutor
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportResult
import com.velumtegra.xuimobile.core.site.SiteRemoteTransportSource

/**
 * Exact-session Site Deployer runtime for Phase 11.12.
 *
 * Read-only evidence is collected before any SFTP mutation. The authorization is then bound to the
 * bounded JSch SFTP capability profile, and the concrete primitive lease is opened only for the
 * executor transaction. No arbitrary command or remote path API is exposed by this runtime.
 */
class SiteRemoteSshDeploymentRuntime(
    private val access: ServerAccess,
    private val session: SshSessionHandle,
    private val observationAdapter: SiteRemoteReadOnlyObservationSshAdapter = SiteRemoteReadOnlyObservationSshAdapter(),
    private val sftpFactory: SiteRemoteSftpPrimitiveFactory = SiteRemoteSftpPrimitiveFactory(),
) : SiteDeploymentRemoteRuntime {
    override val capabilities: SiteRemoteTransportCapabilities
        get() = SiteRemoteSftpPrimitiveFactory.CAPABILITIES

    override suspend fun observe(plan: SiteRemoteDeployPlan): SiteRemotePreflightObservation =
        observationAdapter.collectPreflight(plan, access, session)

    override suspend fun execute(
        authorization: SiteRemoteTransportAuthorization,
        source: SiteRemoteTransportSource,
    ): SiteRemoteTransportResult {
        val primitive = sftpFactory.open(authorization, access, session)
        return try {
            SiteRemoteTransportExecutor(primitive).execute(authorization, source)
        } finally {
            primitive.close()
        }
    }
}

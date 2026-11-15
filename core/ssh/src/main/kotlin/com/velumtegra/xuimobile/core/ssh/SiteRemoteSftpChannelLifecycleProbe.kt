package com.velumtegra.xuimobile.core.ssh

import java.time.Duration

/**
 * Narrow production SFTP lifecycle primitive: open one SFTP channel on one already-verified exact
 * SSH session, prove it became open, then close it without issuing any SFTP file operation.
 *
 * This class deliberately exposes no path/read/write/list/mutation API. The wider bounded SFTP
 * primitive remains behind SiteRemoteSftpPrimitiveFactory and a later deployment boundary.
 */
data class SiteRemoteSftpChannelLifecycleEvidence(
    val channelOpened: Boolean,
    val channelClosed: Boolean,
    val sftpOperationPerformed: Boolean,
)

class SiteRemoteSftpChannelLifecycleProbe {
    fun openAndClose(
        session: SshSessionHandle,
        channelOpenTimeout: Duration = SshTransportConfig().channelOpenTimeout,
    ): SiteRemoteSftpChannelLifecycleEvidence {
        require(session.isOpen) { "SSH session is closed" }
        require(session is VerifiedHostKeySshSessionHandle) {
            "SFTP channel lifecycle requires verified host-key evidence"
        }
        val capable = session as? SiteRemoteSftpCapableSessionHandle
            ?: error("SSH session does not expose the bounded Site SFTP channel")
        val channel = capable.openSiteRemoteSftpChannel(channelOpenTimeout)
        try {
            require(channel.isOpen) { "SFTP channel did not reach open state" }
        } finally {
            channel.close()
        }
        require(!channel.isOpen) { "SFTP channel remained open after close" }
        return SiteRemoteSftpChannelLifecycleEvidence(
            channelOpened = true,
            channelClosed = true,
            sftpOperationPerformed = false,
        )
    }
}

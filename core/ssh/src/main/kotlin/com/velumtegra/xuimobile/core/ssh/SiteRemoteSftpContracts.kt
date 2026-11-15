package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.site.SiteRemoteObservedPathType
import java.time.Duration

internal data class SiteRemoteSftpPathObservation(
    val type: SiteRemoteObservedPathType,
    val sizeBytes: Long,
    val uid: Int,
    val gid: Int,
    val permissions: Int,
)

internal data class SiteRemoteSftpDirectoryEntry(
    val name: String,
    val observation: SiteRemoteSftpPathObservation,
)

internal interface SiteRemoteSftpChannelHandle : AutoCloseable {
    val isOpen: Boolean

    fun lstat(path: String): SiteRemoteSftpPathObservation
    fun mkdir(path: String)
    fun writeFile(path: String, payload: ByteArray)
    fun readFile(path: String, maxBytes: Int): ByteArray
    fun listDirectory(path: String, maxEntries: Int): List<SiteRemoteSftpDirectoryEntry>
    fun chmod(path: String, permissions: Int)
    fun chown(path: String, uid: Int)
    fun chgrp(path: String, gid: Int)
    fun rename(fromPath: String, toPath: String)
    fun removeFile(path: String)
    fun removeDirectory(path: String)

    override fun close()
}

internal interface SiteRemoteSftpCapableSessionHandle : VerifiedHostKeySshSessionHandle {
    fun openSiteRemoteSftpChannel(
        channelOpenTimeout: Duration = SshTransportConfig().channelOpenTimeout,
    ): SiteRemoteSftpChannelHandle
}

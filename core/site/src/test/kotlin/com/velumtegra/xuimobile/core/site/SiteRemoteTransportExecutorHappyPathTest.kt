package com.velumtegra.xuimobile.core.site

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteRemoteTransportExecutorHappyPathTest {
    @Test
    fun `executor commits exact staged tree and preserves backup`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(
            seed = 8191L,
            policy = SiteRemoteExistingTargetPolicy.BACKUP_AND_REPLACE,
        )
        val primitive = InMemoryRemotePrimitive(
            capabilities = SiteRemoteTransportTestFixtures.fullCapabilities(),
            initialTargetRoot = fixture.plan.publish.targetRoot,
        )
        val authorization = SiteRemoteTransportBoundary.authorize(fixture.plan, fixture.preflight, primitive.capabilities)
        val source = fixture.source()

        val result = SiteRemoteTransportExecutor(primitive).execute(authorization, source)

        assertEquals(SiteRemoteTransportOutcome.COMMITTED, result.outcome)
        assertEquals(fixture.plan.fileCount, result.uploadedFileCount)
        assertEquals(fixture.plan.totalBytes, result.uploadedBytes)
        assertEquals(fixture.plan.sourceTreeSha256, result.publishedTreeSha256)
        assertEquals(SiteRemoteObservedPathType.DIRECTORY, primitive.statPath(fixture.plan.publish.targetRoot))
        assertEquals(SiteRemoteObservedPathType.ABSENT, primitive.statPath(fixture.plan.publish.stagingRoot))
        assertEquals(SiteRemoteObservedPathType.DIRECTORY, primitive.statPath(requireNotNull(fixture.plan.publish.backupRoot)))
        assertTrue(primitive.hasFile("${fixture.plan.publish.backupRoot}/legacy.txt"))
        assertTrue(primitive.operationLog.first().startsWith("STAT:"))
        assertTrue(primitive.operationLog.any { it.startsWith("INSPECT_TREE:${fixture.plan.publish.targetRoot}:") })
        SiteRemoteTransportPolicy.validateResult(authorization, result)
    }

    @Test
    fun `upload authorization retains media type needed for real tree verification`() {
        val fixture = SiteRemoteTransportTestFixtures.readyFixture(8192L, SiteRemoteExistingTargetPolicy.REQUIRE_ABSENT)
        val authorization = SiteRemoteTransportBoundary.authorize(
            fixture.plan,
            fixture.preflight,
            SiteRemoteTransportTestFixtures.fullCapabilities(),
        )
        val uploads = authorization.forwardOperations.filterIsInstance<SiteRemoteTransportOperation.UploadFile>()

        assertEquals(fixture.plan.entries.map { it.mediaType }, uploads.map { it.mediaType })
        assertEquals(fixture.plan.entries.map { it.path }, uploads.map { it.relativePath })
    }
}

internal fun SiteRemoteTransportFixture.source(): SiteRemoteTransportSource {
    val bytes = exportPlan.entries.associate { it.path to it.content.encodeToByteArray() }
    return SiteRemoteTransportSource { path -> requireNotNull(bytes[path]).copyOf() }
}

internal class InMemoryRemotePrimitive(
    override val capabilities: SiteRemoteTransportCapabilities,
    initialTargetRoot: String? = null,
    var failAtCall: Int? = null,
    var failAfterApply: Boolean = false,
    var failRemoveTransactionTreeOnce: Boolean = false,
) : SiteRemoteTransportPrimitivePort {
    val operationLog = mutableListOf<String>()
    private val directories = linkedSetOf<String>()
    private val files = linkedMapOf<String, ByteArray>()
    private var callCounter = 0
    private var failureConsumed = false

    init {
        if (initialTargetRoot != null) {
            directories += initialTargetRoot
            files["$initialTargetRoot/legacy.txt"] = "legacy".encodeToByteArray()
        }
    }

    fun hasFile(path: String): Boolean = files.containsKey(path)

    override fun statPath(path: String): SiteRemoteObservedPathType = invoke("STAT:$path") {
        when {
            path in directories -> SiteRemoteObservedPathType.DIRECTORY
            path in files -> SiteRemoteObservedPathType.FILE
            else -> SiteRemoteObservedPathType.ABSENT
        }
    }

    override fun createDirectory(path: String, owner: String, group: String, mode: String) {
        invoke("MKDIR:$path:$owner:$group:$mode") {
            require(path !in files) { "File already exists at directory path" }
            directories += path
        }
    }

    override fun uploadFile(remotePath: String, payload: ByteArray) {
        invoke("UPLOAD:$remotePath:${payload.size}") {
            files[remotePath] = payload.copyOf()
        }
    }

    override fun fileSha256(remotePath: String): String = invoke("SHA:$remotePath") {
        SiteBundleDigest.sha256(requireNotNull(files[remotePath]))
    }

    override fun applyMetadata(path: String, owner: String, group: String, mode: String) {
        invoke("META:$path:$owner:$group:$mode") {
            require(path in directories || path in files) { "Metadata target does not exist: $path" }
        }
    }

    override fun inspectTree(
        rootPath: String,
        entries: List<SiteRemoteTransportTreeEntrySpec>,
    ): SiteRemoteTransportTreeObservation = invoke("INSPECT_TREE:$rootPath:${entries.size}") {
        require(rootPath in directories) { "Tree root does not exist: $rootPath" }
        val prefix = "$rootPath/"
        val actualPaths = files.keys
            .filter { it.startsWith(prefix) }
            .map { it.removePrefix(prefix) }
            .sorted()
        val expectedPaths = entries.map { it.relativePath }.sorted()
        require(actualPaths == expectedPaths) { "Tree paths mismatch" }
        val byPath = entries.associateBy { it.relativePath }
        val documents = actualPaths.map { relative ->
            val bytes = requireNotNull(files[prefix + relative])
            SiteDocument(
                path = relative,
                mediaType = requireNotNull(byPath[relative]).mediaType,
                content = bytes.decodeToString(),
            )
        }
        SiteRemoteTransportTreeObservation(
            rootPath = rootPath,
            treeSha256 = SiteBundleDigest.treeSha256(documents),
            fileCount = documents.size,
            totalBytes = documents.sumOf { it.byteSize.toLong() },
        )
    }

    override fun atomicRename(fromPath: String, toPath: String) {
        invoke("RENAME:$fromPath:$toPath") {
            require(toPath !in directories && toPath !in files) { "Rename destination exists: $toPath" }
            require(fromPath in directories) { "Rename source is not a directory: $fromPath" }
            val dirMoves = directories.filter { it == fromPath || it.startsWith("$fromPath/") }
                .associateWith { toPath + it.removePrefix(fromPath) }
            val fileMoves = files.filterKeys { it.startsWith("$fromPath/") }
                .mapKeys { (path, _) -> toPath + path.removePrefix(fromPath) }
            directories.removeAll(dirMoves.keys)
            directories.addAll(dirMoves.values)
            val oldFilePaths = files.keys.filter { it.startsWith("$fromPath/") }
            oldFilePaths.forEach(files::remove)
            fileMoves.forEach { (path, bytes) -> files[path] = bytes }
        }
    }

    override fun removeTransactionTree(path: String) {
        invoke("REMOVE:$path") {
            if (failRemoveTransactionTreeOnce) {
                failRemoveTransactionTreeOnce = false
                error("Injected rollback cleanup failure: $path")
            }
            directories.removeAll { it == path || it.startsWith("$path/") }
            files.keys.filter { it == path || it.startsWith("$path/") }.toList().forEach(files::remove)
        }
    }

    private fun <T> invoke(label: String, block: () -> T): T {
        callCounter += 1
        operationLog += label
        val shouldFail = !failureConsumed && failAtCall == callCounter
        if (shouldFail && !failAfterApply) {
            failureConsumed = true
            error("Injected primitive failure before call $callCounter: $label")
        }
        val value = block()
        if (shouldFail && failAfterApply) {
            failureConsumed = true
            error("Injected primitive failure after call $callCounter: $label")
        }
        return value
    }
}

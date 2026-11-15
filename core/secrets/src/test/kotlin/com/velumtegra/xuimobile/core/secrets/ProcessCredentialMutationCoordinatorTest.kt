package com.velumtegra.xuimobile.core.secrets

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcessCredentialMutationCoordinatorTest {
    @Test
    fun `separate coordinator instances share one process writer lane`() = runBlocking {
        val first = ProcessCredentialMutationCoordinator()
        val second = ProcessCredentialMutationCoordinator()
        val firstEntered = CompletableDeferred<Unit>()
        val releaseFirst = CompletableDeferred<Unit>()
        val secondEntered = CompletableDeferred<Unit>()

        val firstJob = launch {
            first.runExclusive {
                firstEntered.complete(Unit)
                releaseFirst.await()
            }
        }
        firstEntered.await()

        val secondJob = launch {
            second.runExclusive {
                secondEntered.complete(Unit)
            }
        }
        yield()
        assertFalse(secondEntered.isCompleted)

        releaseFirst.complete(Unit)
        firstJob.join()
        secondJob.join()
        assertTrue(secondEntered.isCompleted)
    }

    @Test
    fun `exception releases process writer lane`() = runBlocking {
        val first = ProcessCredentialMutationCoordinator()
        val second = ProcessCredentialMutationCoordinator()

        runCatching {
            first.runExclusive<Unit> { error("injected failure") }
        }

        var entered = false
        second.runExclusive { entered = true }
        assertTrue(entered)
    }
}

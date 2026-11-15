package com.velumtegra.xuimobile.core.runtime.android

import android.app.ApplicationExitInfo
import android.os.Build
import com.velumtegra.xuimobile.core.runtime.RecoveryExitProvenance
import org.junit.Assert.assertEquals
import org.junit.Test

class ApplicationExitInfoAdapterTest {
    @Test
    fun `api 24 to 29 never query unavailable historical exit api`() {
        val source = CountingExitSource(HistoricalProcessExitRecord(ApplicationExitInfo.REASON_CRASH))
        val adapter = adapter(sdkInt = 29, source = source)

        assertEquals(RecoveryExitProvenance.UNKNOWN, adapter.previousExitProvenance())
        assertEquals(0, source.calls)
    }

    @Test
    fun `missing historical record is UNKNOWN`() {
        val adapter = adapter(sdkInt = 30, source = CountingExitSource(null))

        assertEquals(RecoveryExitProvenance.UNKNOWN, adapter.previousExitProvenance())
    }

    @Test
    fun `historical query security or runtime failure is UNKNOWN`() {
        val security = adapter(
            sdkInt = 30,
            source = HistoricalProcessExitRecordSource { throw SecurityException("denied") },
        )
        val runtime = adapter(
            sdkInt = 30,
            source = HistoricalProcessExitRecordSource { throw IllegalStateException("broken") },
        )

        assertEquals(RecoveryExitProvenance.UNKNOWN, security.previousExitProvenance())
        assertEquals(RecoveryExitProvenance.UNKNOWN, runtime.previousExitProvenance())
    }

    @Test
    fun `crash native crash and ANR are trusted process death evidence`() {
        listOf(
            ApplicationExitInfo.REASON_CRASH,
            ApplicationExitInfo.REASON_CRASH_NATIVE,
            ApplicationExitInfo.REASON_ANR,
        ).forEach { reason ->
            assertEquals(
                RecoveryExitProvenance.PROCESS_DEATH,
                ApplicationExitReasonMapper.map(30, reason),
            )
        }
    }

    @Test
    fun `low memory excessive resource and dependency death are system stop evidence`() {
        listOf(
            ApplicationExitInfo.REASON_LOW_MEMORY,
            ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE,
            ApplicationExitInfo.REASON_DEPENDENCY_DIED,
        ).forEach { reason ->
            assertEquals(
                RecoveryExitProvenance.SYSTEM_STOP,
                ApplicationExitReasonMapper.map(30, reason),
            )
        }
    }

    @Test
    fun `freezer is system stop only where framework reason exists`() {
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(32, ApplicationExitInfo.REASON_FREEZER),
        )
        assertEquals(
            RecoveryExitProvenance.SYSTEM_STOP,
            ApplicationExitReasonMapper.map(33, ApplicationExitInfo.REASON_FREEZER),
        )
    }

    @Test
    fun `user requested is ambiguous before api 34`() {
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(30, ApplicationExitInfo.REASON_USER_REQUESTED),
        )
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(33, ApplicationExitInfo.REASON_USER_REQUESTED),
        )
    }

    @Test
    fun `user requested is user stop on api 34 plus`() {
        assertEquals(
            RecoveryExitProvenance.USER_REQUESTED_STOP,
            ApplicationExitReasonMapper.map(34, ApplicationExitInfo.REASON_USER_REQUESTED),
        )
    }

    @Test
    fun `android user profile stop takes conservative user stop path`() {
        assertEquals(
            RecoveryExitProvenance.USER_REQUESTED_STOP,
            ApplicationExitReasonMapper.map(30, ApplicationExitInfo.REASON_USER_STOPPED),
        )
    }

    @Test
    fun `signal and self exit remain UNKNOWN because cause is ambiguous`() {
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(30, ApplicationExitInfo.REASON_SIGNALED),
        )
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(30, ApplicationExitInfo.REASON_EXIT_SELF),
        )
    }

    @Test
    fun `permission and package change reasons never authorize automatic recovery`() {
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(30, ApplicationExitInfo.REASON_PERMISSION_CHANGE),
        )
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(34, ApplicationExitInfo.REASON_PACKAGE_UPDATED),
        )
        assertEquals(
            RecoveryExitProvenance.UNKNOWN,
            ApplicationExitReasonMapper.map(34, ApplicationExitInfo.REASON_PACKAGE_STATE_CHANGE),
        )
    }

    @Test
    fun `unknown other and future reason fail closed`() {
        listOf(
            ApplicationExitInfo.REASON_UNKNOWN,
            ApplicationExitInfo.REASON_OTHER,
            Int.MAX_VALUE,
        ).forEach { reason ->
            assertEquals(
                RecoveryExitProvenance.UNKNOWN,
                ApplicationExitReasonMapper.map(Build.VERSION_CODES.UPSIDE_DOWN_CAKE, reason),
            )
        }
    }

    @Test
    fun `adapter queries exactly once and returns mapped latest evidence`() {
        val source = CountingExitSource(HistoricalProcessExitRecord(ApplicationExitInfo.REASON_CRASH))
        val adapter = adapter(sdkInt = 30, source = source)

        assertEquals(RecoveryExitProvenance.PROCESS_DEATH, adapter.previousExitProvenance())
        assertEquals(1, source.calls)
    }

    private fun adapter(
        sdkInt: Int,
        source: HistoricalProcessExitRecordSource,
    ): AndroidApplicationExitInfoAdapter = AndroidApplicationExitInfoAdapter(
        sdkIntProvider = { sdkInt },
        recordSource = source,
    )

    private class CountingExitSource(
        private val record: HistoricalProcessExitRecord?,
    ) : HistoricalProcessExitRecordSource {
        var calls: Int = 0
            private set

        override fun latest(): HistoricalProcessExitRecord? {
            calls += 1
            return record
        }
    }
}

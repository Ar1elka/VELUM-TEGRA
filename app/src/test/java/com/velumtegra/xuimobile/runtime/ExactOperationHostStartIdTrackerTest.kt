package com.velumtegra.xuimobile.runtime

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ExactOperationHostStartIdTrackerTest {
    @Test
    fun noStopTokenExistsBeforeAndroidDeliversAStart() {
        assertNull(ExactOperationHostStartIdTracker().latest())
    }

    @Test
    fun newerStartIdBecomesTheOnlySafeTeardownHighWaterMark() {
        val tracker = ExactOperationHostStartIdTracker()

        assertEquals(1, tracker.observe(1))
        assertEquals(2, tracker.observe(2))
        assertEquals(2, tracker.latest())
    }

    @Test
    fun staleOrDuplicateObservationCannotLowerLatestStartId() {
        val tracker = ExactOperationHostStartIdTracker()
        tracker.observe(7)

        assertEquals(7, tracker.observe(7))
        assertEquals(7, tracker.observe(3))
        assertEquals(7, tracker.latest())
    }

    @Test(expected = IllegalArgumentException::class)
    fun nonPositiveStartIdFailsClosed() {
        ExactOperationHostStartIdTracker().observe(0)
    }
}

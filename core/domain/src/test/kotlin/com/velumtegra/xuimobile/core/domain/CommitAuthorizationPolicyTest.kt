package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.RemoteVerificationState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CommitAuthorizationPolicyTest {
    @Test
    fun `exit success without readback cannot commit`() {
        assertFalse(
            CommitAuthorizationPolicy.mayCommitRemoteMutation(
                CommandCompletion.ConfirmedSuccess,
                RemoteVerificationState.UNVERIFIED,
            ),
        )
    }

    @Test
    fun `unknown completion can commit after authoritative readback`() {
        assertTrue(
            CommitAuthorizationPolicy.mayCommitRemoteMutation(
                CommandCompletion.Unknown("transport closed"),
                RemoteVerificationState.VERIFIED,
            ),
        )
    }

    @Test
    fun `confirmed failure does not override authoritative verified remote state`() {
        assertTrue(
            CommitAuthorizationPolicy.mayCommitRemoteMutation(
                CommandCompletion.ConfirmedFailure("remote command reported failure", 1),
                RemoteVerificationState.VERIFIED,
            ),
        )
    }

    @Test
    fun `confirmed failure without authoritative verification cannot commit`() {
        assertFalse(
            CommitAuthorizationPolicy.mayCommitRemoteMutation(
                CommandCompletion.ConfirmedFailure("remote command rejected", 1),
                RemoteVerificationState.CONTRADICTED,
            ),
        )
    }
}

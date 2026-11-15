package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.RemoteVerificationState

object CommitAuthorizationPolicy {
    /**
     * Command completion is evidence about the command/transport, not remote state truth.
     * Local state may be committed only after authoritative remote verification.
     * A confirmed command failure may still coexist with verified desired remote state
     * (for example, the state was already applied); operation outcome is tracked separately.
     */
    fun mayCommitRemoteMutation(
        @Suppress("UNUSED_PARAMETER") commandCompletion: CommandCompletion,
        verification: RemoteVerificationState,
    ): Boolean = verification == RemoteVerificationState.VERIFIED
}

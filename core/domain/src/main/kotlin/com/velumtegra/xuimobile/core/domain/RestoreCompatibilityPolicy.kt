package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*
import java.security.MessageDigest

object RestoreCompatibilityBindingPolicy {
    fun parentMatches(check: VersionedOperationSnapshot, backup: VersionedOperationSnapshot,
        installation: XuiInstallation, access: ServerAccess): Boolean =
        check.snapshot.status==OperationStatus.SUCCEEDED && check.snapshot.checkpoint.semantics==CheckpointSemantics.TERMINAL &&
        RestoreCheckBinding.parse(check.snapshot.checkpoint.phaseName)?.first==RestoreCheckPhase.VERIFIED &&
        RestoreCheckBindingPolicy.matches(check,installation,access,backup)
    fun bind(id: OperationId, installation: XuiInstallation, access: ServerAccess,
        check: VersionedOperationSnapshot, backup: VersionedOperationSnapshot): RestoreCompatibilityBinding {
        require(parentMatches(check,backup,installation,access) && id!=check.snapshot.operationId && id!=backup.snapshot.operationId)
        val source=requireNotNull(RestoreCheckBinding.parse(check.snapshot.checkpoint.phaseName)).second
        val seed=InstallationBackupBindingPolicy.bind(id,installation,access,source.source.version,source.source.architecture).digest
        val canonical=listOf("RESTORE_COMPATIBILITY_V1",seed,check.snapshot.operationId.value,check.revision.value.toString(),
            source.phaseName(RestoreCheckPhase.VERIFIED)).joinToString(""){"${it.length}:$it"}
        val digest=MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)).joinToString(""){"%02x".format(it.toInt() and 255)}
        return RestoreCompatibilityBinding(check.snapshot.operationId,check.revision.value,source,digest)
    }
    fun matches(current: VersionedOperationSnapshot, installation: XuiInstallation, access: ServerAccess,
        check: VersionedOperationSnapshot, backup: VersionedOperationSnapshot): Boolean {
        val b=RestoreCompatibilityBinding.parse(current.snapshot.checkpoint.phaseName)?.second?:return false
        if(current.snapshot.type!=OperationType.RESTORE_COMPATIBILITY || current.snapshot.target!=check.snapshot.target)return false
        return try { b==bind(current.snapshot.operationId,installation,access,check,backup) }catch(_:IllegalArgumentException){false}
    }
}

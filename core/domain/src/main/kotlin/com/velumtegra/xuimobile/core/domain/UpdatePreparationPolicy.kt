package com.velumtegra.xuimobile.core.domain

import com.velumtegra.xuimobile.core.model.*

enum class UpdatePreparationCheck { DIRECT_ROOT, STANDARD_LAYOUT, SERVICE_EXECUTABLE, CURRENT_VERSION, ACTIVE_SERVICE, SAVED_SETTINGS }

/** Reports checks of the current installation only; neither success nor this list is mutation consent. */
object UpdatePreparationPolicy {
    fun blockingChecks(snapshot: UpdatePreflightSnapshot): Set<UpdatePreparationCheck> = buildSet {
        if (snapshot.root != UpdateRootStatus.DIRECT_ROOT) add(UpdatePreparationCheck.DIRECT_ROOT)
        if (snapshot.layout != UpdateLayoutStatus.STANDARD_3X_UI_SYSTEMD) add(UpdatePreparationCheck.STANDARD_LAYOUT)
        if (snapshot.serviceDefinition != DeepDiagnosticServiceDefinitionStatus.CONSISTENT) add(UpdatePreparationCheck.SERVICE_EXECUTABLE)
        if (snapshot.currentVersion == null) add(UpdatePreparationCheck.CURRENT_VERSION)
        if (snapshot.serviceState != ManagementServiceState.ACTIVE) add(UpdatePreparationCheck.ACTIVE_SERVICE)
        if (snapshot.baselineStatus != ManagementBaselineStatus.Matched) add(UpdatePreparationCheck.SAVED_SETTINGS)
    }
}

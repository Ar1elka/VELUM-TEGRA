package com.velumtegra.xuimobile.sitedeployer

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.velumtegra.xuimobile.core.site.BackgroundFamily
import com.velumtegra.xuimobile.core.site.SiteDeployerPreflightState
import com.velumtegra.xuimobile.core.site.SiteExistingSiteReport
import com.velumtegra.xuimobile.core.site.SiteRemotePreflightCheckCode
import com.velumtegra.xuimobile.core.site.SiteReplaceBlocker
import com.velumtegra.xuimobile.core.site.SiteServingBackend
import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import com.velumtegra.xuimobile.core.site.ThemeFamily
import com.velumtegra.xuimobile.core.site.TypographyProfile

@Composable
fun SiteDeployerReviewScreen(
    viewModel: SiteDeployerReviewViewModel,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val state by viewModel.uiState.collectAsState()

    fun navigateBack() {
        viewModel.clearPendingProductionContext()
        onBack()
    }

    BackHandler { navigateBack() }

    Column(
        modifier = modifier
            .fillMaxSize()
            .testTag("site_deployer_review_root")
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = ::navigateBack, modifier = Modifier.testTag("site_deployer_back")) {
                Text("← Назад")
            }
            Text("Конструктор сайта", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        }

        StatusCard(state)

        SiteCard(state, viewModel)
        AddressCard(state, viewModel)

        state.validationMessage?.let { message ->
            MessageCard(message = message, isError = true)
        }

        ServerCard(state, viewModel)
        state.existingSiteConflict?.let { report -> ExistingSiteCard(report, state, viewModel) }

        state.review?.let { review ->
            if (review.preflight.state == SiteDeployerPreflightState.BLOCKED && review.preflightBlockers.isNotEmpty()) {
                SectionCard("Сервер не готов") {
                    review.preflightBlockers.forEach { blocker ->
                        Text("• ${preflightCheckLabel(blocker.code)}", style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        PublishCard(state, viewModel)
    }
}

@Composable
private fun StatusCard(state: SiteDeployerReviewUiState) {
    val receipt = state.productionExecutionReceipt
    val (title, detail) = when {
        receipt != null -> when (publicationResultOf(receipt)) {
            PublicationResult.REACHABLE -> "Сайт доступен извне" to (receipt.servingOutcome?.verifiedUrl ?: "")
            PublicationResult.FILES_ONLY -> "Файлы загружены, но сайт не опубликован" to
                (receipt.servingOutcome?.failureMessage ?: "Доступность сайта снаружи не подтверждена.")
            PublicationResult.ROLLED_BACK -> "Публикация отменена" to "Сервер остался в прежнем состоянии."
        }
        state.productionAttemptConsumed && state.productionExecutionError != null ->
            "Публикация остановилась" to state.productionExecutionError
        state.productionExecutionInProgress -> "Публикация…" to "Не закрывайте экран."
        state.productionAdmission != null -> "Можно публиковать" to "Отметьте три пункта внизу и нажмите «Опубликовать»."
        state.releaseBootstrapInProgress -> "Проверяем сервер…" to "Только чтение, сервер не меняется."
        state.existingSiteConflict != null -> "Нужно решение" to "На сервере уже есть сайт или занят порт."
        state.releaseBootstrapBlockedCategory != null ->
            failureTitle(state.releaseBootstrapBlockedCategory) to "Исправьте и проверьте сервер ещё раз."
        state.selectedReleaseServerAccessId != null -> "Сервер выбран" to "Нажмите «Проверить сервер»."
        else -> "Шаг 1 из 4" to "Настройте сайт и адрес, затем выберите сервер."
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onPrimaryContainer)
        }
    }
}

@Composable
private fun SiteCard(state: SiteDeployerReviewUiState, viewModel: SiteDeployerReviewViewModel) {
    SectionCard("1 · Сайт") {
        OutlinedTextField(
            value = state.form.siteName,
            onValueChange = viewModel::onSiteNameChanged,
            modifier = Modifier.fillMaxWidth().testTag("site_deployer_site_name"),
            label = { Text("Название") },
            placeholder = { Text(state.review?.design?.siteName ?: "Сгенерируется автоматически") },
            singleLine = true,
        )
        OutlinedTextField(
            value = state.form.tagline,
            onValueChange = viewModel::onTaglineChanged,
            modifier = Modifier.fillMaxWidth().testTag("site_deployer_tagline"),
            label = { Text("Подзаголовок") },
            singleLine = true,
        )
        state.review?.let { review ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                ColorDot(review.design.accentHex)
                ColorDot(review.design.backgroundHex)
                Text(
                    "${backgroundLabel(review.design.backgroundFamily)} · ${typographyLabel(review.design.typographyProfile)}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = viewModel::generateNextVariant,
                modifier = Modifier.weight(1f).testTag("site_deployer_new_variant"),
            ) {
                Text("Другой вариант")
            }
            OutlinedButton(
                onClick = viewModel::cycleThemeOverride,
                modifier = Modifier.weight(1f).testTag("site_deployer_theme"),
            ) {
                Text(themeLabel(state.form.themeFamily), maxLines = 1)
            }
        }
        OutlinedTextField(
            value = state.form.seed,
            onValueChange = viewModel::onSeedChanged,
            modifier = Modifier.fillMaxWidth().testTag("site_deployer_seed"),
            label = { Text("Номер варианта") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )
    }
}

@Composable
private fun AddressCard(state: SiteDeployerReviewUiState, viewModel: SiteDeployerReviewViewModel) {
    SectionCard("2 · Адрес") {
        OutlinedTextField(
            value = state.form.domain,
            onValueChange = viewModel::onDomainChanged,
            modifier = Modifier.fillMaxWidth().testTag("site_deployer_domain"),
            label = { Text("Домен") },
            singleLine = true,
        )
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = state.form.port,
                onValueChange = viewModel::onPortChanged,
                modifier = Modifier.weight(0.35f).testTag("site_deployer_port"),
                label = { Text("Порт") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            OutlinedTextField(
                value = state.form.targetRoot,
                onValueChange = viewModel::onTargetRootChanged,
                modifier = Modifier.weight(0.65f).testTag("site_deployer_target_root"),
                label = { Text("Папка на сервере") },
                singleLine = true,
            )
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("HTTPS с сертификатом 3x-ui")
                Text(
                    "Сертификат должен быть выпущен на этот домен",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = state.form.reuseExisting3xUiCertificate,
                onCheckedChange = viewModel::onCertificateReuseChanged,
                modifier = Modifier.testTag("site_deployer_certificate_reuse"),
            )
        }
    }
}

@Composable
private fun ServerCard(state: SiteDeployerReviewUiState, viewModel: SiteDeployerReviewViewModel) {
    SectionCard("3 · Сервер") {
        val busy = state.releaseBootstrapInProgress || state.productionExecutionInProgress
        if (state.releaseTargets.isEmpty()) {
            OutlinedButton(
                onClick = viewModel::loadProductionTargets,
                enabled = !state.releaseTargetsLoading && !busy,
                modifier = Modifier.fillMaxWidth().testTag("site_deployer_load_release_targets"),
            ) {
                Text(if (state.releaseTargetsLoading) "Загрузка…" else "Показать мои серверы")
            }
        }
        state.releaseTargets.forEach { target ->
            val selected = target.serverId == state.selectedReleaseServerId &&
                target.serverAccessId == state.selectedReleaseServerAccessId
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(
                    selected = selected,
                    onClick = { viewModel.selectProductionTarget(target.serverId, target.serverAccessId) },
                    enabled = !busy && !state.productionAttemptConsumed,
                    modifier = Modifier.testTag("site_deployer_release_target_${target.serverAccessId}"),
                )
                Column(Modifier.weight(1f)) {
                    Text(target.serverDisplayName, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
                    Text(
                        "${target.sshUsername}@${target.remoteHostIdentity}:${target.sshPort}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        if (state.releaseTargets.isNotEmpty()) {
            val hasSelection = state.selectedReleaseServerId != null && state.selectedReleaseServerAccessId != null
            Button(
                onClick = viewModel::prepareProductionContext,
                enabled = hasSelection && !busy && !state.productionAttemptConsumed,
                modifier = Modifier.fillMaxWidth().testTag("site_deployer_prepare_production_context"),
            ) {
                Text(if (state.releaseBootstrapInProgress) "Проверяем…" else "Проверить сервер")
            }
        }
        if (state.releaseBootstrapAdmissionSha256 != null) {
            val via = when (state.servingBackend) {
                SiteServingBackend.CADDY -> " Сайт будет обслуживать Caddy."
                SiteServingBackend.NGINX -> " Сайт будет обслуживать nginx."
                null -> ""
            }
            Text(
                "✓ " + (if (state.replacesExistingSite) "Сервер готов. Существующий сайт будет заменён." else "Сервер готов.") + via,
                modifier = Modifier.testTag("site_deployer_release_bootstrap_ready"),
                // primary is the brand red here and reads as an error; success stays neutral.
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.SemiBold,
            )
        }
        state.releaseBootstrapError?.let { error ->
            val title = state.releaseBootstrapBlockedCategory?.let { failureTitle(it) + ". " }.orEmpty()
            MessageCard(message = title + error, isError = true, tag = "site_deployer_release_bootstrap_error")
        }
        var confirmNginx by androidx.compose.runtime.saveable.rememberSaveable { androidx.compose.runtime.mutableStateOf(false) }
        if (state.webServerInstallOffered || state.webServerInstallInProgress) {
            Button(
                onClick = { confirmNginx = true },
                enabled = !busy && !state.webServerInstallInProgress,
                modifier = Modifier.fillMaxWidth().testTag("site_deployer_install_nginx"),
            ) { Text(if (state.webServerInstallInProgress) "Устанавливаем nginx… (до нескольких минут)" else "Установить nginx") }
        }
        state.webServerInstallMessage?.let {
            MessageCard(message = it, isError = false, tag = "site_deployer_install_nginx_result")
        }
        if (confirmNginx) {
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { confirmNginx = false },
                title = { Text("Установить nginx?") },
                text = {
                    Text(
                        "На выбранный сервер будет установлен пакет nginx из репозитория системы и запущена его служба. " +
                            "nginx займёт порт 80. Это изменение VPS; автоматически оно не откатывается.",
                    )
                },
                confirmButton = {
                    Button(onClick = { confirmNginx = false; viewModel.installWebServer() }) { Text("Установить") }
                },
                dismissButton = {
                    androidx.compose.material3.TextButton(onClick = { confirmNginx = false }) { Text("Отмена") }
                },
            )
        }
    }
}

@Composable
private fun ExistingSiteCard(
    report: SiteExistingSiteReport,
    state: SiteDeployerReviewUiState,
    viewModel: SiteDeployerReviewViewModel,
) {
    val busy = state.releaseBootstrapInProgress || state.productionExecutionInProgress
    Card(
        modifier = Modifier.fillMaxWidth().testTag("site_deployer_existing_site"),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
    ) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                if (report.targetFolderPresent) "На сервере уже есть сайт" else "Порт ${report.port} занят",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            if (report.targetFolderPresent) {
                Text("Папка ${report.targetRoot}: ${filesLabel(report.targetFileCount)}.")
            }
            when {
                report.configPresent -> Text("Он открыт на порту ${report.port}.")
                report.portUsedByOtherService -> Text(
                    "Порт ${report.port} уже занят: другой программой или этот домен уже настроен в веб-сервере.",
                )
            }

            report.suggestedPort?.let { port ->
                Button(
                    onClick = viewModel::publishOnSuggestedPort,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth().testTag("site_deployer_use_suggested_port"),
                ) {
                    Text("Поставить рядом на порт $port")
                }
                if (report.suggestedTargetRoot != report.targetRoot) {
                    Text(
                        "Новая папка: ${report.suggestedTargetRoot}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                    )
                }
            }

            if (report.targetFolderPresent) {
                OutlinedButton(
                    onClick = viewModel::replaceExistingSite,
                    enabled = !busy && report.replaceAvailable,
                    modifier = Modifier.fillMaxWidth().testTag("site_deployer_replace_existing"),
                ) {
                    Text("Заменить существующий")
                }
                Text(
                    report.replaceBlocker?.let(::replaceBlockerLabel)
                        ?: "Старые файлы восстановятся автоматически, если что-то пойдёт не так.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                )
            }
            TextButton(onClick = viewModel::dismissExistingSiteConflict, enabled = !busy) {
                Text("Изменить адрес вручную")
            }
        }
    }
}

@Composable
private fun PublishCard(state: SiteDeployerReviewUiState, viewModel: SiteDeployerReviewViewModel) {
    SectionCard("4 · Публикация") {
        val admission = state.productionAdmission
        if (admission == null) {
            Text(
                "Станет доступна после проверки сервера.",
                modifier = Modifier.testTag("site_deployer_production_unavailable"),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(
                onClick = { },
                enabled = false,
                modifier = Modifier.fillMaxWidth().testTag("site_deployer_production_deploy"),
            ) {
                Text("Опубликовать")
            }
            return@SectionCard
        }

        Text(
            state.plannedUrl ?: "${admission.serviceDomain}:${admission.servicePort}",
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            "Адрес будет проверен с этого телефона после публикации.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            "${admission.remoteHostIdentity} · ${admission.targetRoot}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (state.replacesExistingSite) {
            Text("Существующий сайт в этой папке будет заменён.", color = MaterialTheme.colorScheme.error)
        }

        val locked = state.productionAttemptConsumed || state.productionExecutionInProgress
        ConfirmRow(
            checked = state.productionTargetConfirmed,
            onChecked = viewModel::onProductionTargetConfirmed,
            enabled = !locked,
            tag = "site_deployer_confirm_exact_target",
            text = "Адрес и папка верны",
        )
        ConfirmRow(
            checked = state.productionMutationConfirmed,
            onChecked = viewModel::onProductionMutationConfirmed,
            enabled = !locked,
            tag = "site_deployer_confirm_real_mutation",
            text = "Разрешаю изменить сервер",
        )
        ConfirmRow(
            checked = state.productionNoRetryConfirmed,
            onChecked = viewModel::onProductionNoRetryConfirmed,
            enabled = !locked,
            tag = "site_deployer_confirm_no_retry",
            text = "Понимаю: публикация запускается один раз",
        )

        Button(
            onClick = viewModel::executeProductionDeployOnce,
            enabled = state.productionDeployEnabled,
            modifier = Modifier.fillMaxWidth().testTag("site_deployer_production_deploy"),
        ) {
            Text(if (state.productionExecutionInProgress) "Публикация…" else "Опубликовать")
        }

        state.productionExecutionReceipt?.let { receipt ->
            val outcome = receipt.servingOutcome
            when (publicationResultOf(receipt)) {
                PublicationResult.REACHABLE -> MessageCard(
                    message = "Сайт доступен извне: ${outcome?.verifiedUrl ?: state.plannedUrl.orEmpty()}",
                    isError = false,
                    tag = "site_deployer_production_result",
                )
                PublicationResult.FILES_ONLY -> MessageCard(
                    message = buildString {
                        append("Файлы загружены, но сайт не опубликован")
                        outcome?.failureCategory?.let { append(" — ").append(failureTitle(it).lowercase()) }
                        append(".")
                        outcome?.failureMessage?.let { append("\n").append(it) }
                        if (outcome?.servedOnServer == true) append("\nНа самом сервере сайт уже открывается.")
                        if (outcome?.configRolledBack == true) append("\nНастройки веб-сервера возвращены как были.")
                    },
                    isError = true,
                    tag = "site_deployer_production_result",
                )
                PublicationResult.ROLLED_BACK -> MessageCard(
                    message = "Не удалось: изменения отменены, сервер в прежнем состоянии.",
                    isError = true,
                    tag = "site_deployer_production_result",
                )
            }
        }
        state.productionExecutionError?.let { error ->
            MessageCard(message = "Ошибка: $error", isError = true, tag = "site_deployer_production_error")
        }
    }
}

@Composable
private fun ConfirmRow(
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
    enabled: Boolean,
    tag: String,
    text: String,
) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChecked, enabled = enabled, modifier = Modifier.testTag(tag))
        Text(text, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun MessageCard(message: String, isError: Boolean, tag: String? = null) {
    val container = if (isError) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.secondaryContainer
    val content = if (isError) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSecondaryContainer
    Card(
        modifier = Modifier.fillMaxWidth().let { if (tag != null) it.testTag(tag) else it },
        colors = CardDefaults.cardColors(containerColor = container),
    ) {
        Text(message, modifier = Modifier.padding(12.dp), color = content, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            content()
        }
    }
}

@Composable
private fun ColorDot(hex: String) {
    val color = runCatching { Color(android.graphics.Color.parseColor(hex)) }.getOrNull() ?: return
    Box(
        Modifier
            .size(18.dp)
            .clip(CircleShape)
            .background(color)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, CircleShape),
    )
}

private enum class PublicationResult { REACHABLE, FILES_ONLY, ROLLED_BACK }

private fun publicationResultOf(receipt: SiteProductionDeploymentUiExecutionReceipt): PublicationResult = when {
    receipt.status == SiteProductionDeploymentUiExecutionStatus.COORDINATOR_ROLLED_BACK_CLEAN -> PublicationResult.ROLLED_BACK
    receipt.status == SiteProductionDeploymentUiExecutionStatus.COORDINATOR_COMMITTED_SERVING_NOT_VERIFIED -> PublicationResult.FILES_ONLY
    // Only an externally verified result counts as published; files-only commits never do.
    receipt.servingOutcome?.externallyReachable == true -> PublicationResult.REACHABLE
    else -> PublicationResult.FILES_ONLY
}

private fun failureTitle(category: SiteServingFailureCategory): String = when (category) {
    SiteServingFailureCategory.BACKEND_INCOMPATIBLE -> "Неподходящий веб-сервер"
    SiteServingFailureCategory.PORT_CONFLICT -> "Порт занят"
    SiteServingFailureCategory.FIREWALL -> "Порт закрыт файрволом"
    SiteServingFailureCategory.DNS -> "Проблема с DNS"
    SiteServingFailureCategory.CERTIFICATE -> "Проблема с сертификатом"
    SiteServingFailureCategory.CONFIG_INVALID -> "Ошибка конфига веб-сервера"
    SiteServingFailureCategory.RELOAD_FAILED -> "Веб-сервер не перезагрузился"
    SiteServingFailureCategory.SERVING_VERIFICATION -> "Проверка сайта не прошла"
    SiteServingFailureCategory.EXTERNAL_UNREACHABLE -> "Сайт недоступен снаружи"
    SiteServingFailureCategory.SERVER_COMMAND_FAILED -> "Команда на сервере завершилась с ошибкой"
}

private fun filesLabel(count: Int): String {
    val mod100 = count % 100
    val mod10 = count % 10
    val word = when {
        mod100 in 11..14 -> "файлов"
        mod10 == 1 -> "файл"
        mod10 in 2..4 -> "файла"
        else -> "файлов"
    }
    return "$count $word"
}

private fun replaceBlockerLabel(blocker: SiteReplaceBlocker): String = when (blocker) {
    SiteReplaceBlocker.TARGET_ABSENT -> "Заменять нечего: папки нет."
    SiteReplaceBlocker.TARGET_NOT_DIRECTORY -> "Заменить нельзя: по этому пути не папка."
    SiteReplaceBlocker.TARGET_EMPTY -> "Заменить нельзя: папка пустая — укажите другую папку."
    SiteReplaceBlocker.TOO_MANY_FILES -> "Заменить автоматически нельзя: в папке слишком много файлов."
    SiteReplaceBlocker.UNSUPPORTED_ENTRIES -> "Заменить автоматически нельзя: в папке есть ссылки или пустые папки."
    SiteReplaceBlocker.UNSUPPORTED_FILE -> "Заменить автоматически нельзя: в папке есть файлы, кроме html/css/js/svg/txt (например, картинки)."
    SiteReplaceBlocker.TOO_LARGE -> "Заменить автоматически нельзя: файлы слишком большие."
    SiteReplaceBlocker.PORT_USED_BY_OTHER_SERVICE -> "Заменить нельзя: порт занят другой программой."
}

private fun themeLabel(theme: ThemeFamily?): String = when (theme) {
    null -> "Тема: авто"
    ThemeFamily.DARK_TECH -> "Тёмная"
    ThemeFamily.GRAPHITE_NEON -> "Графит и неон"
    ThemeFamily.COOL_BLUE -> "Синяя"
    ThemeFamily.VIOLET_MAGENTA -> "Фиолетовая"
    ThemeFamily.WARM_AMBER -> "Янтарная"
    ThemeFamily.LIGHT_MINIMAL -> "Светлая"
    ThemeFamily.MUTED_PROFESSIONAL -> "Деловая"
    ThemeFamily.MONOCHROME_ACCENT -> "Монохром"
}

private fun backgroundLabel(background: BackgroundFamily): String = when (background) {
    BackgroundFamily.PARTICLE_NETWORK -> "Сеть частиц"
    BackgroundFamily.GLOW_FIELDS -> "Звёзды и свечение"
    BackgroundFamily.MESH_GRADIENT -> "Волны"
    BackgroundFamily.TECH_GRID -> "Схема"
    BackgroundFamily.GEOMETRY -> "Геометрия"
    BackgroundFamily.MINIMAL -> "Минимализм"
    BackgroundFamily.NOISE_TEXTURE -> "Зерно"
}

private fun typographyLabel(profile: TypographyProfile): String = when (profile) {
    TypographyProfile.SYSTEM_MODERN -> "современный шрифт"
    TypographyProfile.SYSTEM_COMPACT -> "компактный шрифт"
    TypographyProfile.SYSTEM_TECH -> "моноширинный шрифт"
    TypographyProfile.SYSTEM_EDITORIAL -> "шрифт с засечками"
}

private fun preflightCheckLabel(code: SiteRemotePreflightCheckCode): String = when (code) {
    SiteRemotePreflightCheckCode.SERVER_HOST_IDENTITY -> "Сервер не совпадает с выбранным"
    SiteRemotePreflightCheckCode.SERVER_KEY_FINGERPRINT -> "Ключ сервера не совпадает с сохранённым"
    SiteRemotePreflightCheckCode.TARGET_STATE -> "Папка сайта в неподходящем состоянии"
    SiteRemotePreflightCheckCode.STAGING_STATE -> "Осталась временная папка от прошлой публикации"
    SiteRemotePreflightCheckCode.BACKUP_STATE -> "Осталась резервная папка от прошлой замены"
    SiteRemotePreflightCheckCode.AVAILABLE_CAPACITY -> "Мало свободного места"
    SiteRemotePreflightCheckCode.OWNER_ACCOUNT -> "Нет пользователя-владельца файлов"
    SiteRemotePreflightCheckCode.GROUP_ACCOUNT -> "Нет группы-владельца файлов"
    SiteRemotePreflightCheckCode.OWNERSHIP_APPLICABLE -> "Нет прав назначить владельца файлов"
    SiteRemotePreflightCheckCode.MODE_APPLICABLE -> "Нет прав выставить права файлов"
    SiteRemotePreflightCheckCode.CERTIFICATE_PRESENT -> "Сертификат 3x-ui не найден"
    SiteRemotePreflightCheckCode.CERTIFICATE_SERVER_IDENTITY -> "Сертификат с другого сервера"
    SiteRemotePreflightCheckCode.CERTIFICATE_DOMAIN -> "Сертификат выпущен на другой домен"
    SiteRemotePreflightCheckCode.CERTIFICATE_USABLE_NOW -> "Сертификат просрочен или ещё не действует"
    SiteRemotePreflightCheckCode.CERTIFICATE_PRIVATE_KEY_SERVER_RESIDENT -> "Нет закрытого ключа сертификата на сервере"
}

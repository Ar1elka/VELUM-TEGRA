package com.velumtegra.xuimobile.integration

import android.os.Bundle
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.discovery.*
import com.velumtegra.xuimobile.readiness.*
import com.velumtegra.xuimobile.ui.theme.VelumTegraTheme
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/** REAL native screen and production ports. Network is opt-in; local publication uses the existing UI save action. */
class Phase15_10T4_17LiveEnrollmentUiInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private enum class Stage { TARGET, OPEN, DISCOVERY, REVIEW, SAVE, READBACK }
    private fun emit(line: String) {
        require(line.length <= 512 && '\n' !in line && '\r' !in line)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply { putString("stream", "$line\n") })
    }
    private fun <T> RepositoryResult<T>.required(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("LOCAL_REPOSITORY_UNAVAILABLE")
    }
    private fun digest(v: String) = MessageDigest.getInstance("SHA-256").digest(v.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
    private fun click(tag: String) = compose.onNodeWithTag(tag).performScrollTo().performClick()
    private fun type(tag: String, value: String) = compose.onNodeWithTag(tag).performScrollTo().performTextInput(value)
    private fun await(success: String, blocked: String? = null) {
        compose.waitUntil(150_000) { present(success) || (blocked != null && present(blocked)) }
        assertTrue(present(success))
    }
    /** Compare known static UI messages without logging text or a Compose tree. */
    private fun reviewDiagnostic(): String = runCatching {
        if (present("xui_enroll_verified")) "READY"
        else if (present("xui_enroll_progress")) "PENDING"
        else if (!present("xui_enroll_review_blocked")) "NO_REVIEW_VIEW"
        else {
            val known = listOf(
                "На сервере не найден sqlite3. Параметры панели не прочитаны." to "SQLITE_CLI_UNAVAILABLE",
                "База панели недоступна для чтения через выбранный SSH-доступ." to "DATABASE_UNREADABLE",
                "Не удалось выполнить запрос к базе панели. Проверьте её формат и состояние." to "SETTINGS_QUERY_FAILED",
                "Ответ с параметрами панели имеет неподдерживаемый формат." to "SETTINGS_MALFORMED",
                "Ответ с параметрами панели превышает допустимый размер." to "SETTINGS_TRUNCATED",
                "Чтение параметров не завершилось с подтверждённым результатом. Повторите проверку." to "SETTINGS_READ_UNCERTAIN",
                "Не удалось подтвердить параметры установки. Ничего не сохранено." to "INSTALLATION_READ_FAILED",
                "Не удалось безопасно прочитать настройки 3x-ui (нужен sqlite3 и право чтения БД)." to "SETTINGS_READ_UNAVAILABLE",
                "Не удалось повторно подтвердить установленную 3x-ui." to "DISCOVERY_RECHECK_FAILED",
                "Идентичность 3x-ui изменилась или недостаточно доказательств." to "IDENTITY_RECHECK_FAILED",
                "Параметры панели не соответствуют установленной 3x-ui." to "SETTINGS_IDENTITY_MISMATCH",
                "Порт и веб-путь не подтверждены. Ничего не сохраняем." to "BASELINE_INCOMPLETE",
                "Проверка прервана или данные несовместимы. Нет новых записей." to "REVIEW_EXCEPTION",
                "Цель, параметры или срок проверки не совпали. Проверьте установку заново." to "UI_REVIEW_FENCE",
                "Подтверждение устарело. Проверьте установку заново." to "UI_REVIEW_EXPIRED",
                "SSH-подключение или проверка ключа отклонены. VPS не изменён." to "SSH_REJECTED",
                "Точная SSH-сессия или отпечаток сервера не подтверждены." to "SSH_SESSION_BINDING_REJECTED",
                "SSH-отпечаток не подтверждён." to "SAVED_PIN_INVALID",
                "Проверка недоступна." to "UI_PORT_EXCEPTION",
            )
            known.firstOrNull { (message, _) ->
                compose.onAllNodes(hasTestTag("xui_enroll_review_blocked") and hasText(message))
                    .fetchSemanticsNodes().isNotEmpty()
            }?.second ?: "OTHER_BLOCKED"
        }
    }.getOrDefault("UI_UNAVAILABLE")
    private fun failed(stage: Stage): Nothing {
        if (stage == Stage.REVIEW) emit("LIVE_UI_REVIEW_DIAGNOSTIC=" + reviewDiagnostic())
        throw AssertionError("LIVE_UI_BLOCKED_STAGE=${stage.name}")
    }
    @Test fun exactAuthorizedNativeUiEnrollment() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("LIVE_UI_OPT_IN_REQUIRED", args.getString("live_authorization") == "REAL_TEST_SERVER_UI_ENROLLMENT")
        assertEquals("192.0.2.169", args.getString("live_host")); assertEquals("22", args.getString("live_port"))
        val nonce = args.getString("live_run_nonce").orEmpty()
        assertTrue(Regex("[0-9a-f]{32}").matches(nonce))
        var stage = Stage.TARGET
        try {
            val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
            fun exact(): Pair<VersionedRecord<Server>, ServerAccess> = runBlocking {
                val servers = app.inventoryServerRepository.list().required()
                assertTrue(servers.size <= 128 && servers.map { it.value.id }.distinct().size == servers.size)
                val matches = mutableListOf<Pair<VersionedRecord<Server>, ServerAccess>>()
                for (server in servers) {
                    val accesses = app.inventoryServerAccessRepository.listForServer(server.value.id).required()
                    assertTrue(accesses.size <= 64 && accesses.all { it.serverId == server.value.id })
                    assertEquals(accesses.size, accesses.map { it.id }.distinct().size)
                    matches += accesses.filter { it.endpoint.host == "192.0.2.169" && it.endpoint.port == 22 }.map { server to it }
                }
                assertEquals(1, matches.size)
                val selected = matches.single()
                assertEquals(selected.first, app.inventoryServerRepository.get(selected.first.value.id).required())
                assertEquals(selected.second, app.inventoryServerAccessRepository.get(selected.second.id).required())
                selected
            }
            val selected = exact(); val server = selected.first.value; val access = selected.second
            fun stable() { assertEquals(selected, exact()) }
            val reviewed = (LocalSshReadinessPolicy.inspect(server.id.value, access.id.value, access) as? LocalSshReadinessResult.MetadataPresent)?.summary
                ?: throw AssertionError("INVALID_SAVED_TARGET")
            val target = LiveSshConnectionPolicy.exactTarget(reviewed)
            fun installations() = runBlocking { app.inventoryInstallationRepository.listForServer(server.id).required() }.also { list ->
                assertTrue(list.size <= 96 && list.all { it.value.serverId == server.id })
                assertEquals(list.size, list.map { it.value.id }.distinct().size)
            }
            fun matches(i: XuiInstallation) = i.identity.let {
                it.serviceUnit == "x-ui.service" && it.binaryPath == "/usr/local/x-ui/x-ui" &&
                    it.rootPath == "/usr/local/x-ui" && it.databasePath == "/etc/x-ui/x-ui.db"
            }
            val before = installations(); assertTrue(before.count { matches(it.value) } <= 1)
            emit("LIVE_UI_ENROLLMENT_BEGIN=192.0.2.169:22"); emit("LIVE_RUN_NONCE=$nonce")
            emit("LIVE_SAVED_TARGET_SHA256=" + digest(listOf(server.id.value, selected.first.revision.value.toString(),
                access.id.value, reviewed.host, reviewed.port.toString(), reviewed.username, reviewed.savedFingerprint,
                reviewed.credentialRefDigest).joinToString("") { "${it.length}:$it" }))
            val navigation = AtomicInteger()
            val readiness = RepositorySshReadinessPort(app.inventoryServerRepository, app.inventoryServerAccessRepository)
            stage = Stage.OPEN
            compose.setContent { VelumTegraTheme { XuiReadOnlyDiscoveryScreen(server.id.value, server.displayName,
                readiness,
                app.xuiReadOnlyDiscoveryPort, {}, app.xuiVerifiedEnrollmentPort, { navigation.incrementAndGet() }) } }
            await("xui_discovery_select_${access.id.value}"); stable()
            assertEquals(before, installations()); emit("LIVE_UI_OPEN=LOCAL_ONLY")
            click("xui_discovery_select_${access.id.value}"); await("xui_discovery_target")
            type("xui_discovery_target", target); click("xui_discovery_consent")
            stage = Stage.DISCOVERY
            stable(); click("xui_discovery_start")
            await("xui_discovery_candidate_identity", "xui_discovery_blocked"); stable()
            emit("LIVE_UI_DISCOVERY=PROVEN")
            stage = Stage.REVIEW
            type("xui_enroll_target", target); click("xui_enroll_read_consent"); stable(); click("xui_enroll_review_start")
            await("xui_enroll_verified", "xui_enroll_review_blocked"); stable()
            assertEquals(before, installations())
            compose.onNodeWithTag("xui_enroll_confirm_target").assertTextContains(target, substring = true)
            compose.onNodeWithTag("xui_enroll_save").assertIsNotEnabled()
            emit("LIVE_UI_REVIEW=REAL_SETTINGS_VERIFIED_NOT_SAVED")
            stage = Stage.SAVE
            click("xui_enroll_save_consent"); stable(); click("xui_enroll_save")
            await("xui_enroll_saved", "xui_enroll_save_blocked"); assertEquals(1, navigation.get()); stable()
            stage = Stage.READBACK
            val after = installations(); val actual = after.single { matches(it.value) }
            val i = actual.value
            assertEquals(server.id, i.serverId); assertEquals(InstallationOwnership.ADOPTED, i.ownership)
            assertNull(i.identity.managedInstallId)
            assertEquals(i.identity.serviceUnit, i.baseline.serviceUnit); assertEquals(i.identity.binaryPath, i.baseline.binaryPath)
            assertEquals(i.identity.rootPath, i.baseline.rootPath); assertEquals(i.identity.databasePath, i.baseline.databasePath)
            assertTrue(i.baseline.panelPort in 1..65535)
            assertTrue(i.baseline.webBasePath.startsWith('/'))
            runBlocking {
                assertEquals(actual, app.inventoryInstallationRepository.get(i.id).required())
                assertEquals(ManagementAccess(i.id, access.id), app.inventoryManagementRepository.get(i.id, access.id).required())
            }
            for (old in before.filterNot { matches(it.value) }) assertEquals(old, after.single { it.value.id == old.value.id })
            assertEquals(before.size + if (before.none { matches(it.value) }) 1 else 0, after.size)
            stable(); emit("LIVE_UI_LOCAL_INSTALLATION_AND_SSH_BINDING=VERIFIED")
            emit("LIVE_UI_INSTALLATION_ID_SHA256=" + digest(i.id.value))
            emit("LIVE_UI_REMOTE_MUTATIONS=NONE_REQUESTED"); emit("LIVE_UI_ENROLLMENT_PASS=192.0.2.169:22")
        } catch (_: Exception) {
            // Never include Compose tree/endpoint settings/secret references or raw transport output in a live failure.
            failed(stage)
        } catch (_: AssertionError) {
            failed(stage)
        }
    }
}

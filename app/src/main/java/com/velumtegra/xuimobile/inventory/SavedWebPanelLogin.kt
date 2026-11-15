package com.velumtegra.xuimobile.inventory

import com.velumtegra.xuimobile.core.domain.ExactWebPanelTargetResolver
import com.velumtegra.xuimobile.core.domain.RepositoryResult
import com.velumtegra.xuimobile.core.domain.ResolvedWebPanelTarget
import com.velumtegra.xuimobile.core.domain.SecretReadResult
import com.velumtegra.xuimobile.core.domain.SecretStore
import com.velumtegra.xuimobile.core.domain.WebPanelAccessRepository
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionRequest
import com.velumtegra.xuimobile.core.domain.WebPanelTargetResolutionResult
import java.net.URI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

internal data class SavedDirectWebPanel(
    val url: String,
    val target: ResolvedWebPanelTarget,
)

internal class SavedWebPanelLogin(
    private val resolver: ExactWebPanelTargetResolver,
    private val accesses: WebPanelAccessRepository,
    private val secrets: SecretStore,
) {
    suspend fun fillScript(
        request: WebPanelTargetResolutionRequest,
        expectedTarget: ResolvedWebPanelTarget,
        pageUrl: String,
    ): String? = withContext(Dispatchers.IO) {
        val current = resolver.resolve(request) as? WebPanelTargetResolutionResult.Resolved
        if (current?.target != expectedTarget) return@withContext null
        val record = (accesses.get(expectedTarget.webPanelAccessId) as? RepositoryResult.Success)?.value
            ?: return@withContext null
        if (record.value.id != expectedTarget.webPanelAccessId ||
            record.revision != expectedTarget.webPanelAccessRevision) return@withContext null
        val secret = secrets.read(record.value.passwordSecretId) as? SecretReadResult.Found
            ?: return@withContext null
        secret.material.use { material ->
            material.useBytes { bytes ->
                webPanelFillScript(pageUrl, record.value.username, bytes.toString(Charsets.UTF_8))
            }
        }
    }
}

internal fun isSavedPanelLoginPage(initialUrl: String, candidateUrl: String): Boolean {
    val initial = runCatching { URI(initialUrl) }.getOrNull() ?: return false
    val candidate = runCatching { URI(candidateUrl) }.getOrNull() ?: return false
    if (initial.scheme != "https" || candidate.scheme != "https" || initial.host == null ||
        initial.rawUserInfo != null || initial.rawAuthority != candidate.rawAuthority || candidate.rawUserInfo != null ||
        candidate.rawQuery != null || candidate.rawFragment != null) return false
    val base = initial.rawPath.orEmpty().trimEnd('/')
    return candidate.rawPath in setOf(base, "$base/", "$base/login", "$base/login/")
}

private fun webPanelFillScript(pageUrl: String, username: String, password: String): String = """
    (() => {
        if (window.top !== window || window.location.href !== ${JSONObject.quote(pageUrl)}) return false;
        const usable = input => !input.disabled && !input.readOnly && input.getClientRects().length > 0;
        const passwords = Array.from(document.querySelectorAll('input[type="password"]')).filter(usable);
        if (passwords.length !== 1) return false;
        const passwordInput = passwords[0];
        const fields = passwordInput.form || document;
        const named = Array.from(fields.querySelectorAll('input[name="username"], input[autocomplete="username"]'))
            .filter(input => usable(input) && ['text', 'email'].includes(input.type));
        const usernames = named.length || !passwordInput.form ? named :
            Array.from(fields.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'))
                .filter(usable);
        if (usernames.length !== 1) return false;
        const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        const fill = (field, value) => {
            setValue.call(field, value);
            field.dispatchEvent(new Event('input', {bubbles: true}));
            field.dispatchEvent(new Event('change', {bubbles: true}));
        };
        fill(usernames[0], ${JSONObject.quote(username)});
        fill(passwordInput, ${JSONObject.quote(password)});
        return true;
    })()
""".trimIndent()

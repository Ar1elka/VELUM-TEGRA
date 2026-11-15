package com.velumtegra.xuimobile.core.site

/** Outcome of choosing the certificate files a VELUM-managed Caddy site may reference. */
sealed interface SiteCaddyCertificateSelection {
    data class Selected(val candidate: SiteCaddyCertificateCandidate) : SiteCaddyCertificateSelection

    data class Blocked(val message: String) : SiteCaddyCertificateSelection
}

/**
 * Chooses which certificate/key files a VELUM-managed Caddy site may reference when the operator
 * asked to reuse an existing certificate.
 *
 * Only a pair that Caddy already loads for another site is eligible, and only when the caddy service
 * user can read both files, the certificate is not expired and its SAN covers the exact domain.
 * The 3x-ui paths (usually under `/root`, `drwx------`) are never written into a Caddy site: the
 * caddy user cannot open them and the reload fails with `permission denied`. Nothing is copied,
 * no permission is changed and the private key never leaves the server.
 */
object SiteCaddyCertificatePolicy {
    const val MAX_CANDIDATES: Int = 16

    fun select(domain: String, candidates: List<SiteCaddyCertificateCandidate>): SiteCaddyCertificateSelection {
        val host = SiteCaddyServingPlanner.canonicalDomain(domain)
        if (candidates.isEmpty()) {
            return SiteCaddyCertificateSelection.Blocked(
                "Caddy на сервере не использует файлы сертификата (директива tls <cert> <key>), поэтому " +
                    "повторно использовать сертификат нельзя. Сертификат 3x-ui в /root недоступен пользователю caddy. " +
                    "Отключите «использовать сертификат 3x-ui» — Caddy выпустит сертификат сам — или настройте файлы, доступные Caddy",
            )
        }
        val covering = candidates.filter { covers(it.dnsNames, host) }
        if (covering.isEmpty()) {
            return SiteCaddyCertificateSelection.Blocked(
                "Ни один сертификат, который уже загружает Caddy, не покрывает домен $host. " +
                    "Пути 3x-ui не подставляются: пользователь caddy не может их прочитать",
            )
        }
        val usable = covering.firstOrNull {
            it.certificateReadableByService == true && it.keyReadableByService == true && it.notExpired == true &&
                it.certificateSha256 != null
        }
        if (usable != null) return SiteCaddyCertificateSelection.Selected(usable)
        val first = covering.first()
        val reason = when {
            first.certificateReadableByService == null || first.keyReadableByService == null ->
                "не удалось проверить права доступа от имени пользователя ${first.serviceUser} (нет runuser?)"
            first.certificateReadableByService == false || first.keyReadableByService == false ->
                "пользователь ${first.serviceUser} не может прочитать ${unreadable(first)}"
            first.notExpired == false -> "срок действия сертификата истёк"
            else -> "не удалось прочитать сертификат (нет openssl?)"
        }
        return SiteCaddyCertificateSelection.Blocked(
            "Сертификат для $host (${first.pair.certificatePath}) нельзя использовать: $reason. Файлы не загружены, сервер не изменён",
        )
    }

    /** Exact or single-label wildcard SAN match, case-insensitive. */
    fun covers(dnsNames: List<String>, host: String): Boolean = dnsNames.map { it.trim().lowercase() }.any { name ->
        name == host || (
            name.startsWith("*.") && host.endsWith(name.substring(1)) &&
                host.length > name.length - 1 && '.' !in host.substring(0, host.length - (name.length - 1))
            )
    }

    /** Turns a selected candidate into the reference the Caddy planner renders into `tls`. */
    fun reference(remoteHostIdentity: String, candidate: SiteCaddyCertificateCandidate): SiteServerCertificateFileReference =
        SiteServerCertificateFileReference(
            remoteHostIdentity = remoteHostIdentity,
            certificateSha256 = requireNotNull(candidate.certificateSha256),
            dnsNames = candidate.dnsNames.map { it.lowercase() },
            certificatePath = candidate.pair.certificatePath,
            privateKeyPath = candidate.pair.keyPath,
            usableNow = candidate.notExpired == true,
            privateKeyPresentOnServer = candidate.keyReadableByService == true,
        )

    private fun unreadable(candidate: SiteCaddyCertificateCandidate): String = listOfNotNull(
        candidate.pair.certificatePath.takeIf { candidate.certificateReadableByService == false },
        candidate.pair.keyPath.takeIf { candidate.keyReadableByService == false },
    ).joinToString(" и ")
}

package com.velumtegra.xuimobile.core.site

/**
 * Read-only inventory of the web serving stack on the selected VPS.
 *
 * Collected in one finite read-only SSH probe (see SiteWebServerInventorySshAdapter). Nothing here
 * grants mutation authority; it only lets the operator see which web server really serves the box
 * and lets the deployer refuse incompatible combinations before any file is written.
 */
data class SiteListeningSocket(
    val port: Int,
    /** Process names reported by `ss -p` (may be empty when not visible). */
    val processes: Set<String>,
)

/** Exact reason text for "no Caddy/nginx at all"; the UI offers a separately confirmed nginx install for it. */
const val SITE_NO_WEB_SERVER_REASON: String =
    "На сервере не найден веб-сервер (Caddy или nginx). Его можно установить кнопкой «Установить nginx»"

enum class SiteServiceState {
    ACTIVE,

    /** systemd reports `reloading`: an earlier reload has not finished (or hung). */
    RELOADING,
    INACTIVE,
    UNKNOWN,
}

enum class SiteFirewallState { ABSENT, INACTIVE, ACTIVE, UNKNOWN }

data class SiteFirewallObservation(
    val state: SiteFirewallState,
    val defaultIncomingAllow: Boolean,
    /** Raw `ufw status verbose` rule lines (To / Action / From). */
    val ruleLines: List<String>,
)

/** One Caddy HTTP server as seen in `caddy adapt` output. */
data class SiteCaddyServer(
    val ports: Set<Int>,
    /** Exact host matchers of the server's routes (lower-case). */
    val hosts: Set<String>,
    /** A route without a host matcher exists (catch-all, e.g. a reverse proxy for any host). */
    val hasCatchAllRoute: Boolean,
)

data class SiteCaddyObservation(
    val binaryPath: String?,
    val state: SiteServiceState,
    val caddyfilePath: String,
    val caddyfileSha256: String?,
    /** `--adapter` value from the systemd unit, or null when none was given. */
    val adapter: String?,
    /** Parsed `caddy adapt` result; null when the config could not be adapted. */
    val servers: List<SiteCaddyServer>?,
    val managedImportPresent: Boolean,
    /** `User=` of the caddy systemd unit ("root" when empty); null when it could not be read. */
    val serviceUser: String? = null,
    /** Certificate/key file pairs Caddy already loads (`tls <cert> <key>` in the adapted config). */
    val tlsFilePairs: List<SiteCaddyTlsFilePair> = emptyList(),
)

/** One `tls <certificate> <key>` file pair taken from the adapted Caddy config. */
data class SiteCaddyTlsFilePair(
    val certificatePath: String,
    val keyPath: String,
)

/**
 * Read-only proof about one certificate/key pair, collected over SSH. Readability is checked as the
 * caddy service user, not as root: `caddy validate` run by root does not prove the service can load
 * the files (e.g. `/root` is `drwx------`).
 */
data class SiteCaddyCertificateCandidate(
    val pair: SiteCaddyTlsFilePair,
    val serviceUser: String,
    /** null when the check itself could not run (no runuser/openssl). */
    val certificateReadableByService: Boolean?,
    val keyReadableByService: Boolean?,
    val notExpired: Boolean?,
    val dnsNames: List<String>,
    val certificateSha256: String?,
)

data class SiteNginxObservation(
    val binaryPath: String?,
    val state: SiteServiceState,
)

enum class SitePortTlsState { TLS, PLAIN_HTTP, CLOSED, UNKNOWN }

data class SiteWebServerInventory(
    val caddy: SiteCaddyObservation,
    val nginx: SiteNginxObservation,
    val listeners: List<SiteListeningSocket>,
    val firewall: SiteFirewallObservation,
    val requestedPortTls: SitePortTlsState,
) {
    val listeningPorts: Set<Int> get() = listeners.map { it.port }.toSet()

    fun processesOn(port: Int): Set<String> =
        listeners.filter { it.port == port }.flatMap { it.processes }.toSet()
}

enum class SiteServingBackend {
    /** Existing accepted nginx conf.d path. */
    NGINX,

    /** Caddy serves the VPS; a VELUM-managed site block is imported into its Caddyfile. */
    CADDY,
}

/** Why publication cannot proceed (or why a published site is not reachable). */
enum class SiteServingFailureCategory {
    BACKEND_INCOMPATIBLE,
    PORT_CONFLICT,
    FIREWALL,
    DNS,
    CERTIFICATE,
    CONFIG_INVALID,
    RELOAD_FAILED,
    SERVING_VERIFICATION,
    EXTERNAL_UNREACHABLE,

    /** A server command ended without a result (non-zero exit, timeout, lost channel). */
    SERVER_COMMAND_FAILED,
}

data class SiteServingBackendDecision(
    val backend: SiteServingBackend?,
    val blockedCategory: SiteServingFailureCategory?,
    val blockedReason: String?,
) {
    val allowed: Boolean get() = backend != null
}

object SiteServingBackendPolicy {
    /**
     * Chooses the web server that will serve the site. Caddy wins when it is running (it usually
     * fronts 80/443 on such boxes); nginx is never installed or started next to a running Caddy.
     */
    fun select(inventory: SiteWebServerInventory): SiteServingBackendDecision {
        val caddy = inventory.caddy
        val nginx = inventory.nginx
        return when {
            caddy.state == SiteServiceState.RELOADING -> blocked(SiteServiceBlock.CADDY_RELOADING)
            caddy.state == SiteServiceState.ACTIVE -> when {
                caddy.binaryPath == null -> blocked(
                    SiteServiceBlock.CADDY_BINARY,
                )
                !caddyfileAdapter(caddy) -> blocked(SiteServiceBlock.CADDY_JSON_CONFIG)
                caddy.caddyfileSha256 == null -> blocked(SiteServiceBlock.CADDYFILE_MISSING)
                caddy.servers == null -> blocked(SiteServiceBlock.CADDY_ADAPT_FAILED)
                else -> SiteServingBackendDecision(SiteServingBackend.CADDY, null, null)
            }
            nginx.state == SiteServiceState.ACTIVE || (nginx.binaryPath != null && caddy.binaryPath == null) ->
                SiteServingBackendDecision(SiteServingBackend.NGINX, null, null)
            caddy.binaryPath != null -> blocked(SiteServiceBlock.CADDY_NOT_RUNNING)
            else -> blocked(SiteServiceBlock.NO_WEB_SERVER)
        }
    }

    private enum class SiteServiceBlock(
        val reason: String,
        val category: SiteServingFailureCategory = SiteServingFailureCategory.BACKEND_INCOMPATIBLE,
    ) {
        CADDY_RELOADING(
            "Caddy сейчас в состоянии reloading: предыдущая перезагрузка не завершилась. Приложение не перезапускает " +
                "Caddy само — проверьте journalctl -u caddy и дождитесь состояния active",
            SiteServingFailureCategory.RELOAD_FAILED,
        ),
        CADDY_BINARY("Caddy запущен, но программа caddy не найдена в PATH — нельзя проверить конфиг"),
        CADDY_JSON_CONFIG("Caddy настроен через JSON-конфиг, а не Caddyfile — автоматическое добавление сайта не поддерживается"),
        CADDYFILE_MISSING("Caddy запущен, но файл Caddyfile не найден"),
        CADDY_ADAPT_FAILED("Не удалось прочитать текущий конфиг Caddy (caddy adapt завершился ошибкой)"),
        CADDY_NOT_RUNNING("Caddy установлен, но не запущен. Запустите его или nginx — приложение не ставит и не запускает веб-сервер само"),
        NO_WEB_SERVER(SITE_NO_WEB_SERVER_REASON),
    }

    private fun blocked(block: SiteServiceBlock) =
        SiteServingBackendDecision(null, block.category, block.reason)

    private fun caddyfileAdapter(caddy: SiteCaddyObservation): Boolean {
        val adapter = caddy.adapter?.lowercase()
        if (adapter != null) return adapter == "caddyfile"
        return caddy.caddyfilePath.substringAfterLast('/').startsWith("Caddyfile")
    }

    /**
     * Endpoint evidence for the Caddy backend. A Caddy-owned port is shared by host name, so it is
     * only "in use" when another program owns it or Caddy already serves this exact host there.
     */
    fun caddyEndpoint(
        inventory: SiteWebServerInventory,
        domain: String,
        port: Int,
        managedSitePresent: Boolean,
    ): SiteEndpointObservation {
        val host = domain.lowercase()
        val owners = inventory.processesOn(port)
        val listening = port in inventory.listeningPorts
        val foreignOwner = listening && (owners.isEmpty() || owners.any { it != "caddy" })
        val hostAlreadyServed = inventory.caddy.servers.orEmpty().any { port in it.ports && host in it.hosts }
        return SiteEndpointObservation(
            configPresent = managedSitePresent,
            portInUse = foreignOwner || hostAlreadyServed,
            listeningPorts = inventory.listeningPorts,
        )
    }

    /** Ports that the selected backend can still share for a new site with a different host name. */
    fun sharablePorts(inventory: SiteWebServerInventory, backend: SiteServingBackend): Set<Int> = when (backend) {
        SiteServingBackend.CADDY -> inventory.listeners
            .filter { it.processes.isNotEmpty() && it.processes.all { p -> p == "caddy" } }
            .map { it.port }.toSet()
        SiteServingBackend.NGINX -> emptySet()
    }
}

object SiteFirewallPolicy {
    /** True when UFW would let a TCP connection to [port] in (or UFW is not filtering). */
    fun allowsTcpPort(firewall: SiteFirewallObservation, port: Int): Boolean? = when (firewall.state) {
        SiteFirewallState.ABSENT, SiteFirewallState.INACTIVE -> true
        SiteFirewallState.UNKNOWN -> null
        SiteFirewallState.ACTIVE -> firewall.defaultIncomingAllow || firewall.ruleLines.any { ruleAllows(it, port) }
    }

    /**
     * Fail-closed gate evaluated before any file is uploaded: returns the operator message when the
     * port is closed by UFW or UFW state could not be read. The app never changes the firewall.
     */
    fun publicationBlock(firewall: SiteFirewallObservation, port: Int): String? = when (allowsTcpPort(firewall, port)) {
        true -> null
        false -> "Порт $port закрыт файрволом UFW. Приложение не меняет файрвол — откройте порт сами: " +
            "sudo ufw allow $port/tcp, затем проверьте сервер ещё раз"
        null -> "Не удалось прочитать состояние UFW на сервере, поэтому нельзя доказать, что порт $port открыт. " +
            "Файлы не загружены. Проверьте sudo ufw status verbose и повторите проверку"
    }

    internal fun ruleAllows(line: String, port: Int): Boolean {
        val match = rule.find(line.trim()) ?: return false
        val target = match.groupValues[1]
        val action = match.groupValues[2].uppercase()
        if (action != "ALLOW") return false
        if (target.equals("Anywhere", ignoreCase = true) || target.equals("Anywhere (v6)", ignoreCase = true)) return true
        val spec = target.removeSuffix(" (v6)").trim()
        val proto = spec.substringAfter('/', "")
        if (proto.isNotEmpty() && proto != "tcp") return false
        val ports = spec.substringBefore('/')
        return ports.split(',').any { part ->
            val range = part.split(':')
            when (range.size) {
                1 -> range[0].toIntOrNull() == port
                2 -> {
                    val lo = range[0].toIntOrNull()
                    val hi = range[1].toIntOrNull()
                    lo != null && hi != null && port in lo..hi
                }
                else -> false
            }
        }
    }

    private val rule = Regex("^(.+?)\\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\\s+IN)?\\s{2,}.+$", RegexOption.IGNORE_CASE)
}

enum class SiteCaddyTlsMode {
    /** Caddy obtains and renews the certificate itself (requires Caddy already serving 80/443). */
    AUTOMATIC,

    /**
     * Reuse a certificate that is already on this server. For Caddy only a pair that Caddy itself
     * already loads and that the caddy service user can read is used (see SiteCaddyCertificatePolicy).
     */
    EXISTING_SERVER_CERTIFICATE,

    /** Plain HTTP on the requested port. */
    NONE,
}

data class SiteCaddyServingPlan(
    val contractVersion: Int,
    val remoteHostIdentity: String,
    val domain: String,
    val port: Int,
    val targetRoot: String,
    val tlsMode: SiteCaddyTlsMode,
    val caddyfilePath: String,
    /** Caddyfile digest observed read-only before publication; apply refuses if it changed. */
    val expectedCaddyfileSha256: String,
    val managedDirectory: String,
    val siteFilePath: String,
    val importLine: String,
    val siteBlockUtf8: String,
    val siteBlockSha256: String,
    val backupPath: String,
    val plannedUrl: String,
    val indexSha256: String,
    /** Ports that were listening before; they must all still listen after reload. */
    val preservedListeningPorts: Set<Int>,
    /** User the caddy service runs as; validation and file readability are checked as this user. */
    val serviceUser: String,
    /** Certificate/key files referenced by the site block (EXISTING_SERVER_CERTIFICATE only). */
    val tlsCertificatePath: String?,
    val tlsKeyPath: String?,
    val dnsMutationAuthorized: Boolean,
    val firewallMutationAuthorized: Boolean,
    val packageInstallAuthorized: Boolean,
    val planSha256: String,
)

object SiteCaddyServingPlanner {
    const val CONTRACT_VERSION: Int = 2
    const val MANAGED_DIRECTORY_NAME: String = "velum-sites"

    /** Managed site files live next to the Caddyfile, e.g. /etc/caddy/velum-sites. */
    fun managedDirectory(caddyfilePath: String): String {
        val canonical = SiteRemoteDeployPolicy.prepareTargetRoot(caddyfilePath)
        val parent = canonical.substringBeforeLast('/')
        require(parent.isNotEmpty()) { "Caddyfile must not live in /" }
        return "$parent/$MANAGED_DIRECTORY_NAME"
    }

    fun importLine(caddyfilePath: String): String = "import ${managedDirectory(caddyfilePath)}/*.caddy"

    private val sha256 = Regex("^[0-9a-f]{64}$")
    private val ipv4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val serviceUserPattern = Regex("^[a-z_][a-z0-9_-]{0,31}$")

    /** Canonical lower-case ASCII host name used for every Caddy matcher and verification. */
    fun canonicalDomain(value: String): String = SiteRemoteDeployPolicy.normalizeDomain(value)

    fun tlsModeFor(
        inventory: SiteWebServerInventory,
        domain: String,
        certificateReuse: Boolean,
    ): SiteCaddyTlsMode = when {
        certificateReuse -> SiteCaddyTlsMode.EXISTING_SERVER_CERTIFICATE
        ipv4.matches(domain) || ':' in domain -> SiteCaddyTlsMode.NONE
        inventory.processesOn(443).let { it.isNotEmpty() && it.all { p -> p == "caddy" } } -> SiteCaddyTlsMode.AUTOMATIC
        else -> SiteCaddyTlsMode.NONE
    }

    fun siteFilePath(
        caddyfilePath: String,
        remoteHostIdentity: String,
        targetRoot: String,
        domain: String,
        port: Int,
    ): String {
        val id = SiteBundleDigest.sha256(
            "velum-caddy-site\nhost=$remoteHostIdentity\nroot=$targetRoot\ndomain=${domain.lowercase()}\nport=$port\n"
                .encodeToByteArray(),
        ).take(16)
        return "${managedDirectory(caddyfilePath)}/velum-$id.caddy"
    }

    fun prepare(
        remoteHostIdentity: String,
        domain: String,
        port: Int,
        targetRoot: String,
        tlsMode: SiteCaddyTlsMode,
        caddy: SiteCaddyObservation,
        indexSha256: String,
        preservedListeningPorts: Set<Int>,
        certificate: SiteServerCertificateFileReference? = null,
    ): SiteCaddyServingPlan {
        val normalizedDomain = SiteRemoteDeployPolicy.normalizeDomain(domain)
        require(port in 1..65535) { "Caddy site port is invalid" }
        val root = SiteRemoteDeployPolicy.prepareTargetRoot(targetRoot)
        val caddyfile = SiteRemoteDeployPolicy.prepareTargetRoot(caddy.caddyfilePath)
        val caddyfileSha = requireNotNull(caddy.caddyfileSha256) { "Caddyfile digest is required" }
        require(sha256.matches(caddyfileSha)) { "Caddyfile digest is invalid" }
        require(sha256.matches(indexSha256)) { "index.html digest is invalid" }
        val serviceUser = requireNotNull(caddy.serviceUser) { "Caddy service user is unknown" }
        require(serviceUserPattern.matches(serviceUser)) { "Caddy service user is invalid" }
        when (tlsMode) {
            SiteCaddyTlsMode.EXISTING_SERVER_CERTIFICATE -> {
                requireNotNull(certificate) { "Certificate reuse requires the proven certificate reference" }
                require(certificate.remoteHostIdentity == remoteHostIdentity)
                require(normalizedDomain in certificate.dnsNames.map(String::lowercase)) {
                    "Certificate does not cover the exact domain"
                }
                require(certificate.usableNow && certificate.privateKeyPresentOnServer)
                require(SiteRemoteDeployPolicy.prepareTargetRoot(certificate.certificatePath) == certificate.certificatePath)
                require(SiteRemoteDeployPolicy.prepareTargetRoot(certificate.privateKeyPath) == certificate.privateKeyPath)
                require(SiteCaddyTlsFilePair(certificate.certificatePath, certificate.privateKeyPath) in caddy.tlsFilePairs) {
                    "Caddy reuses only certificate files it already loads"
                }
            }
            SiteCaddyTlsMode.AUTOMATIC -> require(!ipv4.matches(normalizedDomain)) {
                "Automatic certificates need a domain name"
            }
            SiteCaddyTlsMode.NONE -> require(certificate == null)
        }
        val block = renderSiteBlock(normalizedDomain, port, root, tlsMode, certificate)
        val siteFile = siteFilePath(caddyfile, remoteHostIdentity, root, normalizedDomain, port)
        val scheme = if (tlsMode == SiteCaddyTlsMode.NONE) "http" else "https"
        val defaultPort = if (scheme == "https") 443 else 80
        val url = if (port == defaultPort) "$scheme://$normalizedDomain/" else "$scheme://$normalizedDomain:$port/"
        val base = SiteCaddyServingPlan(
            contractVersion = CONTRACT_VERSION,
            remoteHostIdentity = remoteHostIdentity,
            domain = normalizedDomain,
            port = port,
            targetRoot = root,
            tlsMode = tlsMode,
            caddyfilePath = caddyfile,
            expectedCaddyfileSha256 = caddyfileSha,
            managedDirectory = managedDirectory(caddyfile),
            siteFilePath = siteFile,
            importLine = importLine(caddyfile),
            siteBlockUtf8 = block,
            siteBlockSha256 = SiteBundleDigest.sha256(block.encodeToByteArray()),
            backupPath = "$caddyfile.velum-backup-${caddyfileSha.take(12)}",
            plannedUrl = url,
            indexSha256 = indexSha256,
            preservedListeningPorts = preservedListeningPorts,
            serviceUser = serviceUser,
            tlsCertificatePath = certificate?.certificatePath,
            tlsKeyPath = certificate?.privateKeyPath,
            dnsMutationAuthorized = false,
            firewallMutationAuthorized = false,
            packageInstallAuthorized = false,
            planSha256 = "",
        )
        return base.copy(planSha256 = digest(base)).also(::validate)
    }

    fun validate(plan: SiteCaddyServingPlan) {
        require(plan.contractVersion == CONTRACT_VERSION)
        require(plan.managedDirectory == managedDirectory(plan.caddyfilePath))
        require(plan.importLine == importLine(plan.caddyfilePath))
        require(plan.siteFilePath == siteFilePath(plan.caddyfilePath, plan.remoteHostIdentity, plan.targetRoot, plan.domain, plan.port))
        require(plan.siteBlockSha256 == SiteBundleDigest.sha256(plan.siteBlockUtf8.encodeToByteArray()))
        require(!plan.dnsMutationAuthorized && !plan.firewallMutationAuthorized && !plan.packageInstallAuthorized)
        require(sha256.matches(plan.expectedCaddyfileSha256) && sha256.matches(plan.indexSha256))
        require(serviceUserPattern.matches(plan.serviceUser))
        when (plan.tlsMode) {
            SiteCaddyTlsMode.EXISTING_SERVER_CERTIFICATE -> {
                val cert = requireNotNull(plan.tlsCertificatePath)
                val key = requireNotNull(plan.tlsKeyPath)
                require(plan.siteBlockUtf8.contains("\ttls $cert $key\n"))
            }
            else -> require(plan.tlsCertificatePath == null && plan.tlsKeyPath == null)
        }
        require(plan.planSha256 == digest(plan.copy(planSha256 = ""))) { "Caddy serving plan digest mismatch" }
    }

    internal fun renderSiteBlock(
        domain: String,
        port: Int,
        root: String,
        tlsMode: SiteCaddyTlsMode,
        certificate: SiteServerCertificateFileReference?,
    ): String {
        val address = when (tlsMode) {
            SiteCaddyTlsMode.NONE -> if (port == 80) "http://$domain" else "http://$domain:$port"
            else -> if (port == 443) domain else "$domain:$port"
        }
        return buildString {
            append("# VELUM//TEGRA managed site. Generated by the app; edits are overwritten.\n")
            append(address).append(" {\n")
            append("\troot * ").append(root).append('\n')
            append("\tfile_server\n")
            append("\tencode gzip\n")
            append("\theader X-Content-Type-Options nosniff\n")
            if (tlsMode == SiteCaddyTlsMode.EXISTING_SERVER_CERTIFICATE) {
                val cert = requireNotNull(certificate)
                append("\ttls ").append(cert.certificatePath).append(' ').append(cert.privateKeyPath).append('\n')
            }
            append("}\n")
        }
    }

    private fun digest(plan: SiteCaddyServingPlan): String = SiteBundleDigest.sha256(
        buildString {
            append("contractVersion=").append(plan.contractVersion).append('\n')
            append("host=").append(plan.remoteHostIdentity).append('\n')
            append("domain=").append(plan.domain).append('\n')
            append("port=").append(plan.port).append('\n')
            append("root=").append(plan.targetRoot).append('\n')
            append("tls=").append(plan.tlsMode.name).append('\n')
            append("caddyfile=").append(plan.caddyfilePath).append('\n')
            append("caddyfileSha=").append(plan.expectedCaddyfileSha256).append('\n')
            append("siteFile=").append(plan.siteFilePath).append('\n')
            append("siteSha=").append(plan.siteBlockSha256).append('\n')
            append("backup=").append(plan.backupPath).append('\n')
            append("url=").append(plan.plannedUrl).append('\n')
            append("index=").append(plan.indexSha256).append('\n')
            append("preserved=").append(plan.preservedListeningPorts.sorted().joinToString(",")).append('\n')
            append("serviceUser=").append(plan.serviceUser).append('\n')
            append("tlsCert=").append(plan.tlsCertificatePath.orEmpty()).append('\n')
            append("tlsKey=").append(plan.tlsKeyPath.orEmpty()).append('\n')
        }.encodeToByteArray(),
    )
}

/** What the operator finally gets: honest serving outcome with the verified URL (if any). */
data class SiteServingOutcome(
    val backend: SiteServingBackend?,
    val plannedUrl: String,
    /** URL that was actually fetched with the exact index.html body; null when not verified. */
    val verifiedUrl: String?,
    val servedOnServer: Boolean,
    val externallyReachable: Boolean,
    val configRolledBack: Boolean,
    val failureCategory: SiteServingFailureCategory?,
    val failureMessage: String?,
) {
    init {
        if (externallyReachable) {
            require(verifiedUrl != null && failureCategory == null)
        } else {
            require(verifiedUrl == null && failureCategory != null)
        }
    }
}

/** Parses `caddy adapt` JSON into the minimal server/host/port view used for conflict checks. */
object SiteCaddyConfigReader {
    fun servers(adaptedJson: String): List<SiteCaddyServer> {
        val root = MiniJson.parse(adaptedJson) as? Map<*, *> ?: error("Caddy config is not a JSON object")
        val servers = ((root["apps"] as? Map<*, *>)?.get("http") as? Map<*, *>)?.get("servers") as? Map<*, *>
            ?: return emptyList()
        return servers.values.mapNotNull { it as? Map<*, *> }.map { server ->
            val ports = (server["listen"] as? List<*>).orEmpty().mapNotNull { listenPort(it as? String) }.toSet()
            val routes = (server["routes"] as? List<*>).orEmpty().mapNotNull { it as? Map<*, *> }
            val hosts = mutableSetOf<String>()
            var catchAll = false
            routes.forEach { route ->
                val matchers = (route["match"] as? List<*>).orEmpty().mapNotNull { it as? Map<*, *> }
                val routeHosts = matchers.flatMap { (it["host"] as? List<*>).orEmpty().mapNotNull { h -> (h as? String)?.lowercase() } }
                if (routeHosts.isEmpty()) catchAll = true else hosts += routeHosts
            }
            SiteCaddyServer(ports, hosts, catchAll)
        }
    }

    /** `apps.tls.certificates.load_files` pairs, i.e. every `tls <cert> <key>` in the Caddyfile. */
    fun tlsFilePairs(adaptedJson: String): List<SiteCaddyTlsFilePair> {
        val root = MiniJson.parse(adaptedJson) as? Map<*, *> ?: error("Caddy config is not a JSON object")
        val files = (((root["apps"] as? Map<*, *>)?.get("tls") as? Map<*, *>)?.get("certificates") as? Map<*, *>)
            ?.get("load_files") as? List<*> ?: return emptyList()
        return files.mapNotNull { it as? Map<*, *> }.mapNotNull { entry ->
            val cert = entry["certificate"] as? String
            val key = entry["key"] as? String
            if (cert.isNullOrBlank() || key.isNullOrBlank()) null else SiteCaddyTlsFilePair(cert, key)
        }.distinct()
    }

    internal fun listenPort(listen: String?): Int? {
        if (listen.isNullOrBlank()) return null
        val address = listen.substringAfter("/", listen).substringAfter("tcp/").substringAfter("tcp4/").substringAfter("tcp6/")
        return address.substringAfterLast(':').substringBefore('-').toIntOrNull()?.takeIf { it in 1..65535 }
    }
}

/** Tiny dependency-free JSON reader (objects, arrays, strings, numbers, booleans, null). */
internal object MiniJson {
    fun parse(text: String): Any? {
        val reader = Reader(text)
        val value = reader.value()
        reader.skipWhitespace()
        require(reader.done()) { "Trailing JSON content" }
        return value
    }

    private class Reader(private val s: String) {
        private var i = 0
        private var depth = 0

        fun done() = i >= s.length

        fun skipWhitespace() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        fun value(): Any? {
            skipWhitespace()
            require(i < s.length) { "Unexpected end of JSON" }
            return when (val c = s[i]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c.isDigit()) num() else error("Unexpected JSON character '$c'")
            }
        }

        private fun obj(): Map<String, Any?> {
            require(++depth <= 64) { "JSON nesting too deep" }
            i++
            val out = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (s.getOrNull(i) == '}') { i++; depth--; return out }
            while (true) {
                skipWhitespace()
                val key = str()
                skipWhitespace()
                require(s.getOrNull(i) == ':') { "Expected ':' in JSON object" }
                i++
                out[key] = value()
                skipWhitespace()
                when (s.getOrNull(i)) {
                    ',' -> i++
                    '}' -> { i++; depth--; return out }
                    else -> error("Expected ',' or '}' in JSON object")
                }
            }
        }

        private fun arr(): List<Any?> {
            require(++depth <= 64) { "JSON nesting too deep" }
            i++
            val out = ArrayList<Any?>()
            skipWhitespace()
            if (s.getOrNull(i) == ']') { i++; depth--; return out }
            while (true) {
                out += value()
                skipWhitespace()
                when (s.getOrNull(i)) {
                    ',' -> i++
                    ']' -> { i++; depth--; return out }
                    else -> error("Expected ',' or ']' in JSON array")
                }
            }
        }

        private fun str(): String {
            require(s.getOrNull(i) == '"') { "Expected JSON string" }
            i++
            val out = StringBuilder()
            while (true) {
                require(i < s.length) { "Unterminated JSON string" }
                val c = s[i++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        require(i < s.length) { "Bad JSON escape" }
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> out.append(e)
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                require(i + 4 <= s.length) { "Bad JSON unicode escape" }
                                out.append(s.substring(i, i + 4).toInt(16).toChar())
                                i += 4
                            }
                            else -> error("Bad JSON escape")
                        }
                    }
                    else -> out.append(c)
                }
            }
        }

        private fun num(): Number {
            val start = i
            while (i < s.length && (s[i].isDigit() || s[i] in "+-.eE")) i++
            val text = s.substring(start, i)
            return text.toLongOrNull() ?: text.toDouble()
        }

        private fun literal(word: String, result: Any?): Any? {
            require(s.startsWith(word, i)) { "Bad JSON literal" }
            i += word.length
            return result
        }
    }
}

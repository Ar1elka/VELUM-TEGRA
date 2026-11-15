package com.velumtegra.xuimobile.core.ssh

import com.velumtegra.xuimobile.core.model.CommandCompletion
import com.velumtegra.xuimobile.core.model.OperationId
import com.velumtegra.xuimobile.core.model.ServerAccessId
import com.velumtegra.xuimobile.core.model.SessionBinding
import com.velumtegra.xuimobile.core.model.SessionId
import com.velumtegra.xuimobile.core.model.SessionOwner
import com.velumtegra.xuimobile.core.site.SiteCaddyCertificatePolicy
import com.velumtegra.xuimobile.core.site.SiteCaddyCertificateSelection
import com.velumtegra.xuimobile.core.site.SiteCaddyServingPlanner
import com.velumtegra.xuimobile.core.site.SiteCaddyTlsMode
import com.velumtegra.xuimobile.core.site.SiteFirewallPolicy
import com.velumtegra.xuimobile.core.site.SiteFirewallState
import com.velumtegra.xuimobile.core.site.SitePortTlsState
import com.velumtegra.xuimobile.core.site.SiteServiceState
import com.velumtegra.xuimobile.core.site.SiteServingBackend
import com.velumtegra.xuimobile.core.site.SiteServingBackendPolicy
import com.velumtegra.xuimobile.core.site.SiteServingFailureCategory
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Offline acceptance of the Caddy serving path. The exact remote scripts run in a local bash with
 * stand-in `caddy`, `systemctl`, `ss`, `ufw` and `curl` programs that model a Caddy-only VPS
 * (Caddy owns 80/443 with a VPN reverse proxy, 3x-ui on its own port).
 */
class SiteCaddyServingSshAdapterTest {
    private val adapter = SiteCaddyServingSshAdapter()

    @Test
    fun `caddy only vps is detected read only and selects the caddy backend`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps()
        val before = vps.snapshot()
        val probe = adapter.probe("site.example.com", 443, vps.session())
        assertEquals(before, vps.snapshot())

        val inventory = probe.inventory
        assertEquals(SiteServiceState.ACTIVE, inventory.caddy.state)
        assertEquals(SiteServiceState.INACTIVE, inventory.nginx.state)
        assertEquals(vps.caddyfile.absolutePath, inventory.caddy.caddyfilePath)
        assertEquals(setOf("vpn.example.com"), inventory.caddy.servers!!.flatMap { it.hosts }.toSet())
        assertEquals(setOf(80, 443, 2053, 22), inventory.listeningPorts)
        assertEquals(SiteFirewallState.ACTIVE, inventory.firewall.state)
        assertEquals(SitePortTlsState.TLS, inventory.requestedPortTls)
        assertEquals(SiteServingBackend.CADDY, SiteServingBackendPolicy.select(inventory).backend)

        // A different host name can share Caddy's 443; the VPN host itself cannot be taken.
        val shared = SiteServingBackendPolicy.caddyEndpoint(inventory, "site.example.com", 443, managedSitePresent = false)
        assertFalse(shared.portInUse)
        val taken = SiteServingBackendPolicy.caddyEndpoint(inventory, "vpn.example.com", 443, managedSitePresent = false)
        assertTrue(taken.portInUse)
        val xray = SiteServingBackendPolicy.caddyEndpoint(inventory, "site.example.com", 2053, managedSitePresent = false)
        assertTrue(xray.portInUse)

        assertEquals(true, SiteFirewallPolicy.allowsTcpPort(inventory.firewall, 443))
        assertEquals(false, SiteFirewallPolicy.allowsTcpPort(inventory.firewall, 8443))
        assertEquals(SiteCaddyTlsMode.AUTOMATIC, SiteCaddyServingPlanner.tlsModeFor(inventory, "site.example.com", false))
    }

    @Test
    fun `nginx only and empty servers are classified without touching anything`() = runBlocking<Unit> {
        assumeBash()
        val nginxOnly = FakeVps(caddyInstalled = false, nginxActive = true)
        val nginxInventory = adapter.probe("site.example.com", 8080, nginxOnly.session()).inventory
        assertEquals(SiteServingBackend.NGINX, SiteServingBackendPolicy.select(nginxInventory).backend)

        val empty = FakeVps(caddyInstalled = false, nginxActive = false, nginxInstalled = false)
        val decision = SiteServingBackendPolicy.select(adapter.probe("site.example.com", 8080, empty.session()).inventory)
        assertNull(decision.backend)
        assertEquals(SiteServingFailureCategory.BACKEND_INCOMPATIBLE, decision.blockedCategory)
    }

    @Test
    fun `apply adds one managed site, keeps foreign routes and verifies exact body`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps()
        val inventory = adapter.probe("site.example.com", 443, vps.session()).inventory
        val plan = vps.plan(inventory)
        val originalCaddyfile = vps.caddyfile.readText()

        val applied = adapter.apply(plan, vps.session())
        assertEquals(SiteCaddyApplyResult.APPLIED, applied.result)
        assertTrue(File(plan.siteFilePath).readText().contains("root * ${vps.siteRoot.absolutePath}"))
        assertTrue(vps.caddyfile.readText().startsWith(originalCaddyfile))
        assertTrue(vps.caddyfile.readText().contains(plan.importLine))
        assertTrue(vps.caddyfile.readText().contains("reverse_proxy 127.0.0.1:10000"))
        assertEquals(1, vps.reloadCount())
        assertTrue(File(plan.backupPath).exists())

        val verified = adapter.verify(plan, vps.session(), maxAttempts = 2, delaySeconds = 0)
        assertTrue(verified.caddyActive)
        assertEquals(plan.indexSha256, verified.bodySha256)
        assertTrue(verified.listeningPorts.containsAll(plan.preservedListeningPorts))

        // A second apply of the same plan is refused instead of overwriting (the Caddyfile digest
        // no longer matches the reviewed one, so nothing is touched).
        val afterApply = vps.caddyfile.readText()
        assertEquals(SiteCaddyApplyResult.CADDYFILE_CHANGED, adapter.apply(plan, vps.session()).result)
        assertEquals(afterApply, vps.caddyfile.readText())
        assertEquals(1, vps.reloadCount())

        assertEquals(SiteCaddyRollbackResult.ROLLED_BACK, adapter.rollback(plan, vps.session()))
        assertEquals(originalCaddyfile, vps.caddyfile.readText())
        assertFalse(File(plan.siteFilePath).exists())
        assertFalse(File(plan.backupPath).exists())
    }

    @Test
    fun `invalid config is rolled back before reload`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps(validateFails = true)
        val plan = vps.plan(adapter.probe("site.example.com", 443, vps.session()).inventory)
        val original = vps.caddyfile.readText()
        val result = adapter.apply(plan, vps.session())
        assertEquals(SiteCaddyApplyResult.VALIDATE_FAILED, result.result)
        assertTrue(result.detail!!.contains("validate failed"))
        assertEquals(original, vps.caddyfile.readText())
        assertFalse(File(plan.siteFilePath).exists())
        assertFalse(File(plan.backupPath).exists())
        assertFalse(File(plan.managedDirectory).exists())
        assertEquals(0, vps.reloadCount())
    }

    @Test
    fun `failed reload restores the previous caddyfile`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps(reloadFailsOnce = true)
        val plan = vps.plan(adapter.probe("site.example.com", 443, vps.session()).inventory)
        val original = vps.caddyfile.readText()
        assertEquals(SiteCaddyApplyResult.RELOAD_FAILED_ROLLED_BACK, adapter.apply(plan, vps.session()).result)
        assertEquals(original, vps.caddyfile.readText())
        assertFalse(File(plan.siteFilePath).exists())
    }

    @Test
    fun `concurrent caddyfile change is detected`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps()
        val plan = vps.plan(adapter.probe("site.example.com", 443, vps.session()).inventory)
        vps.caddyfile.appendText("\n# edited by someone else\n")
        assertEquals(SiteCaddyApplyResult.CADDYFILE_CHANGED, adapter.apply(plan, vps.session()).result)
        assertFalse(File(plan.siteFilePath).exists())
    }

    @Test
    fun `verification reports a wrong body`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps()
        val plan = vps.plan(adapter.probe("site.example.com", 443, vps.session()).inventory)
        assertEquals(SiteCaddyApplyResult.APPLIED, adapter.apply(plan, vps.session()).result)
        File(vps.siteRoot, "index.html").writeText("tampered")
        val verified = adapter.verify(plan, vps.session(), maxAttempts = 1, delaySeconds = 0)
        assertTrue(verified.bodySha256 != plan.indexSha256)
    }

    @Test
    fun `certificate reuse picks the caddy readable pair and never the root 3x-ui path`() = runBlocking<Unit> {
        assumeBash()
        assumeTrue(File("/usr/bin/openssl").canExecute())
        val vps = FakeVps(withCertificates = true, rootCertUnreadable = true)
        val inventory = adapter.probe("site.example.com", 8443, vps.session()).inventory
        assertEquals("caddy", inventory.caddy.serviceUser)
        assertEquals(2, inventory.caddy.tlsFilePairs.size)

        val before = vps.snapshot()
        val candidates = adapter.probeCertificates(inventory.caddy.tlsFilePairs, "caddy", vps.session())
        assertEquals(before, vps.snapshot())
        val byCert = candidates.associateBy { it.pair.certificatePath }
        val caddyOwned = byCert.getValue(vps.caddyCert.absolutePath)
        assertEquals(true, caddyOwned.certificateReadableByService)
        assertEquals(true, caddyOwned.keyReadableByService)
        assertEquals(true, caddyOwned.notExpired)
        assertEquals(listOf("site.example.com", "www.site.example.com"), caddyOwned.dnsNames)
        assertEquals(false, byCert.getValue(vps.rootCert.absolutePath).certificateReadableByService)
        assertTrue(candidates.none { it.toString().contains("PRIVATE KEY") })

        val selection = SiteCaddyCertificatePolicy.select("site.example.com", candidates)
        val chosen = (selection as SiteCaddyCertificateSelection.Selected).candidate
        assertEquals(vps.caddyCert.absolutePath, chosen.pair.certificatePath)
        val plan = vps.plan(inventory, SiteCaddyCertificatePolicy.reference("198.51.100.10", chosen), port = 8443)
        assertTrue(plan.siteBlockUtf8.contains("tls ${vps.caddyCert.absolutePath} ${vps.caddyKey.absolutePath}"))
        assertFalse(plan.siteBlockUtf8.contains(vps.rootCert.absolutePath))
        assertEquals(SiteCaddyApplyResult.APPLIED, adapter.apply(plan, vps.session()).result)

        // Only the unreadable /root pair covers the domain: publication is blocked before upload.
        val onlyRoot = candidates.filter { it.pair.certificatePath == vps.rootCert.absolutePath }
        val blocked = SiteCaddyCertificatePolicy.select("site.example.com", onlyRoot) as SiteCaddyCertificateSelection.Blocked
        assertTrue(blocked.message.contains("не может прочитать"))
    }

    @Test
    fun `apply refuses when the service user cannot read the referenced certificate`() = runBlocking<Unit> {
        assumeBash()
        assumeTrue(File("/usr/bin/openssl").canExecute())
        val readable = FakeVps(withCertificates = true)
        val inventory = adapter.probe("site.example.com", 8443, readable.session()).inventory
        val candidate = adapter.probeCertificates(inventory.caddy.tlsFilePairs, "caddy", readable.session())
            .first { it.pair.certificatePath == readable.caddyCert.absolutePath }
        val plan = readable.plan(inventory, SiteCaddyCertificatePolicy.reference("198.51.100.10", candidate), port = 8443)
        // Permissions changed between the read-only proof and apply.
        readable.root.resolve("bin/runuser").writeText(
            "#!/bin/bash\nshift 2; [ \"${'$'}1\" = -- ] && shift\n" +
                "if [ \"${'$'}1\" = test ] && [ \"${'$'}3\" = '${readable.caddyKey.absolutePath}' ]; then exit 1; fi\nexec \"${'$'}@\"\n",
        )
        val original = readable.caddyfile.readText()
        val result = adapter.apply(plan, readable.session())
        assertEquals(SiteCaddyApplyResult.CERTIFICATE_UNREADABLE, result.result)
        assertTrue(result.detail!!.contains("caddy cannot read"))
        assertEquals(original, readable.caddyfile.readText())
        assertFalse(File(plan.siteFilePath).exists())
        assertFalse(File(plan.backupPath).exists())
        assertEquals(0, readable.reloadCount())
    }

    @Test
    fun `reload permission denied is rolled back with the caddy error`() = runBlocking<Unit> {
        assumeBash()
        assumeTrue(File("/usr/bin/openssl").canExecute())
        val vps = FakeVps(withCertificates = true, reloadPermissionDenied = true)
        val inventory = adapter.probe("site.example.com", 8443, vps.session()).inventory
        // Model the old behaviour: a /root pair that the proof wrongly considered readable.
        val rootPair = adapter.probeCertificates(inventory.caddy.tlsFilePairs, "caddy", vps.session())
            .first { it.pair.certificatePath == vps.rootCert.absolutePath }
        val plan = vps.plan(inventory, SiteCaddyCertificatePolicy.reference("198.51.100.10", rootPair), port = 8443)
        val original = vps.caddyfile.readText()
        val result = adapter.apply(plan, vps.session())
        assertEquals(SiteCaddyApplyResult.RELOAD_FAILED_ROLLED_BACK, result.result)
        assertTrue(result.detail!!.contains("permission denied"))
        assertEquals(original, vps.caddyfile.readText())
        assertFalse(File(plan.siteFilePath).exists())
    }

    @Test
    fun `caddy stuck in reloading is refused before any change`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps(caddyState = "reloading")
        val inventory = adapter.probe("site.example.com", 443, vps.session()).inventory
        assertEquals(SiteServiceState.RELOADING, inventory.caddy.state)
        val decision = SiteServingBackendPolicy.select(inventory)
        assertNull(decision.backend)
        assertEquals(SiteServingFailureCategory.RELOAD_FAILED, decision.blockedCategory)

        // Even with a plan prepared earlier (Caddy went into reloading later), apply changes nothing.
        val active = FakeVps()
        val plan = active.plan(adapter.probe("site.example.com", 443, active.session()).inventory)
        active.root.resolve("bin/systemctl").writeText(
            "#!/bin/bash\n[ \"${'$'}1 ${'$'}2\" = 'is-active caddy' ] && { echo reloading; exit 3; }\nexit 0\n",
        )
        val before = active.snapshot()
        val result = adapter.apply(plan, active.session())
        assertEquals(SiteCaddyApplyResult.CADDY_NOT_ACTIVE, result.result)
        assertTrue(result.detail!!.contains("reloading"))
        assertEquals(before, active.snapshot())
    }

    @Test
    fun `hung reload is cut by the time limit and rolled back before ssh gives up`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps(reloadHangs = true)
        val plan = vps.plan(adapter.probe("site.example.com", 443, vps.session()).inventory)
        val original = vps.caddyfile.readText()
        val started = System.nanoTime()
        val result = adapter.apply(plan, vps.session())
        val seconds = (System.nanoTime() - started) / 1_000_000_000
        assertEquals(SiteCaddyApplyResult.RELOAD_FAILED_ROLLED_BACK, result.result)
        assertTrue("apply took ${seconds}s", seconds < 60)
        assertEquals(original, vps.caddyfile.readText())
        assertFalse(File(plan.siteFilePath).exists())
    }

    @Test
    fun `non zero exit and timeout keep bounded redacted diagnostics`() = runBlocking<Unit> {
        assumeBash()
        val vps = FakeVps()
        val plan = vps.plan(adapter.probe("site.example.com", 443, vps.session()).inventory)
        val key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
        val failing = StubSession(
            CommandCompletion.ConfirmedFailure("exit", 1),
            stdout = "",
            stderr = "x".repeat(5000) + "\n" + key + "\nError: open /root/cert/fullchain.pem: permission denied password=hunter2",
        )
        val failure = assertThrows(SiteCaddyCommandFailedException::class.java) { runBlocking { adapter.apply(plan, failing) } }
        assertEquals("site-caddy-apply", failure.label)
        assertEquals(1, failure.exitCode)
        assertFalse(failure.timedOut)
        assertTrue(failure.stderrTail.length <= SiteCommandOutputRedactor.DEFAULT_MAX_CHARS + 1)
        assertTrue(failure.message!!.contains("применение конфига Caddy"))
        assertTrue(failure.message!!.contains("кодом 1"))
        assertTrue(failure.message!!.contains("permission denied"))
        assertFalse(failure.message!!.contains("MIIEvQ"))
        assertFalse(failure.message!!.contains("hunter2"))
        assertFalse(failure.message!!.contains("base64 -d"))

        val timeout = StubSession(CommandCompletion.Unknown("SSH command execution timed out after dispatch"), "", "")
        val timedOut = assertThrows(SiteCaddyCommandFailedException::class.java) { runBlocking { adapter.rollback(plan, timeout) } }
        assertTrue(timedOut.timedOut)
        assertTrue(timedOut.message!!.contains("откат конфига Caddy"))
        assertTrue(timedOut.message!!.contains("не уложилась"))
    }

    private class StubSession(
        private val completion: CommandCompletion,
        private val stdout: String,
        private val stderr: String,
    ) : VerifiedHostKeySshSessionHandle {
        override val binding = SessionBinding(
            SessionId("stub-session"),
            ServerAccessId("access-1"),
            SessionOwner.Operation(OperationId("stub-op")),
        )
        override val verifiedHostKeySha256: String = "7".repeat(64)
        override val isOpen: Boolean = true

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig) = SshCommandResult(
            dispatchState = CommandDispatchState.DISPATCHED,
            completion = completion,
            stdout = CapturedOutput.of(stdout.encodeToByteArray(), false),
            stderr = CapturedOutput.of(stderr.encodeToByteArray(), false),
        )

        override fun close() = Unit
    }

    private fun assumeBash() = assumeTrue(File("/bin/bash").canExecute())

    /** A throw-away directory tree with stand-in programs that behave like a Caddy-only VPS. */
    private class FakeVps(
        private val caddyInstalled: Boolean = true,
        private val nginxActive: Boolean = false,
        private val nginxInstalled: Boolean = true,
        private val validateFails: Boolean = false,
        private val reloadFailsOnce: Boolean = false,
        /** `caddy reload` never answers (like a stuck admin API); `timeout 25` must cut it. */
        private val reloadHangs: Boolean = false,
        /** `caddy reload` fails like Caddy without access to the referenced certificate. */
        private val reloadPermissionDenied: Boolean = false,
        private val caddyState: String = "active",
        /** The caddy service user cannot enter the /root copy (models `/root drwx------`). */
        private val rootCertUnreadable: Boolean = false,
        private val withCertificates: Boolean = false,
    ) {
        val root: File = Files.createTempDirectory("velum-caddy-vps").toFile()
        private val bin = File(root, "bin").apply { mkdirs() }
        private val state = File(root, "state").apply { mkdirs() }
        val caddyfile = File(root, "etc/caddy/Caddyfile").apply {
            parentFile.mkdirs()
            writeText(
                """
                {
                	email admin@example.com
                }

                vpn.example.com {
                	reverse_proxy 127.0.0.1:10000
                }
                """.trimIndent() + "\n",
            )
        }
        val caddyCert = File(root, "etc/caddy/certs/fullchain.pem")
        val caddyKey = File(root, "etc/caddy/certs/privkey.pem")
        val rootCert = File(root, "root/cert/site.example.com/fullchain.pem")
        val rootKey = File(root, "root/cert/site.example.com/privkey.pem")

        init {
            if (withCertificates) {
                selfSigned(caddyCert, caddyKey, "site.example.com")
                selfSigned(rootCert, rootKey, "site.example.com")
            }
        }

        val siteRoot = File(root, "var/www/velum-site").apply {
            mkdirs()
            File(this, "index.html").writeText("<!doctype html><h1>VELUM</h1>")
        }

        init {
            if (caddyInstalled) {
                script(
                    "caddy",
                    """
                    case "${'$'}1" in
                      adapt) cat '${File(state, "adapt.json").absolutePath}' ;;
                      validate)
                        ${if (validateFails) "echo 'validate failed: unrecognized directive' >&2; exit 1" else "exit 0"} ;;
                      reload)
                        if ${if (reloadHangs) "[ ! -e '${File(state, "reload-hung").absolutePath}' ]" else "false"}; then
                          touch '${File(state, "reload-hung").absolutePath}'; sleep 40
                        fi
                        if ${if (reloadPermissionDenied) "grep -rqsF '${rootCert.parentFile.absolutePath}/' '${caddyfile.parentFile.absolutePath}/velum-sites'" else "false"}; then
                          echo 'Error: loading new config: loading tls app module: open /root/cert/fullchain.pem: permission denied' >&2; exit 1
                        fi
                        if ${if (reloadFailsOnce) "[ ! -e '${File(state, "reload-failed").absolutePath}' ]" else "false"}; then
                          touch '${File(state, "reload-failed").absolutePath}'; echo 'Error: reload failed' >&2; exit 1
                        fi
                        echo x >> '${File(state, "reloads").absolutePath}' ;;
                      *) exit 2 ;;
                    esac
                    """,
                )
                val tlsApp = if (withCertificates) {
                    ""","tls":{"certificates":{"load_files":[""" +
                        """{"certificate":"${caddyCert.absolutePath}","key":"${caddyKey.absolutePath}","tags":["cert0"]},""" +
                        """{"certificate":"${rootCert.absolutePath}","key":"${rootKey.absolutePath}","tags":["cert1"]}]}}"""
                } else {
                    ""
                }
                File(state, "adapt.json").writeText(
                    """{"apps":{"http":{"servers":{"srv0":{"listen":[":443"],"routes":[{"match":[{"host":["vpn.example.com"]}],"handle":[{"handler":"subroute"}],"terminal":true}]}}}""" +
                        tlsApp + "}}",
                )
            }
            if (nginxInstalled) script("nginx", "exit 0")
            script(
                "systemctl",
                """
                case "${'$'}1 ${'$'}2" in
                  "is-active caddy") ${if (caddyInstalled) "echo $caddyState" else "echo inactive"} ;;
                  "is-active nginx") ${if (nginxActive) "echo active" else "echo inactive"} ;;
                  "show caddy")
                    if [ "$4" = User ]; then echo caddy; else
                    echo "{ path=/usr/bin/caddy ; argv[]=/usr/bin/caddy run --environ --config ${caddyfile.absolutePath} --adapter caddyfile ; }"; fi ;;
                  "reload caddy") echo 'systemctl reload must not be used' >&2; exit 99 ;;
                  *) exit 0 ;;
                esac
                """,
            )
            script(
                "ss",
                """
                echo 'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))'
                echo 'LISTEN 0 4096 *:443 *:* users:(("caddy",pid=2,fd=7))'
                echo 'LISTEN 0 4096 *:80 *:* users:(("caddy",pid=2,fd=6))'
                echo 'LISTEN 0 4096 *:2053 *:* users:(("x-ui",pid=3,fd=9))'
                """,
            )
            script(
                "ufw",
                """
                printf 'Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\n'
                printf 'To                         Action      From\n--                         ------      ----\n'
                printf '22/tcp                     ALLOW IN    Anywhere\n80,443/tcp                 ALLOW IN    Anywhere\n2053                       ALLOW IN    Anywhere\n'
                """,
            )
            // runuser stand-in: runs the command as-is, but `test -r` fails for paths the caddy
            // service user cannot read on the modelled VPS.
            script(
                "runuser",
                """
                [ "$1" = -u ] || exit 2
                shift 2; [ "$1" = -- ] && shift
                if [ "$1" = test ] && [ "$2" = -r ]; then
                  ${if (rootCertUnreadable) "case \"${'$'}3\" in '${rootCert.parentFile.absolutePath}'/*) exit 1 ;; esac" else ":"}
                fi
                exec "$@"
                """,
            )
            // curl stand-in: Caddy serves the managed site root once its site file exists.
            script(
                "curl",
                """
                out=''; for a in "${'$'}@"; do case "${'$'}a" in /dev/null) out=null ;; esac; done
                served=0; for f in '${caddyfile.parentFile.absolutePath}'/velum-sites/*.caddy; do [ -f "${'$'}f" ] && served=1; done
                case "${'$'}*" in *'%{http_code}'*) echo 200; exit 0 ;; esac
                if [ "${'$'}served" = 1 ]; then [ "${'$'}out" = null ] || cat '${File(siteRoot, "index.html").absolutePath}'; exit 0; fi
                exit 7
                """,
            )
        }

        fun plan(
            inventory: com.velumtegra.xuimobile.core.site.SiteWebServerInventory,
            certificate: com.velumtegra.xuimobile.core.site.SiteServerCertificateFileReference? = null,
            port: Int = 443,
        ) = SiteCaddyServingPlanner.prepare(
            remoteHostIdentity = "198.51.100.10",
            domain = "site.example.com",
            port = port,
            targetRoot = siteRoot.absolutePath,
            tlsMode = if (certificate != null) {
                SiteCaddyTlsMode.EXISTING_SERVER_CERTIFICATE
            } else {
                SiteCaddyServingPlanner.tlsModeFor(inventory, "site.example.com", false)
            },
            caddy = inventory.caddy,
            indexSha256 = sha256(File(siteRoot, "index.html").readBytes()),
            preservedListeningPorts = inventory.listeningPorts,
            certificate = certificate,
        )

        fun reloadCount(): Int = File(state, "reloads").takeIf { it.exists() }?.readLines()?.size ?: 0

        fun snapshot(): Map<String, String> = root.walkTopDown().filter { it.isFile && !it.path.contains("/bin/") }
            .associate { it.path to it.readText() }

        fun session(): VerifiedHostKeySshSessionHandle = LocalSession(bin)

        private fun selfSigned(cert: File, key: File, host: String) {
            cert.parentFile.mkdirs()
            val process = ProcessBuilder(
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                "-subj", "/CN=$host", "-addext", "subjectAltName=DNS:$host,DNS:www.$host",
                "-keyout", key.absolutePath, "-out", cert.absolutePath,
            ).redirectErrorStream(true).start()
            process.inputStream.readBytes()
            check(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0) { "openssl failed" }
        }

        private fun script(name: String, body: String) {
            File(bin, name).apply {
                writeText("#!/bin/bash\n" + body.trimIndent() + "\n")
                setExecutable(true)
            }
        }
    }

    private class LocalSession(private val bin: File) : VerifiedHostKeySshSessionHandle {
        override val binding = SessionBinding(
            SessionId("caddy-session"),
            ServerAccessId("access-1"),
            SessionOwner.Operation(OperationId("caddy-op")),
        )
        override val verifiedHostKeySha256: String = "7".repeat(64)
        override val isOpen: Boolean = true

        override suspend fun execute(command: RemoteCommand, config: SshTransportConfig): SshCommandResult {
            val out = File.createTempFile("caddy-out", ".txt")
            val err = File.createTempFile("caddy-err", ".txt")
            val process = ProcessBuilder("/bin/bash", "-c", command.rawForTransport())
                .apply { environment()["PATH"] = "${bin.absolutePath}:/usr/bin:/bin" }
                .redirectOutput(out)
                .redirectError(err)
                .start()
            val finished = process.waitFor(config.commandExecutionTimeout.toMillis(), TimeUnit.MILLISECONDS)
            if (!finished) process.destroyForcibly().waitFor()
            val stdout = out.readBytes().also { out.delete() }
            val stderr = err.readBytes().also { err.delete() }
            if (!finished) {
                return SshCommandResult(
                    dispatchState = CommandDispatchState.DISPATCHED,
                    completion = CommandCompletion.Unknown("SSH command execution timed out after dispatch"),
                    stdout = CapturedOutput.of(stdout, false),
                    stderr = CapturedOutput.of(stderr, false),
                )
            }
            return SshCommandResult(
                dispatchState = CommandDispatchState.DISPATCHED,
                completion = if (process.exitValue() == 0) {
                    CommandCompletion.ConfirmedSuccess
                } else {
                    CommandCompletion.ConfirmedFailure("exit", process.exitValue())
                },
                stdout = CapturedOutput.of(stdout, false),
                stderr = CapturedOutput.of(stderr, false),
            )
        }

        override fun close() = Unit
    }

    private companion object {
        fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}

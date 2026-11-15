package com.velumtegra.xuimobile.integration
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.discovery.*
import com.velumtegra.xuimobile.readiness.*
import java.security.MessageDigest
import java.time.Instant
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt-in REAL integration. Production app graph, saved credentials and pin; no injected transport or fixture data. */
@RunWith(AndroidJUnit4::class)
class Phase15_10T4_16Live01ServerBaselineInstrumentedTest{
    companion object {
        private const val HOST = "192.0.2.169"
        private const val PORT = 22
        private const val CONSENT = "REAL_TEST_SERVER_READ_ONLY"
    }
    private fun emit(line:String){
        require(line.length<=512 && !line.contains('\n') && !line.contains('\r'))
        InstrumentationRegistry.getInstrumentation().sendStatus(0,Bundle().apply{putString("stream",line+"\n")})
    }
    private fun <T> RepositoryResult<T>.required(code: String): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("LIVE_BLOCKED:"+code)
    }
    private fun digest(value:String)=MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString(""){"%02x".format(it.toInt() and 255)}
    @Test fun exactAuthorizedRealSshAndPanelBaseline()=runBlocking{
        val args=InstrumentationRegistry.getArguments()
        // Normal automatic/local suites cannot authorize network or turn a skipped run into live proof.
        assumeTrue("LIVE_OPT_IN_REQUIRED",args.getString("live_authorization")==CONSENT)
        assertEquals("LIVE_EXACT_HOST_REQUIRED",HOST,args.getString("live_host"))
        assertEquals("LIVE_EXACT_PORT_REQUIRED", "22", args.getString("live_port"))
        val nonce=args.getString("live_run_nonce").orEmpty();assertTrue("LIVE_NONCE_REQUIRED",Regex("[0-9a-f]{32}").matches(nonce))
        val app=InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
        withTimeout(240_000){
            emit("LIVE_SERVER_BASELINE_BEGIN=$HOST:$PORT");emit("LIVE_RUN_NONCE=$nonce")
            suspend fun exact():Pair<VersionedRecord<Server>,ServerAccess>{
                val servers=app.inventoryServerRepository.list().required("SERVER_INVENTORY_UNAVAILABLE")
                assertTrue("LIVE_SERVER_INVENTORY_BOUND",servers.size<=128 && servers.map{it.value.id}.distinct().size==servers.size)
                val matches=mutableListOf<Pair<VersionedRecord<Server>,ServerAccess>>()
                for(server in servers){
                    val accesses=app.inventoryServerAccessRepository.listForServer(server.value.id).required("ACCESS_INVENTORY_UNAVAILABLE")
                    assertTrue("LIVE_ACCESS_INVENTORY_BOUND",accesses.size<=64 && accesses.map{it.id}.distinct().size==accesses.size)
                    assertTrue("LIVE_ACCESS_OWNERSHIP",accesses.all{it.serverId==server.value.id})
                    matches+=accesses.filter{it.endpoint.host==HOST && it.endpoint.port==PORT}.map{server to it}
                }
                if(matches.size!=1){emit("LIVE_EXACT_ACCESS_MATCHES="+matches.size);throw AssertionError(if(matches.isEmpty())"LIVE_BLOCKED:SAVED_ACCESS_ABSENT"else "LIVE_BLOCKED:AMBIGUOUS_SAVED_ACCESS")}
                val selected=matches.single()
                assertEquals("LIVE_SERVER_LOOKUP_DRIFT",selected.first,app.inventoryServerRepository.get(selected.first.value.id).required("SERVER_MISSING"))
                assertEquals("LIVE_ACCESS_LOOKUP_DRIFT",selected.second,app.inventoryServerAccessRepository.get(selected.second.id).required("ACCESS_MISSING"))
                return selected
            }
            val selected=exact();val access=selected.second;val server=selected.first.value
            val reviewed=(LocalSshReadinessPolicy.inspect(server.id.value,access.id.value,access) as? LocalSshReadinessResult.MetadataPresent)?.summary
                ?:throw AssertionError("LIVE_BLOCKED:INVALID_SAVED_ACCESS_OR_PIN")
            val target=LiveSshConnectionPolicy.exactTarget(reviewed)
            suspend fun stable(){assertEquals("LIVE_SAVED_TARGET_CHANGED",selected,exact())}
            emit("LIVE_SAVED_TARGET_SHA256="+digest(listOf(server.id.value,selected.first.revision.value.toString(),access.id.value,reviewed.host,reviewed.port.toString(),reviewed.username,reviewed.savedFingerprint,reviewed.credentialRefDigest).joinToString(""){"${it.length}:$it"}))
            stable()
            when(val connected=app.liveSshConnectionPort.connectExact(server.id.value,access.id.value,reviewed,target,true)){
                is LiveSshConnectionResult.Verified->{assertEquals(target,connected.target);assertEquals(reviewed.savedFingerprint,connected.fingerprint)}
                is LiveSshConnectionResult.Blocked->throw AssertionError("LIVE_SSH_BLOCKED:"+connected.message)
            }
            stable();emit("LIVE_SSH_AUTH_AND_SAVED_HOST_KEY=VERIFIED")
            val observation=when(val result=app.xuiReadOnlyDiscoveryPort.inspectDiagnosticExact(server.id.value,access.id.value,reviewed,target,true)){
                is XuiReadOnlyDiscoveryResult.Observation->result
                is XuiReadOnlyDiscoveryResult.Blocked->throw AssertionError("LIVE_DISCOVERY_BLOCKED:"+result.message)
            }
            stable()
            val diagnostic=observation.diagnostics?:throw AssertionError("LIVE_DISCOVERY_DIAGNOSTIC_MISSING")
            emit("LIVE_DISCOVERY_DIAGNOSTIC="+diagnostic.summary())
            val candidate=observation.candidateIdentity?:throw AssertionError("LIVE_BLOCKED:SUPPORTED_PANEL_IDENTITY_NOT_PROVED")
            assertTrue("LIVE_UNSUPPORTED_CANDIDATE",XuiServiceVerificationPolicy.approvedCandidate(candidate))
            stable();emit("LIVE_PANEL_KNOWN_PATHS=OBSERVED")
            val service=when(val result=app.xuiReadOnlyDiscoveryPort.verifyServiceExact(server.id.value,access.id.value,reviewed,target,true,candidate)){
                is XuiServiceVerificationResult.Observed->result.state
                is XuiServiceVerificationResult.Blocked->throw AssertionError("LIVE_SERVICE_BLOCKED:"+result.message)
            }
            stable();emit("LIVE_SERVICE_STATE="+service.name)
            val version=when(val result=app.xuiReadOnlyDiscoveryPort.verifyVersionExact(server.id.value,access.id.value,reviewed,target,true,candidate)){
                is XuiVersionVerificationResult.Observed->result.version
                is XuiVersionVerificationResult.Blocked->throw AssertionError("LIVE_VERSION_BLOCKED:"+result.message)
            }
            assertTrue("LIVE_VERSION_NOT_CANONICAL",Regex("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}").matches(version))
            stable();emit("LIVE_PANEL_VERSION="+version)
            val installations=app.inventoryInstallationRepository.listForServer(server.id).required("INSTALLATION_INVENTORY_UNAVAILABLE")
            assertTrue("LIVE_INSTALLATION_INVENTORY_BOUND",installations.size<=96 && installations.all{it.value.serverId==server.id})
            val matching=installations.filter{it.value.identity.let{i->i.serviceUnit==candidate.serviceUnit && i.binaryPath==candidate.binaryPath && i.rootPath==candidate.rootPath && i.databasePath==candidate.databasePath}}
            emit("LIVE_LOCAL_MATCHING_INSTALLATIONS="+matching.size)
            stable();emit("LIVE_OBSERVED_AT="+Instant.now().toString());emit("LIVE_REMOTE_MUTATIONS=NONE_REQUESTED")
            emit("LIVE_SERVER_BASELINE_PASS=$HOST:$PORT")
        }
    }
}

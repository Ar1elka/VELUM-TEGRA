package com.velumtegra.xuimobile.integration

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import com.velumtegra.xuimobile.VelumTegraApplication
import com.velumtegra.xuimobile.core.domain.*
import com.velumtegra.xuimobile.core.model.*
import com.velumtegra.xuimobile.core.ssh.*
import com.velumtegra.xuimobile.readiness.*
import java.security.MessageDigest
import java.time.Duration
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** User rebound the dedicated test server on 2026-10-31. Fixed read-only metadata only. */
class Phase15_10T4_18ExistingBackupAuditInstrumentedTest {
    private fun emit(key: String, value: Any) {
        val line = "EXISTING_BACKUP_AUDIT_$key=$value"
        require(line.length <= 256 && '\n' !in line && '\r' !in line)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply { putString("stream", "$line\n") })
    }
    private fun <T> RepositoryResult<T>.required(): T = when (this) {
        is RepositoryResult.Success -> value
        else -> throw AssertionError("AUDIT_LOCAL_REPOSITORY_UNAVAILABLE")
    }
    private fun digest(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun quote(value: String) = "'" + value.replace("'", "'\"'\"'") + "'"

    @Test fun exactAuthorizedReadOnlyServiceMetadata() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("live_authorization") == "READ_ONLY_EXISTING_BACKUP_RECONCILIATION")
        val nonce = args.getString("audit_nonce").orEmpty()
        assertTrue(Regex("[0-9a-f]{32}").matches(nonce))
        emit("NONCE", nonce)
        var gate = "TARGET"
        try {
            val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as VelumTegraApplication
            val deps = app.debugMaintenanceDependencies()
            suspend fun exact(): Triple<VersionedRecord<Server>, ServerAccess, VersionedRecord<XuiInstallation>> {
                val servers = app.inventoryServerRepository.list().required()
                assertTrue(servers.size <= 128 && servers.map { it.value.id }.distinct().size == servers.size)
                val matches = mutableListOf<Pair<VersionedRecord<Server>, ServerAccess>>()
                for (server in servers) {
                    val accesses = app.inventoryServerAccessRepository.listForServer(server.value.id).required()
                    assertTrue(accesses.size <= 64 && accesses.all { it.serverId == server.value.id })
                    assertEquals(accesses.size, accesses.map { it.id }.distinct().size)
                    matches += accesses.filter { it.endpoint.host == "192.0.2.139" && it.endpoint.port == 21578 }.map { server to it }
                }
                assertEquals(1, matches.size)
                val (server, access) = matches.single()
                assertEquals("d497bfe2-781a-4fff-bac9-16816bdc1d6b", server.value.id.value)
                assertEquals("root", access.username)
                assertEquals(HostKeyFingerprint("SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"), access.pinnedHostKey)
                assertEquals(server, app.inventoryServerRepository.get(server.value.id).required())
                assertEquals(access, app.inventoryServerAccessRepository.get(access.id).required())
                val installations = app.inventoryInstallationRepository.listForServer(server.value.id).required()
                assertTrue(installations.size <= 96 && installations.all { it.value.serverId == server.value.id })
                assertEquals(installations.size, installations.map { it.value.id }.distinct().size)
                val installation = installations.single { it.value.identity.let { identity ->
                    identity.serviceUnit == "x-ui.service" && identity.binaryPath == "/usr/local/x-ui/x-ui" &&
                        identity.rootPath == "/usr/local/x-ui" && identity.databasePath == "/etc/x-ui/x-ui.db"
                } }
                assertEquals(installation, app.inventoryInstallationRepository.get(installation.value.id).required())
                assertEquals(ManagementAccess(installation.value.id, access.id),
                    app.inventoryManagementRepository.get(installation.value.id, access.id).required())
                return Triple(server, access, installation)
            }
            val selected = exact()
            val server = selected.first.value
            val access = selected.second
            suspend fun stable() { assertEquals(selected, exact()) }
            val reviewed = (LocalSshReadinessPolicy.inspect(server.id.value, access.id.value, access)
                as? LocalSshReadinessResult.MetadataPresent)?.summary ?: error("INVALID_SAVED_TARGET")
            emit("TARGET_SHA256", digest(listOf(server.id.value, selected.first.revision.value.toString(), access.id.value,
                reviewed.host, reviewed.port.toString(), reviewed.username, reviewed.savedFingerprint,
                reviewed.credentialRefDigest).joinToString("") { "${it.length}:$it" }))
            emit("INSTALLATION_SHA256", digest(selected.third.value.id.value))
            gate = "JOURNAL"
            val operation = OperationId("49c230f1-4dad-4cb6-8b19-1affc369b64d")
            val before = (deps.journal.get(operation) as? OperationJournalResult.Success)?.value ?: error("MISSING_ORIGINAL_OPERATION")
            assertTrue(InstallationBackupBindingPolicy.matches(before, selected.third.value, access))
            assertEquals(OperationStatus.RECONCILIATION_REQUIRED, before.snapshot.status)
            assertEquals(CheckpointSemantics.POST_VERIFY_REQUIRED, before.snapshot.checkpoint.semantics)
            val parsed = requireNotNull(InstallationBackupBinding.parse(before.snapshot.checkpoint.phaseName))
            assertEquals(InstallationBackupPhase.COMMAND_FAILED, parsed.first)
            val binding = parsed.second
            val scope = ManagementScope(operation, server.id, access.id, selected.third.value.id)
            val history = (deps.journal.history(operation) as? OperationJournalResult.Success)?.value ?: error("MISSING_HISTORY")
            assertEquals(1, history.count { it.checkpoint.semantics == CheckpointSemantics.MUTATION_IN_FLIGHT })
            assertEquals(1, history.count { it.checkpoint.semantics == CheckpointSemantics.POST_VERIFY_REQUIRED })
            suspend fun unchanged() {
                stable()
                assertEquals(before, (deps.journal.get(operation) as? OperationJournalResult.Success)?.value)
                val entries = (deps.journal.listNonTerminal() as? OperationJournalResult.Success)?.value ?: error("JOURNAL_UNAVAILABLE")
                assertTrue(entries.size <= 512)
                assertEquals(listOf(operation), entries.filter { it.snapshot.target.serverId == server.id }.map { it.snapshot.operationId })
            }
            unchanged()
            emit("ORIGINAL_OPERATION", operation.value); emit("BINDING_SHA256", binding.digest)
            val owner = SessionOwner.Operation(operation)
            val outcome = deps.coordinator.withExclusiveServerMaintenanceLease(server.id, operation) {
                unchanged(); gate = "SESSION"
                val pin = (CanonicalHostKeyFingerprint.parse(access.pinnedHostKey) as? HostKeyFingerprintParseResult.Valid)?.fingerprint ?: error("INVALID_PIN")
                val handle = (deps.connections.connect(access, owner) as? SshConnectResult.Connected)?.handle ?: error("SSH_REJECTED")
                try {
                    assertTrue(handle.isOpen); assertEquals(access.id, handle.binding.serverAccessId); assertEquals(owner, handle.binding.owner)
                    assertEquals(pin.asHexSha256(), (handle as? VerifiedHostKeySshSessionHandle)?.verifiedHostKeySha256)
                    emit("PINNED_SESSION", "VERIFIED")
                    suspend fun read(command: String, tag: String): String {
                        unchanged()
                        val result = handle.execute(RemoteCommand.create(command, tag), SshTransportConfig(
                            channelOpenTimeout = Duration.ofSeconds(5), commandExecutionTimeout = Duration.ofSeconds(30),
                            stdoutCaptureLimitBytes = 4096, stderrCaptureLimitBytes = 128))
                        emit("QUERY", tag); emit("COMPLETION", result.completion.javaClass.simpleName)
                        assertEquals(CommandDispatchState.DISPATCHED, result.dispatchState)
                        assertEquals(CommandCompletion.ConfirmedSuccess, result.completion)
                        assertFalse(result.stdout.truncated); assertFalse(result.stderr.truncated); assertEquals(0, result.stderr.sizeBytes)
                        val bytes = result.stdout.copyBytes()
                        return try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
                    }
                    gate = "READ_ONLY_PROBE"
                    val definitions = """
'''Closed standard-layout installation artifact worker. No extraction, service mutation or network.'''
import os, sys, stat, sqlite3, json, hashlib, tarfile, io, fcntl, subprocess, time, re, resource

ROOT = '/root/.velum-tegra-installation-backups'
HOME = '/root'
RUNTIME = '/usr/local/x-ui'
DATABASE = '/etc/x-ui/x-ui.db'
PREFIXES = ('/root/', '/etc/', '/usr/local/x-ui/', '/usr/lib/systemd/system/', '/lib/systemd/system/', '/var/lib/')
MAX_DB = 134217728
MAX_FILES = 96
MAX_BYTES = 536870912
MAX_ARCHIVE = 738197504
DEADLINE = time.monotonic() + 85

class Rejected(Exception):
    pass

def need(condition):
    if not condition:
        raise Rejected()

def tick(*unused):
    need(time.monotonic() < DEADLINE)

def safe(path):
    return isinstance(path, str) and 2 <= len(path) <= 240 and re.fullmatch(r'/[A-Za-z0-9_./@:+-]+', path) is not None and '//' not in path and all(p not in ('.', '..') for p in path.split('/')) and path.startswith(PREFIXES)

def signature(s):
    return (s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode), s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)

def checked(path, directory=False, secret=False):
    '''Open each directory relative to its checked parent; never follow a symlink or FIFO.'''
    need(path.startswith('/') and '//' not in path and all(p not in ('.', '..') for p in path.split('/')))
    parts = path.strip('/').split('/')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, part in enumerate(parts):
            isdir = index < len(parts) - 1 or directory
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if isdir else 0), dir_fd=fd)
            os.close(fd); fd = child
            s = os.fstat(fd); mode = stat.S_IMODE(s.st_mode)
            need(s.st_uid == 0 and mode & 0o022 == 0)
            if isdir:
                need(stat.S_ISDIR(s.st_mode))
            else:
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and mode & 0o7000 == 0 and mode & 0o400 != 0)
                need(not secret or mode in (0o400, 0o600))
        return fd, os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise

def file_info(path, secret=False, limit=268435456):
    need(safe(path))
    fd, s = checked(path, secret=secret)
    os.close(fd)
    need(s.st_size <= limit)
    return signature(s)

def private_dir(path):
    fd, s = checked(path, directory=True)
    os.close(fd)
    need(stat.S_IMODE(s.st_mode) == 0o700)

def read_file(path, limit, secret=False):
    fd, s = checked(path, secret=secret)
    with os.fdopen(fd, 'rb') as f:
        need(s.st_size <= limit)
        value = f.read(limit + 1)
        need(len(value) == s.st_size and signature(os.fstat(f.fileno())) == signature(s))
    return value

def digest_file(path, limit, secret=False):
    fd, s = checked(path, secret=secret)
    with os.fdopen(fd, 'rb') as f:
        need(s.st_size <= limit)
        digest = hashlib.sha256(); count = 0
        while True:
            tick(); value = f.read(1048576)
            if not value: break
            count += len(value); need(count <= limit); digest.update(value)
        need(count == s.st_size and signature(os.fstat(f.fileno())) == signature(s))
    return digest.hexdigest()

def absent_dependency(directory, name):
    # Anchor the absence check in root-owned, non-writable, no-follow directories.
    fd, unused = checked(directory, directory=True)
    try:
        try: os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: return
        raise Rejected()
    finally: os.close(fd)

def standard_environment(fields):
    need(fields['Environment'] in ('', 'XRAY_VMESS_AEAD_FORCED=false'))
    if fields['EnvironmentFiles']:
        need(fields['EnvironmentFiles'] == '/etc/default/x-ui (ignore_errors=yes)')
        absent_dependency('/etc/default', 'x-ui')
    # Separate node keyrings are outside this closed backup format; never omit one.
    absent_dependency('/etc/x-ui', 'node_token_key.json')

def standard_reload(value):
    if not value: return True
    arguments = re.findall(r'argv\[\]=([^;]+)', value)
    executables = re.findall(r'path=([^ ;]+)', value)
    return len(arguments) == 1 and len(executables) == 1 and executables[0] in ('/bin/kill', '/usr/bin/kill') and arguments[0].strip() == executables[0] + ' -USR1 ' + chr(36) + 'MAINPID'

def empty_service_array(name):
    # A text formatter omission/placeholder is never proof that a dependency is absent.
    types = {'ExecStartPre':'a(sasbttttuii)', 'ExecStartPost':'a(sasbttttuii)',
             'ExecStop':'a(sasbttttuii)', 'ExecReload':'a(sasbttttuii)',
             'LoadCredential':'a(ss)', 'LoadCredentialEncrypted':'a(ss)'}
    need(name in types)
    result = subprocess.run(['/usr/bin/busctl', '--system', '--no-pager', 'get-property',
        'org.freedesktop.systemd1', '/org/freedesktop/systemd1/unit/x_2dui_2eservice',
        'org.freedesktop.systemd1.Service', name], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=5, check=True, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    expected = (types[name] + ' 0').encode('ascii')
    need(result.stderr == b'' and result.stdout in (expected, expected + b'\n'))

def service():
    extras = ('RootDirectory','RootImage','BindPaths','BindReadOnlyPaths','LoadCredential','LoadCredentialEncrypted','RuntimeDirectory','StateDirectory','ConfigurationDirectory','ExecStartPre','ExecStartPost','ExecStop','ExecReload')
    names = ('FragmentPath', 'DropInPaths', 'WorkingDirectory', 'Environment', 'EnvironmentFiles', 'ExecStart') + extras
    result = subprocess.run(['/usr/bin/systemctl', 'show', '--all', '--no-pager'] + ['--property=' + p for p in names] + ['--', 'x-ui.service'],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(len(result.stdout) <= 8192)
    pairs = [line.split('=', 1) for line in result.stdout.decode('utf-8', 'strict').splitlines()]
    need(all(len(p) == 2 for p in pairs))
    fields = dict(pairs); need(len(fields) == len(pairs) and set(fields) <= set(names))
    missing = set(names) - set(fields)
    need(missing <= {'ExecStartPre','ExecStartPost','ExecStop','ExecReload'})
    for name in sorted(missing):
        empty_service_array(name)
        fields[name] = ''
    for name in ('LoadCredential', 'LoadCredentialEncrypted'):
        if fields[name] == '[unprintable]':
            empty_service_array(name)
            fields[name] = ''
    need(set(fields) == set(names))
    need(fields['WorkingDirectory'].rstrip('/') == RUNTIME)
    standard_environment(fields)
    need(standard_reload(fields['ExecReload']))
    need(all(not fields[k] for k in extras if k != 'ExecReload'))
    arguments = re.findall(r'argv\[\]=([^;]+)', fields['ExecStart'])
    need(len(arguments) == 1 and arguments[0].strip() == RUNTIME + '/x-ui')
    executables = re.findall(r'path=([^ ;]+)', fields['ExecStart'])
    need(executables == [RUNTIME + '/x-ui'])
    paths = [fields['FragmentPath']] + fields['DropInPaths'].split()
    need(1 <= len(paths) <= 9 and len(set(paths)) == len(paths))
    need(all(p.startswith(('/etc/systemd/system/', '/usr/lib/systemd/system/', '/lib/systemd/system/')) and safe(p) for p in paths))
    return fields, paths

def database_guard():
    info = file_info(DATABASE, True); need(0 < info[4] <= MAX_DB)
    for suffix, limit in (('-wal',MAX_DB),('-shm',8388608)):
        if os.path.lexists(DATABASE + suffix): file_info(DATABASE + suffix, True, limit)

def connect(path, immutable=False):
    if path == DATABASE: database_guard()
    con = sqlite3.connect('file:' + path + '?mode=ro' + ('&immutable=1' if immutable else ''), uri=True, timeout=3)
    con.execute('PRAGMA query_only=ON'); con.execute('PRAGMA temp_store=MEMORY'); con.execute('PRAGMA trusted_schema=OFF')
    con.set_progress_handler(lambda: 0 if time.monotonic() < DEADLINE else 1, 10000)
    return con

def unique_object(pairs):
    result = {}
    for k, v in pairs:
        need(k not in result); result[k] = v
    return result

def json_object(raw):
    need(isinstance(raw, str) and len(raw.encode('utf-8')) <= 65536)
    result = json.loads(raw, object_pairs_hook=unique_object)
    need(isinstance(result, dict))
    return result

def references(path, active):
    '''One database read transaction, bounded rows/values. Private values never leave this worker.'''
    con = connect(path, path != DATABASE)
    try:
        con.execute('BEGIN')
        for table, required in (('settings', {'key', 'value'}), ('inbounds', {'settings', 'stream_settings'})):
            need(con.execute('SELECT type FROM sqlite_master WHERE name=?', (table,)).fetchall() == [('table',)])
            need(required <= {r[1] for r in con.execute('PRAGMA table_info(' + table + ')')})
        names = ('webCertFile', 'webKeyFile', 'subCertFile', 'subKeyFile', 'xrayTemplateConfig')
        rows = con.execute('SELECT key, length(CAST(value AS BLOB)), substr(value,1,65537) FROM settings WHERE key IN (?,?,?,?,?) LIMIT 6', names).fetchall()
        need(len(rows) <= 5 and len({r[0] for r in rows}) == len(rows))
        settings = {}
        for key, length, value in rows:
            need(isinstance(length, int) and length <= 65536 and isinstance(value, str)); settings[key] = value
        need('xrayTemplateConfig' in settings)
        docs = [json_object(settings['xrayTemplateConfig'])]
        raw_docs = [settings['xrayTemplateConfig']]
        rows = con.execute('SELECT length(CAST(settings AS BLOB)), substr(settings,1,65537), length(CAST(stream_settings AS BLOB)), substr(stream_settings,1,65537) FROM inbounds LIMIT 257').fetchall()
        need(len(rows) <= 256)
        for row in rows:
            for length, raw in ((row[0], row[1]), (row[2], row[3])):
                need(isinstance(length, int) and length <= 65536); docs.append(json_object(raw)); raw_docs.append(raw)
        if active:
            raw = read_file(RUNTIME + '/bin/config.json', 65536, True).decode('utf-8', 'strict')
            docs.append(json_object(raw)); raw_docs.append(raw)
        need(len(docs) <= 514 and sum(len(r.encode('utf-8')) for r in raw_docs) <= 2097152)
        refs = {}
        def add(p, secret, group):
            need(safe(p))
            old = refs.setdefault(p, [False, set()]); old[0] |= secret; old[1].add(group)
            need(len(refs) <= 32)
        for key in names[:4]:
            if settings.get(key): add(settings[key], key.endswith('KeyFile'), 'PANEL_TLS')
        def walk(value, key='', depth=0):
            need(depth <= 32); tick()
            if isinstance(value, dict):
                for k, v in value.items(): walk(v, k, depth + 1)
            elif isinstance(value, list):
                for v in value: walk(v, key, depth + 1)
            elif key in ('certificateFile', 'keyFile', 'echKeyFile'):
                need(isinstance(value, str))
                if value: add(value, key != 'certificateFile', 'XRAY_TLS')
            elif isinstance(value, str) and value.startswith(('ext:', 'ext-ip:')):
                m = re.fullmatch(r'ext(?:-ip)?:([A-Za-z0-9_-][A-Za-z0-9_.-]{0,95}\.dat):([^\s]+)', value)
                need(m is not None); add(RUNTIME + '/bin/' + m[1], False, 'XRAY_DATA')
            elif isinstance(value, str) and (value.startswith('/') and key not in ('access', 'error') or value.startswith(('file:', 'unix:', 'fd:'))):
                raise Rejected()
        for doc in docs: walk(doc)
        # Same private source values must survive the copy and archive interval; digest stays on server.
        binding = hashlib.sha256(json.dumps([settings, raw_docs], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return refs, binding
    finally: con.close()

def collect(db):
    candidates = {}
    def add(p, secret, group):
        need(safe(p) and p not in (DATABASE, DATABASE + '-wal', DATABASE + '-shm') and not p.startswith(ROOT + '/')); v = candidates.setdefault(p, [False, set()]); v[0] |= secret; v[1].add(group)
        need(len(candidates) <= MAX_FILES)
    rootfd, rootstat = checked(RUNTIME, directory=True); os.close(rootfd)
    count = 0
    for parent, dirs, files in os.walk(RUNTIME, followlinks=False):
        tick()
        depth = parent[len(RUNTIME):].count('/')
        need(depth < 4 or not dirs and not files)
        for name in dirs + files:
            count += 1; need(count <= 192)
            p = parent + '/' + name; need(safe(p))
            item = os.lstat(p); need(item.st_dev == rootstat.st_dev and not stat.S_ISLNK(item.st_mode))
            if name in dirs:
                fd, unused = checked(p, directory=True); os.close(fd)
            else: add(p, p.endswith('/config.json'), 'RUNTIME')
    need(RUNTIME + '/x-ui' in candidates)
    xray = RUNTIME + '/bin/xray-linux-' + ('amd64' if ARCH == 'AMD64' else 'arm64')
    need(xray in candidates)
    fields, paths = service()
    for p in paths: add(p, False, 'SERVICE')
    refs, ref_digest = references(db, RUNTIME + '/bin/config.json' in candidates)
    for p, (secret, groups) in refs.items():
        for group in groups: add(p, secret, group)
    for p, v in candidates.items():
        v.append(file_info(p, v[0]))
        if p in (RUNTIME + '/x-ui', xray): need(v[2][4] > 0 and v[2][3] & 0o100 != 0)
    need(sum(v[2][4] for v in candidates.values()) <= MAX_BYTES)
    return candidates, fields, ref_digest

def storage():
    need(os.geteuid() == 0 and hasattr(sqlite3.Connection, 'backup'))
    private_dir(HOME)
    slots = 0
    if os.path.lexists(ROOT):
        private_dir(ROOT); slots = len([p for p in os.listdir(ROOT) if p != '.writer.lock'])
    need(slots <= 4)
    v = os.statvfs(HOME)
    return slots, v.f_bavail * v.f_frsize

def fingerprint(observation):
    rows = []
    for path, (secret, groups, metadata) in sorted(observation[0].items()):
        dev, ino, uid, mode, size, mtime, ctime, links = metadata
        fields = (path, ','.join(sorted(groups)), '1' if secret else '0', str(dev), str(ino), str(uid), format(mode,'o'), str(size), str(mtime//1000000000), str(ctime//1000000000), str(links))
        rows.append('|'.join(fields) + '\n')
    return hashlib.sha256(''.join(rows).encode('utf-8')).hexdigest()

def version_check():
    binary = RUNTIME + '/x-ui'
    metadata = file_info(binary)
    need(metadata[4] > 0 and metadata[3] & 0o100 != 0)
    result = subprocess.run([binary, '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3,
                            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(result.returncode == 0 and not result.stderr and len(result.stdout) <= 96)
    need(result.stdout.decode('ascii').rstrip('\r\n') in (VERSION, 'v' + VERSION))
    need(os.uname().machine == ('x86_64' if ARCH == 'AMD64' else 'aarch64'))

""".trimIndent()
                    val probe = definitions + "\nVERSION=" + quote(binding.version) + "\nARCH=" + quote(binding.architecture.name) + "\nSCOPE=" + quote(binding.digest) + "\nDIRECTORY=" + quote(binding.remoteDirectory) + "\n" + """
for label, action in (('SERVICE', service), ('COLLECT', lambda: collect(DATABASE)), ('VERSION', version_check)):
    try:
        action(); print(label + '=PASSED')
    except Exception:
        print(label + '=BLOCKED')
try:
    unused, available = storage()
    info = file_info(DATABASE, True)
    files = collect(DATABASE)[0]
    need(available >= 2*(sum(v[2][4] for v in files.values())+info[4])+50331648)
    print('CAPACITY=PASSED')
except Exception:
    print('CAPACITY=BLOCKED')
resource.setrlimit(resource.RLIMIT_AS, (536870912,2147483648))
for label, action in (('LIMITED_SERVICE', service), ('LIMITED_COLLECT', lambda: collect(DATABASE)), ('LIMITED_VERSION', version_check)):
    try:
        action(); print(label + '=PASSED')
    except Exception:
        print(label + '=BLOCKED')
original_run = subprocess.run
def bounded_version_run(command, **kwargs):
    need(command == [RUNTIME+'/x-ui', '-v'])
    kwargs['preexec_fn'] = lambda: resource.setrlimit(resource.RLIMIT_AS, (2147483648,2147483648))
    return original_run(command, **kwargs)
subprocess.run = bounded_version_run
try:
    version_check(); print('BOUNDED_CHILD_VERSION=PASSED')
except Exception:
    print('BOUNDED_CHILD_VERSION=BLOCKED')
finally:
    subprocess.run = original_run
print('PARENT_MEMORY_LIMIT='+('PASSED' if resource.getrlimit(resource.RLIMIT_AS)==(536870912,2147483648) else 'BLOCKED'))
for label, path, directory in (('PRIVATE_ROOT', ROOT, True), ('SLOT', DIRECTORY, True), ('DATABASE_COPY', DIRECTORY+'/database.sqlite', False), ('ARCHIVE_PENDING', DIRECTORY+'/installation.pending', False), ('ARCHIVE', DIRECTORY+'/installation.tar', False), ('MANIFEST_PENDING', DIRECTORY+'/manifest.pending', False), ('MANIFEST', DIRECTORY+'/manifest.v1', False)):
    if not os.path.lexists(path):
        print(label+'=ABSENT'); continue
    try:
        fd, info=checked(path, directory=directory, secret=not directory); os.close(fd)
        print(label+'=SAFE:'+str(info.st_size)+':'+format(stat.S_IMODE(info.st_mode),'o'))
    except Exception:
        print(label+'=UNSAFE')
""".trimIndent()
                    val facts = read("timeout --kill-after=2s 25s python3 -I -c " + quote(probe), "existing-backup-read-only-probe").trimEnd().lines()
                    assertEquals(16, facts.size)
                    val labels = listOf("SERVICE", "COLLECT", "VERSION", "CAPACITY", "LIMITED_SERVICE", "LIMITED_COLLECT", "LIMITED_VERSION", "BOUNDED_CHILD_VERSION", "PARENT_MEMORY_LIMIT", "PRIVATE_ROOT", "SLOT", "DATABASE_COPY", "ARCHIVE_PENDING", "ARCHIVE", "MANIFEST_PENDING", "MANIFEST")
                    facts.forEachIndexed { index, fact ->
                        val parts = fact.split('=', limit=2); assertEquals(2, parts.size); assertEquals(labels[index], parts[0])
                        assertTrue(Regex("PASSED|BLOCKED|ABSENT|UNSAFE|SAFE:[0-9]{1,12}:[0-7]{3,4}").matches(parts[1]))
                        emit(parts[0], parts[1])
                    }
                    gate = "VERIFY_EXISTING"
                    val receipt = InstallationBackupSshAdapter().verify(scope, binding, handle)
                    emit("EXISTING_RECEIPT", receipt != null)
                    receipt?.let { emit("ARCHIVE_SHA256", it.sha256); emit("DATABASE_SHA256", it.databaseSha256); emit("FILES", it.fileCount); emit("BYTES", it.sizeBytes) }
                    gate = "HEALTH"
                    assertEquals("active\n", read("systemctl is-active -- x-ui.service", "existing-backup-active-service"))
                    emit("SERVICE_ACTIVE", "VERIFIED")
                    unchanged(); true
                } finally { handle.close() }
            }
            assertEquals(true, outcome); unchanged()
            emit("JOURNAL", "UNCHANGED"); emit("MUTATIONS", "NONE_REQUESTED"); emit("RESULT", "COMPLETE")
        } catch (_: Exception) { throw AssertionError("EXISTING_BACKUP_AUDIT_BLOCKED_GATE=$gate") }
          catch (_: AssertionError) { throw AssertionError("EXISTING_BACKUP_AUDIT_BLOCKED_GATE=$gate") }
    }
}

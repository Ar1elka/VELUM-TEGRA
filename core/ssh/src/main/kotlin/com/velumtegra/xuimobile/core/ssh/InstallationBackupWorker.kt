package com.velumtegra.xuimobile.core.ssh

/** Closed Python 3.8+ standard-library worker. Never extracts or mutates a service. */
internal object InstallationBackupWorker {
    val source: String = """
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
        # A panel whose Xray template was never edited has no such row and runs the built-in default;
        # then the generated config.json must be present so the effective config is still walked.
        need('xrayTemplateConfig' in settings or active)
        raw_docs = [settings['xrayTemplateConfig']] if 'xrayTemplateConfig' in settings else []
        docs = [json_object(raw) for raw in raw_docs]
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
        # URL paths, not files: REALITY spider path, web-transport path, HTTP-header path list, fallback matcher.
        web_parents = ('wsSettings', 'httpupgradeSettings', 'xhttpSettings', 'splithttpSettings', 'httpSettings', 'fallbacks', 'request')
        def walk(value, key='', depth=0, parent=''):
            need(depth <= 32); tick()
            if isinstance(value, dict):
                for k, v in value.items(): walk(v, k, depth + 1, key)
            elif isinstance(value, list):
                for v in value: walk(v, key, depth + 1, parent)
            elif isinstance(value, str) and value.startswith('/') and (key == 'spiderX' or key == 'path' and parent in web_parents):
                return
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
                            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
                            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS, (2147483648,2147483648)))
    need(result.returncode == 0 and not result.stderr and len(result.stdout) <= 96)
    need(result.stdout.decode('ascii').rstrip('\r\n') in (VERSION, 'v' + VERSION))
    need(os.uname().machine == ('x86_64' if ARCH == 'AMD64' else 'aarch64'))

def create():
    slots, available = storage(); need(slots < 4)
    before_db = file_info(DATABASE, True); need(0 < before_db[4] <= MAX_DB)
    initial = collect(DATABASE)
    version_check()
    need(fingerprint(initial) == REVIEWED)
    total = sum(v[2][4] for v in initial[0].values())
    need(available >= 2 * (total + before_db[4]) + 50331648)
    if not os.path.lexists(ROOT): os.mkdir(ROOT, 0o700)
    private_dir(ROOT)
    lock = os.open(ROOT + '/.writer.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        need(stat.S_ISREG(os.fstat(lock).st_mode) and os.fstat(lock).st_uid == 0 and stat.S_IMODE(os.fstat(lock).st_mode) == 0o600 and os.fstat(lock).st_nlink == 1)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(storage()[0] < 4)
        os.mkdir(DIRECTORY, 0o700)
        copy = DIRECTORY + '/database.sqlite'
        fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.close(fd)
        source = connect(DATABASE)
        target = sqlite3.connect(copy, timeout=3)
        try:
            source.backup(target, pages=64, progress=tick, sleep=0.02)
            target.execute('PRAGMA journal_mode=DELETE')
            need(target.execute('PRAGMA quick_check').fetchall() == [('ok',)])
        finally: target.close(); source.close()
        copied = file_info(copy, True); need(0 < copied[4] <= MAX_DB)
        need(not os.path.lexists(copy + '-wal') and not os.path.lexists(copy + '-shm'))
        identity = file_info(DATABASE, True)
        need(identity[:4] == before_db[:4] and identity[7] == before_db[7])
        paired = collect(copy); need(paired == initial)
        entries = []
        pending = DIRECTORY + '/installation.pending'
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            with tarfile.open(fileobj=output, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                for path, details in sorted(paired[0].items()):
                    tick(); secret, groups, metadata = details
                    f, observed = checked(path, secret=secret)
                    with os.fdopen(f, 'rb') as stream:
                        need(signature(observed) == metadata)
                        hasher = hashlib.sha256()
                        class Reader:
                            def read(self, n):
                                tick(); value = stream.read(n); hasher.update(value); return value
                        info = tarfile.TarInfo('files' + path)
                        info.size = observed.st_size; info.mode = stat.S_IMODE(observed.st_mode); info.uid = 0; info.gid = 0
                        archive.addfile(info, Reader())
                        need(signature(os.fstat(stream.fileno())) == metadata)
                    entries.append({'path':path, 'member':'files' + path, 'mode':metadata[3], 'bytes':metadata[4], 'sha256':hasher.hexdigest(), 'groups':sorted(groups)})
                dbhash = digest_file(copy, MAX_DB, True)
                with open(copy, 'rb') as stream:
                    info = tarfile.TarInfo('database.sqlite'); info.size = copied[4]; info.mode = 0o600
                    archive.addfile(info, stream)
                inventory = json.dumps({'format':'VELUM_KNOWN_INSTALLATION_V1', 'scope':SCOPE, 'version':VERSION, 'arch':ARCH, 'databaseSha256':dbhash, 'files':entries}, sort_keys=True, separators=(',', ':')).encode()
                need(len(inventory) <= 65536)
                info = tarfile.TarInfo('inventory.json'); info.size = len(inventory); info.mode = 0o600
                archive.addfile(info, io.BytesIO(inventory))
            output.flush(); os.fsync(output.fileno())
        need(collect(DATABASE) == paired)
        for entry in entries:
            detail = paired[0][entry['path']]
            need(file_info(entry['path'], detail[0]) == detail[2])
            need(digest_file(entry['path'], 268435456, detail[0]) == entry['sha256'])
            need(file_info(entry['path'], detail[0]) == detail[2])
        need(service()[0] == paired[1])
        need(references(DATABASE, RUNTIME + '/bin/config.json' in paired[0])[1] == paired[2])
        version_check()
        need(digest_file(copy, MAX_DB, True) == dbhash)
        need(file_info(DATABASE, True)[:4] == before_db[:4])
        archive_hash = digest_file(pending, MAX_ARCHIVE, True)
        archive_bytes = file_info(pending, True, MAX_ARCHIVE)[4]
        invhash = hashlib.sha256(inventory).hexdigest()
        os.rename(pending, DIRECTORY + '/installation.tar')
        manifest = ('FORMAT=VELUM_KNOWN_INSTALLATION_V1\nSCOPE=' + SCOPE + '\nVERSION=' + VERSION + '\nARCH=' + ARCH + '\nBYTES=' + str(archive_bytes) + '\nSHA256=' + archive_hash + '\nDATABASE_SHA256=' + dbhash + '\nFILES=' + str(len(entries)) + '\nINVENTORY_SHA256=' + invhash + '\n').encode()
        need(len(manifest) <= 1024)
        fd = os.open(DIRECTORY + '/manifest.pending', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output: output.write(manifest); output.flush(); os.fsync(output.fileno())
        fd, unused = checked(copy, secret=True); os.fsync(fd); os.close(fd)
        os.rename(DIRECTORY + '/manifest.pending', DIRECTORY + '/manifest.v1')
        fd, unused = checked(DIRECTORY, directory=True); os.fsync(fd); os.close(fd)
        fd, unused = checked(ROOT, directory=True); os.fsync(fd); os.close(fd)
        print('CREATED')
    finally: os.close(lock)

def verify():
    '''Read-only: stream every closed tar member and compare bytes, types and private manifest.'''
    private_dir(HOME); private_dir(ROOT); private_dir(DIRECTORY)
    before = tuple(file_info(DIRECTORY + '/' + n, True, MAX_ARCHIVE if n == 'installation.tar' else MAX_DB) for n in ('installation.tar', 'database.sqlite', 'manifest.v1'))
    raw = read_file(DIRECTORY + '/manifest.v1', 1024, True)
    rows = raw.decode('ascii').splitlines(); pairs = [r.split('=') for r in rows]
    need(raw.endswith(b'\n') and len(pairs) == 9 and all(len(r) == 2 for r in pairs))
    manifest = dict(pairs)
    need(set(manifest) == {'FORMAT','SCOPE','VERSION','ARCH','BYTES','SHA256','DATABASE_SHA256','FILES','INVENTORY_SHA256'})
    need(manifest['FORMAT'] == 'VELUM_KNOWN_INSTALLATION_V1' and manifest['SCOPE'] == SCOPE and manifest['VERSION'] == VERSION and manifest['ARCH'] == ARCH)
    need(all(re.fullmatch('[0-9a-f]{64}', manifest[k]) for k in ('SHA256','DATABASE_SHA256','INVENTORY_SHA256')))
    need(re.fullmatch('[1-9][0-9]{0,9}', manifest['BYTES']) and re.fullmatch('[1-9][0-9]?', manifest['FILES']))
    need(int(manifest['BYTES']) == before[0][4] <= MAX_ARCHIVE and int(manifest['FILES']) <= MAX_FILES)
    need(digest_file(DIRECTORY + '/installation.tar', MAX_ARCHIVE, True) == manifest['SHA256'])
    records = {}; inventory = None; database_hash = None
    f, unused = checked(DIRECTORY + '/installation.tar', secret=True)
    with os.fdopen(f, 'rb') as stream:
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for index, info in enumerate(archive):
                tick(); need(index < MAX_FILES + 2 and info.isfile() and not info.pax_headers and info.uid == 0 and info.gid == 0)
                need(info.name not in records and 0 <= info.size <= MAX_BYTES and 0 <= info.mode <= 0o777 and info.mode & 0o022 == 0)
                if info.name.startswith('files/'):
                    need(safe(info.name[5:]) and info.size <= 268435456)
                else: need(info.name in ('database.sqlite','inventory.json') and info.mode == 0o600)
                digest = hashlib.sha256(); size = 0; data = bytearray()
                content = archive.extractfile(info); need(content is not None)
                while True:
                    tick(); value = content.read(1048576)
                    if not value: break
                    size += len(value); need(size <= info.size); digest.update(value)
                    if info.name == 'inventory.json': need(size <= 65536); data.extend(value)
                need(size == info.size)
                records[info.name] = (info.mode, info.size, digest.hexdigest())
                if info.name == 'inventory.json': inventory = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
                if info.name == 'database.sqlite': database_hash = digest.hexdigest()
    need(isinstance(inventory, dict) and set(inventory) == {'format','scope','version','arch','databaseSha256','files'})
    need(inventory['format'] == manifest['FORMAT'] and inventory['scope'] == SCOPE and inventory['version'] == VERSION and inventory['arch'] == ARCH)
    need(records['inventory.json'][2] == manifest['INVENTORY_SHA256'])
    need(database_hash == inventory['databaseSha256'] == manifest['DATABASE_SHA256'] == digest_file(DIRECTORY + '/database.sqlite', MAX_DB, True))
    entries = inventory['files']; need(isinstance(entries,list) and len(entries) == int(manifest['FILES']))
    need(len({r['path'] for r in entries}) == len(entries) and len(records) == len(entries) + 2)
    for entry in entries:
        need(set(entry) == {'path','member','mode','bytes','sha256','groups'} and safe(entry['path']) and entry['member'] == 'files' + entry['path'])
        need(records[entry['member']] == (entry['mode'], entry['bytes'], entry['sha256']))
        need(isinstance(entry['groups'],list) and entry['groups'] and set(entry['groups']) <= {'RUNTIME','SERVICE','PANEL_TLS','XRAY_TLS','XRAY_DATA'})
    con = connect(DIRECTORY + '/database.sqlite', True)
    try: need(con.execute('PRAGMA quick_check').fetchall() == [('ok',)])
    finally: con.close()
    after = tuple(file_info(DIRECTORY + '/' + n, True, MAX_ARCHIVE if n == 'installation.tar' else MAX_DB) for n in ('installation.tar', 'database.sqlite', 'manifest.v1'))
    need(before == after)
    sys.stdout.write(raw.decode('ascii'))

def main():
    global SCOPE, VERSION, ARCH, DIRECTORY, DEADLINE, REVIEWED
    need(len(sys.argv) == 6 and sys.argv[1] in ('storage', 'create', 'verify'))
    SCOPE, VERSION, ARCH = sys.argv[2:5]
    REVIEWED = sys.argv[5]; need(re.fullmatch("[0-9a-f]{64}", REVIEWED))
    need(re.fullmatch('[0-9a-f]{64}', SCOPE) and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', VERSION) and ARCH in ('AMD64','ARM64'))
    DIRECTORY = ROOT + '/' + SCOPE[:32]
    need(os.geteuid() == 0 and sys.version_info >= (3,8))
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
    resource.setrlimit(resource.RLIMIT_CPU, (80,80))
    resource.setrlimit(resource.RLIMIT_AS, (536870912,2147483648))
    DEADLINE = time.monotonic() + (70 if sys.argv[1] == 'verify' else 85)
    if sys.argv[1] == 'storage':
        a,b = storage(); print(str(a) + '\n' + str(b))
    elif sys.argv[1] == 'create': create()
    else: verify()

if __name__ == '__main__':
    try: main()
    except BaseException: sys.exit(81)

""".trimIndent()
}

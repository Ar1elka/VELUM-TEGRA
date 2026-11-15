package com.velumtegra.xuimobile.core.ssh

/** Reuses the immutable T4.6 source verifier; restores only below a separate fixed private root. */
internal object RestoreCheckWorker {
    val source: String = InstallationBackupWorker.source.substringBefore("\nif __name__ == '__main__':") + "\n" + """
# This appendix reuses the unchanged T4.6 read-only archive verifier above.
import contextlib
RESTORE_ROOT = '/root/.velum-tegra-restore-checks'
MAX_RESTORED = 671088640


def restore_source():
    capture = io.StringIO()
    with contextlib.redirect_stdout(capture): verify()
    pairs = [line.split('=') for line in capture.getvalue().splitlines()]
    need(len(pairs) == 9 and all(len(p) == 2 for p in pairs))
    manifest = dict(pairs)
    need(manifest['SHA256'] == EXPECTED_ARCHIVE and manifest['DATABASE_SHA256'] == EXPECTED_DB and
         manifest['INVENTORY_SHA256'] == EXPECTED_INVENTORY and int(manifest['BYTES']) == EXPECTED_BYTES and
         int(manifest['FILES']) == EXPECTED_FILES)
    fd, unused = checked(DIRECTORY + '/installation.tar', secret=True)
    with os.fdopen(fd, 'rb') as stream:
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            member = archive.getmember('inventory.json')
            need(member.isfile() and member.size <= 65536)
            raw = archive.extractfile(member).read(65537)
    need(hashlib.sha256(raw).hexdigest() == EXPECTED_INVENTORY)
    inventory = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
    entries = inventory['files']; need(len(entries) == EXPECTED_FILES)
    total = 0; paths = set()
    for entry in entries:
        need(safe(entry['path']) and entry['member'] == 'files' + entry['path'] and len(entry['member'].split('/')) <= 32)
        need(type(entry['bytes']) is int and 0 <= entry['bytes'] <= 268435456)
        total += entry['bytes']; paths.add(entry['member'])
    need(len(paths) == len(entries) and total <= MAX_BYTES)
    total += file_info(DIRECTORY + '/database.sqlite', True, MAX_DB)[4]
    need(0 < total <= MAX_RESTORED)
    return inventory, raw, total


def restore_space():
    private_dir(HOME)
    if not os.path.lexists(RESTORE_ROOT):
        info = os.statvfs(HOME); return 0, info.f_bavail * info.f_frsize
    private_dir(RESTORE_ROOT)
    names = os.listdir(RESTORE_ROOT); need(len(names) <= 5)
    slots = 0
    for name in names:
        if name == '.lock': file_info(RESTORE_ROOT + '/.lock', True, 4096)
        else:
            need(re.fullmatch('[0-9a-f]{32}', name)); private_dir(RESTORE_ROOT + '/' + name); slots += 1
    need(slots <= 4)
    info = os.statvfs(RESTORE_ROOT)
    return slots, info.f_bavail * info.f_frsize


def restore_source_stamp():
    return tuple(file_info(DIRECTORY + '/' + name, True, MAX_ARCHIVE if name == 'installation.tar' else MAX_DB)
                 for name in ('installation.tar', 'database.sqlite', 'manifest.v1'))


def restore_leaf(relative, directories):
    parts = relative.split('/')
    need(not relative.startswith('/') and len(parts) <= 32 and all(p not in ('', '.', '..') for p in parts) and
         re.fullmatch('[A-Za-z0-9_./@:+-]+', relative))
    parent = DESTINATION
    for part in parts[:-1]:
        parent += '/' + part
        if not os.path.lexists(parent): os.mkdir(parent, 0o700)
        private_dir(parent); directories.add(parent); need(len(directories) <= 1024)
    path = DESTINATION + '/' + relative
    return path, os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)


def restore_manifest(total):
    return ('FORMAT=VELUM_RESTORE_FILES_V1\nSCOPE=' + RUN_SCOPE + '\nSOURCE_SCOPE=' + SCOPE +
            '\nVERSION=' + VERSION + '\nARCH=' + ARCH + '\nFILES=' + str(EXPECTED_FILES) + '\nBYTES=' + str(total) +
            '\nSHA256=' + EXPECTED_ARCHIVE + '\nDATABASE_SHA256=' + EXPECTED_DB +
            '\nINVENTORY_SHA256=' + EXPECTED_INVENTORY + '\n').encode('ascii')


def restore_copy():
    before = restore_source_stamp(); inventory, raw, total = restore_source()
    slots, available = restore_space(); need(slots < 4 and available >= EXPECTED_BYTES * 2 + 50331648)
    if not os.path.lexists(RESTORE_ROOT): os.mkdir(RESTORE_ROOT, 0o700)
    private_dir(RESTORE_ROOT)
    lock = os.open(RESTORE_ROOT + '/.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        s = os.fstat(lock)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        slots, available = restore_space(); need(slots < 4 and available >= EXPECTED_BYTES * 2 + 50331648)
        need(restore_source_stamp() == before)
        expected = {e['member']:(e['mode'], e['bytes'], e['sha256']) for e in inventory['files']}
        expected['database.sqlite'] = (0o600, file_info(DIRECTORY + '/database.sqlite', True, MAX_DB)[4], EXPECTED_DB)
        expected['inventory.json'] = (0o600, len(raw), EXPECTED_INVENTORY)
        os.mkdir(DESTINATION, 0o700); private_dir(DESTINATION)
        seen = set(); directories = {DESTINATION}
        fd, unused = checked(DIRECTORY + '/installation.tar', secret=True)
        with os.fdopen(fd, 'rb') as stream:
            with tarfile.open(fileobj=stream, mode='r|') as archive:
                for member in archive:
                    tick(); need(member.name in expected and member.name not in seen and member.isfile() and not member.pax_headers)
                    mode, size, digest = expected[member.name]
                    need(member.mode == mode and member.size == size and member.uid == 0 and member.gid == 0)
                    content = archive.extractfile(member); need(content is not None)
                    path, output_fd = restore_leaf(member.name, directories)
                    actual = hashlib.sha256(); count = 0
                    with os.fdopen(output_fd, 'wb') as output:
                        while True:
                            tick(); value = content.read(1048576)
                            if not value: break
                            count += len(value); need(count <= size); output.write(value); actual.update(value)
                        need(count == size and actual.hexdigest() == digest)
                        output.flush(); os.fchmod(output.fileno(), mode); os.fsync(output.fileno())
                    need(file_info(path, member.name in ('database.sqlite', 'inventory.json'), MAX_ARCHIVE)[3:5] == (mode, size))
                    seen.add(member.name)
        need(seen == set(expected))
        con = connect(DESTINATION + '/database.sqlite', True)
        try: need(con.execute('PRAGMA quick_check').fetchall() == [('ok',)])
        finally: con.close()
        restore_source(); need(restore_source_stamp() == before)
        path, fd = restore_leaf('restore-check.pending', directories)
        with os.fdopen(fd, 'wb') as output:
            output.write(restore_manifest(total)); output.flush(); os.fsync(output.fileno())
        need(not os.path.lexists(DESTINATION + '/restore-check.v1'))
        os.rename(path, DESTINATION + '/restore-check.v1')
        for path in sorted(directories, key=lambda v: -len(v)) + [RESTORE_ROOT]:
            fd, unused = checked(path, directory=True); os.fsync(fd); os.close(fd)
        print('RESTORED')
    finally: os.close(lock)


def restore_walk():
    actual = set(); queue = [(DESTINATION, '')]; count = 0
    while queue:
        directory, relative = queue.pop(); private_dir(directory)
        names = os.listdir(directory); need(len(names) <= MAX_FILES + 4)
        for name in names:
            tick(); count += 1; need(count <= 1125)
            path = directory + '/' + name; rel = (relative + '/' + name).lstrip('/')
            need(re.fullmatch('[A-Za-z0-9_./@:+-]+', rel) and len(rel.split('/')) <= 32)
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode): queue.append((path, rel))
            else: need(stat.S_ISREG(mode)); file_info(path, False, MAX_ARCHIVE); actual.add(rel)
    return actual


def restore_verify():
    before = restore_source_stamp(); inventory, raw, total = restore_source()
    private_dir(RESTORE_ROOT); private_dir(DESTINATION)
    initial = file_info(DESTINATION + '/restore-check.v1', True, 1024)
    need(read_file(DESTINATION + '/restore-check.v1', 1024, True) == restore_manifest(total))
    expected = {e['member']:(e['mode'], e['bytes'], e['sha256']) for e in inventory['files']}
    expected['database.sqlite'] = (0o600, file_info(DIRECTORY + '/database.sqlite', True, MAX_DB)[4], EXPECTED_DB)
    expected['inventory.json'] = (0o600, len(raw), EXPECTED_INVENTORY)
    wanted = set(expected) | {'restore-check.v1'}
    need(restore_walk() == wanted)
    for relative, (mode, size, digest) in expected.items():
        path = DESTINATION + '/' + relative; tick()
        info = file_info(path, relative in ('database.sqlite', 'inventory.json'), MAX_ARCHIVE)
        need(info[3] == mode and info[4] == size and digest_file(path, MAX_ARCHIVE) == digest)
        need(file_info(path, False, MAX_ARCHIVE) == info)
    con = connect(DESTINATION + '/database.sqlite', True)
    try: need(con.execute('PRAGMA quick_check').fetchall() == [('ok',)])
    finally: con.close()
    need(restore_walk() == wanted and restore_source_stamp() == before)
    need(file_info(DESTINATION + '/restore-check.v1', True, 1024) == initial)
    sys.stdout.write(restore_manifest(total).decode('ascii'))


def restore_main():
    global SCOPE, VERSION, ARCH, DIRECTORY, DEADLINE, RUN_SCOPE, DESTINATION
    global EXPECTED_ARCHIVE, EXPECTED_DB, EXPECTED_INVENTORY, EXPECTED_BYTES, EXPECTED_FILES
    need(len(sys.argv) == 11 and sys.argv[1] in ('space', 'copy', 'check'))
    RUN_SCOPE, SCOPE, VERSION, ARCH = sys.argv[2:6]
    EXPECTED_ARCHIVE, EXPECTED_DB, EXPECTED_INVENTORY = sys.argv[6:9]
    need(all(re.fullmatch('[0-9a-f]{64}', p) for p in (RUN_SCOPE, SCOPE, EXPECTED_ARCHIVE, EXPECTED_DB, EXPECTED_INVENTORY)))
    need(re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', VERSION) and ARCH in ('AMD64', 'ARM64'))
    need(re.fullmatch('[1-9][0-9]{0,9}', sys.argv[9]) and re.fullmatch('[1-9][0-9]?', sys.argv[10]))
    EXPECTED_BYTES, EXPECTED_FILES = int(sys.argv[9]), int(sys.argv[10])
    need(EXPECTED_BYTES <= MAX_ARCHIVE and EXPECTED_FILES <= MAX_FILES and RUN_SCOPE != SCOPE)
    DIRECTORY = ROOT + '/' + SCOPE[:32]; DESTINATION = RESTORE_ROOT + '/' + RUN_SCOPE[:32]
    need(os.geteuid() == 0 and sys.version_info >= (3,8)); os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
    # Keep this worker's soft limit at 512 MiB. The read-only version probe needs a
    # 2 GiB child; an inherited 512 MiB hard limit cannot be raised without a capability.
    resource.setrlimit(resource.RLIMIT_CPU, (120,120)); resource.setrlimit(resource.RLIMIT_AS, (536870912,2147483648))
    DEADLINE = time.monotonic() + (125 if sys.argv[1] == 'copy' else 80)
    if sys.argv[1] == 'space':
        count, available = restore_space(); print(str(count) + '\n' + str(available))
    elif sys.argv[1] == 'copy': restore_copy()
    else: restore_verify()


if __name__ == '__main__':
    try: restore_main()
    except BaseException: sys.exit(81)

""".trimIndent()
}

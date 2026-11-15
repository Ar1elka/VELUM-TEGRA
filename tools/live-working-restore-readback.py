"""Independent read-only proof of the authorized working-database restoration."""
import hashlib
import json
from pathlib import Path
import sqlite3
import stat
import subprocess

def private(path, directory=False):
    info = path.lstat()
    assert info.st_uid == 0 and not stat.S_ISLNK(info.st_mode)
    assert stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
    if not directory:
        assert info.st_nlink == 1

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1048576), b''):
            h.update(data)
    return h.hexdigest()

def logical(path, immutable=False):
    con = sqlite3.connect(path.as_uri() + '?mode=ro' + ('&immutable=1' if immutable else ''), uri=True)
    try:
        con.execute('PRAGMA query_only=ON')
        con.execute('BEGIN')
        assert con.execute('PRAGMA quick_check').fetchall() == [('ok',)]
        assert con.execute('PRAGMA foreign_key_check').fetchone() is None
        meta = [con.execute('PRAGMA user_version').fetchone()[0], con.execute('PRAGMA application_id').fetchone()[0]]
        lines = []; size = 0
        for line in con.iterdump():
            size += len(line.encode('utf-8'))
            assert size <= 134217728 and len(lines) < 100000
            lines.append(line)
        h = hashlib.sha256(json.dumps([meta, sorted(lines)], separators=(',', ':')).encode()).hexdigest()
        return h, con.execute('SELECT count(*) FROM inbounds').fetchone()[0]
    finally:
        con.close()

backup_root = Path('/root/.velum-tegra-installation-backups')
archives = [p for p in backup_root.iterdir() if p.is_dir()]
assert len(archives) == 1
manifest = dict(line.split('=', 1) for line in (archives[0] / 'manifest.v1').read_text('ascii').splitlines())
assert manifest['SHA256'] == EXPECTED_ARCHIVE_SHA and manifest['DATABASE_SHA256'] == EXPECTED_DATABASE_SHA
source = archives[0] / 'database.sqlite'
private(source)
assert sha(source) == EXPECTED_DATABASE_SHA
root = Path('/root/.velum-tegra-working-db-restores')
private(root, True)
copies = [p for p in root.iterdir() if p.is_dir()]
assert len(copies) == 1
copy = copies[0]
private(copy, True)
for name in ('before.sqlite', 'before.json', 'restored.json'):
    private(copy / name)
assert {p.name for p in copy.iterdir()} == {'before.sqlite', 'before.json', 'restored.json'}
before = json.loads((copy / 'before.json').read_text('ascii'))
restored = json.loads((copy / 'restored.json').read_text('ascii'))
assert before['format'] == 'VELUM_WORKING_DB_BEFORE_V1' and restored['format'] == 'VELUM_WORKING_DB_RESTORED_V1'
assert before['scope'] == restored['scope'] and before['scope'][:32] == copy.name
assert before['source'] == restored['source'] == EXPECTED_DATABASE_SHA
assert before['previousSha256'] == restored['previousSha256'] == sha(copy / 'before.sqlite')
assert before['previousBytes'] == (copy / 'before.sqlite').stat().st_size
logical(copy / 'before.sqlite', True)
current = Path('/etc/x-ui/x-ui.db')
private(current)
source_logical, source_inbounds = logical(source, True)
current_logical, current_inbounds = logical(current)
state = subprocess.run(['systemctl', 'show', '--property=ActiveState,SubState,MainPID', 'x-ui.service'],
    check=True, capture_output=True, text=True).stdout
fields = dict(line.split('=', 1) for line in state.splitlines())
matches = current_logical == source_logical
if EXPECTED_STATE == 'inactive':
    assert fields == {'MainPID': '0', 'SubState': 'dead', 'ActiveState': 'inactive'}
    assert matches and current_inbounds == source_inbounds
else:
    assert fields['ActiveState'] == 'active' and fields['SubState'] == 'running' and int(fields['MainPID']) > 0
print(json.dumps({'verified': True, 'service': fields['ActiveState'], 'previousDatabaseSaved': True,
    'previousDatabaseSha256': before['previousSha256'], 'previousBytes': before['previousBytes'],
    'logicalMatchesArchive': matches, 'sourceInbounds': source_inbounds, 'currentInbounds': current_inbounds,
    'sourceDatabaseSha256': EXPECTED_DATABASE_SHA, 'sqlite': 'ok'}))

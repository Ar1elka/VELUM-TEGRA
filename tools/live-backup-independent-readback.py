"""Read-only verification on the authorized test VPS. No extraction or restoration."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tarfile

root = Path('/root/.velum-tegra-installation-backups')
def private(path, directory=False):
    info = path.lstat()
    assert info.st_uid == 0 and not stat.S_ISLNK(info.st_mode)
    assert (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    assert stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
    if not directory:
        assert info.st_nlink == 1

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1048576), b''):
            h.update(data)
    return h.hexdigest()

private(root, True)
slots = [p for p in root.iterdir() if p.is_dir()]
assert len(slots) == 1, 'Expected exactly one archive after the empty baseline'
folder = slots[0]
private(folder, True)
for name in ['manifest.v1', 'database.sqlite', 'installation.tar']:
    private(folder / name)
manifest = dict(line.split('=', 1) for line in (folder / 'manifest.v1').read_text('ascii').splitlines())
assert manifest['FORMAT'] == 'VELUM_KNOWN_INSTALLATION_V1'
assert manifest['VERSION'] == '3.11.0' and manifest['ARCH'] == 'AMD64'
assert manifest['SCOPE'][:32] == folder.name
archive_path = folder / 'installation.tar'
assert archive_path.stat().st_size == int(manifest['BYTES']) <= 738197504
assert digest(archive_path) == manifest['SHA256']
assert digest(folder / 'database.sqlite') == manifest['DATABASE_SHA256']
records = {}
inventory = None
with tarfile.open(archive_path, mode='r|') as archive:
    for member in archive:
        assert len(records) < 98 and member.isfile() and member.name not in records
        assert not member.name.startswith('/') and '..' not in member.name.split('/')
        assert member.uid == member.gid == 0 and not member.pax_headers
        assert member.name in ('database.sqlite', 'inventory.json') or member.name.startswith('files/')
        assert 0 <= member.size <= 536870912
        h = hashlib.sha256()
        size = 0
        data = bytearray()
        with archive.extractfile(member) as stream:
            for chunk in iter(lambda: stream.read(1048576), b''):
                size += len(chunk)
                h.update(chunk)
                if member.name == 'inventory.json':
                    assert size <= 65536
                    data.extend(chunk)
        assert size == member.size
        records[member.name] = (member.mode, size, h.hexdigest())
        if member.name == 'inventory.json':
            inventory = json.loads(data)
assert inventory['scope'] == manifest['SCOPE'] and inventory['version'] == manifest['VERSION']
assert inventory['arch'] == manifest['ARCH'] and inventory['format'] == manifest['FORMAT']
assert inventory['databaseSha256'] == manifest['DATABASE_SHA256']
assert records['inventory.json'][2] == manifest['INVENTORY_SHA256']
assert records['database.sqlite'][2] == manifest['DATABASE_SHA256']
assert len(inventory['files']) == int(manifest['FILES'])
assert len(records) == len(inventory['files']) + 2
assert {e['member'] for e in inventory['files']} == set(records) - {'database.sqlite', 'inventory.json'}
for entry in inventory['files']:
    assert entry['member'] == 'files' + entry['path']
    assert records[entry['member']] == (entry['mode'], entry['bytes'], entry['sha256'])
con = sqlite3.connect((folder / 'database.sqlite').as_uri() + '?mode=ro&immutable=1', uri=True)
try:
    con.execute('PRAGMA query_only=ON')
    assert con.execute('PRAGMA quick_check').fetchall() == [('ok',)]
    assert con.execute('PRAGMA foreign_key_check').fetchone() is None
    inbounds = con.execute('SELECT count(*) FROM inbounds').fetchone()[0]
finally:
    con.close()
trial_verified = False
if globals().get('REQUIRE_TRIAL', False):
    trial_root = Path('/root/.velum-tegra-restore-checks')
    private(trial_root, True)
    trials = [p for p in trial_root.iterdir() if p.is_dir()]
    assert len(trials) == 1
    trial = trials[0]
    private(trial, True)
    private(trial / 'restore-check.v1')
    trial_manifest = dict(line.split('=', 1) for line in (trial / 'restore-check.v1').read_text('ascii').splitlines())
    assert trial_manifest['FORMAT'] == 'VELUM_RESTORE_FILES_V1'
    assert trial_manifest['SOURCE_SCOPE'] == manifest['SCOPE']
    assert trial_manifest['SHA256'] == manifest['SHA256']
    assert trial_manifest['DATABASE_SHA256'] == manifest['DATABASE_SHA256']
    assert trial_manifest['INVENTORY_SHA256'] == manifest['INVENTORY_SHA256']
    observed = set()
    for path in trial.rglob('*'):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
        if path.is_dir():
            private(path, True)
        else:
            relative = path.relative_to(trial).as_posix()
            observed.add(relative)
            if relative != 'restore-check.v1':
                assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                assert (stat.S_IMODE(info.st_mode), info.st_size, digest(path)) == records[relative]
    assert observed == set(records) | {'restore-check.v1'}
    con = sqlite3.connect((trial / 'database.sqlite').as_uri() + '?mode=ro&immutable=1', uri=True)
    try:
        assert con.execute('PRAGMA quick_check').fetchall() == [('ok',)]
    finally:
        con.close()
    trial_verified = True
service = subprocess.run(['systemctl', 'is-active', 'x-ui.service'], check=True, capture_output=True, text=True).stdout.strip()
assert service == 'active'
print(json.dumps({'verified': True, 'archives': 1, 'version': manifest['VERSION'], 'bytes': int(manifest['BYTES']),
    'files': int(manifest['FILES']), 'sha256': manifest['SHA256'], 'databaseSha256': manifest['DATABASE_SHA256'],
    'inventorySha256': manifest['INVENTORY_SHA256'], 'sqlite': 'ok', 'inbounds': inbounds, 'service': service,
    'trialVerified': trial_verified}))

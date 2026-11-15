#!/usr/bin/env python3
"""Isolated Linux command fixtures. Python SQLite backup shim; NOT the real sqlite3 CLI or a VPS test."""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/DatabaseBackupSshAdapter.kt"


def commands(digest):
    source = SOURCE.read_text()
    def string(value):
        return json.loads(value.replace(r"\$", "$"))
    def val(name):
        expression = re.search(r"private val " + name + r" = (.*?)(?=\n    (?:private |fun ))", source, re.S)[1]
        return "".join(string(x) for x in re.findall(r'"(?:\\.|[^"\\])*"', expression))
    root = "/root/.velum-tegra-db-backups"
    values = {"ROOT": root, "tools": val("tools")}
    values["privateRoot"] = val("privateRoot").replace("$ROOT", root)
    values["slots"] = val("slots").replace("$ROOT", root)
    raw = re.search(r'return """(.*?)"""\.trimIndent', source, re.S)[1]
    for k, v in values.items():
        raw = raw.replace("$" + k, v)
    raw = raw.replace("${b.digest}", digest).replace("${b.version}", "3.10.0").replace("${b.architecture.name}", "AMD64")
    raw = raw.replace("$d", root + "/" + digest[:32])
    raw = raw.replace("${'$'}", "$")
    storage = "set -eu; " + values["tools"] + "; " + values["privateRoot"] + "; " + values["slots"] + "; stat -f -c '%a|%S' -- '/root'"
    return raw, storage


SHIM = r"""#!/usr/bin/env python3
import os,sqlite3,sys,time
a=sys.argv[1:]
if '-cmd' in a:
    n=a.index('-cmd'); del a[n:n+2]
readonly='-readonly' in a
a=[x for x in a if x not in ('-readonly','-batch','-noheader')]
path,sql=a
connection=sqlite3.connect('file:'+path+'?mode=ro',uri=True) if readonly else sqlite3.connect(path)
if sql.startswith('.backup '):
    if os.environ.get('FIXTURE_DELAY'): time.sleep(float(os.environ['FIXTURE_DELAY']))
    destination=sql[len('.backup '):].strip("'")
    copy=sqlite3.connect(destination)
    connection.backup(copy)
    copy.close()
    if os.environ.get('FIXTURE_REPLACE_SOURCE'):
        os.rename(path,path+'.previous')
        replacement=sqlite3.connect(path); replacement.execute('CREATE TABLE foreign_database(value TEXT)'); replacement.close()
        os.chmod(path,0o600)
elif 'journal_mode=DELETE' in sql:
    print(connection.execute('PRAGMA journal_mode=DELETE').fetchone()[0])
    print(connection.execute('PRAGMA quick_check').fetchone()[0])
else:
    print(connection.execute('PRAGMA quick_check').fetchone()[0])
connection.close()
"""


class BackupCommands(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="velum-dbb-local-")
        self.base = Path(self.temp.name)
        self.home = self.base / "root"
        self.home.mkdir(mode=0o700)
        self.etc = self.base / "etc"
        (self.etc / "x-ui").mkdir(parents=True)
        self.database = self.etc / "x-ui/x-ui.db"
        self.db = sqlite3.connect(self.database)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA wal_autocheckpoint=0")
        self.db.execute("CREATE TABLE settings(value TEXT)")
        self.db.execute("INSERT INTO settings VALUES ('fixture-private-value')")
        self.db.commit()
        self.database.chmod(0o600)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        shim = self.bin / "sqlite3"
        shim.write_text(SHIM); shim.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        self.digest = "a" * 64

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def command(self, digest=None, storage=False):
        raw = commands(digest or self.digest)[1 if storage else 0]
        # Rewrite every fixed path before executing. Nothing addresses the host's /root or /etc.
        raw = raw.replace("/root", str(self.home)).replace("/etc", str(self.etc))
        assert "'/root" not in raw and "'/etc" not in raw
        return raw

    def run_copy(self, digest=None):
        return subprocess.run(["sh", "-c", self.command(digest)], env=self.env, capture_output=True, timeout=12)

    def artifact(self, digest=None):
        return self.home / ".velum-tegra-db-backups" / (digest or self.digest)[:32]

    def test_live_wal_database_has_consistent_private_copy_and_exact_manifest(self):
        self.assertTrue(Path(str(self.database) + "-wal").exists())
        result = self.run_copy()
        self.assertEqual((0, b"CREATED\n", b""), (result.returncode, result.stdout, result.stderr))
        folder = self.artifact()
        copy = folder / "database.sqlite"
        connection = sqlite3.connect("file:" + str(copy) + "?mode=ro", uri=True)
        self.assertEqual([("fixture-private-value",)], connection.execute("SELECT value FROM settings").fetchall())
        self.assertEqual("ok", connection.execute("PRAGMA quick_check").fetchone()[0])
        connection.close()
        manifest = dict(x.split("=") for x in (folder / "manifest.v1").read_text().splitlines())
        self.assertEqual(hashlib.sha256(copy.read_bytes()).hexdigest(), manifest["SHA256"])
        self.assertEqual(self.digest, manifest["SCOPE"])
        self.assertEqual(copy.stat().st_size, int(manifest["BYTES"]))
        self.assertEqual(0o700, folder.stat().st_mode & 0o777)
        self.assertEqual(0o600, copy.stat().st_mode & 0o777)
        self.assertEqual(0o600, (folder / "manifest.v1").stat().st_mode & 0o777)
        self.assertFalse(Path(str(copy) + "-wal").exists())
        self.assertFalse(Path(str(copy) + "-shm").exists())

    def test_source_replaced_during_copy_cannot_publish_manifest(self):
        self.env["FIXTURE_REPLACE_SOURCE"] = "1"
        result = self.run_copy()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.artifact() / "manifest.v1").exists())

    def test_repeated_artifact_id_cannot_overwrite(self):
        self.assertEqual(0, self.run_copy().returncode)
        before = (self.artifact() / "database.sqlite").read_bytes()
        self.assertNotEqual(0, self.run_copy().returncode)
        self.assertEqual(before, (self.artifact() / "database.sqlite").read_bytes())

    def test_four_slots_include_partials_and_fifth_is_blocked(self):
        for digit in "abcd":
            self.assertEqual(0, self.run_copy(digit * 64).returncode)
        self.assertNotEqual(0, self.run_copy("e" * 64).returncode)
        self.assertFalse(self.artifact("e" * 64).exists())
        status = subprocess.run(["sh", "-c", self.command(storage=True)], env=self.env, capture_output=True, timeout=3)
        self.assertEqual(0, status.returncode); self.assertEqual(b"4", status.stdout.splitlines()[0])

    def test_unsafe_backup_root_does_not_get_permission_repair(self):
        root = self.home / ".velum-tegra-db-backups"; root.mkdir(mode=0o755)
        self.assertNotEqual(0, self.run_copy().returncode)
        self.assertEqual(0o755, root.stat().st_mode & 0o777); self.assertEqual([], list(root.iterdir()))

    def test_symlink_source_never_creates_private_artifact(self):
        self.db.close(); actual = self.database.with_name("actual.db"); self.database.rename(actual)
        self.database.symlink_to(actual)
        self.assertNotEqual(0, self.run_copy().returncode); self.assertFalse(self.artifact().exists())

    def test_unsafe_source_mode_blocks_before_writes(self):
        self.database.chmod(0o644)
        self.assertNotEqual(0, self.run_copy().returncode); self.assertFalse(self.artifact().exists())

    def test_root_private_readonly_database_can_be_copied(self):
        self.database.chmod(0o400)
        self.assertEqual(0, self.run_copy().returncode)

    def test_remote_lock_prevents_parallel_writers_from_bypassing_quota(self):
        self.env["FIXTURE_DELAY"] = "0.5"
        first = subprocess.Popen(["sh", "-c", self.command()], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            limit = time.monotonic() + 3
            while not self.artifact().exists() and time.monotonic() < limit:
                time.sleep(0.01)
            second = self.run_copy("b" * 64)
            self.assertNotEqual(0, second.returncode); self.assertFalse(self.artifact("b" * 64).exists())
            out, err = first.communicate(timeout=5)
            self.assertEqual((0, b"CREATED\n", b""), (first.returncode, out, err))
        finally:
            if first.poll() is None: first.kill(); first.communicate()


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("These private root-owner fixtures require an isolated root Linux container.")
    unittest.main()

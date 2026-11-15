"""Isolated Linux protocol fixtures, never a real server/CLI acceptance result."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/ManagementSshProbeExecutor.kt"
source = SOURCE.read_text()
block = source.split("internal object ManagementReadOnlyCommandCompiler", 1)[1].split("is ManagementProbeSpec.PanelSettingsReadback -> {", 1)[1].split("is ManagementProbeSpec.ExactListenerPresence", 1)[0]
strings = lambda value: [json.loads('"' + part + '"') for part in re.findall(r'"((?:[^"\\]|\\.)*)"', value)]
SQL = "".join(strings(block.split("val sql =", 1)[1].split("val database =", 1)[0]))
TEMPLATE = "".join(strings(block.split("val database =", 1)[1]))
for name, value in re.findall(r"const val (SQLITE_UNAVAILABLE|DATABASE_UNREADABLE|QUERY_FAILED) = ([0-9]+)", source):
    TEMPLATE = TEMPLATE.replace("${ManagementPanelSettingsExit." + name + "}", value)


class SettingsReaderFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.database = self.root / "panel.db"

    def cli(self, exit_code=None):
        script = self.bin / "sqlite3"
        if exit_code is not None:
            script.write_text("#!/bin/sh\nexit " + str(exit_code) + "\n")
        else:
            script.write_text("#!" + sys.executable + "\n" + '''import pathlib, sqlite3, sys
assert sys.argv[1:4] == ['-readonly', '-batch', '-noheader']
try:
    db = sqlite3.connect(pathlib.Path(sys.argv[4]).as_uri() + '?mode=ro', uri=True)
    for statement in sys.argv[5].split(';'):
        if statement.strip():
            for row in db.execute(statement): print('|'.join(str(v) for v in row))
    db.close()
except sqlite3.Error: sys.exit(1)
''')
        script.chmod(0o700)

    def create_database(self, wal=False):
        db = sqlite3.connect(self.database)
        if wal:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA wal_autocheckpoint=0")
        db.execute("CREATE TABLE settings(key TEXT, value TEXT)")
        db.executemany("INSERT INTO settings VALUES (?,?)", [("webPort", "54321"), ("webBasePath", "/fixture/"), ("webListen", "127.0.0.1")])
        db.commit()
        self.addCleanup(db.close)
        return db

    def run_reader(self):
        raw = TEMPLATE.replace("${shellQuote(sql)}", shlex.quote(SQL)).replace("$database", shlex.quote(str(self.database)))
        self.assertNotIn("${", raw)
        return subprocess.run(["/bin/sh", "-c", raw], env={"PATH": str(self.bin)}, capture_output=True, timeout=10)

    def test_missing_cli_is_distinct(self):
        self.assertEqual(69, self.run_reader().returncode)
        self.assertFalse(self.database.exists())

    def test_missing_database_is_not_created(self):
        self.cli()
        self.assertEqual(77, self.run_reader().returncode)
        self.assertFalse(self.database.exists())

    def test_directory_is_not_treated_as_database(self):
        self.cli()
        self.database.mkdir()
        self.assertEqual(77, self.run_reader().returncode)

    def test_corrupt_database_is_a_query_error(self):
        self.cli()
        self.database.write_bytes(b"not-a-database")
        self.assertEqual(74, self.run_reader().returncode)
        self.assertEqual(b"not-a-database", self.database.read_bytes())

    def test_unrecognized_schema_does_not_become_defaults(self):
        self.cli()
        db = sqlite3.connect(self.database)
        db.close()
        self.assertEqual(74, self.run_reader().returncode)

    def test_cli_exit_cannot_impersonate_dependency_gate(self):
        self.cli(exit_code=69)
        self.database.touch()
        self.assertEqual(74, self.run_reader().returncode)

    def test_actual_sqlite_read_returns_existing_protocol(self):
        self.cli()
        self.create_database()
        before = self.database.read_bytes()
        result = self.run_reader()
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"PORT=54321\nWEB_BASE_PATH=/fixture/\nLISTEN_ADDRESS=127.0.0.1\n", result.stdout)
        self.assertEqual(before, self.database.read_bytes())

    def test_active_wal_contents_are_read_without_database_or_wal_replacement(self):
        self.cli()
        self.create_database(wal=True)
        paths = [self.database, Path(str(self.database) + "-wal")]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        result = self.run_reader()
        self.assertEqual(0, result.returncode)
        self.assertIn(b"PORT=54321\n", result.stdout)
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})


if __name__ == "__main__":
    unittest.main()

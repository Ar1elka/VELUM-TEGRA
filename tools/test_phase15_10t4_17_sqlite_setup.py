"""Synthetic setup-protocol fixtures. All commands and paths stay inside a temporary tree."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "app/src/androidTest/assets/t4_17_sqlite_setup.sh").read_text()


class SqliteSetupFixtures(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = {"PATH": str(self.bin), "FIXTURE_ROOT": str(self.root), "FIXTURE_UID": "0", "FIXTURE_SERVICE": "active"}
        for name, code in {
            "id": 'printf "%s\\n" "$FIXTURE_UID"',
            "grep": 'exit 0',
            "stat": 'if [ "$2" = %a ]; then printf "700\\n"; else printf "0\\n"; fi',
            "systemctl": 'printf "%s\\n" "$FIXTURE_SERVICE"',
            "timeout": 'shift 3; exec "$@"',
        }.items():
            self.executable(name, "#!/bin/sh\n" + code + "\n")
        for name in ("sh", "mkdir"):
            (self.bin / name).symlink_to("/bin/" + name)
        self.executable("apt-get", "#!" + sys.executable + "\n" + '''import json, os, pathlib, sys
r = pathlib.Path(os.environ['FIXTURE_ROOT'])
with (r/'apt.log').open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
if 'update' in sys.argv and os.environ.get('FAIL_UPDATE') == '1': sys.exit(1)
if 'install' in sys.argv:
    if os.environ.get('FAIL_INSTALL') == '1': sys.exit(1)
    p = r/'bin/sqlite3'; p.write_text('#!/bin/sh\\nexit 0\\n'); p.chmod(0o700)
''')
        self.script = SCRIPT
        for source, destination in (("/usr/local/x-ui", self.root / "panel"), ("/etc/x-ui/x-ui.db", self.root / "panel.db"), ("/var/tmp", self.root / "temporary")):
            self.script = self.script.replace(source, str(destination))
        (self.root / "panel").mkdir()
        panel_binary = self.root / "panel/x-ui"
        panel_binary.touch()
        panel_binary.chmod(0o700)
        (self.root / "panel.db").write_bytes(b"fixture database bytes never read or changed by setup")
        (self.root / "temporary").mkdir()
        self.intent = self.root / "temporary/velum-test-sqlite-192-0-2-169-v1"

    def executable(self, name, text):
        p = self.bin / name
        p.write_text(text)
        p.chmod(0o700)

    def run_setup(self, mode):
        return subprocess.run(["/bin/sh", "-c", self.script, "--", mode], env=self.env, capture_output=True, timeout=5)

    def test_missing_dependency_preflight_writes_nothing(self):
        before = set(self.root.rglob("*"))
        result = self.run_setup("preflight")
        self.assertEqual((0, b"SETUP_SQLITE_MISSING\n"), (result.returncode, result.stdout))
        self.assertEqual(before, set(self.root.rglob("*")))

    def test_existing_cli_preflight_never_installs(self):
        self.executable("sqlite3", "#!/bin/sh\nexit 0\n")
        self.assertEqual(b"SETUP_ALREADY_READY\n", self.run_setup("preflight").stdout)
        self.assertFalse((self.root / "apt.log").exists())

    def test_nonroot_cannot_create_intent_or_install(self):
        self.env["FIXTURE_UID"] = "1000"
        self.assertEqual(70, self.run_setup("install").returncode)
        self.assertFalse(self.intent.exists())

    def test_inactive_service_blocks_setup(self):
        self.env["FIXTURE_SERVICE"] = "inactive"
        self.assertEqual(70, self.run_setup("install").returncode)
        self.assertFalse(self.intent.exists())

    def test_install_then_independent_readback_preserves_panel_bytes(self):
        before = (self.root / "panel.db").read_bytes()
        self.assertEqual(b"SETUP_INSTALLED\n", self.run_setup("install").stdout)
        self.assertEqual(b"SETUP_READY\n", self.run_setup("readback").stdout)
        self.assertTrue(self.intent.is_dir())
        calls = [json.loads(v) for v in (self.root / "apt.log").read_text().splitlines()]
        self.assertEqual(2, len(calls))
        self.assertEqual(["install", "sqlite3"], calls[1][-2:])
        self.assertIn("--no-upgrade", calls[1]); self.assertIn("--no-remove", calls[1])
        self.assertEqual(before, (self.root / "panel.db").read_bytes())

    def test_prior_intent_blocks_redispatch_even_if_cli_missing(self):
        self.assertEqual(0, self.run_setup("install").returncode)
        (self.bin / "sqlite3").unlink()
        before = (self.root / "apt.log").read_bytes()
        self.assertEqual(b"SETUP_PRIOR_INTENT\n", self.run_setup("install").stdout)
        self.assertEqual(before, (self.root / "apt.log").read_bytes())

    def test_update_failure_retains_intent_and_does_not_install(self):
        self.env["FAIL_UPDATE"] = "1"
        self.assertEqual((74, b"SETUP_INSTALL_UNVERIFIED\n"), (lambda r: (r.returncode, r.stdout))(self.run_setup("install")))
        self.assertTrue(self.intent.is_dir())
        self.assertEqual(1, len((self.root / "apt.log").read_text().splitlines()))
        self.assertFalse((self.bin / "sqlite3").exists())

    def test_install_failure_retains_intent(self):
        self.env["FAIL_INSTALL"] = "1"
        self.assertEqual(74, self.run_setup("install").returncode)
        self.assertTrue(self.intent.is_dir())
        self.assertEqual(73, self.run_setup("install").returncode)

    def test_visible_cli_does_not_clear_an_incomplete_intent(self):
        self.intent.mkdir()
        self.executable("sqlite3", "#!/bin/sh\nexit 0\n")
        for mode in ("preflight", "readback"):
            self.assertEqual((73, b"SETUP_PRIOR_INTENT\n"), (lambda r: (r.returncode, r.stdout))(self.run_setup(mode)))
        self.assertFalse((self.root / "apt.log").exists())

    def test_unknown_mode_is_rejected_without_creating_intent(self):
        self.assertEqual(64, self.run_setup("other").returncode)
        self.assertFalse(self.intent.exists())

    def test_readback_never_installs_missing_dependency(self):
        self.assertEqual(70, self.run_setup("readback").returncode)
        self.assertFalse((self.root / "apt.log").exists())


if __name__ == "__main__":
    unittest.main()

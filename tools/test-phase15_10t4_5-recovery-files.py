#!/usr/bin/env python3
"""Isolated SQL/Linux read fixtures from the actual Kotlin command literals; no SSH/VPS or real keys.

SQLite executes through Python's SQLite library, not an installed server sqlite3 CLI.
All filesystem fixtures live in a new private temporary directory and are removed afterwards.
"""
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import textwrap
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/RecoveryFileInventorySshReader.kt"
TEXT = SOURCE.read_text()
LITERAL = r'"(?:\\.|[^"\\])*"'


def literals(expression):
    return [json.loads(value.replace(r"\$", "$")) for value in re.findall(LITERAL, expression)]


def expand(value, variables):
    return re.sub(r'\$([A-Za-z][A-Za-z0-9_]*)', lambda m: variables[m[1]], value)


def sql(active=False):
    body = TEXT.split("fun references(activeConfig: Boolean): String {", 1)[1]
    active_value = literals(re.search(r'val active = (.*?)\n', body)[1])[0] if active else ""
    values = {"active": active_value}
    for name in ("docs", "valid", "sql"):
        expression = re.search(r'val ' + name + r' = (.*?)(?=\n        (?:val |// Validate))', body, re.S)[1]
        tokens = re.findall(LITERAL + r'|\b[A-Za-z][A-Za-z0-9_]*\b|\+', expression)
        pieces = []
        for token in tokens:
            if token == "+":
                continue
            pieces.append(expand(literals(token)[0], values) if token.startswith('"') else values[token])
        values[name] = "".join(pieces)
    return values["sql"]


GUARD = textwrap.dedent(re.search(r'private val guard = """(.*?)"""\.trimIndent', TEXT, re.S)[1]).strip().replace("${'$'}", "$")


def metadata(paths):
    body = TEXT.split("fun metadata(paths: List<String>): String {", 1)[1].split("fun references", 1)[0]
    prefix = literals(re.search(r'return (.*?) \+ paths.mapIndexed', body, re.S)[1])[0]
    template = "".join(literals(re.search(r'paths.mapIndexed.*?->(.*?)\n        \}\.joinToString', body, re.S)[1]))
    return expand(prefix, {"guard": GUARD}) + "\n".join(expand(template, {"path": path, "index": str(index)}) for index, path in enumerate(paths))


def runtime():
    expression = TEXT.split("fun runtime() =", 1)[1].split("fun service()", 1)[0]
    return expand("".join(literals(expression)), {"guard": GUARD})


class ReferenceSql(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE settings(key TEXT, value TEXT)")
        self.db.execute("CREATE TABLE inbounds(enable INTEGER, stream_settings TEXT, settings TEXT)")
        self.config_reads = []
        self.active = {"inbounds": [{"streamSettings": {"tlsSettings": {"certificates": [
            {"certificateFile": "/root/cert/active.pem", "keyFile": "/root/cert/active.key"}]}}}]}
        def readfile(path):
            self.assertEqual("/usr/local/x-ui/bin/config.json", path)
            self.config_reads.append(path)
            return json.dumps(self.active).encode()
        self.db.create_function("readfile", 1, readfile)
        self.setting("xrayTemplateConfig", json.dumps({"outbounds": [], "routing": {"rules": [{"domain": ["ext:custom.dat:tag"]}]}}))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def setting(self, key, value):
        self.db.execute("INSERT INTO settings VALUES (?,?)", (key, value))

    def run_sql(self, active=False):
        self.db.commit()
        output = []
        try:
            for statement in sql(active).split(";"):
                if statement.strip():
                    output.extend("" if row[0] is None else str(row[0]) for row in self.db.execute(statement))
        finally:
            # The production CLI exits after each request. Reset only this synthetic :memory: fixture
            # connection so the next case can replace its own test rows.
            self.db.execute("PRAGMA query_only=OFF")
        return output

    def refs(self, output):
        return {(kind, bytes.fromhex(value).decode()) for kind, value in (line.split("|") for line in output[1:])}

    def test_panel_subscription_inbound_and_template_references_are_selected_without_secrets(self):
        self.setting("webCertFile", "/root/cert/panel.pem")
        self.setting("webKeyFile", "/root/cert/panel.key")
        self.setting("subKeyFile", "/root/cert/sub.key")
        self.setting("tgBotToken", "NeverPrintPrivateToken")
        self.db.execute("INSERT INTO inbounds VALUES (1,?,?)", (json.dumps({"tlsSettings": {"certificates": [{"keyFile": "/root/cert/inbound.key"}]}}),
            json.dumps({"clients": [{"password": "NeverPrintPrivatePassword"}]})))
        output = self.run_sql(); refs = self.refs(output)
        self.assertIn(("PANEL_KEY", "/root/cert/panel.key"), refs)
        self.assertIn(("PANEL_KEY", "/root/cert/sub.key"), refs)
        self.assertIn(("XRAY_KEY", "/root/cert/inbound.key"), refs)
        self.assertIn(("XRAY_DATA", "ext:custom.dat:tag"), refs)
        self.assertNotIn("NeverPrint", "\n".join(output))

    def test_inline_certificate_key_arrays_and_client_secrets_are_not_output(self):
        self.db.execute("INSERT INTO inbounds VALUES (1,?,?)", (json.dumps({"tlsSettings": {"certificates": [{
            "certificate": ["PrivateCertificateBytes"], "key": ["PrivateKeyBytes"]}]}}), json.dumps({"password": "PrivatePassword"})))
        output = self.run_sql()
        self.assertFalse(any("Private" in bytes.fromhex(line.split("|")[1]).decode() for line in output[1:]))
        self.assertNotIn("Private", "\n".join(output))

    def test_generated_active_config_is_read_only_at_the_fixed_path(self):
        output = self.run_sql(active=True)
        self.assertEqual(["/usr/local/x-ui/bin/config.json"], self.config_reads)
        self.assertIn(("XRAY_KEY", "/root/cert/active.key"), self.refs(output))

    def test_invalid_json_and_oversized_documents_cannot_be_a_valid_zero_reference_header(self):
        for value in ("{invalid", json.dumps({"large": "x" * 65536})):
            self.db.execute("DELETE FROM inbounds")
            self.db.execute("INSERT INTO inbounds VALUES (1,?,?)", (value, "{}"))
            header = self.run_sql()[0].split("|")
            self.assertGreater(int(header[3]), 0)

    def test_duplicate_critical_settings_are_explicit_in_header(self):
        self.setting("webKeyFile", "/root/first.key"); self.setting("webKeyFile", "/root/second.key")
        self.assertEqual("1", self.run_sql()[0].split("|")[4])

    def test_disabled_inbound_references_are_included_for_future_recovery(self):
        self.db.execute("INSERT INTO inbounds VALUES (0,?,?)", (json.dumps({"tlsSettings": {"certificates": [{"keyFile": "/root/cert/disabled.key"}]}}), "{}"))
        self.assertIn(("XRAY_KEY", "/root/cert/disabled.key"), self.refs(self.run_sql()))

    def test_unknown_paths_remain_unclassified_and_reference_overflow_has_a_sentinel_row(self):
        self.db.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (json.dumps({"files": ["/root/f%d" % n for n in range(40)]}),))
        output = self.run_sql()
        self.assertEqual(34, len(output))  # header + 33, over the accepted 32 reference maximum
        self.assertTrue(all(kind == "UNKNOWN" for kind, _ in self.refs(output)))


@unittest.skipUnless(os.getuid() == 0 and (Path('/root').stat().st_mode & 0o777) == 0o700,
                     'Private root directory is required for unmodified ancestor permission guards')
class FileCommands(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="velum-inventory-fixture-", dir="/root")
        self.base = Path(self.temp.name)
        self.runtime = self.base / "runtime"
        (self.runtime / "bin").mkdir(parents=True, mode=0o700)
        self.panel = self.runtime / "x-ui"; self.panel.write_bytes(b"fixture executable"); self.panel.chmod(0o755)
        self.key = self.base / "fixture.key"; self.key.write_bytes(b"synthetic fixture bytes"); self.key.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def run_command(self, command):
        self.assertNotIn("'/etc/x-ui", command)
        self.assertNotIn("'/usr/local/x-ui", command)
        return subprocess.run(["sh", "-c", command], capture_output=True, timeout=5)

    def test_private_file_and_runtime_metadata_are_read_without_contents(self):
        result = self.run_command(metadata([str(self.panel), str(self.key)]))
        self.assertEqual((0, b""), (result.returncode, result.stderr))
        rows = result.stdout.decode().splitlines()
        self.assertEqual("755", rows[0].split("|")[5]); self.assertEqual("600", rows[1].split("|")[5])
        self.assertNotIn(b"synthetic", result.stdout)

    def test_symlink_parent_and_symlink_file_never_return_regular_file_metadata(self):
        link = self.base / "linked"; link.symlink_to(self.runtime, target_is_directory=True)
        key_link = self.base / "key-link"; key_link.symlink_to(self.key)
        result = self.run_command(metadata([str(link / "x-ui"), str(key_link)]))
        self.assertEqual(b"U|0\nU|1\n", result.stdout)

    def test_writable_parent_is_unsafe_and_is_not_repaired(self):
        self.runtime.chmod(0o777)
        result = self.run_command(metadata([str(self.panel)]))
        self.assertEqual(b"U|0\n", result.stdout); self.assertEqual(0o777, self.runtime.stat().st_mode & 0o777)

    def test_hardlinks_and_missing_files_are_visible_to_the_strict_parser(self):
        hardlink = self.base / "same-key"; os.link(self.key, hardlink)
        result = self.run_command(metadata([str(self.key), str(self.base / "missing")]))
        self.assertTrue(result.stdout.splitlines()[0].endswith(b"|2")); self.assertEqual(b"M|1", result.stdout.splitlines()[1])

    def test_runtime_enumeration_keeps_symlink_type_and_does_not_follow_it(self):
        (self.runtime / "bin/linked-key").symlink_to(self.key)
        command = runtime().replace("/usr/local/x-ui", str(self.runtime))
        result = self.run_command(command)
        self.assertEqual((0, b""), (result.returncode, result.stderr))
        self.assertIn(("l|" + str(self.runtime / "bin/linked-key")).encode(), result.stdout)
        self.assertNotIn(b"synthetic", result.stdout)




def service_command():
    body=TEXT.split('fun service() =',1)[1].split('fun metadata(',1)[0].split('"""',2)[1]
    return 'set -eu\n'+GUARD+'\n'+textwrap.dedent(body).strip().replace("${'$'}", '$')


class ServiceEnvironment(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='velum-service-read-',dir='/root')
        self.base=Path(self.tmp.name);self.etc=self.base/'etc';self.etc.mkdir()
        (self.etc/'default').mkdir();(self.etc/'x-ui').mkdir()
        self.bin=self.base/'bin';self.bin.mkdir()
        self.fields={'FragmentPath':'/etc/systemd/system/x-ui.service','DropInPaths':'','WorkingDirectory':'/usr/local/x-ui/','Environment':'XRAY_VMESS_AEAD_FORCED=false','EnvironmentFiles':str(self.etc)+'/default/x-ui (ignore_errors=yes)'}
        self.config=self.base/'fields.json'
        exe=self.bin/'systemctl'
        exe.write_text('#!/usr/bin/python3\nimport json,sys\nf=json.load(open('+repr(str(self.config))+'))\np=next(a.split("=",1)[1] for a in sys.argv if a.startswith("--property="))\nprint(f[p])\n')
        exe.chmod(0o700)
    def tearDown(self):self.tmp.cleanup()
    def query(self):
        self.config.write_text(json.dumps(self.fields))
        command=service_command().replace('/etc/',str(self.etc)+'/')
        env={'PATH':str(self.bin)+':/usr/bin:/bin','LC_ALL':'C'}
        result=subprocess.run(['/bin/sh','-c',command],env=env,capture_output=True,timeout=5)
        self.assertEqual((0,b''),(result.returncode,result.stderr))
        return result.stdout.decode()
    def test_stock_flag_and_optional_absent_file_have_exact_attestations(self):
        raw=self.query();self.assertIn('ENVIRONMENT=STOCK_VMESS_FALSE\n',raw);self.assertIn('ENVFILES=STOCK_OPTIONAL_DEFAULT_ABSENT\n',raw);self.assertIn('NODEKEY=ABSENT\n',raw)
    def test_other_environment_is_a_finding_without_leaking_its_value(self):
        self.fields['Environment']='XUI_DB_DSN=fixture-private-value'
        raw=self.query();self.assertIn('ENVIRONMENT=PRESENT\n',raw);self.assertNotIn('fixture-private-value',raw)
    def test_existing_or_dangling_environment_file_cannot_attest_absence(self):
        p=self.etc/'default/x-ui'
        for raw in [b'',b'XUI_DB_TYPE=postgres\n']:
            p.write_bytes(raw);self.assertIn('ENVFILES=PRESENT\n',self.query());p.unlink()
        p.symlink_to(self.etc/'missing');self.assertIn('ENVFILES=PRESENT\n',self.query())
    def test_optional_environment_parent_must_be_protected_and_not_symlinked(self):
        p=self.etc/'default';p.chmod(0o777);self.assertIn('ENVFILES=PRESENT\n',self.query())
        p.chmod(0o755);p.rmdir();p.symlink_to(self.etc/'x-ui',target_is_directory=True);self.assertIn('ENVFILES=PRESENT\n',self.query())
    def test_node_keyring_is_reported_without_reading_its_contents(self):
        p=self.etc/'x-ui/node_token_key.json';p.write_bytes(b'fixture-private-key-material');p.chmod(0o600)
        raw=self.query();self.assertIn('NODEKEY=PRESENT\n',raw);self.assertNotIn('fixture-private-key-material',raw)
        p.unlink();p.symlink_to(self.etc/'missing');self.assertIn('NODEKEY=UNSAFE\n',self.query())

if __name__ == "__main__":
    unittest.main(verbosity=2)

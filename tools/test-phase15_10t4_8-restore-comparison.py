#!/usr/bin/env python3
"""Synthetic archive + isolated restoration + real SQLite schema comparisons; no SSH/VPS."""
from pathlib import Path
import importlib.util,subprocess,sqlite3,json,os,unittest
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('accepted_restore_fixture',PROJECT/'tools/test-phase15_10t4_7-restore-check.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
class Comparison(unittest.TestCase):
    source=old.RestoreCheck.source;expected=old.RestoreCheck.expected;run_worker=old.RestoreCheck.run_worker
    folder=old.RestoreCheck.folder;create_ok=old.RestoreCheck.create_ok;script=old.RestoreCheck.script
    run_restore=old.RestoreCheck.run_restore;destination=old.RestoreCheck.destination;copy_ok=old.RestoreCheck.copy_ok
    def setUp(self):old.RestoreCheck.setUp(self);self.copy_ok()
    def tearDown(self):old.RestoreCheck.tearDown(self)
    def compare(self,tail='',version='3.10.0'):
        prefix=self.script().split("\nif __name__ == '__main__':",1)[0]
        text=(PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/RestoreCompatibilityWorker.kt').read_text()
        extra=text.split(' + """\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        boundary="\nfrom types import SimpleNamespace\ndef only_version(args,**kwargs):\n    need(args==[RUNTIME+'/x-ui','-v'])\n    return SimpleNamespace(returncode=0,stdout="+repr((version+'\n').encode())+",stderr=b'')\nsubprocess.run=only_version\n"+tail+'\n'
        extra=extra.replace("\nif __name__ == '__main__':",boundary+"\nif __name__ == '__main__':")
        p=self.proof
        args=['c'*64,self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        return subprocess.run(['python3','-I','-c',prefix+'\n'+extra,*args],capture_output=True,timeout=15)
    def values(self,**kw):
        r=self.compare(**kw);self.assertEqual((0,b''),(r.returncode,r.stderr),r.stdout)
        rows=dict(line.split('=') for line in r.stdout.decode().splitlines());self.assertEqual(14,len(rows));return rows
    def test_matching_version_architecture_schema_and_known_set(self):
        p=self.values();self.assertEqual('VELUM_RESTORE_COMPARISON_V1',p['FORMAT']);self.assertEqual('c'*64,p['SCOPE']);self.assertEqual(self.run_scope,p['SOURCE_RESTORE'])
        self.assertEqual('3.10.0',p['CURRENT_VERSION']);self.assertEqual('AMD64',p['CURRENT_ARCH']);self.assertEqual(p['SOURCE_SCHEMA'],p['CURRENT_SCHEMA']);self.assertEqual('MATCH',p['FILE_SET']);self.assertEqual('0',p['CHANGED_FILES'])
    def test_column_change_has_different_schema(self):
        self.con.execute('ALTER TABLE inbounds ADD COLUMN label TEXT');self.con.commit();p=self.values();self.assertNotEqual(p['SOURCE_SCHEMA'],p['CURRENT_SCHEMA'])
    def test_application_table_near_internal_prefix_is_included_in_schema(self):
        self.con.execute('CREATE TABLE sqlitex_custom(value TEXT)');self.con.commit();p=self.values();self.assertNotEqual(p['SOURCE_SCHEMA'],p['CURRENT_SCHEMA'])
    def test_user_version_change_is_not_accepted_as_same_schema(self):
        self.con.execute('PRAGMA user_version=2');self.con.commit();p=self.values();self.assertNotEqual(p['SOURCE_SCHEMA'],p['CURRENT_SCHEMA'])
    def test_new_inbound_is_counted_without_changing_schema(self):
        self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();p=self.values();self.assertEqual(p['SOURCE_SCHEMA'],p['CURRENT_SCHEMA']);self.assertEqual(('1','2'),(p['SOURCE_INBOUNDS'],p['CURRENT_INBOUNDS']))
    def test_changed_key_bytes_are_only_a_finite_count(self):
        self.key.write_bytes(b'different private key');p=self.values();self.assertEqual('MATCH',p['FILE_SET']);self.assertEqual('1',p['CHANGED_FILES']);self.assertNotIn('different private key',str(p))
    def test_new_runtime_file_changes_the_known_file_set(self):
        (self.runtime/'extra').write_bytes(b'extra');p=self.values();self.assertEqual('DIFFERENT',p['FILE_SET'])
    def test_external_key_path_change_is_reported_as_file_set_difference(self):
        p=self.key.with_name('new.key');p.write_bytes(b'new private bytes');p.chmod(0o600)
        self.con.execute("UPDATE settings SET value=? WHERE key='webKeyFile'",(str(p),));self.con.commit();r=self.values();self.assertEqual('DIFFERENT',r['FILE_SET']);self.assertNotIn(str(p),str(r))
    def test_unsafe_private_key_never_claims_a_complete_file_set(self):
        self.key.chmod(0o644);p=self.values();self.assertEqual('UNAVAILABLE',p['FILE_SET']);self.assertEqual('-',p['CHANGED_FILES'])
    def test_unresolved_socket_reference_is_not_a_complete_file_set(self):
        self.con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'",('{"value":"unix:/tmp/socket"}',));self.con.commit();self.assertEqual('UNAVAILABLE',self.values()['FILE_SET'])
    def test_cross_version_is_observed_without_running_migration(self):self.assertEqual('3.10.2',self.values(version='3.10.2')['CURRENT_VERSION'])
    def test_different_architecture_is_observed_without_running_restored_binary(self):
        p=self.values(tail="os.uname=lambda: SimpleNamespace(machine='aarch64')");self.assertEqual('ARM64',p['CURRENT_ARCH']);self.assertEqual('UNAVAILABLE',p['FILE_SET'])
    def test_missing_restored_directory_does_not_create_a_new_one(self):
        (self.destination()/'restore-check.v1').unlink();before=set(self.destination().iterdir());r=self.compare();self.assertEqual(81,r.returncode);self.assertEqual(b'',r.stdout);self.assertEqual(before,set(self.destination().iterdir()))
    def test_corrupt_source_archive_has_no_comparison_proof(self):
        p=self.folder()/'installation.tar';p.write_bytes(b'x'+p.read_bytes()[1:]);r=self.compare();self.assertEqual(81,r.returncode);self.assertEqual(b'',r.stdout)
    def test_corrupt_restored_database_has_no_comparison_proof(self):
        (self.destination()/'database.sqlite').write_bytes(b'not sqlite');self.assertEqual(81,self.compare().returncode)
    def test_target_database_symlink_cannot_be_followed(self):
        self.con.close();self.db.unlink();self.db.symlink_to(self.destination()/'database.sqlite');p=self.values();self.assertEqual('-',p['CURRENT_SCHEMA']);self.assertEqual('UNAVAILABLE',p['FILE_SET']);self.con=sqlite3.connect(':memory:')
    def test_current_version_drift_during_readback_rejects_report(self):
        tail="original_version=compatibility_version\ncalls=0\ndef compatibility_version():\n    global calls\n    calls+=1\n    v=original_version()\n    return ('3.10.2',*v[1:]) if calls>1 else v\n"
        self.assertEqual(81,self.compare(tail=tail).returncode)
    def test_views_or_unbounded_schema_do_not_appear_compatible(self):
        self.con.execute('CREATE VIEW extra_view AS SELECT 1');self.con.commit();self.assertEqual('-',self.values()['CURRENT_SCHEMA'])
    def test_read_only_comparison_preserves_source_and_live_file_bytes(self):
        paths=[self.db,Path(str(self.db)+'-wal'),self.key,self.cert,self.runtime/'x-ui',self.unit,self.folder()/'installation.tar',self.folder()/'database.sqlite',self.destination()/'database.sqlite']
        before={str(p):p.read_bytes() for p in paths};self.values();self.assertEqual(before,{str(p):p.read_bytes() for p in paths})
    def test_private_settings_and_schema_text_never_enter_proof(self):
        p=self.values();self.assertNotIn(str(self.base),str(p));self.assertNotIn('CREATE TABLE',str(p));self.assertNotIn('fixture key',str(p))
    def test_all_write_entry_points_are_unreachable(self):
        tail="def forbidden(*a,**kw): raise AssertionError('write entry called')\nrestore_copy=forbidden\ncreate=forbidden\nos.mkdir=forbidden\nos.rename=forbidden\nos.unlink=forbidden\n"
        self.assertEqual('MATCH',self.values(tail=tail)['FILE_SET'])
if __name__=='__main__':unittest.main(verbosity=2)

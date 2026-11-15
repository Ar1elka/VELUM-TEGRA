#!/usr/bin/env python3
"""Synthetic local read-only before-copy fixtures. Accepted systemd/version boundaries remain scripted."""
from pathlib import Path
import importlib.util,subprocess,unittest,json,hashlib,os,fcntl
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('wdb',PROJECT/'tools/test-phase15_10t4_9-working-database-restore.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
class BeforeCopy(unittest.TestCase):
    setUp=old.WorkingRestore.setUp;tearDown=old.WorkingRestore.tearDown
    source=old.WorkingRestore.source;expected=old.WorkingRestore.expected;run_worker=old.WorkingRestore.run_worker;folder=old.WorkingRestore.folder;create_ok=old.WorkingRestore.create_ok
    script=old.WorkingRestore.script;run_restore=old.WorkingRestore.run_restore;destination=old.WorkingRestore.destination;copy_ok=old.WorkingRestore.copy_ok
    wdb_dir=old.WorkingRestore.wdb_dir;worker=old.WorkingRestore.worker;run_wdb=old.WorkingRestore.run_wdb;write_ok=old.WorkingRestore.write_ok;count=old.WorkingRestore.count
    def read_before(self,tail=''):
        prefix=self.worker().split("\nif __name__=='__main__':",1)[0]
        extra=(PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/BeforeCopyEvidenceWorker.kt').read_text().split('+"""\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        extra=extra.replace("\nif __name__=='__main__':",'\n'+tail+"\nif __name__=='__main__':")
        p=self.proof;args=['space',self.wdb_scope,hashlib.sha256(b'4:20537:/panel/9:127.0.0.1').hexdigest(),self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        return subprocess.run(['python3','-I','-c',prefix+'\n'+extra,*args],capture_output=True,timeout=25)
    def observed(self):
        r=self.read_before();self.assertEqual((0,b''),(r.returncode,r.stderr));p=dict(x.split('=') for x in r.stdout.decode().splitlines());self.assertEqual(10,len(p));self.assertEqual('OBSERVED',p['STATE']);return p
    def before_only(self):
        self.write_ok();(self.wdb_dir()/'restored.json').unlink()
    def test_completed_prior_copy_is_observed(self):
        self.write_ok();p=self.observed();self.assertEqual('COMPLETE',p['COPY_STATE']);self.assertEqual('DIFFERENT',p['CURRENT_DB']);self.assertEqual('MATCH',p['STRUCTURE'])
    def test_partial_prior_copy_does_not_need_restored_manifest(self):
        self.before_only();self.assertEqual('PARTIAL',self.observed()['COPY_STATE'])
    def test_interrupted_sqlite_copy_has_independent_before_evidence(self):
        tail="def working_apply(source,target):\n    raise Rejected()\n"
        self.assertEqual(81,self.run_wdb('write',tail).returncode);self.assertEqual('SAME',self.observed()['CURRENT_DB']);self.assertEqual('PARTIAL',self.observed()['COPY_STATE'])
    def test_read_leaves_artifact_bytes_db_rows_and_service_commands_unchanged(self):
        self.write_ok();before={p.name:p.read_bytes() for p in self.wdb_dir().iterdir()};count=self.count();log=self.stop_log.read_text();self.observed();self.assertEqual(before,{p.name:p.read_bytes() for p in self.wdb_dir().iterdir()});self.assertEqual(count,self.count());self.assertEqual(log,self.stop_log.read_text())
    def test_absence_creates_nothing_and_proves_nothing(self):
        self.assertEqual(81,self.read_before().returncode);self.assertFalse(self.wdb_dir().parent.exists());self.assertEqual('',self.stop_log.read_text())
    def test_busy_writer_lock_rejects_without_read_success(self):
        self.write_ok()
        with open(self.wdb_dir().parent/'.lock','rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(81,self.read_before().returncode)
    def test_corrupt_before_copy_rejects(self):
        self.write_ok();(self.wdb_dir()/'before.sqlite').write_bytes(b'bad');self.assertEqual(81,self.read_before().returncode)
    def test_foreign_manifest_scope_rejects(self):
        self.write_ok();p=self.wdb_dir()/'before.json';m=json.loads(p.read_text());m['scope']='f'*64;p.write_text(json.dumps(m));self.assertEqual(81,self.read_before().returncode)
    def test_foreign_source_db_rejects(self):
        self.write_ok();p=self.wdb_dir()/'before.json';m=json.loads(p.read_text());m['source']='f'*64;p.write_text(json.dumps(m));self.assertEqual(81,self.read_before().returncode)
    def test_duplicate_manifest_key_rejects(self):
        self.write_ok();p=self.wdb_dir()/'before.json';p.write_text(p.read_text().replace('{','{"scope":"'+self.wdb_scope+'",',1));self.assertEqual(81,self.read_before().returncode)
    def test_symlink_before_copy_rejects(self):
        self.write_ok();p=self.wdb_dir()/'before.sqlite';other=self.home/'other.sqlite';p.rename(other);p.symlink_to(other);self.assertEqual(81,self.read_before().returncode)
    def test_public_before_copy_rejects(self):
        self.write_ok();(self.wdb_dir()/'before.sqlite').chmod(0o644);self.assertEqual(81,self.read_before().returncode)
    def test_active_service_does_not_claim_stable_current_db(self):
        self.write_ok();self.state.write_text('active');p=self.observed();self.assertEqual('ACTIVE',p['SERVICE']);self.assertEqual('UNAVAILABLE',p['CURRENT_DB']);self.assertEqual('active',self.state.read_text())
    def test_different_current_schema_is_finite(self):
        self.write_ok();self.con.execute('ALTER TABLE inbounds ADD COLUMN newer TEXT');self.con.commit();self.assertEqual('DIFFERENT',self.observed()['STRUCTURE'])
    def test_changed_runtime_file_is_not_restore_eligibility(self):
        self.write_ok();self.key.write_bytes(b'changed');self.assertEqual('DIFFERENT',self.observed()['STRUCTURE'])
    def test_partial_final_manifest_does_not_destroy_valid_before_copy(self):
        self.write_ok();(self.wdb_dir()/'restored.json').write_bytes(b'{');self.assertEqual('PARTIAL',self.observed()['COPY_STATE'])
    def test_changed_before_bytes_during_read_rejects(self):
        self.write_ok();tail="old_logical=working_logical\ndef changed(path,immutable=False):\n    value=old_logical(path,immutable)\n    if path.endswith('/before.sqlite'):\n        with open(WDB_DIRECTORY+'/before.json','ab') as output:output.write(b' ')\n    return value\nworking_logical=changed\n";self.assertEqual(81,self.read_before(tail).returncode)
    def test_unknown_artifact_file_rejects(self):
        self.write_ok();(self.wdb_dir()/'unknown').write_bytes(b'bad');self.assertEqual(81,self.read_before().returncode)
    def test_missing_before_manifest_rejects_without_repair(self):
        self.write_ok();p=self.wdb_dir()/'before.json';p.unlink();self.assertEqual(81,self.read_before().returncode);self.assertFalse(p.exists())
    def test_plain_output_has_no_paths_keys_or_sql(self):
        self.write_ok();r=self.read_before();self.assertEqual(0,r.returncode);self.assertNotIn(str(self.home).encode(),r.stdout);self.assertNotIn(b'SELECT',r.stdout);self.assertNotIn(b'fixture-private-key',r.stdout)
if __name__=='__main__':unittest.main()

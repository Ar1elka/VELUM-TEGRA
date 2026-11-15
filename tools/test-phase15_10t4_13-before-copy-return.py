#!/usr/bin/env python3
"""Actual synthetic SQLite/WAL return; systemd/version boundaries scripted; no VPS."""
from pathlib import Path
import importlib.util,json,hashlib,os,fcntl,subprocess,unittest
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('wdb',PROJECT/'tools/test-phase15_10t4_9-working-database-restore.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
class Return(unittest.TestCase):
    source=old.WorkingRestore.source;expected=old.WorkingRestore.expected;run_worker=old.WorkingRestore.run_worker;folder=old.WorkingRestore.folder;create_ok=old.WorkingRestore.create_ok
    script=old.WorkingRestore.script;run_restore=old.WorkingRestore.run_restore;destination=old.WorkingRestore.destination;copy_ok=old.WorkingRestore.copy_ok
    wdb_dir=old.WorkingRestore.wdb_dir;worker=old.WorkingRestore.worker;run_wdb=old.WorkingRestore.run_wdb;write_ok=old.WorkingRestore.write_ok;count=old.WorkingRestore.count
    def setUp(self):
        old.WorkingRestore.setUp(self);self.write_ok();self.return_scope='e'*64;self.before=json.loads((self.wdb_dir()/'before.json').read_text())
    def tearDown(self):old.WorkingRestore.tearDown(self)
    def return_dir(self):return self.home/'.velum-tegra-before-copy-returns'/self.wdb_scope[:32]
    def return_worker(self,tail=''):
        prefix=self.worker().split("\nif __name__=='__main__':",1)[0]
        p=PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/BeforeCopyReturnWorker.kt';extra=p.read_text().split('+"""\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        extra=extra.replace("'/root/.velum-tegra-before-copy-returns'",repr(str(self.home/'.velum-tegra-before-copy-returns')))
        boundary="""
base_subprocess=subprocess.run
def no_service_mutation(args,**kwargs):
    if args==['/usr/bin/systemctl','show','--no-pager','--property=Job','--','x-ui.service']:return SimpleNamespace(returncode=0,stdout=b'Job=0\\n',stderr=b'')
    need(not any(v in ('start','stop','restart') for v in args))
    return base_subprocess(args,**kwargs)
subprocess.run=no_service_mutation
"""
        return prefix+'\n'+extra.replace("\nif __name__=='__main__':",'\n'+boundary+'\n'+tail+"\nif __name__=='__main__':")
    def run_return(self,mode,tail='',scope=None,db=None):
        p=self.proof;b=self.before;args=[mode,scope or self.return_scope,db or b['previousSha256'],b['previousLogicalSha256'],str(b['previousBytes']),self.wdb_scope,hashlib.sha256(b'4:20537:/panel/9:127.0.0.1').hexdigest(),self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        return subprocess.run(['python3','-I','-c',self.return_worker(tail),*args],capture_output=True,timeout=25)
    def returned(self):
        r=self.run_return('write');self.assertEqual((0,b'BEFORE_DATABASE_RETURNED\n',b''),(r.returncode,r.stdout,r.stderr));return r
    def test_actual_wal_return_and_separate_readback(self):
        self.assertEqual(1,self.count());self.returned();self.assertEqual(2,self.count());r=self.run_return('read');self.assertEqual((0,b''),(r.returncode,r.stderr));v=dict(x.split('=') for x in r.stdout.decode().splitlines());self.assertEqual('VERIFIED_STOPPED',v['STATE']);self.assertEqual(9,len(v))
    def test_current_displaced_database_is_preserved_privately(self):
        self.returned();self.assertEqual(1,self.count(self.return_dir()/'displaced.sqlite'));self.assertEqual(0o600,(self.return_dir()/'displaced.sqlite').stat().st_mode&0o777);self.assertEqual(0o700,self.return_dir().stat().st_mode&0o777)
    def test_partial_original_completion_does_not_block_valid_before_copy(self):
        (self.wdb_dir()/'restored.json').unlink();self.returned();self.assertEqual(0,self.run_return('read').returncode)
    def test_malformed_original_completion_does_not_become_authority(self):
        (self.wdb_dir()/'restored.json').write_bytes(b'{');self.returned();self.assertEqual(2,self.count())
    def test_no_service_mutation_or_automatic_start(self):
        log=self.stop_log.read_text();self.returned();self.assertEqual(0,self.run_return('read').returncode);self.assertEqual(log,self.stop_log.read_text());self.assertEqual('inactive',self.state.read_text())
    def test_same_parent_second_write_never_replays(self):
        self.returned();self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();self.assertEqual(81,self.run_return('write').returncode);self.assertEqual(3,self.count())
    def test_new_scope_cannot_reuse_same_parent_slot(self):
        self.returned();self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();self.assertEqual(81,self.run_return('write',scope='f'*64).returncode)
    def test_active_service_blocks_without_stopping_it(self):
        self.state.write_text('active');self.assertEqual(81,self.run_return('write').returncode);self.assertEqual(1,self.count());self.assertFalse(self.return_dir().parent.exists())
    def test_queued_job_blocks_before_any_private_return_storage(self):
        tail="base=subprocess.run\ndef job(args,**kw):\n    r=base(args,**kw)\n    if '--property=Job' in args:r.stdout=b'Job=99\\n'\n    return r\nsubprocess.run=job\n"
        self.assertEqual(81,self.run_return('write',tail).returncode);self.assertFalse(self.return_dir().parent.exists())
    def test_before_hash_mismatch_blocks(self):
        self.assertEqual(81,self.run_return('write',db='0'*64).returncode);self.assertEqual(1,self.count())
    def test_corrupt_before_copy_blocks(self):
        (self.wdb_dir()/'before.sqlite').write_bytes(b'bad');self.assertEqual(81,self.run_return('write').returncode)
    def test_symlink_before_copy_blocks(self):
        p=self.wdb_dir()/'before.sqlite';other=self.home/'outside.sqlite';p.rename(other);p.symlink_to(other);self.assertEqual(81,self.run_return('write').returncode)
    def test_nonprivate_before_copy_blocks(self):
        (self.wdb_dir()/'before.sqlite').chmod(0o644);self.assertEqual(81,self.run_return('write').returncode)
    def test_foreign_before_scope_blocks(self):
        p=self.wdb_dir()/'before.json';m=json.loads(p.read_text());m['scope']='f'*64;p.write_text(json.dumps(m));self.assertEqual(81,self.run_return('write').returncode)
    def test_duplicate_manifest_keys_block(self):
        p=self.wdb_dir()/'before.json';p.write_text(p.read_text().replace('{','{"scope":"'+self.wdb_scope+'",',1));self.assertEqual(81,self.run_return('write').returncode)
    def test_missing_before_source_never_recreated(self):
        p=self.wdb_dir()/'before.json';p.unlink();self.assertEqual(81,self.run_return('write').returncode);self.assertFalse(p.exists())
    def test_parent_busy_writer_prevents_read_or_write(self):
        with open(self.wdb_dir().parent/'.lock','rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(81,self.run_return('write').returncode);self.assertFalse(self.return_dir().parent.exists())
    def test_different_schema_blocks(self):
        self.con.execute('ALTER TABLE inbounds ADD COLUMN extra TEXT');self.con.commit();self.assertEqual(81,self.run_return('write').returncode)
    def test_changed_known_key_blocks_without_repair(self):
        self.key.write_bytes(b'changed');self.assertEqual(81,self.run_return('write').returncode);self.assertEqual(b'changed',self.key.read_bytes())
    def test_wrong_endpoint_blocks(self):
        self.con.execute("UPDATE settings SET value='9999' WHERE key='webPort'");self.con.commit();self.assertEqual(81,self.run_return('write').returncode)
    def test_same_content_does_not_need_another_write(self):
        self.returned();self.assertEqual(81,self.run_return('write').returncode)
    def test_interrupted_target_backup_retains_displaced_and_no_replay(self):
        tail="def working_apply(source,target):\n    def fail(status,remaining,total):\n        if remaining>0:raise Rejected()\n    source.backup(target,pages=1,progress=fail,sleep=0.01)\n"
        self.assertEqual(81,self.run_return('write',tail).returncode);self.assertEqual(1,self.count());self.assertTrue((self.return_dir()/'displaced.json').exists());self.assertEqual(81,self.run_return('read').returncode);self.assertEqual(81,self.run_return('write').returncode)
    def test_lost_completion_after_commit_is_uncertain_not_replayed(self):
        tail="store=returning_store\ndef lose(path,value):\n    if path.endswith('/returned.json'):raise Rejected()\n    return store(path,value)\nreturning_store=lose\n"
        self.assertEqual(81,self.run_return('write',tail).returncode);self.assertEqual(2,self.count());self.assertEqual(81,self.run_return('read').returncode);self.assertEqual(81,self.run_return('write').returncode)
    def test_missing_readback_creates_nothing(self):
        self.assertEqual(81,self.run_return('read').returncode);self.assertFalse(self.return_dir().parent.exists())
    def test_current_drift_blocks_readback_without_writing(self):
        self.returned();self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();self.assertEqual(81,self.run_return('read').returncode);self.assertEqual(3,self.count())
    def test_readback_preserves_db_rows_manifest_bytes_and_service(self):
        self.returned();before={p.name:p.read_bytes() for p in self.return_dir().iterdir()};log=self.stop_log.read_text();self.assertEqual(0,self.run_return('read').returncode);self.assertEqual(before,{p.name:p.read_bytes() for p in self.return_dir().iterdir()});self.assertEqual(2,self.count());self.assertEqual(log,self.stop_log.read_text())
    def test_foreign_return_scope_rejects_readback(self):
        self.returned();self.assertEqual(81,self.run_return('read',scope='f'*64).returncode)
    def test_displaced_copy_tamper_rejects_readback(self):
        self.returned();(self.return_dir()/'displaced.sqlite').write_bytes(b'bad');self.assertEqual(81,self.run_return('read').returncode)
    def test_current_inode_and_private_mode_are_preserved(self):
        info=self.db.stat();self.returned();after=self.db.stat();self.assertEqual((info.st_ino,info.st_mode),(after.st_ino,after.st_mode))
    def test_unknown_return_file_rejects_readback(self):
        self.returned();(self.return_dir()/'extra').write_bytes(b'x');self.assertEqual(81,self.run_return('read').returncode)
    def test_quota_blocks_before_database_copy(self):
        root=self.return_dir().parent;root.mkdir(mode=0o700)
        for i in range(4):(root/str(i).zfill(32)).mkdir(mode=0o700)
        self.assertEqual(81,self.run_return('write').returncode);self.assertEqual(1,self.count());self.assertFalse(self.return_dir().exists())
    def test_source_changes_before_target_copy_block_without_replacement(self):
        tail="original=returning_source\ncalls=0\ndef change():\n    global calls\n    calls+=1\n    if calls==2:\n        with open(RUNTIME+'/x-ui','ab') as out:out.write(b'x')\n    return original()\nreturning_source=change\n"
        self.assertEqual(81,self.run_return('write',tail).returncode);self.assertEqual(1,self.count());self.assertTrue((self.return_dir()/'displaced.json').exists())
    def test_service_activates_before_target_copy_block_without_stop(self):
        tail="original=returning_source\ncalls=0\ndef change():\n    global calls\n    calls+=1\n    if calls==2:\n        with open(STATE_FILE,'w') as out:out.write('active')\n    return original()\nreturning_source=change\n"
        log=self.stop_log.read_text();self.assertEqual(81,self.run_return('write',tail).returncode);self.assertEqual(1,self.count());self.assertEqual(log,self.stop_log.read_text())
    def test_current_changes_after_displaced_copy_block_without_overwrite(self):
        tail="original=returning_source\ncalls=0\ndef change():\n    global calls\n    calls+=1\n    if calls==2:\n        con=sqlite3.connect(DATABASE);con.execute(\"UPDATE userData SET payload='external change'\");con.commit();con.close()\n    return original()\nreturning_source=change\n"
        self.assertEqual(81,self.run_return('write',tail).returncode);self.assertEqual(1,self.count())
    def test_duplicate_readback_manifest_key_rejects(self):
        self.returned();p=self.return_dir()/'returned.json';p.write_text(p.read_text().replace('{','{\"scope\":\"'+self.return_scope+'\",',1));self.assertEqual(81,self.run_return('read').returncode)
    def test_output_has_no_database_keys_sql_or_paths(self):
        self.returned();r=self.run_return('read');self.assertEqual(0,r.returncode)
        for v in (str(self.home).encode(),b'SELECT',b'payload',b'fixture-private-key'):self.assertNotIn(v,r.stdout)
if __name__=='__main__':unittest.main()

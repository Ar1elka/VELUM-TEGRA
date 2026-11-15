#!/usr/bin/env python3
"""Synthetic local SQLite/WAL working DB restore. Only fixed service/version boundaries are scripted."""
from pathlib import Path
import os,fcntl,hashlib,importlib.util,json,sqlite3,subprocess,unittest
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('accepted_restore',PROJECT/'tools/test-phase15_10t4_7-restore-check.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
class WorkingRestore(unittest.TestCase):
    source=old.RestoreCheck.source;expected=old.RestoreCheck.expected;run_worker=old.RestoreCheck.run_worker;folder=old.RestoreCheck.folder;create_ok=old.RestoreCheck.create_ok
    script=old.RestoreCheck.script;run_restore=old.RestoreCheck.run_restore;destination=old.RestoreCheck.destination;copy_ok=old.RestoreCheck.copy_ok
    def setUp(self):
        old.old.InstallationArtifact.setUp(self)
        self.con.executemany('INSERT INTO settings VALUES (?,?)',[('webPort','2053'),('webBasePath','/panel/'),('webListen','127.0.0.1')]);self.con.execute('CREATE TABLE userData(payload TEXT)');self.con.execute('INSERT INTO userData VALUES (?)',('source '*90000,));self.con.commit()
        self.create_ok();result=self.run_worker('verify');self.assertEqual(0,result.returncode);self.proof=dict(line.split('=') for line in result.stdout.decode().splitlines());self.run_scope='b'*64;self.copy_ok()
        self.wdb_scope='d'*64;self.state=self.home/'fixture-state';self.state.write_text('active');self.stop_log=self.home/'fixture-stop-log';self.stop_log.write_text('')
        self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{"new":"client"}','{}'));self.con.commit()
    def tearDown(self):old.old.InstallationArtifact.tearDown(self)
    def wdb_dir(self):return self.home/'.velum-tegra-working-db-restores'/self.wdb_scope[:32]
    def worker(self,tail=''):
        prefix=self.script().split("\nif __name__ == '__main__':",1)[0]
        path=PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh'
        comp=(path/'RestoreCompatibilityWorker.kt').read_text().split(' + """\n',1)[1].rsplit('\n""".trimIndent()',1)[0].split("\nif __name__ == '__main__':",1)[0]
        extra=(path/'WorkingDatabaseRestoreWorker.kt').read_text().split('+"""\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        extra=extra.replace("'/root/.velum-tegra-working-db-restores'",repr(str(self.home/'.velum-tegra-working-db-restores'))).replace("'/sys/fs/cgroup/system.slice/x-ui.service'",repr(str(self.base/'unused-cgroup')))
        boundary="""
from types import SimpleNamespace
STATE_FILE=__STATE__
STOP_LOG=__LOG__
def fixture_subprocess(args,**kwargs):
    if args==[RUNTIME+'/x-ui','-v']:return SimpleNamespace(returncode=0,stdout=b'3.10.0\\n',stderr=b'')
    if args==['/usr/bin/systemctl','stop','--','x-ui.service']:
        with open(STATE_FILE,'w') as f:f.write('inactive')
        with open(STOP_LOG,'a') as f:f.write('stop\\n')
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    need(args[:3]==['/usr/bin/systemctl','show','--no-pager'])
    names=('LoadState','ActiveState','SubState','MainPID','ControlPID','TriggeredBy','KillMode','ControlGroup')
    with open(STATE_FILE) as f:active=f.read()=='active'
    fields={'LoadState':'loaded','ActiveState':'active' if active else 'inactive','SubState':'running' if active else 'dead','MainPID':'123' if active else '0','ControlPID':'0','TriggeredBy':'','KillMode':'control-group','ControlGroup':''}
    return SimpleNamespace(returncode=0,stdout=''.join(k+'='+fields[k]+'\\n' for k in names).encode(),stderr=b'')
subprocess.run=fixture_subprocess
""".replace('__STATE__',repr(str(self.state))).replace('__LOG__',repr(str(self.stop_log)))
        extra=extra.replace("\nif __name__=='__main__':",'\n'+boundary+'\n'+tail+"\nif __name__=='__main__':")
        return prefix+'\n'+comp+'\n'+extra
    def run_wdb(self,mode,tail='',endpoint=None):
        p=self.proof;args=[mode,self.wdb_scope,endpoint or hashlib.sha256(b'4:20537:/panel/9:127.0.0.1').hexdigest(),self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        return subprocess.run(['python3','-I','-c',self.worker(tail),*args],capture_output=True,timeout=20)
    def write_ok(self):
        result=self.run_wdb('write');self.assertEqual((0,b'DATABASE_RESTORED\n',b''),(result.returncode,result.stdout,result.stderr));return result
    def count(self,path=None):
        con=sqlite3.connect(path or self.db)
        try:return con.execute('SELECT count(*) FROM inbounds').fetchone()[0]
        finally:con.close()
    def test_real_wal_database_restore_and_separate_readback(self):
        self.assertEqual(2,self.count());self.write_ok();self.assertEqual(1,self.count());self.assertEqual(2,self.count(self.wdb_dir()/'before.sqlite'))
        result=self.run_wdb('read');self.assertEqual(0,result.returncode,result.stderr);p=dict(line.split('=') for line in result.stdout.decode().splitlines());self.assertEqual(9,len(p));self.assertEqual('INACTIVE',p['SERVICE']);self.assertEqual('VERIFIED',p['STATE']);self.assertEqual('inactive',self.state.read_text());self.assertEqual('stop\n',self.stop_log.read_text())
    def test_previous_copy_is_private_integral_and_from_before_replacement(self):
        self.write_ok();p=self.wdb_dir()/'before.sqlite';self.assertEqual(0o600,p.stat().st_mode&0o777);self.assertEqual(0o700,p.parent.stat().st_mode&0o777);m=json.loads((p.parent/'before.json').read_text());self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),m['previousSha256']);self.assertEqual(2,self.count(p))
    def test_current_database_inode_and_mode_preserved(self):
        before=self.db.stat();self.write_ok();after=self.db.stat();self.assertEqual((before.st_ino,before.st_mode&0o777),(after.st_ino,after.st_mode&0o777))
    def test_readback_cannot_write_replay_or_stop_service(self):
        self.write_ok();before={p.name:p.read_bytes() for p in self.wdb_dir().iterdir()};log=self.stop_log.read_text();self.assertEqual(0,self.run_wdb('read').returncode);self.assertEqual(before,{p.name:p.read_bytes() for p in self.wdb_dir().iterdir()});self.assertEqual(log,self.stop_log.read_text())
    def test_read_without_manifest_creates_nothing(self):
        self.assertEqual(81,self.run_wdb('read').returncode);self.assertFalse(self.wdb_dir().parent.exists());self.assertEqual('',self.stop_log.read_text())
    def test_duplicate_write_cannot_stop_or_restore_again(self):
        self.write_ok();before=self.stop_log.read_text();self.assertEqual(81,self.run_wdb('write').returncode);self.assertEqual(before,self.stop_log.read_text())
    def test_changed_known_key_bytes_block_before_stop(self):
        self.key.write_bytes(b'changed');self.assertEqual(81,self.run_wdb('write').returncode);self.assertEqual('',self.stop_log.read_text());self.assertEqual(2,self.count())
    def test_schema_change_blocks_before_stop(self):
        self.con.execute('ALTER TABLE inbounds ADD COLUMN extra TEXT');self.con.commit();self.assertEqual(81,self.run_wdb('write').returncode);self.assertEqual('',self.stop_log.read_text())
    def test_panel_endpoint_difference_blocks_before_stop(self):
        self.con.execute("UPDATE settings SET value='9999' WHERE key='webPort'");self.con.commit();self.assertEqual(81,self.run_wdb('write').returncode);self.assertEqual('',self.stop_log.read_text())
    def test_wrong_saved_endpoint_digest_blocks_before_stop(self):
        result=self.run_wdb('write',endpoint='0'*64)
        self.assertEqual(81,result.returncode);self.assertEqual(b'NOT_STARTED\n',result.stdout);self.assertEqual('',self.stop_log.read_text())
    def test_other_version_blocks_before_stop(self):
        tail="subprocess_original=subprocess.run\ndef other(args,**kw):\n    if args==[RUNTIME+'/x-ui','-v']:return SimpleNamespace(returncode=0,stdout=b'3.10.2\\n',stderr=b'')\n    return subprocess_original(args,**kw)\nsubprocess.run=other\n"
        self.assertEqual(81,self.run_wdb('write',tail).returncode);self.assertEqual('',self.stop_log.read_text())
    def test_unsupported_kill_mode_blocks_before_stop(self):
        tail="subprocess_original=subprocess.run\ndef other(args,**kw):\n    r=subprocess_original(args,**kw)\n    r.stdout=r.stdout.replace(b'KillMode=control-group',b'KillMode=process');return r\nsubprocess.run=other\n"
        self.assertEqual(81,self.run_wdb('write',tail).returncode);self.assertEqual('',self.stop_log.read_text())
    def test_failed_stop_leaves_live_database_unchanged(self):
        tail="subprocess_original=subprocess.run\ndef other(args,**kw):\n    if args==['/usr/bin/systemctl','stop','--','x-ui.service']:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'')\n    return subprocess_original(args,**kw)\nsubprocess.run=other\n"
        self.assertEqual(81,self.run_wdb('write',tail).returncode);self.assertEqual(2,self.count());self.assertFalse(self.wdb_dir().exists())
    def test_service_still_active_after_stop_blocks_database_write(self):
        tail="subprocess_original=subprocess.run\ndef other(args,**kw):\n    if args==['/usr/bin/systemctl','stop','--','x-ui.service']:return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')\n    return subprocess_original(args,**kw)\nsubprocess.run=other\n"
        self.assertEqual(81,self.run_wdb('write',tail).returncode);self.assertEqual(2,self.count())
    def test_interrupted_sqlite_backup_rolls_back_current_database(self):
        tail="def working_apply(source,target):\n    def interrupted(status,remaining,total):\n        if remaining>0:raise Rejected()\n    source.backup(target,pages=1,progress=interrupted,sleep=0.01)\n"
        self.assertEqual(81,self.run_wdb('write',tail).returncode);self.assertEqual(2,self.count());self.assertTrue((self.wdb_dir()/'before.sqlite').exists());self.assertFalse((self.wdb_dir()/'restored.json').exists());self.assertEqual(81,self.run_wdb('read').returncode)
    def test_corrupt_previous_copy_blocks_result(self):
        self.write_ok();(self.wdb_dir()/'before.sqlite').write_bytes(b'invalid');self.assertEqual(81,self.run_wdb('read').returncode)
    def test_changed_current_database_blocks_result(self):
        self.write_ok();self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();self.assertEqual(81,self.run_wdb('read').returncode)
    def test_started_service_blocks_result_without_stopping_it(self):
        self.write_ok();self.state.write_text('active');log=self.stop_log.read_text();self.assertEqual(81,self.run_wdb('read').returncode);self.assertEqual(log,self.stop_log.read_text())
    def test_source_and_runtime_keys_are_unchanged(self):
        paths=[self.key,self.cert,self.runtime/'x-ui',self.unit,self.folder()/'installation.tar',self.destination()/'database.sqlite'];before={str(p):p.read_bytes() for p in paths};self.write_ok();self.assertEqual(before,{str(p):p.read_bytes() for p in paths})
    def test_four_partial_slots_reject_before_stop(self):
        base=self.wdb_dir().parent;base.mkdir(mode=0o700)
        for n in range(4):(base/str(n).zfill(32)).mkdir(mode=0o700)
        self.assertEqual(81,self.run_wdb('write').returncode);self.assertEqual('',self.stop_log.read_text())
    def test_writer_lock_blocks_write_and_read_without_waiting(self):
        base=self.wdb_dir().parent;base.mkdir(mode=0o700);fd=os.open(base/'.lock',os.O_WRONLY|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(81,self.run_wdb('write').returncode);self.assertEqual(81,self.run_wdb('read').returncode);self.assertEqual('',self.stop_log.read_text())
        finally:os.close(fd)
    def test_nonprivate_storage_root_is_not_repaired(self):
        self.wdb_dir().parent.mkdir(mode=0o755);self.assertEqual(81,self.run_wdb('write').returncode);self.assertEqual('',self.stop_log.read_text());self.assertEqual(0o755,self.wdb_dir().parent.stat().st_mode&0o777)
    def test_manifest_scope_tampering_rejects_result(self):
        self.write_ok();p=self.wdb_dir()/'restored.json';m=json.loads(p.read_text());m['scope']='0'*64;p.write_text(json.dumps(m));self.assertEqual(81,self.run_wdb('read').returncode)
    def test_no_private_rows_or_paths_are_in_success_output(self):
        self.write_ok();r=self.run_wdb('read');self.assertEqual(0,r.returncode);self.assertNotIn(str(self.base).encode(),r.stdout);self.assertNotIn(b'new',r.stdout);self.assertNotIn(b'CREATE',r.stdout)
if __name__=='__main__':unittest.main(verbosity=2)

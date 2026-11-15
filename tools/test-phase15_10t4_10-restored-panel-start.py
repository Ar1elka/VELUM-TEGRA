#!/usr/bin/env python3
"""Real synthetic local SQLite/file verification; systemd and /proc boundaries are scripted."""
from pathlib import Path
import importlib.util,os,fcntl,json,hashlib,subprocess,unittest
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('accepted_wdb',PROJECT/'tools/test-phase15_10t4_9-working-database-restore.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
class Start(unittest.TestCase):
    for_name=None
    source=old.WorkingRestore.source;expected=old.WorkingRestore.expected;run_worker=old.WorkingRestore.run_worker;folder=old.WorkingRestore.folder;create_ok=old.WorkingRestore.create_ok
    script=old.WorkingRestore.script;run_restore=old.WorkingRestore.run_restore;destination=old.WorkingRestore.destination;copy_ok=old.WorkingRestore.copy_ok
    wdb_dir=old.WorkingRestore.wdb_dir;worker=old.WorkingRestore.worker;run_wdb=old.WorkingRestore.run_wdb;write_ok=old.WorkingRestore.write_ok;count=old.WorkingRestore.count
    def setUp(self):
        old.WorkingRestore.setUp(self);self.write_ok();self.start_scope='e'*64;self.start_log=self.home/'fixture-start-log';self.start_log.write_text('')
    def tearDown(self):old.WorkingRestore.tearDown(self)
    def start_dir(self):return self.home/'.velum-tegra-restored-panel-starts'/self.wdb_scope[:32]
    def start_worker(self,tail=''):
        prefix=self.worker().split("\nif __name__=='__main__':",1)[0]
        p=PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/RestoredPanelStartWorker.kt';extra=p.read_text().split('+"""\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        extra=extra.replace("'/root/.velum-tegra-restored-panel-starts'",repr(str(self.home/'.velum-tegra-restored-panel-starts')))
        boundary="""
START_LOG=__LOG__
base_subprocess=subprocess.run
base_readlink=os.readlink
def service_boundary(args,**kwargs):
    if args==['/usr/bin/systemctl','start','--','x-ui.service']:
        with open(STATE_FILE,'w') as f:f.write('active')
        with open(START_LOG,'a') as f:f.write('start\\n')
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    if args==['/usr/bin/systemctl','show','--no-pager','--property=Job','--','x-ui.service']:return SimpleNamespace(returncode=0,stdout=b'Job=0\\n',stderr=b'')
    return base_subprocess(args,**kwargs)
subprocess.run=service_boundary
os.readlink=lambda path: RUNTIME+'/x-ui' if path=='/proc/123/exe' else base_readlink(path)
""".replace('__LOG__',repr(str(self.start_log)))
        return prefix+'\n'+extra.replace("\nif __name__=='__main__':",'\n'+boundary+'\n'+tail+"\nif __name__=='__main__':")
    def run_start(self,mode,tail='',scope=None):
        p=self.proof;args=[mode,scope or self.start_scope,self.wdb_scope,hashlib.sha256(b'4:20537:/panel/9:127.0.0.1').hexdigest(),self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        return subprocess.run(['python3','-I','-c',self.start_worker(tail),*args],capture_output=True,timeout=25)
    def start_ok(self):
        r=self.run_start('write');self.assertEqual((0,b'SERVICE_START_REQUESTED\n',b''),(r.returncode,r.stdout,r.stderr));return r
    def test_preflight_is_readonly_and_does_not_allocate_or_start(self):
        r=self.run_start('preflight');self.assertEqual((0,b'READY\n',b''),(r.returncode,r.stdout,r.stderr));self.assertFalse(self.start_dir().parent.exists());self.assertEqual('',self.start_log.read_text())
    def test_start_is_once_and_success_requires_separate_read(self):
        self.start_ok();self.assertEqual('start\n',self.start_log.read_text());r=self.run_start('read');self.assertEqual(0,r.returncode,r.stderr);p=dict(v.split('=') for v in r.stdout.decode().splitlines());self.assertEqual(8,len(p));self.assertEqual('ACTIVE',p['SERVICE']);self.assertEqual('1',p['INBOUNDS'])
    def test_database_before_copy_keys_archive_and_program_unchanged(self):
        paths=[self.db,self.key,self.cert,self.unit,self.runtime/'x-ui',self.wdb_dir()/'before.sqlite',self.wdb_dir()/'before.json',self.wdb_dir()/'restored.json',self.folder()/'installation.tar'];before={str(p):p.read_bytes() for p in paths};self.start_ok();self.assertEqual(0,self.run_start('read').returncode);self.assertEqual(before,{str(p):p.read_bytes() for p in paths})
    def test_same_parent_cannot_be_started_twice_even_from_new_child(self):
        self.start_ok();self.assertEqual(81,self.run_start('write').returncode);self.assertEqual(81,self.run_start('write',scope='f'*64).returncode);self.assertEqual('start\n',self.start_log.read_text())
    def test_already_running_service_does_not_start_again(self):
        self.state.write_text('active');r=self.run_start('write');self.assertEqual(81,r.returncode);self.assertEqual(b'NOT_STARTED\n',r.stdout);self.assertEqual('',self.start_log.read_text())
    def test_changed_database_before_start_rejects(self):
        self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();r=self.run_start('write');self.assertEqual(81,r.returncode);self.assertEqual(b'NOT_STARTED\n',r.stdout);self.assertEqual('',self.start_log.read_text())
    def test_changed_key_rejects_without_start(self):
        self.key.write_bytes(b'changed');self.assertEqual(81,self.run_start('write').returncode);self.assertEqual('',self.start_log.read_text())
    def test_missing_manifest_read_creates_nothing(self):
        self.assertEqual(81,self.run_start('read').returncode);self.assertFalse(self.start_dir().parent.exists());self.assertEqual('',self.start_log.read_text())
    def test_failed_start_cannot_claim_not_started_or_success(self):
        tail="base_start=subprocess.run\ndef failed(args,**kw):\n    if args==['/usr/bin/systemctl','start','--','x-ui.service']:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'')\n    return base_start(args,**kw)\nsubprocess.run=failed\n"
        r=self.run_start('write',tail);self.assertEqual((81,b''),(r.returncode,r.stdout));self.assertTrue((self.start_dir()/'intent.json').exists());self.assertEqual(81,self.run_start('read').returncode)
    def test_unknown_after_dispatch_can_only_observe_not_replay(self):
        tail="base_start=subprocess.run\ndef lost(args,**kw):\n    result=base_start(args,**kw)\n    if args==['/usr/bin/systemctl','start','--','x-ui.service']:raise Rejected()\n    return result\nsubprocess.run=lost\n"
        r=self.run_start('write',tail);self.assertEqual((81,b''),(r.returncode,r.stdout));self.assertEqual(0,self.run_start('read').returncode);self.assertEqual('start\n',self.start_log.read_text())
    def test_read_never_starts_a_stopped_service(self):
        self.start_ok();self.state.write_text('inactive');self.assertEqual(81,self.run_start('read').returncode);self.assertEqual('start\n',self.start_log.read_text())
    def test_wrong_running_executable_rejects(self):
        self.start_ok();self.assertEqual(81,self.run_start('read',"os.readlink=lambda path:'/wrong/program'\n").returncode)
    def test_pending_systemd_job_rejects(self):
        self.start_ok();tail="base_start=subprocess.run\ndef pending(args,**kw):\n    r=base_start(args,**kw)\n    if '--property=Job' in args:r.stdout=b'Job=123\\n'\n    return r\nsubprocess.run=pending\n";self.assertEqual(81,self.run_start('read',tail).returncode)
    def test_runtime_database_updates_are_not_claimed_byte_equal(self):
        self.start_ok();self.con.execute("UPDATE userData SET payload='service counters changed'");self.con.commit();self.assertEqual(0,self.run_start('read').returncode);self.assertNotEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(),self.proof['DATABASE_SHA256'])
    def test_schema_or_inbound_count_drift_rejects(self):
        self.start_ok();self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();self.assertEqual(81,self.run_start('read').returncode)
    def test_exact_child_manifest_scope_and_private_mode_required(self):
        self.start_ok();self.assertEqual(0o700,self.start_dir().stat().st_mode&0o777);self.assertEqual(0o600,(self.start_dir()/'intent.json').stat().st_mode&0o777);self.assertEqual(81,self.run_start('read',scope='f'*64).returncode)
    def test_parent_lock_prevents_concurrent_writer_and_readback(self):
        fd=os.open(self.wdb_dir().parent/'.lock',os.O_RDONLY)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(81,self.run_start('write').returncode);self.assertEqual('',self.start_log.read_text())
        finally:os.close(fd)
    def test_output_contains_no_keys_sql_rows_paths_or_claimed_login(self):
        self.start_ok();r=self.run_start('read');self.assertEqual(0,r.returncode)
        for value in [str(self.home).encode(),b'payload',b'CREATE',b'COOKIE',b'PASSWORD',b'AUTHENTICATED']:self.assertNotIn(value,r.stdout)
if __name__=='__main__':unittest.main(verbosity=2)

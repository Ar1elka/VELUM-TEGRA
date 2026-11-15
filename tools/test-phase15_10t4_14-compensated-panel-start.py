#!/usr/bin/env python3
"""Real synthetic SQLite/known-file proofs; systemd/process boundaries are scripted. No VPS."""
from pathlib import Path
import importlib.util,os,json,hashlib,fcntl,subprocess,unittest
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prior_return',PROJECT/'tools/test-phase15_10t4_13-before-copy-return.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
class CompensatedStart(unittest.TestCase):
    source=old.Return.source;expected=old.Return.expected;run_worker=old.Return.run_worker;folder=old.Return.folder;create_ok=old.Return.create_ok
    script=old.Return.script;run_restore=old.Return.run_restore;destination=old.Return.destination;copy_ok=old.Return.copy_ok
    wdb_dir=old.Return.wdb_dir;worker=old.Return.worker;run_wdb=old.Return.run_wdb;write_ok=old.Return.write_ok;count=old.Return.count
    return_dir=old.Return.return_dir;return_worker=old.Return.return_worker;run_return=old.Return.run_return;returned=old.Return.returned
    def setUp(self):
        old.Return.setUp(self);self.returned();self.cps_scope='f'*64;self.start_log=self.home/'fixture-compensated-start-log';self.start_log.write_text('')
    def tearDown(self):old.Return.tearDown(self)
    def cps_dir(self):return self.home/'.velum-tegra-compensated-panel-starts'/self.wdb_scope[:32]
    def cps_worker(self,tail=''):
        prefix=self.return_worker().split("\nif __name__=='__main__':",1)[0]
        p=PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/CompensatedPanelStartWorker.kt'
        extra=p.read_text().split('+"""\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        extra=extra.replace("'/root/.velum-tegra-compensated-panel-starts'",repr(str(self.cps_dir().parent)))
        boundary="""
START_LOG=__LOG__
base_cps_subprocess=subprocess.run
base_readlink=os.readlink
def cps_service_boundary(args,**kw):
    if args==['/usr/bin/systemctl','start','--','x-ui.service']:
        with open(STATE_FILE,'w') as out:out.write('active')
        with open(START_LOG,'a') as out:out.write('start\\n')
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    need(not any(v in ('stop','restart') for v in args))
    return base_cps_subprocess(args,**kw)
subprocess.run=cps_service_boundary
os.readlink=lambda path:RUNTIME+'/x-ui' if path=='/proc/123/exe' else base_readlink(path)
""".replace('__LOG__',repr(str(self.start_log)))
        return prefix+'\n'+extra.replace("\nif __name__=='__main__':",'\n'+boundary+'\n'+tail+"\nif __name__=='__main__':")
    def run_cps(self,mode,tail='',scope=None):
        p=self.proof;b=self.before
        args=[mode,scope or self.cps_scope,self.return_scope,b['previousSha256'],b['previousLogicalSha256'],str(b['previousBytes']),self.wdb_scope,hashlib.sha256(b'4:20537:/panel/9:127.0.0.1').hexdigest(),self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        return subprocess.run(['python3','-I','-c',self.cps_worker(tail),*args],capture_output=True,timeout=25)
    def start_ok(self):
        r=self.run_cps('write');self.assertEqual((0,b'COMPENSATED_START_REQUESTED\n',b''),(r.returncode,r.stdout,r.stderr));return r
    def test_actual_returned_database_then_start_and_independent_read(self):
        self.assertEqual(2,self.count());self.start_ok();r=self.run_cps('read');self.assertEqual((0,b''),(r.returncode,r.stderr));p=dict(x.split('=') for x in r.stdout.decode().splitlines());self.assertEqual(9,len(p));self.assertEqual('2',p['INBOUNDS']);self.assertEqual('ACTIVE',p['SERVICE'])
    def test_start_does_not_copy_database_keys_archive_or_return_artifacts(self):
        paths=[self.db,self.key,self.cert,self.unit,self.runtime/'x-ui',*self.return_dir().iterdir(),*self.wdb_dir().iterdir(),self.folder()/'installation.tar'];before={str(p):p.read_bytes() for p in paths};self.start_ok();self.assertEqual(0,self.run_cps('read').returncode);self.assertEqual(before,{str(p):p.read_bytes() for p in paths})
    def test_active_service_never_started_again(self):
        self.state.write_text('active');self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('',self.start_log.read_text());self.assertFalse(self.cps_dir().parent.exists())
    def test_same_parent_restart_attempt_with_new_digest_is_blocked(self):
        self.start_ok();self.state.write_text('inactive');self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual(81,self.run_cps('write',scope='a'*64).returncode);self.assertEqual('start\n',self.start_log.read_text())
    def test_lost_start_response_keeps_intent_and_supports_only_readback(self):
        tail="base=subprocess.run\ndef lost(args,**kw):\n    r=base(args,**kw)\n    if args==['/usr/bin/systemctl','start','--','x-ui.service']:raise Rejected()\n    return r\nsubprocess.run=lost\n"
        self.assertEqual(81,self.run_cps('write',tail).returncode);self.assertEqual(0,self.run_cps('read').returncode);self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('start\n',self.start_log.read_text())
    def test_failed_start_does_not_stop_retry_or_claim_success(self):
        tail="base=subprocess.run\ndef failed(args,**kw):\n    if args==['/usr/bin/systemctl','start','--','x-ui.service']:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'')\n    return base(args,**kw)\nsubprocess.run=failed\n"
        self.assertEqual(81,self.run_cps('write',tail).returncode);self.assertTrue((self.cps_dir()/'intent.json').exists());self.assertEqual(81,self.run_cps('read').returncode);self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('',self.start_log.read_text())
    def test_missing_return_completion_never_authorizes_start_or_repairs(self):
        p=self.return_dir()/'returned.json';p.unlink();self.assertEqual(81,self.run_cps('write').returncode);self.assertFalse(p.exists());self.assertFalse(self.cps_dir().parent.exists())
    def test_partial_start_intent_is_not_repaired_or_replayed(self):
        tail="base=returning_store\ndef fail(path,value):\n    if CPS_ROOT in path:raise Rejected()\n    return base(path,value)\nreturning_store=fail\n"
        self.assertEqual(81,self.run_cps('write',tail).returncode);self.assertTrue(self.cps_dir().exists());self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('',self.start_log.read_text())
    def test_missing_start_readback_creates_nothing(self):
        self.assertEqual(81,self.run_cps('read').returncode);self.assertFalse(self.cps_dir().parent.exists());self.assertEqual('',self.start_log.read_text())
    def test_readback_never_starts_stopped_service(self):
        self.start_ok();self.state.write_text('inactive');self.assertEqual(81,self.run_cps('read').returncode);self.assertEqual('start\n',self.start_log.read_text())
    def test_private_exclusive_intent_and_foreign_scope(self):
        self.start_ok();self.assertEqual(0o700,self.cps_dir().stat().st_mode&0o777);self.assertEqual(0o600,(self.cps_dir()/'intent.json').stat().st_mode&0o777);self.assertEqual(81,self.run_cps('read',scope='a'*64).returncode)
    def test_current_database_must_equal_exact_before_copy_at_activation(self):
        self.con.execute("UPDATE userData SET payload='different'");self.con.commit();self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('',self.start_log.read_text())
    def test_active_counters_do_not_claim_semantic_or_byte_equivalence(self):
        self.start_ok();self.con.execute("UPDATE userData SET payload='running counters changed'");self.con.commit();self.assertEqual(0,self.run_cps('read').returncode)
    def test_known_file_drift_blocks_without_restoring_files(self):
        self.key.write_bytes(b'drift');self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual(b'drift',self.key.read_bytes());self.assertEqual('',self.start_log.read_text())
    def test_schema_drift_rejects_active_readback(self):
        self.start_ok();self.con.execute('ALTER TABLE userData ADD COLUMN other TEXT');self.con.commit();self.assertEqual(81,self.run_cps('read').returncode)
    def test_current_inbound_count_compares_before_copy_not_archive(self):
        self.start_ok();self.con.execute('DELETE FROM inbounds WHERE rowid=(SELECT min(rowid) FROM inbounds)');self.con.commit();self.assertEqual(1,self.count());self.assertEqual(81,self.run_cps('read').returncode)
    def test_endpoint_drift_blocks(self):
        self.con.execute("UPDATE settings SET value='9999' WHERE key='webPort'");self.con.commit();self.assertEqual(81,self.run_cps('write').returncode)
    def test_corrupt_displaced_copy_blocks(self):
        (self.return_dir()/'displaced.sqlite').write_bytes(b'bad');self.assertEqual(81,self.run_cps('write').returncode)
    def test_duplicate_json_key_blocks(self):
        p=self.return_dir()/'returned.json';p.write_text(p.read_text().replace('{','{"scope":"'+self.return_scope+'",',1));self.assertEqual(81,self.run_cps('write').returncode)
    def test_symlink_source_blocks(self):
        p=self.return_dir()/'returned.json';other=self.home/'other.json';p.rename(other);p.symlink_to(other);self.assertEqual(81,self.run_cps('write').returncode)
    def test_nonprivate_return_source_blocks(self):
        (self.return_dir()/'returned.json').chmod(0o644);self.assertEqual(81,self.run_cps('write').returncode)
    def test_parent_writer_lock_blocks(self):
        with open(self.wdb_dir().parent/'.lock','rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('',self.start_log.read_text())
    def test_return_writer_lock_blocks(self):
        with open(self.return_dir().parent/'.lock','rb') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('',self.start_log.read_text())
    def test_quota_full_before_start(self):
        root=self.cps_dir().parent;root.mkdir(mode=0o700)
        for i in range(4):(root/str(i).zfill(32)).mkdir(mode=0o700)
        self.assertEqual(81,self.run_cps('write').returncode);self.assertEqual('',self.start_log.read_text())
    def test_pending_job_blocks_before_start(self):
        tail="base=subprocess.run\ndef job(args,**kw):\n    r=base(args,**kw)\n    if '--property=Job' in args:r.stdout=b'Job=9\\n'\n    return r\nsubprocess.run=job\n"
        self.assertEqual(81,self.run_cps('write',tail).returncode);self.assertEqual('',self.start_log.read_text())
    def test_unexpected_executable_cannot_publish_active_proof(self):
        self.start_ok();self.assertEqual(81,self.run_cps('read',"os.readlink=lambda path:'/wrong/program'\n").returncode)
    def test_service_drift_after_intent_never_retries_or_stops(self):
        tail="source=compensated_source\ncalls=0\ndef drift(stopped):\n    global calls\n    calls+=1\n    if calls==2:\n        with open(STATE_FILE,'w') as f:f.write('active')\n    return source(stopped)\ncompensated_source=drift\n"
        self.assertEqual(81,self.run_cps('write',tail).returncode);self.assertEqual('',self.start_log.read_text());self.assertTrue((self.cps_dir()/'intent.json').exists())
    def test_output_is_finite_and_redacted(self):
        self.start_ok();r=self.run_cps('read');self.assertEqual(0,r.returncode)
        for v in (str(self.home).encode(),b'SELECT',b'payload',b'fixture-private-key',b'AUTHENTICATED',b'ROLLBACK'):self.assertNotIn(v,r.stdout)
if __name__=='__main__':unittest.main(verbosity=2)

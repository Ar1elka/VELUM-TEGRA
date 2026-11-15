#!/usr/bin/env python3
"""Synthetic local file/SQLite readiness; scripted systemd/version only, no SSH/VPS."""
from pathlib import Path
import importlib.util,subprocess,sqlite3,json,os,unittest,fcntl
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('accepted_comparison_fixture',PROJECT/'tools/test-phase15_10t4_8-restore-comparison.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
class Readiness(unittest.TestCase):
    source=old.Comparison.source;expected=old.Comparison.expected;run_worker=old.Comparison.run_worker
    folder=old.Comparison.folder;create_ok=old.Comparison.create_ok;script=old.Comparison.script
    run_restore=old.Comparison.run_restore;destination=old.Comparison.destination;copy_ok=old.Comparison.copy_ok
    def setUp(self):
        old.old.old.InstallationArtifact.setUp(self)
        self.con.executemany('INSERT INTO settings VALUES (?,?)',[('webPort','2053'),('webBasePath','/panel/'),('webListen','127.0.0.1')]);self.con.commit()
        self.create_ok();r=self.run_worker('verify');self.assertEqual(0,r.returncode)
        self.proof=dict(p.split('=') for p in r.stdout.decode().splitlines());self.run_scope='b'*64;self.copy_ok()
    def tearDown(self):old.Comparison.tearDown(self)
    def readiness(self,tail='',version='3.10.0',state='active',job='0',delegate='no'):
        def extra(name):
            t=(PROJECT/('core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/'+name+'Worker.kt')).read_text()
            return t.split('+ """\n',1)[-1].split('+"""\n',1)[-1].rsplit('\n""".trimIndent()',1)[0].split("\nif __name__ == '__main__':",1)[0].replace("'/sys/fs/cgroup/system.slice/x-ui.service'",repr(str(self.base/'sys/fs/cgroup/system.slice/x-ui.service')))
        # Accepted fixtures rewrite the fixed source roots into one private temp directory.
        prefix=self.script().split("\nif __name__ == '__main__':",1)[0]
        service={'LoadState':'loaded','ActiveState':state,'SubState':'running' if state=='active' else 'dead','MainPID':'123' if state=='active' else '0','ControlPID':'0','TriggeredBy':'','KillMode':'control-group','ControlGroup':'','Job':job,'Delegate':delegate}
        boundary="\nfrom types import SimpleNamespace\ndef only_reads(args,**kwargs):\n    if args==[RUNTIME+'/x-ui','-v']:return SimpleNamespace(returncode=0,stdout="+repr((version+'\n').encode())+",stderr=b'')\n    need(args[0]=='/usr/bin/systemctl' and args[1]=='show')\n    return SimpleNamespace(returncode=0,stdout="+repr(''.join(k+'='+v+'\n' for k,v in service.items()).encode())+",stderr=b'')\nsubprocess.run=only_reads\n"+tail+'\n'
        p=self.proof
        args=['c'*64,'4',self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        text=prefix+'\n'+extra('RestoreCompatibility')+'\n'+extra('RecoveryReadiness')+boundary+"\ntry:readiness_main()\nexcept BaseException:sys.exit(81)\n"
        return subprocess.run(['python3','-I','-c',text,*args],capture_output=True,timeout=20)
    def values(self,**kwargs):
        r=self.readiness(**kwargs);self.assertEqual((0,b''),(r.returncode,r.stderr),r.stdout);v=dict(p.split('=') for p in r.stdout.decode().splitlines());self.assertEqual(25,len(v));return v
    def reject(self,**kwargs):
        r=self.readiness(**kwargs);self.assertEqual((81,b'',b''),(r.returncode,r.stdout,r.stderr))
    def test_group_coverage_and_totals_are_exact(self):
        p=self.values();self.assertEqual('VELUM_RECOVERY_READINESS_V1',p['FORMAT']);n=int(self.proof['FILES']);self.assertEqual(f'{n},{n},0,0,0',p['TOTAL']);self.assertEqual('UNVERIFIED',p['MIGRATION']);self.assertTrue(int(p['RUNTIME'].split(',')[0])>=2);self.assertEqual('2,2,0,0,0',p['PANEL_TLS'])
    def test_live_service_requires_separate_quiescence(self):self.assertEqual('REQUIRED',self.values()['QUIESCENCE'])
    def test_stopped_service_is_observed_without_start(self):self.assertEqual('STOPPED',self.values(state='inactive')['QUIESCENCE'])
    def test_queued_job_cannot_claim_stopped(self):self.assertEqual('UNAVAILABLE',self.values(state='inactive',job='21')['QUIESCENCE'])
    def test_running_wal_not_mistaken_for_raw_copy(self):self.assertEqual('WAL',self.values()['JOURNAL']);self.assertEqual('PRESENT',self.values()['WAL'])
    def test_changed_key_is_counted_in_its_group_only(self):
        self.key.write_bytes(b'new private material');p=self.values();self.assertEqual('1',p['TOTAL'].split(',')[2]);self.assertEqual('1',p['PANEL_TLS'].split(',')[2]);self.assertEqual('0',p['SERVICE'].split(',')[2]);self.assertNotIn('new private',str(p))
    def test_new_runtime_file_is_an_addition(self):
        (self.runtime/'extra').write_bytes(b'extra');p=self.values();self.assertEqual('1',p['TOTAL'].split(',')[3]);self.assertEqual('1',p['RUNTIME'].split(',')[3])
    def test_missing_required_runtime_is_rejected(self):
        (self.runtime/'bin/xray-linux-amd64').unlink();self.reject()
    def test_external_dat_is_counted_in_overlapping_groups(self):
        p=self.runtime/'bin/custom.dat';p.write_bytes(b'fixture data');self.con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'",('{"domain":["ext:custom.dat:group"]}',));self.con.commit();v=self.values();self.assertEqual('0,1,0,1,0',v['XRAY_DATA']);self.assertEqual('1',v['RUNTIME'].split(',')[3]);self.assertEqual('1',v['TOTAL'].split(',')[3])
    def test_delegated_service_is_not_quiescent(self):self.assertEqual('UNAVAILABLE',self.values(state='inactive',delegate='yes')['QUIESCENCE'])
    def test_nonempty_cgroup_is_not_quiescent(self):
        p=self.base/'sys/fs/cgroup/system.slice/x-ui.service';p.mkdir(parents=True);(p/'cgroup.procs').write_bytes(b'123\n');self.assertEqual('UNAVAILABLE',self.values(state='inactive')['QUIESCENCE'])
    def test_nested_cgroup_cannot_hide_child_processes(self):
        p=self.base/'sys/fs/cgroup/system.slice/x-ui.service';p.mkdir(parents=True);(p/'cgroup.procs').write_bytes(b'');(p/'child').mkdir();self.reject(state='inactive')
    def test_external_reference_replacement_has_added_and_missing(self):
        p=self.key.with_name('replacement.key');p.write_bytes(b'new');p.chmod(0o600);self.con.execute('UPDATE settings SET value=? WHERE key=?',(str(p),'webKeyFile'));self.con.commit();v=self.values();self.assertEqual(['1','1'],v['PANEL_TLS'].split(',')[3:]);self.assertEqual(['1','1'],v['TOTAL'].split(',')[3:])
    def test_unknown_external_dependency_cannot_publish_complete_plan(self):
        self.con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'",('{"path":"unix:/tmp/socket"}',));self.con.commit();self.reject()
    def test_unsafe_key_fails_without_permission_repair(self):self.key.chmod(0o644);self.reject();self.assertEqual(0o644,self.key.stat().st_mode&0o777)
    def test_schema_difference_is_observed_without_migration(self):
        self.con.execute('ALTER TABLE inbounds ADD COLUMN label TEXT');self.con.commit();p=self.values();self.assertNotEqual(p['SOURCE_SCHEMA'],p['CURRENT_SCHEMA']);self.assertEqual('UNVERIFIED',p['MIGRATION'])
    def test_numeric_version_difference_is_not_migration_proof(self):self.assertEqual('3.10.2',self.values(version='3.10.2')['CURRENT_VERSION'])
    def test_endpoint_difference_is_explicit(self):
        self.con.execute("UPDATE settings SET value='2083' WHERE key='webPort'");self.con.commit();self.assertEqual('DIFFERENT',self.values()['ENDPOINT'])
    def test_same_schema_different_data_stays_only_structural(self):
        self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();p=self.values();self.assertEqual(p['SOURCE_SCHEMA'],p['CURRENT_SCHEMA']);self.assertEqual('UNVERIFIED',p['MIGRATION'])
    def test_archive_corruption_rejects_without_receipt(self):
        p=self.folder()/'installation.tar';p.write_bytes(b'x'+p.read_bytes()[1:]);self.reject()
    def test_isolated_key_corruption_rejects(self):
        p=self.destination()/('files'+str(self.key));p.write_bytes(b'changed');self.reject()
    def test_missing_completion_never_creates_artifacts(self):
        (self.destination()/'restore-check.v1').unlink();before=set(self.destination().rglob('*'));self.reject();self.assertEqual(before,set(self.destination().rglob('*')))
    def test_missing_lock_does_not_create_it(self):
        p=self.home/'.velum-tegra-installation-backups/.writer.lock';p.unlink();self.reject();self.assertFalse(p.exists())
    def test_archive_writer_lock_is_respected(self):
        p=self.home/'.velum-tegra-installation-backups/.writer.lock';fd=os.open(p,os.O_RDONLY)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.reject()
        finally:os.close(fd)
    def test_restoration_writer_lock_is_respected(self):
        fd=os.open(self.destination().parent/'.lock',os.O_RDONLY)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.reject()
        finally:os.close(fd)
    def test_target_database_symlink_rejected(self):
        self.con.close();self.db.unlink();self.db.symlink_to(self.destination()/'database.sqlite');self.con=sqlite3.connect(':memory:');self.reject()
    def test_version_drift_rejected(self):
        self.reject(tail="old_version=compatibility_version\ncalls=0\ndef compatibility_version():\n    global calls\n    calls+=1\n    value=old_version()\n    return ('3.10.2',*value[1:]) if calls>1 else value\n")
    def test_no_mutation_entrypoint_is_reachable(self):
        self.values(tail="def forbidden(*a,**kw):raise AssertionError('write not allowed')\nrestore_copy=create=os.mkdir=os.rename=os.unlink=forbidden\n")
    def test_bytes_and_modes_of_live_and_private_sources_are_preserved(self):
        paths=[self.db,Path(str(self.db)+'-wal'),self.key,self.cert,self.runtime/'x-ui',self.unit,self.folder()/'installation.tar',self.folder()/'database.sqlite',self.destination()/'database.sqlite'];before={str(p):(p.read_bytes(),p.stat().st_mode) for p in paths};self.values();self.assertEqual(before,{str(p):(p.read_bytes(),p.stat().st_mode) for p in paths})
    def test_output_has_no_paths_keys_sql_or_settings(self):
        p=self.values();self.assertNotIn(str(self.base),str(p));self.assertNotIn('CREATE TABLE',str(p));self.assertNotIn('fixture key',str(p));self.assertNotIn('/panel',str(p))
if __name__=='__main__':unittest.main(verbosity=2)

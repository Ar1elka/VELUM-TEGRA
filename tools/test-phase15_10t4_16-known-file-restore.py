#!/usr/bin/env python3
"""Actual synthetic file replacement/private snapshots/SQLite; scripted systemd/version, no SSH/VPS."""
from pathlib import Path
import importlib.util,subprocess,sqlite3,json,os,unittest,fcntl,re,hashlib
PROJECT=Path(__file__).resolve().parents[1]
sp=importlib.util.spec_from_file_location('accepted_readiness_fixture',PROJECT/'tools/test-phase15_10t4_15-recovery-readiness.py')
old=importlib.util.module_from_spec(sp);sp.loader.exec_module(old)
class FileRestore(unittest.TestCase):
    source=old.Readiness.source;expected=old.Readiness.expected;run_worker=old.Readiness.run_worker;folder=old.Readiness.folder
    create_ok=old.Readiness.create_ok;script=old.Readiness.script;run_restore=old.Readiness.run_restore;destination=old.Readiness.destination;copy_ok=old.Readiness.copy_ok
    readiness=old.Readiness.readiness
    def setUp(self):
        old.Readiness.setUp(self);self.key.write_bytes(b'current private key');self.changed=1;self.file_scope='d'*64;self.bind()
    def tearDown(self):old.Readiness.tearDown(self)
    def bind(self):self.current_set=old.Readiness.values(self)['CURRENT_SET']
    def directory(self):return self.home/'.velum-tegra-known-file-restores'/self.file_scope[:32]
    def run_files(self,mode,manifest=None,tail='',state='inactive',version='3.10.0'):
        def extra(name):
            text=(PROJECT/('core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/'+name+'Worker.kt')).read_text()
            value=re.split(r'\+\s*"""\n',text,maxsplit=1)[1].rsplit('\n""".trimIndent()',1)[0]
            value=re.split(r"\nif __name__\s*==\s*'__main__':",value,maxsplit=1)[0]
            return value.replace('/root/.velum-',str(self.home)+'/.velum-').replace('/sys/fs/cgroup/system.slice/x-ui.service',str(self.base/'sys/fs/cgroup/system.slice/x-ui.service'))
        prefix=self.script().split("\nif __name__ == '__main__':",1)[0]
        service={'LoadState':'loaded','ActiveState':state,'SubState':'running' if state=='active' else 'dead','MainPID':'123' if state=='active' else '0','ControlPID':'0','TriggeredBy':'','KillMode':'control-group','ControlGroup':'','Job':'0','Delegate':'no'}
        boundary="\nfrom types import SimpleNamespace\ndef only_reads(args,**kwargs):\n    if args==[RUNTIME+'/x-ui','-v']:return SimpleNamespace(returncode=0,stdout="+repr((version+'\n').encode())+",stderr=b'')\n    need(args[0]=='/usr/bin/systemctl' and args[1]=='show')\n    return SimpleNamespace(returncode=0,stdout="+repr(''.join(k+'='+v+'\n' for k,v in service.items()).encode())+",stderr=b'')\nsubprocess.run=only_reads\n"+tail+'\n'
        p=self.proof;args=[mode,self.file_scope,self.current_set,str(self.changed),self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES'],manifest or '0'*64]
        text=prefix+'\n'+extra('RestoreCompatibility')+'\n'+extra('WorkingDatabaseRestore')+'\n'+extra('RecoveryReadiness')+'\n'+extra('KnownFileRestore')+boundary+"\ntry:file_main()\nexcept BaseException:sys.exit(81)\n"
        return subprocess.run(['python3','-I','-c',text,*args],capture_output=True,timeout=30)
    def apply_ok(self):
        r=self.run_files('apply');self.assertEqual((0,b'FILES_WRITTEN\n',b''),(r.returncode,r.stdout,r.stderr));return self.read_ok()
    def read_ok(self):
        r=self.run_files('read');self.assertEqual((0,b''),(r.returncode,r.stderr),r.stdout);p=dict(v.split('=') for v in r.stdout.decode().splitlines());self.assertEqual(7,len(p));return p
    def reject(self,mode='apply',**kwargs):
        r=self.run_files(mode,**kwargs);self.assertEqual((81,b'',b''),(r.returncode,r.stdout,r.stderr))
    def two_changes(self):self.cert.write_bytes(b'current certificate');self.changed=2;self.bind()
    def partial(self):
        self.two_changes();self.reject(tail="original_replace=file_replace\nreplacement_calls=0\ndef file_replace(e,r):\n    global replacement_calls\n    if replacement_calls==1:raise Rejected()\n    original_replace(e,r);replacement_calls+=1\n")
        p=self.read_ok();self.assertEqual(('1','1'),(p['DESIRED'],p['PREVIOUS']));return p
    def test_plan_is_read_only_and_mints_no_artifact(self):
        r=self.run_files('plan');self.assertEqual(0,r.returncode,r.stderr);self.assertIn(b'VELUM_KNOWN_FILE_PREPARED_V1',r.stdout);self.assertFalse(self.directory().parent.exists())
    def test_apply_preserves_private_before_image_and_reads_expected_source(self):
        prior=self.key.read_bytes();p=self.apply_ok();self.assertEqual('1',p['DESIRED']);self.assertEqual(b'fixture key bytes\n',self.key.read_bytes());self.assertEqual(prior,(self.directory()/'before/0').read_bytes());self.assertEqual(0o600,(self.directory()/'before/0').stat().st_mode&0o777)
    def test_independent_read_never_replays_apply(self):
        self.apply_ok();before=self.key.stat().st_ino;self.read_ok();self.assertEqual(before,self.key.stat().st_ino)
    def test_apply_cannot_repeat_same_operation(self):self.apply_ok();self.reject()
    def test_partial_apply_has_positive_mixed_readback(self):self.partial()
    def test_explicit_compensation_restores_prior_bytes_then_reads(self):
        prior=self.key.read_bytes();p=self.apply_ok();r=self.run_files('return',p['MANIFEST']);self.assertEqual((0,b'FILES_RETURNED\n',b''),(r.returncode,r.stdout,r.stderr));self.assertEqual(prior,self.key.read_bytes());self.assertEqual('1',self.read_ok()['PREVIOUS'])
    def test_partial_apply_can_explicitly_return_both_files(self):
        p=self.partial();r=self.run_files('return',p['MANIFEST']);self.assertEqual(0,r.returncode,r.stderr);self.assertEqual('2',self.read_ok()['PREVIOUS']);self.assertEqual(b'current private key',self.key.read_bytes());self.assertEqual(b'current certificate',self.cert.read_bytes())
    def test_compensation_cannot_replay(self):
        p=self.apply_ok();self.assertEqual(0,self.run_files('return',p['MANIFEST']).returncode);self.reject('return',manifest=p['MANIFEST'])
    def test_partial_return_can_be_read_but_not_automatically_repeated(self):
        self.two_changes();p=self.apply_ok();self.reject('return',manifest=p['MANIFEST'],tail="original_replace=file_replace\nreplacement_calls=0\ndef file_replace(e,r):\n    global replacement_calls\n    if replacement_calls==1:raise Rejected()\n    original_replace(e,r);replacement_calls+=1\n");self.read_ok();self.reject('return',manifest=p['MANIFEST'])
    def test_live_service_blocks_before_destination_mutation(self):
        prior=self.key.read_bytes();self.reject(state='active');self.assertEqual(prior,self.key.read_bytes())
    def test_different_release_cannot_restore(self):self.reject(version='3.10.2')
    def test_changed_database_data_blocks(self):
        self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}'));self.con.commit();self.bind();self.reject()
    def test_changed_executable_cannot_be_replaced(self):
        (self.runtime/'x-ui').write_bytes(b'changed executable');self.bind();self.reject()
    def test_changed_service_unit_cannot_be_replaced(self):
        self.unit.write_text('changed service');self.bind();self.reject()
    def test_changed_file_set_blocks(self):
        (self.runtime/'extra').write_bytes(b'extra');self.bind();self.reject()
    def test_new_reference_blocks(self):
        p=self.key.with_name('new.key');p.write_bytes(b'new');p.chmod(0o600);self.con.execute("UPDATE settings SET value=? WHERE key='webKeyFile'",(str(p),));self.con.commit();self.bind();self.reject()
    def test_stale_current_set_blocks(self):self.key.write_bytes(b'late change');self.reject()
    def test_symlink_target_blocks(self):
        self.key.unlink();self.key.symlink_to(self.cert);self.reject()
    def test_hardlinked_target_blocks(self):os.link(self.key,self.key.with_name('shared'));self.reject()
    def test_xattrs_on_changed_file_are_not_silently_lost(self):
        os.setxattr(self.key,'user.fixture',b'keep');self.reject();self.assertEqual(b'keep',os.getxattr(self.key,'user.fixture'))
    def test_corrupt_before_image_blocks_read_and_compensation(self):
        p=self.apply_ok();(self.directory()/'before/0').write_bytes(b'corrupt');self.reject('read');self.reject('return',manifest=p['MANIFEST'])
    def test_corrupt_stage_blocks_read(self):self.apply_ok();(self.directory()/'after/0').write_bytes(b'corrupt');self.reject('read')
    def test_other_bytes_after_apply_are_not_overwritten_by_compensation(self):
        p=self.apply_ok();self.key.write_bytes(b'third party update');self.reject('return',manifest=p['MANIFEST']);self.assertEqual(b'third party update',self.key.read_bytes())
    def test_missing_manifest_is_not_reconstructed(self):
        self.apply_ok();(self.directory()/'manifest.json').unlink();self.reject('read');self.assertFalse((self.directory()/'manifest.json').exists())
    def test_staging_failure_leaves_no_destination_change(self):
        prior=self.key.read_bytes();self.reject(tail="def file_private_copy(*a,**k):raise Rejected()\n");self.assertEqual(prior,self.key.read_bytes());self.reject('read')
    def test_original_writer_lock_is_respected(self):
        fd=os.open(self.home/'.velum-tegra-installation-backups/.writer.lock',os.O_RDONLY)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.reject()
        finally:os.close(fd)
    def test_existing_db_writer_lock_is_respected(self):
        p=self.home/'.velum-tegra-working-db-restores';p.mkdir(mode=0o700);fd=os.open(p/'.lock',os.O_CREAT|os.O_RDWR,0o600)
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.reject()
        finally:os.close(fd)
    def test_four_partial_slots_block_new_writer(self):
        p=self.directory().parent;p.mkdir(mode=0o700);fd=os.open(p/'.lock',os.O_CREAT|os.O_RDWR,0o600);os.close(fd)
        for n in range(4):(p/str(n).zfill(32)).mkdir(mode=0o700)
        self.reject();self.assertFalse(self.directory().exists())
    def test_database_wal_archive_executable_service_bytes_stay_unchanged(self):
        paths=[self.db,Path(str(self.db)+'-wal'),self.runtime/'x-ui',self.runtime/'bin/xray-linux-amd64',self.unit,self.folder()/'installation.tar',self.destination()/'database.sqlite'];prior={str(p):p.read_bytes() for p in paths};self.apply_ok();self.assertEqual(prior,{str(p):p.read_bytes() for p in paths})
    def test_nonroot_group_observation_is_not_silently_replaced(self):
        # This host maps only gid0; script the unsupported metadata observation, not chown.
        prior=self.key.read_bytes()
        tail="original_checked=checked\ndef checked(path,*a,**k):\n    fd,s=original_checked(path,*a,**k)\n    if path=="+repr(str(self.key))+":\n        values={n:getattr(s,n) for n in dir(s) if n.startswith('st_')};values['st_gid']=1;s=SimpleNamespace(**values)\n    return fd,s\n"
        self.reject(tail=tail);self.assertEqual(prior,self.key.read_bytes());self.assertEqual(0,self.key.stat().st_gid)
    def test_output_never_contains_paths_keys_sql_or_private_values(self):
        p=self.apply_ok();self.assertNotIn(str(self.base),str(p));self.assertNotIn('fixture key',str(p));self.assertNotIn('CREATE TABLE',str(p))
if __name__=='__main__':unittest.main(verbosity=2)

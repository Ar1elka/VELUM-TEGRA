#!/usr/bin/env python3
"""Synthetic local archive + real SQLite/WAL and private isolated file restoration. No SSH/VPS."""
import fcntl, hashlib, importlib.util, json, os, re, sqlite3, subprocess, unittest
from pathlib import Path
PROJECT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('accepted_installation_fixture',PROJECT/'tools/test-phase15_10t4_6-installation-artifact.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)

class RestoreCheck(unittest.TestCase):
    source=old.InstallationArtifact.source
    expected=old.InstallationArtifact.expected
    run_worker=old.InstallationArtifact.run_worker
    folder=old.InstallationArtifact.folder
    create_ok=old.InstallationArtifact.create_ok
    def setUp(self):
        old.InstallationArtifact.setUp(self)
        self.create_ok();r=self.run_worker('verify');self.assertEqual(0,r.returncode)
        self.proof=dict(p.split('=') for p in r.stdout.decode().splitlines());self.run_scope='b'*64
    def tearDown(self):old.InstallationArtifact.tearDown(self)
    def script(self,tail=''):
        prefix=self.source().split("\nif __name__ == '__main__':",1)[0]
        text=(PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/RestoreCheckWorker.kt').read_text()
        extra=text.split(' + """\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        extra=extra.replace("'/root/.velum-tegra-restore-checks'",repr(str(self.home/'.velum-tegra-restore-checks')))
        extra=extra.replace("\nif __name__ == '__main__':",'\n'+tail+"\nif __name__ == '__main__':")
        return prefix+'\n'+extra
    def run_restore(self,mode,scope=None,proof=None,tail=''):
        p=proof or self.proof
        args=[mode,scope or self.run_scope,self.scope,'3.10.0','AMD64',p['SHA256'],p['DATABASE_SHA256'],p['INVENTORY_SHA256'],p['BYTES'],p['FILES']]
        return subprocess.run(['python3','-I','-c',self.script(tail),*args],capture_output=True,timeout=15)
    def destination(self,scope=None):return self.home/'.velum-tegra-restore-checks'/(scope or self.run_scope)[:32]
    def restored(self,path):return self.destination()/('files'+str(path))
    def copy_ok(self):
        r=self.run_restore('copy');self.assertEqual((0,b'RESTORED\n',b''),(r.returncode,r.stdout,r.stderr));return self.destination()
    def snapshot(self,base):
        return {str(p.relative_to(base)):(p.read_bytes(),p.stat().st_mode&0o777,p.stat().st_mtime_ns) for p in base.rglob('*') if p.is_file()}
    def test_restore_streamed_files_and_real_sqlite_snapshot_to_private_directory(self):
        d=self.copy_ok();r=self.run_restore('check');self.assertEqual(0,r.returncode,r.stderr)
        proof=dict(p.split('=') for p in r.stdout.decode().splitlines())
        self.assertEqual('VELUM_RESTORE_FILES_V1',proof['FORMAT']);self.assertEqual(self.run_scope,proof['SCOPE'])
        self.assertEqual(self.scope,proof['SOURCE_SCOPE']);self.assertEqual(self.proof['SHA256'],proof['SHA256'])
        self.assertEqual(self.key.read_bytes(),self.restored(self.key).read_bytes());self.assertEqual(0o600,self.restored(self.key).stat().st_mode&0o777)
        self.assertEqual(0o700,d.stat().st_mode&0o777)
        con=sqlite3.connect('file:'+str(d/'database.sqlite')+'?mode=ro',uri=True)
        self.assertEqual('{}',con.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0]);con.close()
        self.assertNotIn(str(self.key).encode(),r.stdout);self.assertNotIn(b'fixture key',r.stdout)
    def test_live_files_and_original_archive_are_unchanged(self):
        old=self.snapshot(self.folder());key=self.key.read_bytes();binary=(self.runtime/'x-ui').read_bytes();db=self.db.read_bytes()
        self.copy_ok();self.assertEqual(0,self.run_restore('check').returncode)
        self.assertEqual(old,self.snapshot(self.folder()));self.assertEqual(key,self.key.read_bytes());self.assertEqual(binary,(self.runtime/'x-ui').read_bytes());self.assertEqual(db,self.db.read_bytes())
    def test_readback_never_changes_restored_files(self):
        d=self.copy_ok();before=self.snapshot(d);self.assertEqual(0,self.run_restore('check').returncode);self.assertEqual(before,self.snapshot(d))
    def test_readback_missing_folder_does_not_create_anything(self):
        self.assertNotEqual(0,self.run_restore('check').returncode);self.assertFalse(self.destination().parent.exists())
    def test_wrong_scope_has_no_readback_and_no_new_directory(self):
        self.copy_ok();r=self.run_restore('check',scope='c'*64);self.assertNotEqual(0,r.returncode);self.assertEqual(b'',r.stdout);self.assertFalse(self.destination('c'*64).exists())
    def test_same_operation_never_overwrites_previous_restoration(self):
        d=self.copy_ok();before=self.snapshot(d);self.assertNotEqual(0,self.run_restore('copy').returncode);self.assertEqual(before,self.snapshot(d))
    def test_corrupt_restored_file_has_no_success_proof(self):
        self.copy_ok();self.restored(self.key).write_bytes(b'corrupted');r=self.run_restore('check');self.assertNotEqual(0,r.returncode);self.assertEqual(b'',r.stdout)
    def test_corrupt_restored_database_is_rejected(self):
        d=self.copy_ok();(d/'database.sqlite').write_bytes(b'invalid sqlite');self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_archive_changed_after_native_review_blocks_before_creation(self):
        p=self.folder()/'installation.tar';data=p.read_bytes();p.write_bytes(b'x'+data[1:]);self.assertNotEqual(0,self.run_restore('copy').returncode);self.assertFalse(self.destination().parent.exists())
    def test_exact_review_hash_mismatch_blocks_before_creation(self):
        p=dict(self.proof,SHA256='0'*64);self.assertNotEqual(0,self.run_restore('copy',proof=p).returncode);self.assertFalse(self.destination().parent.exists())
    def test_retained_source_database_mismatch_blocks_before_creation(self):
        (self.folder()/'database.sqlite').write_bytes(b'changed');self.assertNotEqual(0,self.run_restore('copy').returncode);self.assertFalse(self.destination().parent.exists())
    def test_nonprivate_root_is_not_repaired(self):
        root=self.destination().parent;root.mkdir(mode=0o755);self.assertNotEqual(0,self.run_restore('copy').returncode);self.assertEqual(0o755,root.stat().st_mode&0o777)
    def test_root_symlink_cannot_redirect_writes(self):
        root=self.destination().parent;root.symlink_to(self.cert.parent);self.assertNotEqual(0,self.run_restore('copy').returncode);self.assertFalse((self.cert.parent/self.run_scope[:32]).exists())
    def test_destination_symlink_is_rejected(self):
        root=self.destination().parent;root.mkdir(mode=0o700);self.destination().symlink_to(self.cert.parent);self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_restored_key_hardlink_is_rejected(self):
        self.copy_ok();os.link(self.restored(self.key),self.destination()/'shared-key');self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_special_file_is_rejected_without_waiting_for_pipe(self):
        d=self.copy_ok();os.mkfifo(d/'pipe');self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_unexpected_files_reject_readback(self):
        d=self.copy_ok();(d/'unexpected').write_bytes(b'not in archive');self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_wrong_destination_manifest_is_rejected(self):
        d=self.copy_ok();p=d/'restore-check.v1';p.write_bytes(p.read_bytes().replace(self.run_scope.encode(),b'c'*64));self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_four_partial_slots_block_fifth_creation(self):
        root=self.destination().parent;root.mkdir(mode=0o700)
        for n in range(4):(root/str(n).zfill(32)).mkdir(mode=0o700)
        self.assertEqual(b'4',self.run_restore('space').stdout.splitlines()[0]);self.assertNotEqual(0,self.run_restore('copy').returncode);self.assertFalse(self.destination().exists())
    def test_concurrent_writer_lock_is_respected(self):
        root=self.destination().parent;root.mkdir(mode=0o700);fd=os.open(root/'.lock',os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);self.assertNotEqual(0,self.run_restore('copy').returncode);self.assertFalse(self.destination().exists())
        finally:os.close(fd)
    def test_partial_write_has_no_verified_result_and_is_not_replayed_by_check(self):
        tail="original_restore_leaf=restore_leaf\ndef restore_leaf(relative,directories):\n    if relative=='database.sqlite': raise Rejected()\n    return original_restore_leaf(relative,directories)\n"
        r=self.run_restore('copy',tail=tail);self.assertEqual(81,r.returncode);self.assertTrue(self.destination().exists());self.assertFalse((self.destination()/'restore-check.v1').exists());self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_symlink_restored_database_cannot_escape_verification(self):
        d=self.copy_ok();(d/'database.sqlite').unlink();(d/'database.sqlite').symlink_to(self.folder()/'database.sqlite');self.assertNotEqual(0,self.run_restore('check').returncode)
    def test_rehearsal_never_invokes_service_or_binary_commands(self):
        tail="def forbidden(*args,**kwargs): raise AssertionError('no service execution')\nsubprocess.run=forbidden\nservice=forbidden\nversion_check=forbidden\n"
        self.assertEqual(0,self.run_restore('copy',tail=tail).returncode);self.assertEqual(0,self.run_restore('check',tail=tail).returncode)

if __name__=='__main__':unittest.main(verbosity=2)

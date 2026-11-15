#!/usr/bin/env python3
"""Isolated generated local files + real Python SQLite backup API. No server/SSH, no restore/extraction."""
import hashlib, io, json, os, re, sqlite3, subprocess, tarfile, tempfile, time, unittest
from types import SimpleNamespace
from pathlib import Path
PROJECT=Path(__file__).resolve().parents[1]
SOURCE=PROJECT/'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh/InstallationBackupWorker.kt'

class InstallationArtifact(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='velum-ibb-local-',dir='/root')
        self.base=Path(self.tmp.name); self.home=self.base/'root'; self.home.mkdir(mode=0o700)
        self.runtime=self.base/'usr/local/x-ui'; (self.runtime/'bin').mkdir(parents=True)
        self.unit=self.base/'etc/systemd/system/x-ui.service'; self.unit.parent.mkdir(parents=True)
        self.unit.write_text('[Service]\nExecStart=/usr/local/x-ui/x-ui\n'); self.unit.chmod(0o644)
        for name in ['x-ui','bin/xray-linux-amd64']:
            p=self.runtime/name; p.write_bytes(b'fixture executable bytes\n'); p.chmod(0o700)
        self.cert=self.home/'cert/panel.pem'; self.cert.parent.mkdir(); self.cert.write_bytes(b'fixture certificate\n'); self.cert.chmod(0o600)
        self.key=self.home/'cert/private.key'; self.key.write_bytes(b'fixture key bytes\n'); self.key.chmod(0o600)
        self.db=self.base/'etc/x-ui/x-ui.db'; self.db.parent.mkdir(); self.db.touch(mode=0o600)
        self.con=sqlite3.connect(self.db); self.con.execute('PRAGMA journal_mode=WAL'); self.con.execute('PRAGMA wal_autocheckpoint=0')
        self.con.execute('CREATE TABLE settings(key TEXT,value TEXT)'); self.con.execute('CREATE TABLE inbounds(settings TEXT,stream_settings TEXT)')
        self.con.executemany('INSERT INTO settings VALUES (?,?)',[('xrayTemplateConfig','{}'),('webCertFile',str(self.cert)),('webKeyFile',str(self.key))])
        self.con.execute('INSERT INTO inbounds VALUES (?,?)',('{}','{}')); self.con.commit(); self.db.chmod(0o600)
        self.scope='a'*64
        self.module=None
    def tearDown(self):
        self.con.close(); self.tmp.cleanup()
    def source(self, tail=''):
        text=SOURCE.read_text(); text=text.split('val source: String = """\n',1)[1].rsplit('\n""".trimIndent()',1)[0]
        prefixes=['/usr/local/x-ui','/usr/lib/systemd/system','/lib/systemd/system','/var/lib','/root','/etc']
        text=re.sub('|'.join(re.escape(p) for p in prefixes),lambda m: str(self.base)+m[0],text)
        fields={'FragmentPath':str(self.unit),'DropInPaths':'','WorkingDirectory':str(self.runtime),'Environment':'','EnvironmentFiles':'','ExecStart':'{ path='+str(self.runtime)+'/x-ui ; }'}
        # The systemctl boundary is scripted; all file/SQLite/tar operations run actual worker code.
        fixture='\nversion_check = lambda: None\nservice = lambda: ('+repr(fields)+', ['+repr(str(self.unit))+'])\n'+tail+'\n'
        text=text.replace("if __name__ == '__main__':",fixture+"\nif __name__ == '__main__':")
        return text
    def expected(self):
        candidates=[(self.runtime/'x-ui','RUNTIME',False),(self.runtime/'bin/xray-linux-amd64','RUNTIME',False),(self.unit,'SERVICE',False),(self.cert,'PANEL_TLS',False),(self.key,'PANEL_TLS',True)]
        rows=[]
        for p,group,secret in sorted(candidates):
            st=p.lstat()
            rows.append('|'.join((str(p),group,'1' if secret else '0',str(st.st_dev),str(st.st_ino),str(st.st_uid),format(st.st_mode&0o7777,'o'),str(st.st_size),str(st.st_mtime_ns//1000000000),str(st.st_ctime_ns//1000000000),str(st.st_nlink)))+'\n')
        return hashlib.sha256(''.join(rows).encode()).hexdigest()
    def run_worker(self, mode, scope=None, tail=''):
        return subprocess.run(['python3','-I','-c',self.source(tail),mode,scope or self.scope,'3.10.0','AMD64',self.expected()],capture_output=True,timeout=15)
    def folder(self, scope=None): return self.home/'.velum-tegra-installation-backups'/(scope or self.scope)[:32]
    def create_ok(self):
        r=self.run_worker('create'); self.assertEqual((0,b'CREATED\n',b''),(r.returncode,r.stdout,r.stderr)); return self.folder()
    def test_consistent_live_wal_copy_private_tar_and_exact_scope(self):
        self.assertTrue(Path(str(self.db)+'-wal').exists()); folder=self.create_ok()
        result=self.run_worker('verify'); self.assertEqual(0,result.returncode,result.stderr)
        proof=dict(x.split('=') for x in result.stdout.decode().splitlines())
        self.assertEqual(self.scope,proof['SCOPE']); self.assertEqual('5',proof['FILES'])
        self.assertEqual(hashlib.sha256((folder/'installation.tar').read_bytes()).hexdigest(),proof['SHA256'])
        self.assertEqual(0o700,folder.stat().st_mode&0o777)
        self.assertEqual(0o600,(folder/'installation.tar').stat().st_mode&0o777)
        with tarfile.open(folder/'installation.tar') as archive:
            self.assertTrue(all(x.isfile() and not x.name.startswith('/') for x in archive))
            raw=archive.extractfile('database.sqlite').read()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),proof['DATABASE_SHA256'])
        copied=sqlite3.connect('file:'+str(folder/'database.sqlite')+'?mode=ro',uri=True)
        self.assertEqual('{}',copied.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0]); copied.close()
        self.assertNotIn(str(self.key).encode(),result.stdout); self.assertNotIn(b'fixture key',result.stdout)
    def test_read_only_verification_does_not_change_artifacts(self):
        f=self.create_ok(); before={p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in f.iterdir()}
        self.assertEqual(0,self.run_worker('verify').returncode)
        self.assertEqual(before,{p.name:(p.read_bytes(),p.stat().st_mtime_ns) for p in f.iterdir()})
    def test_repeated_scope_cannot_overwrite(self):
        f=self.create_ok(); before=(f/'installation.tar').read_bytes()
        self.assertNotEqual(0,self.run_worker('create').returncode); self.assertEqual(before,(f/'installation.tar').read_bytes())
    def test_wrong_scope_has_no_receipt_and_cannot_create_on_check(self):
        self.create_ok(); r=self.run_worker('verify','b'*64)
        self.assertNotEqual(0,r.returncode); self.assertEqual(b'',r.stdout); self.assertFalse(self.folder('b'*64).exists())
    def test_missing_or_partial_artifact_never_creates_from_verification(self):
        r=self.run_worker('verify'); self.assertNotEqual(0,r.returncode); self.assertFalse(self.folder().exists())
    def test_symlink_private_key_blocks_before_archive_creation(self):
        self.key.unlink(); self.key.symlink_to(self.cert)
        self.assertNotEqual(0,self.run_worker('create').returncode); self.assertFalse(self.folder().exists())
    def test_shared_or_unsafe_private_key_blocks(self):
        self.key.chmod(0o644); self.assertNotEqual(0,self.run_worker('create').returncode)
        self.key.chmod(0o600); os.link(self.key,self.key.with_name('other.key'))
        self.assertNotEqual(0,self.run_worker('create').returncode); self.assertFalse(self.folder().exists())
    def test_database_sidecar_symlink_is_rejected(self):
        self.con.close(); self.con=sqlite3.connect(self.db)
        target=Path(str(self.db)+'-wal'); target.symlink_to(self.cert)
        self.assertNotEqual(0,self.run_worker('create').returncode); self.assertFalse(self.folder().exists())
    def test_unresolved_reference_or_external_socket_blocks(self):
        self.con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'",('{"extra":"unix:/tmp/private.socket"}',)); self.con.commit()
        self.assertNotEqual(0,self.run_worker('create').returncode); self.assertFalse(self.folder().exists())
    def test_relative_tls_reference_is_rejected(self):
        self.con.execute("UPDATE settings SET value='cert/key.pem' WHERE key='webKeyFile'");self.con.commit()
        self.assertNotEqual(0,self.run_worker('create').returncode)
    def test_malformed_or_duplicate_json_is_rejected(self):
        for raw in ['{"a":1,"a":2}','[]','not json']:
            self.con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'",(raw,)); self.con.commit()
            self.assertNotEqual(0,self.run_worker('create').returncode)
    def test_symlink_runtime_and_special_file_never_get_archived(self):
        link=self.runtime/'bin/link'; link.symlink_to(self.cert)
        self.assertNotEqual(0,self.run_worker('create').returncode); link.unlink()
        os.mkfifo(self.runtime/'pipe'); self.assertNotEqual(0,self.run_worker('create').returncode)
    def test_content_drift_before_publication_never_creates_manifest(self):
        tail="original_digest=digest_file\ndef digest_file(path,*args,**kwargs):\n    if path=="+repr(str(self.key))+":\n        with open(path,'ab') as f: f.write(b'changed')\n    return original_digest(path,*args,**kwargs)\n"
        r=self.run_worker('create',tail=tail); self.assertNotEqual(0,r.returncode); self.assertFalse((self.folder()/'manifest.v1').exists())
    def test_corrupt_archive_and_database_are_independently_rejected(self):
        f=self.create_ok(); archive=f/'installation.tar'; data=archive.read_bytes(); archive.write_bytes(b'x'+data[1:])
        self.assertNotEqual(0,self.run_worker('verify').returncode); archive.write_bytes(data)
        db=f/'database.sqlite'; raw=db.read_bytes(); db.write_bytes(b'x'+raw[1:])
        self.assertNotEqual(0,self.run_worker('verify').returncode)
    def test_manifest_scope_mismatch_or_duplicates_reject(self):
        f=self.create_ok(); p=f/'manifest.v1'; data=p.read_text(); p.write_text(data.replace(self.scope,'b'*64))
        self.assertNotEqual(0,self.run_worker('verify').returncode); p.write_text(data+'SECRET=hidden\n')
        self.assertNotEqual(0,self.run_worker('verify').returncode)
    def test_full_quota_counts_unfinished_slots(self):
        root=self.home/'.velum-tegra-installation-backups'; root.mkdir(mode=0o700)
        for n in range(4): (root/str(n)).mkdir(mode=0o700)
        self.assertNotEqual(0,self.run_worker('create').returncode); self.assertFalse(self.folder().exists())
        self.assertEqual(b'4',self.run_worker('storage').stdout.splitlines()[0])
    def test_private_root_mode_not_repaired(self):
        root=self.home/'.velum-tegra-installation-backups'; root.mkdir(mode=0o755)
        self.assertNotEqual(0,self.run_worker('create').returncode); self.assertEqual(0o755,root.stat().st_mode&0o777)
    def service_policy(self):
        text=self.source()
        text=re.sub(r"^service = lambda:.*$", "", text, flags=re.M)
        namespace={'__name__':'local_fixture'}; exec(compile(text,'isolated-worker','exec'),namespace)
        binary=str(self.runtime)+'/x-ui'
        base={k:'' for k in ('RootDirectory','RootImage','BindPaths','BindReadOnlyPaths','LoadCredential','LoadCredentialEncrypted','RuntimeDirectory','StateDirectory','ConfigurationDirectory','ExecStartPre','ExecStartPost','ExecStop','ExecReload','Environment','EnvironmentFiles','DropInPaths')}
        base.update(FragmentPath=str(self.unit),WorkingDirectory=str(self.runtime),ExecStart='{ path='+binary+' ; argv[]='+binary+' ; }')
        def run(fields, typed=None, stderr=b'', failure=False):
            raw=''.join(k+'='+v+'\n' for k,v in fields.items()).encode()
            def query(command, **kwargs):
                if command[0] == '/usr/bin/systemctl': return SimpleNamespace(stdout=raw)
                self.assertEqual(['/usr/bin/busctl','--system','--no-pager','get-property','org.freedesktop.systemd1',
                    '/org/freedesktop/systemd1/unit/x_2dui_2eservice','org.freedesktop.systemd1.Service'],command[:-1])
                self.assertIn(command[-1],('ExecStartPre','ExecStartPost','ExecStop','ExecReload','LoadCredential','LoadCredentialEncrypted'))
                self.assertTrue(kwargs['check']); self.assertEqual(5,kwargs['timeout'])
                if failure: raise OSError('fixture query failure')
                default=b'a(ss) 0\n' if command[-1].startswith('LoadCredential') else b'a(sasbttttuii) 0\n'
                return SimpleNamespace(stdout=default if typed is None else typed,stderr=stderr)
            namespace['subprocess']=SimpleNamespace(PIPE=-1,DEVNULL=-3,run=query)
            return namespace['service']()
        return namespace,base,run
    def test_service_extra_arguments_environment_or_hidden_mounts_are_rejected(self):
        namespace,base,run=self.service_policy()
        binary=str(self.runtime)+'/x-ui'
        self.assertEqual([str(self.unit)],run(base)[1])
        for key,value in [('Environment','PRIVATE=value'),('RootDirectory','/other'),('LoadCredential','tls:/secret'),('ExecStart','{ path='+binary+' ; argv[]='+binary+' -config /other ; }')]:
            with self.assertRaises(namespace['Rejected']): run(dict(base,**{key:value}))
    def test_stock_environment_absent_optional_file_and_known_reload_are_supported(self):
        namespace,base,run=self.service_policy()
        (self.base/'etc/default').mkdir(mode=0o755)
        stock=dict(base,Environment='XRAY_VMESS_AEAD_FORCED=false',EnvironmentFiles=str(self.base)+'/etc/default/x-ui (ignore_errors=yes)',ExecReload='{ path=/bin/kill ; argv[]=/bin/kill -USR1 $MAINPID ; }')
        self.assertEqual([str(self.unit)],run(stock)[1])
    def test_existing_empty_nonempty_or_symlink_environment_file_is_rejected(self):
        namespace,base,run=self.service_policy()
        folder=self.base/'etc/default';folder.mkdir(mode=0o755)
        fields=dict(base,Environment='XRAY_VMESS_AEAD_FORCED=false',EnvironmentFiles=str(folder)+'/x-ui (ignore_errors=yes)')
        p=folder/'x-ui'
        for raw in [b'',b'XUI_DB_TYPE=postgres\n']:
            p.write_bytes(raw)
            with self.assertRaises(namespace['Rejected']):run(fields)
            p.unlink()
        p.symlink_to(folder/'missing')
        with self.assertRaises(namespace['Rejected']):run(fields)
    def test_environment_parent_write_permissions_or_symlink_are_rejected(self):
        namespace,base,run=self.service_policy()
        folder=self.base/'etc/default';folder.mkdir(mode=0o777);folder.chmod(0o777)
        fields=dict(base,EnvironmentFiles=str(folder)+'/x-ui (ignore_errors=yes)')
        with self.assertRaises(namespace['Rejected']):run(fields)
        folder.rmdir();folder.symlink_to(self.db.parent,target_is_directory=True)
        with self.assertRaises((namespace['Rejected'],OSError)):run(fields)
    def test_node_keyring_regular_or_dangling_symlink_cannot_be_omitted(self):
        namespace,base,run=self.service_policy();p=self.db.parent/'node_token_key.json'
        p.write_bytes(b'fixture only');p.chmod(0o600)
        with self.assertRaises(namespace['Rejected']):run(base)
        p.unlink();p.symlink_to(self.db.parent/'missing')
        with self.assertRaises(namespace['Rejected']):run(base)
    def test_near_stock_environment_and_reload_commands_remain_rejected(self):
        namespace,base,run=self.service_policy()
        for key,value in [('Environment','XRAY_VMESS_AEAD_FORCED=true'),('Environment','XRAY_VMESS_AEAD_FORCED=false XUI_DB_TYPE=postgres'),('EnvironmentFiles','/other (ignore_errors=yes)'),('ExecReload','{ path=/bin/sh ; argv[]=/bin/sh -c id ; }'),('ExecReload','{ path=/bin/kill ; argv[]=/bin/kill -USR1 1234 ; }')]:
            with self.assertRaises(namespace['Rejected']):run(dict(base,**{key:value}))
    def test_missing_fixed_exec_arrays_require_typed_empty_proof(self):
        namespace,base,run=self.service_policy()
        fields={k:v for k,v in base.items() if k not in ('ExecStartPre','ExecStartPost','ExecStop','ExecReload')}
        actual,paths=run(fields)
        self.assertEqual(base,actual);self.assertEqual([str(self.unit)],paths)
    def test_unknown_missing_property_or_exec_start_cannot_use_empty_fallback(self):
        namespace,base,run=self.service_policy()
        for key in ('RootImage','LoadCredentialEncrypted','ExecStart','Environment'):
            with self.assertRaises(namespace['Rejected']):run({k:v for k,v in base.items() if k!=key})
    def test_nonempty_or_malformed_typed_exec_array_is_rejected(self):
        namespace,base,run=self.service_policy();fields={k:v for k,v in base.items() if k!='ExecStartPre'}
        for value in (b'',b'as 0\n',b'a(sasbttttuii) 1 "/bin/true"\n',b'a(sasbttttuii) 0\nEXTRA',b'a(sasbttttuii) 0 \n',b'x'*9000):
            with self.assertRaises(namespace['Rejected']):run(fields,typed=value)
    def test_failed_or_noisy_typed_query_does_not_mean_empty(self):
        namespace,base,run=self.service_policy();fields={k:v for k,v in base.items() if k!='ExecStop'}
        with self.assertRaises(namespace['Rejected']):run(fields,stderr=b'warning')
        with self.assertRaises(OSError):run(fields,failure=True)
    def test_duplicate_or_unexpected_systemctl_fields_are_rejected(self):
        namespace,base,run=self.service_policy()
        with self.assertRaises(namespace['Rejected']):run(dict(base,Unexpected=''))
        with self.assertRaises(namespace['Rejected']):run(dict(base,ExecStop='\nExecStop='))
    def test_unprintable_credentials_require_both_typed_empty_arrays(self):
        namespace,base,run=self.service_policy()
        fields=dict(base,LoadCredential='[unprintable]',LoadCredentialEncrypted='[unprintable]')
        self.assertEqual(base,run(fields)[0])
    def test_nonempty_wrong_type_or_failed_credential_array_stays_blocked(self):
        namespace,base,run=self.service_policy()
        for name in ('LoadCredential','LoadCredentialEncrypted'):
            fields=dict(base,**{name:'[unprintable]'})
            for raw in (b'a(ss) 1 "id" "/secret"\n',b'a(sasbttttuii) 0\n',b'',b'a(ss) 0\nextra'):
                with self.assertRaises(namespace['Rejected']):run(fields,typed=raw)
            with self.assertRaises(namespace['Rejected']):run(fields,stderr=b'warning')
            with self.assertRaises(OSError):run(fields,failure=True)
    def test_unknown_credential_text_is_not_normalized(self):
        namespace,base,run=self.service_policy()
        for text in ('tls:/secret','[unknown]','[unprintable] extra'):
            with self.assertRaises(namespace['Rejected']):run(dict(base,LoadCredential=text))
    def test_version_child_has_bounded_address_space_and_parent_soft_limit_is_preserved(self):
        binary=self.runtime/'x-ui'
        binary.write_text('#!/usr/bin/python3\nimport resource,sys\nif resource.getrlimit(resource.RLIMIT_AS)!=(2147483648,2147483648):sys.exit(7)\nprint("3.10.0")\n')
        binary.chmod(0o700)
        text=self.source().replace('version_check = lambda: None','').replace("if __name__ == '__main__':",'if False:')
        driver=text+"\nVERSION='3.10.0'\nARCH='AMD64'\nresource.setrlimit(resource.RLIMIT_AS,(536870912,2147483648))\nversion_check()\nassert resource.getrlimit(resource.RLIMIT_AS)==(536870912,2147483648)\n"
        result=subprocess.run(['python3','-I','-c',driver],capture_output=True,timeout=10)
        self.assertEqual((0,b'',b''),(result.returncode,result.stdout,result.stderr))
    def test_parallel_writer_holds_global_quota_lock(self):
        tail="original_collect=collect\ndef collect(path):\n    value=original_collect(path)\n    if path!=DATABASE: time.sleep(0.4)\n    return value\n"
        first=subprocess.Popen(['python3','-I','-c',self.source(tail),'create',self.scope,'3.10.0','AMD64',self.expected()],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            end=time.monotonic()+5
            while not self.folder().exists() and time.monotonic()<end: time.sleep(0.01)
            second=self.run_worker('create','b'*64)
            self.assertNotEqual(0,second.returncode); self.assertFalse(self.folder('b'*64).exists())
            out,err=first.communicate(timeout=10); self.assertEqual((0,b'CREATED\n',b''),(first.returncode,out,err))
        finally:
            if first.poll() is None: first.kill();first.communicate()
    def test_changed_reviewed_fingerprint_cannot_create_any_artifact(self):
        script=self.source()
        result=subprocess.run(['python3','-I','-c',script,'create',self.scope,'3.10.0','AMD64','0'*64],capture_output=True,timeout=10)
        self.assertNotEqual(0,result.returncode); self.assertFalse(self.folder().exists())
    def test_no_permission_to_restore_or_mutate_services_is_present(self):
        text=SOURCE.read_text()
        for banned in ['extractall(', 'systemctl stop', 'systemctl restart', 'curl ', 'wget ', 'chown(', 'chmod(']: self.assertNotIn(banned,text)
        self.assertIn('source.backup(target',text); self.assertIn('fcntl.LOCK_EX | fcntl.LOCK_NB',text)

if __name__=='__main__': unittest.main()

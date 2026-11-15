package com.velumtegra.xuimobile.core.ssh
/** Same-release database-only recovery; no file-set restore, migration or automatic service start. */
internal object WorkingDatabaseRestoreWorker {
    val source:String=RestoreCompatibilityWorker.source.substringBefore("\nif __name__ == '__main__':")+"\n"+"""
# Same-release working database restore. Never executes restored binaries or starts a service.
WDB_ROOT='/root/.velum-tegra-working-db-restores'


def working_space():
    private_dir(HOME)
    if not os.path.lexists(WDB_ROOT):
        v=os.statvfs(HOME);return 0,v.f_bavail*v.f_frsize
    private_dir(WDB_ROOT);names=os.listdir(WDB_ROOT);need(len(names)<=5)
    slots=0
    for name in names:
        if name=='.lock':file_info(WDB_ROOT+'/.lock',True,4096)
        else:need(re.fullmatch('[0-9a-f]{32}',name));private_dir(WDB_ROOT+'/'+name);slots+=1
    need(slots<=4);v=os.statvfs(WDB_ROOT);return slots,v.f_bavail*v.f_frsize


def working_lock(create):
    if create and not os.path.lexists(WDB_ROOT):os.mkdir(WDB_ROOT,0o700)
    private_dir(WDB_ROOT)
    flags=os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_WRONLY|os.O_CREAT if create else os.O_RDONLY)
    fd=os.open(WDB_ROOT+'/.lock',flags,0o600)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd
    except BaseException:os.close(fd);raise


def working_service(stopped=False):
    names=('LoadState','ActiveState','SubState','MainPID','ControlPID','TriggeredBy','KillMode','ControlGroup')
    result=subprocess.run(['/usr/bin/systemctl','show','--no-pager']+['--property='+p for p in names]+['--','x-ui.service'],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,check=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(not result.stderr and len(result.stdout)<=2048)
    pairs=[line.split('=',1) for line in result.stdout.decode('ascii').splitlines()]
    need(len(pairs)==len(names) and all(len(p)==2 for p in pairs));fields=dict(pairs);need(set(fields)==set(names))
    need(fields['LoadState']=='loaded' and fields['ActiveState'] in ('active','inactive') and fields['ControlPID']=='0' and not fields['TriggeredBy'])
    need(fields['KillMode'] in ('control-group','mixed') and re.fullmatch('0|[1-9][0-9]{0,8}',fields['MainPID']))
    need(fields['ControlGroup'] in ('','/system.slice/x-ui.service'))
    if stopped:
        need(fields['ActiveState']=='inactive' and fields['SubState']=='dead' and fields['MainPID']=='0')
        group='/sys/fs/cgroup/system.slice/x-ui.service'
        if os.path.lexists(group):
            fd,unused=checked(group+'/cgroup.procs')
            try:need(os.read(fd,4097).strip()==b'')
            finally:os.close(fd)
    return fields


def working_endpoint(path,immutable):
    con=connect(path,immutable)
    try:
        rows=con.execute("SELECT key,value FROM settings WHERE key IN ('webPort','webBasePath','webListen') LIMIT 4").fetchall()
        need(2<=len(rows)<=3 and len({r[0] for r in rows})==len(rows))
        values=dict(rows);need('webPort' in values and 'webBasePath' in values)
        need(all(isinstance(k,str) and isinstance(v,str) and len(v)<=1024 for k,v in rows))
        fields=[values['webPort'],values['webBasePath'],values.get('webListen','')]
        endpoint=''.join(str(len(v.encode('utf-8')))+':'+v for v in fields).encode('utf-8')
        need(hashlib.sha256(endpoint).hexdigest()==EXPECTED_ENDPOINT)
        return values
    finally:con.close()


def working_logical(path,immutable=False):
    # No SQL text/rows leave this bounded transient digest computation.
    compatibility_schema(path,immutable)
    con=connect(path,immutable)
    try:
        con.execute('BEGIN');need(con.execute('PRAGMA foreign_key_check').fetchone() is None)
        digest=hashlib.sha256();total=0;lines=0
        meta=json.dumps([con.execute('PRAGMA user_version').fetchone()[0],con.execute('PRAGMA application_id').fetchone()[0]],separators=(',',':')).encode('ascii')
        digest.update(meta+b'\n')
        for line in con.iterdump():
            tick();data=line.encode('utf-8');total+=len(data);lines+=1
            need(len(data)<=16777216 and total<=536870912 and lines<=262144)
            digest.update(str(len(data)).encode('ascii')+b':'+data)
        return digest.hexdigest()
    finally:con.close()


def working_compare():
    global DEADLINE
    capture=io.StringIO()
    with contextlib.redirect_stdout(capture):compatibility_main()
    DEADLINE=WORKING_DEADLINE
    pairs=[line.split('=') for line in capture.getvalue().splitlines()];need(len(pairs)==14 and all(len(p)==2 for p in pairs))
    proof=dict(pairs)
    need(proof['CURRENT_VERSION']==VERSION and proof['CURRENT_ARCH']==ARCH and proof['SOURCE_SCHEMA']==proof['CURRENT_SCHEMA'])
    need(proof['FILE_SET']=='MATCH' and proof['CHANGED_FILES']=='0')
    need(working_endpoint(DESTINATION+'/database.sqlite',True)==working_endpoint(DATABASE,False))
    source_con=connect(DESTINATION+'/database.sqlite',True);target_con=connect(DATABASE)
    try:
        need(source_con.execute('PRAGMA page_size').fetchone()==target_con.execute('PRAGMA page_size').fetchone())
        need(target_con.execute('PRAGMA journal_mode').fetchone()[0] in ('delete','wal'))
    finally:target_con.close();source_con.close()
    working_logical(DESTINATION+'/database.sqlite',True);working_logical(DATABASE)
    return proof


def working_sync_dir(path):
    fd,unused=checked(path,directory=True)
    try:os.fsync(fd)
    finally:os.close(fd)


def working_apply(source,target):
    source.backup(target,pages=64,progress=tick,sleep=0.01)


def working_fsync(path):
    fd,unused=checked(path,secret=True)
    try:os.fsync(fd)
    finally:os.close(fd)


def working_write():
    global STOP_DISPATCHED
    lock=working_lock(True)
    try:
        slots,available=working_space();need(slots<4 and available>=2*MAX_DB+67108864 and not os.path.lexists(WDB_DIRECTORY))
        working_compare();working_service();tick()
        source_stamp=restore_source_stamp();old_identity=file_info(DATABASE,True)
        # This fixed command is the first service mutation. Never restart implicitly.
        STOP_DISPATCHED=True
        result=subprocess.run(['/usr/bin/systemctl','stop','--','x-ui.service'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        need(result.returncode==0 and not result.stdout and not result.stderr);working_service(True);tick()
        need(file_info(DATABASE,True)[:4]==old_identity[:4])
        os.mkdir(WDB_DIRECTORY,0o700);private_dir(WDB_DIRECTORY)
        previous=WDB_DIRECTORY+'/before.sqlite'
        fd=os.open(previous,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        source=connect(DATABASE);target=sqlite3.connect(previous,timeout=3)
        try:
            target.execute('PRAGMA synchronous=FULL');source.backup(target,pages=64,progress=tick,sleep=0.01)
            target.execute('PRAGMA journal_mode=DELETE');need(target.execute('PRAGMA quick_check').fetchall()==[('ok',)])
        finally:target.close();source.close()
        previous_info=file_info(previous,True,MAX_DB);need(previous_info[4]>0)
        previous_sha=digest_file(previous,MAX_DB,True);previous_logical=working_logical(previous,True)
        need(previous_logical==working_logical(DATABASE));working_fsync(previous);working_sync_dir(WDB_DIRECTORY)
        # Publish pre-change evidence before touching current database bytes.
        before={'format':'VELUM_WORKING_DB_BEFORE_V1','scope':WDB_SCOPE,'source':EXPECTED_DB,'previousSha256':previous_sha,'previousLogicalSha256':previous_logical,'previousBytes':previous_info[4]}
        raw=json.dumps(before,sort_keys=True,separators=(',',':')).encode('ascii')
        fd=os.open(WDB_DIRECTORY+'/before.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:need(output.write(raw)==len(raw));output.flush();os.fsync(output.fileno())
        working_sync_dir(WDB_DIRECTORY)
        restored_logical=working_logical(DESTINATION+'/database.sqlite',True)
        need(restore_source_stamp()==source_stamp);working_service(True)
        need(working_endpoint(DESTINATION+'/database.sqlite',True)==working_endpoint(DATABASE,False))
        identity=file_info(DATABASE,True);need(identity[:4]==old_identity[:4] and identity[7]==1)
        source=connect(DESTINATION+'/database.sqlite',True)
        target=sqlite3.connect('file:'+DATABASE+'?mode=rw',uri=True,timeout=3)
        try:
            target.execute('PRAGMA trusted_schema=OFF');target.execute('PRAGMA synchronous=FULL')
            # SQLite owns the destination transaction, including existing WAL handling.
            working_apply(source,target)
            need(target.execute('PRAGMA quick_check').fetchall()==[('ok',)])
        finally:target.close();source.close()
        need(file_info(DATABASE,True)[:4]==identity[:4] and working_logical(DATABASE)==restored_logical)
        working_service(True);need(restore_source_stamp()==source_stamp)
        working_fsync(DATABASE)
        if os.path.lexists(DATABASE+'-wal'):working_fsync(DATABASE+'-wal')
        working_sync_dir(os.path.dirname(DATABASE))
        final=dict(before);final['format']='VELUM_WORKING_DB_RESTORED_V1';final['restoredLogicalSha256']=restored_logical
        raw=json.dumps(final,sort_keys=True,separators=(',',':')).encode('ascii')
        fd=os.open(WDB_DIRECTORY+'/restored.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as output:need(output.write(raw)==len(raw));output.flush();os.fsync(output.fileno())
        working_sync_dir(WDB_DIRECTORY);sys.stdout.write('DATABASE_RESTORED\n')
    finally:os.close(lock)


def working_read():
    lock=working_lock(False)
    try:
        private_dir(WDB_DIRECTORY);need(set(os.listdir(WDB_DIRECTORY))=={'before.sqlite','before.json','restored.json'})
        final=json.loads(read_file(WDB_DIRECTORY+'/restored.json',2048,True).decode('ascii'),object_pairs_hook=unique_object)
        before=json.loads(read_file(WDB_DIRECTORY+'/before.json',2048,True).decode('ascii'),object_pairs_hook=unique_object)
        need(set(final)=={'format','scope','source','previousSha256','previousLogicalSha256','previousBytes','restoredLogicalSha256'})
        expected=dict(final);expected.pop('restoredLogicalSha256');expected['format']='VELUM_WORKING_DB_BEFORE_V1';need(before==expected)
        need(final['format']=='VELUM_WORKING_DB_RESTORED_V1' and final['scope']==WDB_SCOPE and final['source']==EXPECTED_DB)
        need(all(isinstance(final[k],str) and re.fullmatch('[0-9a-f]{64}',final[k]) for k in ('previousSha256','previousLogicalSha256','restoredLogicalSha256')))
        need(type(final['previousBytes'])is int and 1<=final['previousBytes']<=MAX_DB)
        previous=WDB_DIRECTORY+'/before.sqlite';need(file_info(previous,True,MAX_DB)[4]==final['previousBytes'])
        need(digest_file(previous,MAX_DB,True)==final['previousSha256'] and working_logical(previous,True)==final['previousLogicalSha256'])
        working_compare();working_service(True)
        need(working_logical(DESTINATION+'/database.sqlite',True)==final['restoredLogicalSha256']==working_logical(DATABASE))
        working_service(True)
        rows=[('FORMAT','VELUM_WORKING_DB_V1'),('SCOPE',WDB_SCOPE),('SOURCE_DB_SHA256',EXPECTED_DB),('RESTORED_LOGICAL_SHA256',final['restoredLogicalSha256']),
            ('PREVIOUS_DB_SHA256',final['previousSha256']),('PREVIOUS_LOGICAL_SHA256',final['previousLogicalSha256']),('PREVIOUS_BYTES',str(final['previousBytes'])),('SERVICE','INACTIVE'),('STATE','VERIFIED')]
        sys.stdout.write(''.join(k+'='+v+'\n' for k,v in rows))
    finally:os.close(lock)


def working_main():
    global WDB_SCOPE,WDB_DIRECTORY,DEADLINE,WORKING_DEADLINE,EXPECTED_ENDPOINT,STOP_DISPATCHED,WDB_MODE
    STOP_DISPATCHED=False;WDB_MODE=None
    started=time.monotonic();need(len(sys.argv)==13 and sys.argv[1] in ('space','write','read'))
    mode=sys.argv.pop(1);WDB_MODE=mode;EXPECTED_ENDPOINT=sys.argv.pop(2);need(re.fullmatch('[0-9a-f]{64}',EXPECTED_ENDPOINT));WDB_SCOPE=sys.argv[1];need(re.fullmatch('[0-9a-f]{64}',WDB_SCOPE))
    WDB_DIRECTORY=WDB_ROOT+'/'+WDB_SCOPE[:32]
    # Initialize accepted source bindings without copying into the isolated directory.
    saved=sys.argv[1];sys.argv[1]='space';capture=io.StringIO()
    with contextlib.redirect_stdout(capture):restore_main()
    sys.argv[1]=saved;DEADLINE=WORKING_DEADLINE=started+(8 if mode=='space' else 135)
    if mode=='space':
        slots,available=working_space();sys.stdout.write(str(slots)+'\n'+str(available)+'\n')
    elif mode=='write':working_write()
    else:working_read()

if __name__=='__main__':
    try:working_main()
    except BaseException:
        if globals().get('WDB_MODE')=='write' and not globals().get('STOP_DISPATCHED',True):sys.stdout.write('NOT_STARTED\n')
        sys.exit(81)

""".trimIndent()
}

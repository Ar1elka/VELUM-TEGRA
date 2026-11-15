package com.velumtegra.xuimobile.core.ssh
/** Compensating DB-only return. Service MUST already be stopped; never starts/stops/reinstalls it. */
internal object BeforeCopyReturnWorker{
    val source:String=WorkingDatabaseRestoreWorker.source.substringBefore("\nif __name__=='__main__':")+"\n"+"""
RETURN_ROOT='/root/.velum-tegra-before-copy-returns'

def returning_stopped():
    fields=working_service(True)
    result=subprocess.run(['/usr/bin/systemctl','show','--no-pager','--property=Job','--','x-ui.service'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,check=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(not result.stderr and result.stdout in (b'Job=0\n',b'Job=\n'));return fields

def returning_store(path,value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii');need(len(raw)<=2048)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:need(out.write(raw)==len(raw));out.flush();os.fsync(out.fileno())
    working_sync_dir(os.path.dirname(path))

def returning_capacity(create):
    private_dir(HOME)
    if not os.path.lexists(RETURN_ROOT):
        need(create);os.mkdir(RETURN_ROOT,0o700);working_sync_dir(HOME)
    private_dir(RETURN_ROOT)
    names=os.listdir(RETURN_ROOT);need(len(names)<=5)
    for name in names:
        if name=='.lock':file_info(RETURN_ROOT+'/.lock',True,4096)
        else:need(re.fullmatch('[0-9a-f]{32}',name));private_dir(RETURN_ROOT+'/'+name)
    slots=len([n for n in names if n!='.lock']);need(slots<=4)
    v=os.statvfs(RETURN_ROOT);return slots,v.f_bavail*v.f_frsize

def returning_lock(create):
    returning_capacity(create)
    fd=os.open(RETURN_ROOT+'/.lock',os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_WRONLY|os.O_CREAT if create else os.O_RDONLY),0o600)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd
    except BaseException:os.close(fd);raise

def returning_source():
    private_dir(WDB_DIRECTORY);names=set(os.listdir(WDB_DIRECTORY));need(names in ({'before.sqlite','before.json'},{'before.sqlite','before.json','restored.json'}))
    path=WDB_DIRECTORY+'/before.sqlite';manifest=WDB_DIRECTORY+'/before.json'
    raw=read_file(manifest,2048,True);value=json.loads(raw.decode('ascii'),object_pairs_hook=unique_object)
    expected={'format':'VELUM_WORKING_DB_BEFORE_V1','scope':WDB_SCOPE,'source':EXPECTED_DB,'previousSha256':RETURN_DB,'previousLogicalSha256':RETURN_LOGICAL,'previousBytes':RETURN_BYTES}
    need(value==expected and type(value['previousBytes'])is int)
    need(file_info(path,True,MAX_DB)[4]==RETURN_BYTES and digest_file(path,MAX_DB,True)==RETURN_DB and working_logical(path,True)==RETURN_LOGICAL)
    working_endpoint(path,True);args=list(sys.argv)
    try:proof=working_compare()
    finally:sys.argv[:]=args
    schema,unused=compatibility_schema(path,True);need(schema==proof['CURRENT_SCHEMA'])
    con=connect(path,True);target=connect(DATABASE)
    try:need(con.execute('PRAGMA page_size').fetchone()==target.execute('PRAGMA page_size').fetchone())
    finally:target.close();con.close()
    returning_stopped();current=working_logical(DATABASE)
    return (file_info(path,True,MAX_DB),file_info(manifest,True,2048),raw,restore_source_stamp()),current

def returning_intent():return {'format':'VELUM_BEFORE_RETURN_INTENT_V1','scope':RETURN_SCOPE,'restore':WDB_SCOPE,'beforeSha256':RETURN_DB,'beforeLogical':RETURN_LOGICAL,'beforeBytes':RETURN_BYTES}

def returning_write():
    # Parent lock cannot be created here. A valid before copy proves the original writer
    # acquired this lock; acquiring it now excludes that original one-shot writer.
    parent=working_lock(False)
    try:
        stamp,current=returning_source();need(current!=RETURN_LOGICAL)
        own=returning_lock(True)
        try:
            slots,available=returning_capacity(False);need(slots<4 and available>=2*MAX_DB+67108864)
            need(not os.path.lexists(RETURN_DIRECTORY));os.mkdir(RETURN_DIRECTORY,0o700);private_dir(RETURN_DIRECTORY)
            # Exclusive reservation BEFORE any DB copy. Never repair/reuse/replay this directory.
            returning_store(RETURN_DIRECTORY+'/intent.json',returning_intent());working_sync_dir(RETURN_ROOT)
            previous=RETURN_DIRECTORY+'/displaced.sqlite';fd=os.open(previous,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
            source=connect(DATABASE);target=sqlite3.connect(previous,timeout=3)
            try:
                target.execute('PRAGMA synchronous=FULL');page_size=source.execute('PRAGMA page_size').fetchone()[0]
                def bounded_copy(status,remaining,total):
                    tick();need(type(total)is int and total*page_size<=MAX_DB)
                source.backup(target,pages=64,progress=bounded_copy,sleep=0.01)
                target.execute('PRAGMA journal_mode=DELETE');need(target.execute('PRAGMA quick_check').fetchall()==[('ok',)])
            finally:target.close();source.close()
            displaced=file_info(previous,True,MAX_DB);need(displaced[4]>0 and working_logical(previous,True)==current)
            displaced_sha=digest_file(previous,MAX_DB,True);working_fsync(previous)
            displaced_value={'format':'VELUM_BEFORE_RETURN_DISPLACED_V1','scope':RETURN_SCOPE,'sha256':displaced_sha,'logical':current,'bytes':displaced[4]}
            returning_store(RETURN_DIRECTORY+'/displaced.json',displaced_value)
            checked,again=returning_source();need(checked==stamp and again==current);returning_stopped();tick()
            identity=file_info(DATABASE,True);source=connect(WDB_DIRECTORY+'/before.sqlite',True);target=sqlite3.connect('file:'+DATABASE+'?mode=rw',uri=True,timeout=3)
            try:
                target.execute('PRAGMA trusted_schema=OFF');target.execute('PRAGMA synchronous=FULL')
                working_apply(source,target);need(target.execute('PRAGMA quick_check').fetchall()==[('ok',)])
            finally:target.close();source.close()
            need(file_info(DATABASE,True)[:4]==identity[:4]);after,value=returning_source();need(after==stamp and value==RETURN_LOGICAL)
            working_fsync(DATABASE)
            if os.path.lexists(DATABASE+'-wal'):working_fsync(DATABASE+'-wal')
            working_sync_dir(os.path.dirname(DATABASE));returning_stopped()
            final=dict(displaced_value);final['format']='VELUM_BEFORE_RETURN_COMPLETED_V1';final['beforeLogical']=RETURN_LOGICAL
            returning_store(RETURN_DIRECTORY+'/returned.json',final);sys.stdout.write('BEFORE_DATABASE_RETURNED\n')
        finally:os.close(own)
    finally:os.close(parent)

def returning_read():
    parent=working_lock(False)
    try:
        own=returning_lock(False)
        try:
            private_dir(RETURN_DIRECTORY);need(set(os.listdir(RETURN_DIRECTORY))=={'intent.json','displaced.sqlite','displaced.json','returned.json'})
            paths=['intent.json','displaced.json','returned.json'];raws=[read_file(RETURN_DIRECTORY+'/'+n,2048,True) for n in paths]
            values=[json.loads(raw.decode('ascii'),object_pairs_hook=unique_object) for raw in raws];intent,displaced,final=values
            need(intent==returning_intent() and set(displaced)=={'format','scope','sha256','logical','bytes'})
            need(displaced['format']=='VELUM_BEFORE_RETURN_DISPLACED_V1' and displaced['scope']==RETURN_SCOPE)
            need(type(displaced['bytes'])is int and 1<=displaced['bytes']<=MAX_DB)
            need(all(isinstance(displaced[k],str) and re.fullmatch('[0-9a-f]{64}',displaced[k]) for k in ('sha256','logical')))
            expected=dict(displaced);expected['format']='VELUM_BEFORE_RETURN_COMPLETED_V1';expected['beforeLogical']=RETURN_LOGICAL;need(final==expected)
            path=RETURN_DIRECTORY+'/displaced.sqlite';stamp=file_info(path,True,MAX_DB);need(stamp[4]==displaced['bytes'])
            need(digest_file(path,MAX_DB,True)==displaced['sha256'] and working_logical(path,True)==displaced['logical'])
            source,current=returning_source();need(current==RETURN_LOGICAL)
            need([read_file(RETURN_DIRECTORY+'/'+n,2048,True) for n in paths]==raws)
            need(file_info(path,True,MAX_DB)==stamp and digest_file(path,MAX_DB,True)==displaced['sha256']);returning_stopped()
            again,current=returning_source();need(again==source and current==RETURN_LOGICAL)
            rows=[('FORMAT','VELUM_BEFORE_RETURN_V1'),('SCOPE',RETURN_SCOPE),('RESTORE',WDB_SCOPE),('BEFORE_SHA256',RETURN_DB),('BEFORE_LOGICAL',RETURN_LOGICAL),('DISPLACED_SHA256',displaced['sha256']),('DISPLACED_BYTES',str(displaced['bytes'])),('SERVICE','INACTIVE'),('STATE','VERIFIED_STOPPED')]
            sys.stdout.write(''.join(k+'='+v+'\n' for k,v in rows))
        finally:os.close(own)
    finally:os.close(parent)

def returning_main():
    global RETURN_SCOPE,RETURN_DB,RETURN_LOGICAL,RETURN_BYTES,RETURN_DIRECTORY,DEADLINE,WORKING_DEADLINE
    started=time.monotonic();need(len(sys.argv)==17 and sys.argv[1] in ('write','read'));mode=sys.argv.pop(1)
    RETURN_SCOPE=sys.argv.pop(1);RETURN_DB=sys.argv.pop(1);RETURN_LOGICAL=sys.argv.pop(1);size=sys.argv.pop(1)
    need(all(re.fullmatch('[0-9a-f]{64}',v) for v in (RETURN_SCOPE,RETURN_DB,RETURN_LOGICAL)) and re.fullmatch('[1-9][0-9]{0,9}',size))
    RETURN_BYTES=int(size);need(1<=RETURN_BYTES<=MAX_DB);sys.argv.insert(1,'space')
    with contextlib.redirect_stdout(io.StringIO()):working_main()
    DEADLINE=WORKING_DEADLINE=started+135;RETURN_DIRECTORY=RETURN_ROOT+'/'+WDB_SCOPE[:32]
    if mode=='write':returning_write()
    else:returning_read()

if __name__=='__main__':
    try:returning_main()
    except BaseException:sys.exit(81)
""".trimIndent()
}

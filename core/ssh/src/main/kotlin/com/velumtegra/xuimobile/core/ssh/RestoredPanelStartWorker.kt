package com.velumtegra.xuimobile.core.ssh
/** Explicit exact-source service start and separate readback; no database/file restoration. */
internal object RestoredPanelStartWorker {
    val source:String=WorkingDatabaseRestoreWorker.source.substringBefore("\nif __name__=='__main__':")+"\n"+"""
# Explicit service activation. No database backup/copy/restore call is reachable from these modes.
START_ROOT='/root/.velum-tegra-restored-panel-starts'

def starting_path():return START_ROOT+'/'+WDB_SCOPE[:32]

def starting_capacity():
    private_dir(HOME)
    if not os.path.lexists(START_ROOT):return
    private_dir(START_ROOT);names=os.listdir(START_ROOT);need(len(names)<=5)
    slots=0
    for name in names:
        if name=='.lock':file_info(START_ROOT+'/.lock',True,4096)
        else:need(re.fullmatch('[0-9a-f]{32}',name));private_dir(START_ROOT+'/'+name);slots+=1
    need(slots<4)

def starting_lock(create):
    if create and not os.path.lexists(START_ROOT):os.mkdir(START_ROOT,0o700)
    private_dir(START_ROOT)
    fd=os.open(START_ROOT+'/.lock',os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_WRONLY|os.O_CREAT if create else os.O_RDONLY),0o600)
    try:
        v=os.fstat(fd);need(stat.S_ISREG(v.st_mode) and v.st_uid==0 and stat.S_IMODE(v.st_mode)==0o600 and v.st_nlink==1)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd
    except BaseException:os.close(fd);raise

def starting_source(require_equal):
    # Caller holds the accepted parent's existing lock; never creates/repairs a parent.
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
    proof=working_compare();need(proof['SOURCE_INBOUNDS']==proof['CURRENT_INBOUNDS'])
    source=working_logical(DESTINATION+'/database.sqlite',True);need(source==final['restoredLogicalSha256'])
    if require_equal:need(working_logical(DATABASE)==source);working_service(True)
    return proof,source

def starting_active():
    fields=working_service(False)
    need(fields['ActiveState']=='active' and fields['SubState']=='running' and int(fields['MainPID'])>0)
    result=subprocess.run(['/usr/bin/systemctl','show','--no-pager','--property=Job','--','x-ui.service'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,check=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(not result.stderr and result.stdout in (b'Job=0\n',b'Job=\n'))
    # The running process must be the existing verified program, never a restored executable.
    executable=os.readlink('/proc/'+fields['MainPID']+'/exe');need(executable==RUNTIME+'/x-ui')
    return fields['MainPID']

def starting_store(path,value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii');need(len(raw)<=2048)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as output:need(output.write(raw)==len(raw));output.flush();os.fsync(output.fileno())
    working_sync_dir(os.path.dirname(path))

def starting_preflight():
    parent=working_lock(False)
    try:
        starting_capacity();need(not os.path.lexists(starting_path()));private_dir(WDB_DIRECTORY)
        marker=json.loads(read_file(WDB_DIRECTORY+'/restored.json',2048,True).decode('ascii'),object_pairs_hook=unique_object)
        need(marker.get('format')=='VELUM_WORKING_DB_RESTORED_V1' and marker.get('scope')==WDB_SCOPE and marker.get('source')==EXPECTED_DB)
        working_service(True);tick()
        sys.stdout.write('READY\n')
    finally:os.close(parent)

def starting_write():
    global START_DISPATCHED
    own=starting_lock(True)
    try:
        parent=working_lock(False)
        try:
            starting_capacity();directory=starting_path();need(not os.path.lexists(directory))
            proof,logical=starting_source(True);stamp=restore_source_stamp();tick()
            # A private exclusive per-parent reservation prevents a second activation attempt,
            # even if the command or its client disappears after publishing this intent.
            os.mkdir(directory,0o700);private_dir(directory)
            intent={'format':'VELUM_RESTORED_START_INTENT_V1','scope':START_SCOPE,'restore':WDB_SCOPE,'source':EXPECTED_DB,'logical':logical,'schema':proof['SOURCE_SCHEMA'],'inbounds':int(proof['SOURCE_INBOUNDS'])}
            starting_store(directory+'/intent.json',intent);working_sync_dir(START_ROOT)
            working_service(True);need(restore_source_stamp()==stamp);tick()
            START_DISPATCHED=True
            result=subprocess.run(['/usr/bin/systemctl','start','--','x-ui.service'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            need(result.returncode==0 and not result.stdout and not result.stderr);tick()
            # This exit is only request evidence. A separate invocation must observe current state.
            sys.stdout.write('SERVICE_START_REQUESTED\n')
        finally:os.close(parent)
    finally:os.close(own)

def starting_read():
    own=starting_lock(False)
    try:
        parent=working_lock(False)
        try:
            directory=starting_path();private_dir(directory);need(set(os.listdir(directory))=={'intent.json'})
            intent=json.loads(read_file(directory+'/intent.json',2048,True).decode('ascii'),object_pairs_hook=unique_object)
            need(set(intent)=={'format','scope','restore','source','logical','schema','inbounds'})
            need(intent['format']=='VELUM_RESTORED_START_INTENT_V1' and intent['scope']==START_SCOPE and intent['restore']==WDB_SCOPE and intent['source']==EXPECTED_DB)
            need(type(intent['inbounds'])is int and 0<=intent['inbounds']<=256)
            need(all(isinstance(intent[k],str) and re.fullmatch('[0-9a-f]{64}',intent[k]) for k in ('logical','schema')))
            pid=starting_active();proof,logical=starting_source(False)
            need(intent['logical']==logical and intent['schema']==proof['CURRENT_SCHEMA']==proof['SOURCE_SCHEMA'] and str(intent['inbounds'])==proof['CURRENT_INBOUNDS'])
            tick();need(starting_active()==pid)
            rows=[('FORMAT','VELUM_RESTORED_PANEL_START_V1'),('SCOPE',START_SCOPE),('SOURCE_RESTORE',WDB_SCOPE),('VERSION',VERSION),('ARCH',ARCH),('SCHEMA',intent['schema']),('INBOUNDS',str(intent['inbounds'])),('SERVICE','ACTIVE')]
            sys.stdout.write(''.join(k+'='+v+'\n' for k,v in rows))
        finally:os.close(parent)
    finally:os.close(own)

def starting_main():
    global START_SCOPE,WDB_SCOPE,WDB_DIRECTORY,EXPECTED_ENDPOINT,DEADLINE,WORKING_DEADLINE,START_DISPATCHED,START_MODE
    START_DISPATCHED=False;START_MODE=None;started=time.monotonic()
    need(len(sys.argv)==14 and sys.argv[1] in ('preflight','write','read'))
    START_MODE=sys.argv.pop(1);START_SCOPE=sys.argv.pop(1);WDB_SCOPE=sys.argv[1];EXPECTED_ENDPOINT=sys.argv.pop(2)
    need(all(re.fullmatch('[0-9a-f]{64}',v) for v in (START_SCOPE,WDB_SCOPE,EXPECTED_ENDPOINT)))
    WDB_DIRECTORY=WDB_ROOT+'/'+WDB_SCOPE[:32]
    saved=sys.argv[1];sys.argv[1]='space';capture=io.StringIO()
    with contextlib.redirect_stdout(capture):restore_main()
    sys.argv[1]=saved;DEADLINE=WORKING_DEADLINE=started+(8 if START_MODE=='preflight' else 135)
    if START_MODE=='preflight':starting_preflight()
    elif START_MODE=='write':starting_write()
    else:starting_read()

if __name__=='__main__':
    try:starting_main()
    except BaseException:
        if globals().get('START_MODE')=='write' and not globals().get('START_DISPATCHED',True):sys.stdout.write('NOT_STARTED\n')
        sys.exit(81)

""".trimIndent()
}

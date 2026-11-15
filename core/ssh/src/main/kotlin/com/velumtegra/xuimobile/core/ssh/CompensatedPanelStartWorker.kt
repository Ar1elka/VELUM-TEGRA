package com.velumtegra.xuimobile.core.ssh
/** Fixed service activation after exact completed DB compensation; separate readback, no DB copy. */
internal object CompensatedPanelStartWorker{
    val source:String=BeforeCopyReturnWorker.source.substringBefore("\nif __name__=='__main__':")+"\n"+"""

CPS_ROOT='/root/.velum-tegra-compensated-panel-starts'

def compensated_source(stopped):
    # Read immutable return artifacts. Never repair or infer a missing completion.
    private_dir(RETURN_DIRECTORY);need(set(os.listdir(RETURN_DIRECTORY))=={'intent.json','displaced.sqlite','displaced.json','returned.json'})
    names=['intent.json','displaced.json','returned.json'];raws=[read_file(RETURN_DIRECTORY+'/'+n,2048,True) for n in names]
    intent,displaced,final=[json.loads(raw.decode('ascii'),object_pairs_hook=unique_object) for raw in raws]
    need(intent==returning_intent() and type(intent.get('beforeBytes'))is int)
    need(set(displaced)=={'format','scope','sha256','logical','bytes'} and displaced['format']=='VELUM_BEFORE_RETURN_DISPLACED_V1' and displaced['scope']==RETURN_SCOPE)
    need(type(displaced['bytes'])is int and 1<=displaced['bytes']<=MAX_DB)
    need(all(isinstance(displaced[k],str) and re.fullmatch('[0-9a-f]{64}',displaced[k]) for k in ('sha256','logical')))
    expected=dict(displaced);expected['format']='VELUM_BEFORE_RETURN_COMPLETED_V1';expected['beforeLogical']=RETURN_LOGICAL;need(final==expected and type(final.get('bytes'))is int)
    displaced_path=RETURN_DIRECTORY+'/displaced.sqlite';info=file_info(displaced_path,True,MAX_DB)
    need(info[4]==displaced['bytes'] and digest_file(displaced_path,MAX_DB,True)==displaced['sha256'] and working_logical(displaced_path,True)==displaced['logical'])
    private_dir(WDB_DIRECTORY);need(set(os.listdir(WDB_DIRECTORY)) in ({'before.sqlite','before.json'},{'before.sqlite','before.json','restored.json'}))
    before_path=WDB_DIRECTORY+'/before.sqlite';raw=read_file(WDB_DIRECTORY+'/before.json',2048,True)
    before=json.loads(raw.decode('ascii'),object_pairs_hook=unique_object)
    need(before=={'format':'VELUM_WORKING_DB_BEFORE_V1','scope':WDB_SCOPE,'source':EXPECTED_DB,'previousSha256':RETURN_DB,'previousLogicalSha256':RETURN_LOGICAL,'previousBytes':RETURN_BYTES} and type(before.get('previousBytes'))is int)
    need(file_info(before_path,True,MAX_DB)[4]==RETURN_BYTES and digest_file(before_path,MAX_DB,True)==RETURN_DB and working_logical(before_path,True)==RETURN_LOGICAL)
    args=list(sys.argv)
    try:proof=working_compare()
    finally:sys.argv[:]=args
    schema,count=compatibility_schema(before_path,True)
    need((schema,count)==compatibility_schema(DATABASE,False) and schema==proof['CURRENT_SCHEMA']);working_endpoint(before_path,True)
    if stopped:returning_stopped();need(working_logical(DATABASE)==RETURN_LOGICAL)
    need([read_file(RETURN_DIRECTORY+'/'+n,2048,True) for n in names]==raws)
    need(read_file(WDB_DIRECTORY+'/before.json',2048,True)==raw and file_info(displaced_path,True,MAX_DB)==info)
    stamp=(raw,tuple(raws),file_info(before_path,True,MAX_DB),info,restore_source_stamp())
    return schema,count,stamp

def compensated_active():
    fields=working_service(False)
    need(fields['ActiveState']=='active' and fields['SubState']=='running' and int(fields['MainPID'])>0)
    result=subprocess.run(['/usr/bin/systemctl','show','--no-pager','--property=Job','--','x-ui.service'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,check=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(not result.stderr and result.stdout in (b'Job=0\n',b'Job=\n'))
    need(os.readlink('/proc/'+fields['MainPID']+'/exe')==RUNTIME+'/x-ui')
    return fields['MainPID']

def compensated_capacity(create):
    private_dir(HOME)
    if not os.path.lexists(CPS_ROOT):need(create);os.mkdir(CPS_ROOT,0o700);working_sync_dir(HOME)
    private_dir(CPS_ROOT);names=os.listdir(CPS_ROOT);need(len(names)<=5)
    for name in names:
        if name=='.lock':file_info(CPS_ROOT+'/.lock',True,4096)
        else:need(re.fullmatch('[0-9a-f]{32}',name));private_dir(CPS_ROOT+'/'+name)
    slots=len([n for n in names if n!='.lock']);need(slots<=4);return slots

def compensated_lock(create):
    compensated_capacity(create)
    fd=os.open(CPS_ROOT+'/.lock',os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_WRONLY|os.O_CREAT if create else os.O_RDONLY),0o600)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd
    except BaseException:os.close(fd);raise

def compensated_intent(schema,count):return {'format':'VELUM_COMPENSATED_START_INTENT_V1','scope':CPS_SCOPE,'return':RETURN_SCOPE,'restore':WDB_SCOPE,'beforeLogical':RETURN_LOGICAL,'schema':schema,'inbounds':count}

def compensated_write():
    parent=working_lock(False)
    try:
        returned=returning_lock(False)
        try:
            schema,count,stamp=compensated_source(True)
            own=compensated_lock(True)
            try:
                need(compensated_capacity(False)<4 and not os.path.lexists(CPS_DIRECTORY))
                os.mkdir(CPS_DIRECTORY,0o700);private_dir(CPS_DIRECTORY)
                returning_store(CPS_DIRECTORY+'/intent.json',compensated_intent(schema,count));working_sync_dir(CPS_ROOT)
                need(compensated_source(True)==(schema,count,stamp));returning_stopped();tick()
                # Exactly one fixed activation; request success is never active/authenticated proof.
                result=subprocess.run(['/usr/bin/systemctl','start','--','x-ui.service'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                need(result.returncode==0 and not result.stdout and not result.stderr);tick()
                sys.stdout.write('COMPENSATED_START_REQUESTED\n')
            finally:os.close(own)
        finally:os.close(returned)
    finally:os.close(parent)

def compensated_read():
    parent=working_lock(False)
    try:
        returned=returning_lock(False)
        try:
            own=compensated_lock(False)
            try:
                private_dir(CPS_DIRECTORY);need(set(os.listdir(CPS_DIRECTORY))=={'intent.json'})
                raw=read_file(CPS_DIRECTORY+'/intent.json',2048,True);intent=json.loads(raw.decode('ascii'),object_pairs_hook=unique_object)
                pid=compensated_active();schema,count,stamp=compensated_source(False)
                need(intent==compensated_intent(schema,count) and type(intent.get('inbounds'))is int)
                tick();need(compensated_active()==pid and read_file(CPS_DIRECTORY+'/intent.json',2048,True)==raw)
                need(compensated_source(False)==(schema,count,stamp) and compensated_active()==pid)
                rows=[('FORMAT','VELUM_COMPENSATED_PANEL_START_V1'),('SCOPE',CPS_SCOPE),('RETURN',RETURN_SCOPE),('VERSION',VERSION),('ARCH',ARCH),('SCHEMA',schema),('INBOUNDS',str(count)),('SERVICE','ACTIVE'),('STATE','STRUCTURAL_READBACK')]
                sys.stdout.write(''.join(k+'='+v+'\n' for k,v in rows))
            finally:os.close(own)
        finally:os.close(returned)
    finally:os.close(parent)

def compensated_main():
    global CPS_SCOPE,CPS_DIRECTORY,RETURN_SCOPE,RETURN_DB,RETURN_LOGICAL,RETURN_BYTES,RETURN_DIRECTORY,DEADLINE,WORKING_DEADLINE
    started=time.monotonic();need(len(sys.argv)==18 and sys.argv[1] in ('write','read'));mode=sys.argv.pop(1);CPS_SCOPE=sys.argv.pop(1)
    RETURN_SCOPE=sys.argv.pop(1);RETURN_DB=sys.argv.pop(1);RETURN_LOGICAL=sys.argv.pop(1);size=sys.argv.pop(1)
    need(all(re.fullmatch('[0-9a-f]{64}',v) for v in (CPS_SCOPE,RETURN_SCOPE,RETURN_DB,RETURN_LOGICAL)) and re.fullmatch('[1-9][0-9]{0,9}',size))
    RETURN_BYTES=int(size);need(1<=RETURN_BYTES<=MAX_DB);sys.argv.insert(1,'space')
    with contextlib.redirect_stdout(io.StringIO()):working_main()
    DEADLINE=WORKING_DEADLINE=started+135;RETURN_DIRECTORY=RETURN_ROOT+'/'+WDB_SCOPE[:32];CPS_DIRECTORY=CPS_ROOT+'/'+WDB_SCOPE[:32]
    if mode=='write':compensated_write()
    else:compensated_read()

if __name__=='__main__':
    try:compensated_main()
    except BaseException:sys.exit(81)

""".trimIndent()
}

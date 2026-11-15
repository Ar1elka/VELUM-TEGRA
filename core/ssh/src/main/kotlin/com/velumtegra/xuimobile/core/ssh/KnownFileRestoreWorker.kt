package com.velumtegra.xuimobile.core.ssh
/** Same-release non-executable file recovery. No DB write, service command or restored program execution. */
internal object KnownFileRestoreWorker{
    val source:String=WorkingDatabaseRestoreWorker.source.substringBefore("\nif __name__=='__main__':")+
        "\ndef readiness_lock(path):"+RecoveryReadinessWorker.source.substringAfter("\ndef readiness_lock(path):").substringBefore("\nif __name__ == '__main__':")+"\n"+"""
FILE_ROOT='/root/.velum-tegra-known-file-restores'

def file_locks(create):
    locks=[]
    try:
        for path in (ROOT+'/.writer.lock',RESTORE_ROOT+'/.lock'):
            locks.append(readiness_lock(path))
        for root in ('/root/.velum-tegra-working-db-restores','/root/.velum-tegra-before-copy-returns','/root/.velum-tegra-compensated-panel-starts'):
            if os.path.lexists(root):private_dir(root);locks.append(readiness_lock(root+'/.lock'))
        if create and not os.path.lexists(FILE_ROOT):os.mkdir(FILE_ROOT,0o700);working_sync_dir(HOME)
        if os.path.lexists(FILE_ROOT):
            private_dir(FILE_ROOT)
            if create and not os.path.lexists(FILE_ROOT+'/.lock'):
                fd=os.open(FILE_ROOT+'/.lock',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.fsync(fd);os.close(fd);working_sync_dir(FILE_ROOT)
            locks.append(readiness_lock(FILE_ROOT+'/.lock'))
        elif not create:pass
        return locks
    except BaseException:
        for fd in reversed(locks):os.close(fd)
        raise

def file_slots():
    if not os.path.lexists(FILE_ROOT):return 0
    private_dir(FILE_ROOT);names=os.listdir(FILE_ROOT);need(len(names)<=5)
    for name in names:
        if name=='.lock':file_info(FILE_ROOT+'/.lock',True,4096)
        else:need(re.fullmatch('[0-9a-f]{32}',name));private_dir(FILE_ROOT+'/'+name)
    count=len([n for n in names if n!='.lock']);need(count<=4);return count

def file_inventory():
    with contextlib.redirect_stdout(io.StringIO()):restore_verify()
    raw=read_file(DESTINATION+'/inventory.json',65536,True);need(hashlib.sha256(raw).hexdigest()==EXPECTED_INVENTORY)
    inv=json.loads(raw.decode(),object_pairs_hook=unique_object)
    need(len(inv['files'])==EXPECTED_FILES);return {e['path']:e for e in inv['files']}

def file_hash_rows(inv,cur,digests):
    return [[p,sorted(inv[p]['groups']),cur[p][2][3],cur[p][2][4],digests[p]] for p in sorted(inv)]

def file_set_hash(rows):return hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()

def file_observe():
    stamp=restore_source_stamp();inv=file_inventory();version=compatibility_version();state=readiness_service()
    need(version[0]==VERSION and version[1]==ARCH and state[0]=='STOPPED')
    source_db=DESTINATION+'/database.sqlite';source_schema=compatibility_schema(source_db,True)
    need(compatibility_schema(DATABASE,False)==source_schema)
    sd=readiness_database(source_db,True);cd=readiness_database(DATABASE,False);need(sd[0]==cd[0] and sd[2]==cd[2])
    logical=working_logical(source_db,True);need(working_logical(DATABASE)==logical)
    observed=collect(DATABASE);cur=observed[0]
    need({p:sorted(v[1]) for p,v in cur.items()}=={p:e['groups'] for p,e in inv.items()})
    digests={};dev=os.stat(HOME).st_dev
    for path,(secret,groups,info) in cur.items():
        tick();need(info[0]==dev)
        fd,metadata=checked(path,secret=secret)
        try:need(signature(metadata)==info and metadata.st_gid==0)
        finally:os.close(fd)
        parent,unused=checked(os.path.dirname(path),directory=True)
        try:need(os.fstat(parent).st_dev==dev)
        finally:os.close(parent)
        digests[path]=digest_file(path,268435456,secret);need(file_info(path,secret)==info)
        e=inv[path]
        if e['mode']&0o111 or info[3]&0o111 or 'SERVICE' in groups:
            need((info[3],info[4],digests[path])==(e['mode'],e['bytes'],e['sha256']))
    need(collect(DATABASE)==observed and restore_source_stamp()==stamp and compatibility_version()==version and readiness_service()==state)
    need(working_logical(DATABASE)==logical)
    return inv,cur,digests,logical

def file_changes(observation):
    inv,cur,digests,logical=observation
    need(file_set_hash(file_hash_rows(inv,cur,digests))==EXPECTED_SET)
    changes=[]
    if os.path.lexists(FILE_ROOT):need(os.stat(FILE_ROOT).st_dev==os.stat(HOME).st_dev)
    for path in sorted(inv):
        e=inv[path];info=cur[path][2]
        if (info[3],info[4],digests[path])!=(e['mode'],e['bytes'],e['sha256']):
            need(not(e['mode']&0o111 or info[3]&0o111) and 'SERVICE' not in e['groups'])
            need(not os.listxattr(path,follow_symlinks=False))
            changes.append(dict(path=path,mode=e['mode'],bytes=e['bytes'],sha256=e['sha256'],oldMode=info[3],oldBytes=info[4],oldHash=digests[path],index=str(len(changes))))
    need(len(changes)==EXPECTED_COUNT)
    need(file_slots()<4 and not os.path.lexists(FILE_DIRECTORY))
    v=os.statvfs(HOME);need(v.f_bavail*v.f_frsize>=sum(e['oldBytes']+2*e['bytes'] for e in changes)+50331648)
    return changes

def file_private_copy(source,destination,size,digest):
    fd,info=checked(source);need(info.st_size==size)
    output=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    os.fchown(output,0,0)
    count=0;h=hashlib.sha256()
    with os.fdopen(fd,'rb') as inp,os.fdopen(output,'wb') as out:
        while True:
            tick();b=inp.read(1048576)
            if not b:break
            count+=len(b);need(count<=size);h.update(b);out.write(b)
        need(count==size and h.hexdigest()==digest and signature(os.fstat(inp.fileno()))==signature(info))
        out.flush();os.fsync(out.fileno())

def file_write_private(path,raw):
    need(len(raw)<=65536)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:need(out.write(raw)==len(raw));out.flush();os.fsync(out.fileno())

def file_expected_manifest(entries,logical):
    return {'format':'VELUM_KNOWN_FILE_BEFORE_V1','scope':FILE_SCOPE,'oldSet':EXPECTED_SET,'databaseLogical':logical,
        'archive':EXPECTED_ARCHIVE,'database':EXPECTED_DB,'inventory':EXPECTED_INVENTORY,'entries':entries}

def file_artifacts():
    private_dir(FILE_ROOT);private_dir(FILE_DIRECTORY)
    names=set(os.listdir(FILE_DIRECTORY));need(names in ({'before','after','pending','manifest.json'},{'before','after','pending','manifest.json','pending-return','return.intent'}))
    raw=read_file(FILE_DIRECTORY+'/manifest.json',65536,True);manifest=json.loads(raw.decode('ascii'),object_pairs_hook=unique_object)
    need(set(manifest)=={'format','scope','oldSet','databaseLogical','archive','database','inventory','entries'})
    entries=manifest['entries'];need(isinstance(entries,list) and len(entries)==EXPECTED_COUNT)
    observation=file_observe();inv,cur,digests,logical=observation
    need(manifest==file_expected_manifest(entries,logical))
    old={p:[p,sorted(e['groups']),e['mode'],e['bytes'],e['sha256']] for p,e in inv.items()}
    paths=set();desired=previous=0
    for index,e in enumerate(entries):
        tick();need(isinstance(e,dict) and set(e)=={'path','mode','bytes','sha256','oldMode','oldBytes','oldHash','index'})
        path=e['path'];need(path in inv and path not in paths and e['index']==str(index));paths.add(path)
        need(all(type(e[k])is int for k in ('mode','bytes','oldMode','oldBytes')))
        need(0<=e['oldMode']<=0o777 and e['oldMode']&0o022==0 and e['oldMode']&0o400!=0 and not(e['oldMode']&0o111))
        need(type(e['oldHash'])is str and re.fullmatch('[0-9a-f]{64}',e['oldHash']) and 0<=e['oldBytes']<=268435456)
        source=inv[path];need((e['mode'],e['bytes'],e['sha256'])==(source['mode'],source['bytes'],source['sha256']) and not e['mode']&0o111 and 'SERVICE' not in source['groups'])
        need((e['oldMode'],e['oldBytes'],e['oldHash'])!=(e['mode'],e['bytes'],e['sha256']))
        need(not os.listxattr(path,follow_symlinks=False))
        old[path]=[path,sorted(source['groups']),e['oldMode'],e['oldBytes'],e['oldHash']]
        current=(cur[path][2][3],cur[path][2][4],digests[path])
        if current==(e['mode'],e['bytes'],e['sha256']):desired+=1
        else:need(current==(e['oldMode'],e['oldBytes'],e['oldHash']));previous+=1
        for directory,size,hash in (('before',e['oldBytes'],e['oldHash']),('after',e['bytes'],e['sha256'])):
            private_dir(FILE_DIRECTORY+'/'+directory);leaf=FILE_DIRECTORY+'/'+directory+'/'+e['index']
            info=file_info(leaf,True,268435456);need(info[3]==0o600 and info[4]==size and digest_file(leaf,268435456,True)==hash)
    need(file_set_hash([old[p] for p in sorted(old)])==EXPECTED_SET)
    for path,e in inv.items():
        if path not in paths:need((cur[path][2][3],cur[path][2][4],digests[path])==(e['mode'],e['bytes'],e['sha256']))
    for directory in ('before','after'):need(set(os.listdir(FILE_DIRECTORY+'/'+directory))=={e['index'] for e in entries})
    for directory,returning in (('pending',False),('pending-return',True)):
        if directory not in names:continue
        private_dir(FILE_DIRECTORY+'/'+directory);remaining=set(os.listdir(FILE_DIRECTORY+'/'+directory));need(remaining<={e['index'] for e in entries})
        for e in entries:
            if e['index'] not in remaining:continue
            leaf=FILE_DIRECTORY+'/'+directory+'/'+e['index'];mode,size,hash=(e['oldMode'],e['oldBytes'],e['oldHash']) if returning else (e['mode'],e['bytes'],e['sha256'])
            info=file_info(leaf,False,268435456);need(info[3] in (0o600,mode) and info[4]==size and digest_file(leaf,268435456)==hash)
    mh=hashlib.sha256(raw).hexdigest()
    if 'return.intent' in names:need(read_file(FILE_DIRECTORY+'/return.intent',256,True)==(FILE_SCOPE+'\n'+mh+'\n').encode('ascii'))
    return entries,logical,mh,desired,previous

def file_replace(entry,returning):
    path=entry['path'];name=os.path.basename(path);parent_path=os.path.dirname(path)
    mode,size,hash=(entry['oldMode'],entry['oldBytes'],entry['oldHash']) if returning else (entry['mode'],entry['bytes'],entry['sha256'])
    current=file_info(path);actual=digest_file(path,268435456)
    if returning and (current[3],current[4],actual)==(mode,size,hash):return
    expected=(entry['mode'],entry['bytes'],entry['sha256']) if returning else (entry['oldMode'],entry['oldBytes'],entry['oldHash'])
    need((current[3],current[4],actual)==expected and not os.listxattr(path,follow_symlinks=False))
    parent,pstat=checked(parent_path,directory=True);directory=FILE_DIRECTORY+('/pending-return' if returning else '/pending');pending,unused=checked(directory,directory=True)
    try:
        leaf=directory+'/'+entry['index'];fd,info=checked(leaf)
        try:
            need(info.st_size==size and digest_file(leaf,268435456)==hash)
            need(info.st_dev==pstat.st_dev and current[0]==pstat.st_dev and info.st_gid==0 and not os.listxattr(leaf,follow_symlinks=False))
            os.fchmod(fd,mode);os.fsync(fd)
            need(file_info(path)==current and digest_file(path,268435456)==expected[2])
            again,unused=checked(parent_path,directory=True)
            try:need((os.fstat(again).st_dev,os.fstat(again).st_ino)==(pstat.st_dev,pstat.st_ino))
            finally:os.close(again)
            need(os.stat(entry['index'],dir_fd=pending,follow_symlinks=False).st_ino==info.st_ino)
            os.replace(entry['index'],name,src_dir_fd=pending,dst_dir_fd=parent)
            os.fsync(parent);os.fsync(pending)
        finally:os.close(fd)
    finally:os.close(pending);os.close(parent)

def file_apply():
    observation=file_observe();changes=file_changes(observation);inv,cur,digests,logical=observation
    os.mkdir(FILE_DIRECTORY,0o700);private_dir(FILE_DIRECTORY)
    for directory in ('before','after','pending'):os.mkdir(FILE_DIRECTORY+'/'+directory,0o700)
    for e in changes:
        need(file_info(e['path'])==cur[e['path']][2])
        file_private_copy(e['path'],FILE_DIRECTORY+'/before/'+e['index'],e['oldBytes'],e['oldHash'])
        source=DESTINATION+'/'+inv[e['path']]['member']
        file_private_copy(source,FILE_DIRECTORY+'/after/'+e['index'],e['bytes'],e['sha256'])
        file_private_copy(FILE_DIRECTORY+'/after/'+e['index'],FILE_DIRECTORY+'/pending/'+e['index'],e['bytes'],e['sha256'])
    need(file_observe()==observation)
    raw=json.dumps(file_expected_manifest(changes,logical),sort_keys=True,separators=(',',':')).encode('ascii')
    for directory in ('before','after','pending'):working_sync_dir(FILE_DIRECTORY+'/'+directory)
    file_write_private(FILE_DIRECTORY+'/manifest.json',raw);working_sync_dir(FILE_DIRECTORY);working_sync_dir(FILE_ROOT)
    file_artifacts()
    for e in changes:
        need(readiness_service()[0]=='STOPPED' and working_logical(DATABASE)==logical);file_replace(e,False)
    result=file_artifacts();need(result[3]==EXPECTED_COUNT);sys.stdout.write('FILES_WRITTEN\n')

def file_return():
    entries,logical,mh,desired,previous=file_artifacts();need(mh==EXPECTED_BEFORE_MANIFEST)
    need(not os.path.lexists(FILE_DIRECTORY+'/return.intent') and not os.path.lexists(FILE_DIRECTORY+'/pending-return'))
    v=os.statvfs(FILE_ROOT);need(v.f_bavail*v.f_frsize>=sum(e['oldBytes'] for e in entries)+16777216)
    os.mkdir(FILE_DIRECTORY+'/pending-return',0o700)
    for e in entries:file_private_copy(FILE_DIRECTORY+'/before/'+e['index'],FILE_DIRECTORY+'/pending-return/'+e['index'],e['oldBytes'],e['oldHash'])
    working_sync_dir(FILE_DIRECTORY+'/pending-return')
    file_write_private(FILE_DIRECTORY+'/return.intent',(FILE_SCOPE+'\n'+mh+'\n').encode('ascii'));working_sync_dir(FILE_DIRECTORY)
    need(file_artifacts()[2]==mh)
    for e in entries:
        need(readiness_service()[0]=='STOPPED' and working_logical(DATABASE)==logical);file_replace(e,True)
    result=file_artifacts();need(result[4]==EXPECTED_COUNT);sys.stdout.write('FILES_RETURNED\n')

def file_main():
    global FILE_SCOPE,EXPECTED_SET,EXPECTED_COUNT,FILE_DIRECTORY,EXPECTED_BEFORE_MANIFEST,DEADLINE
    started=time.monotonic();args=list(sys.argv);need(len(args)==15 and args[1] in ('plan','apply','read','return'))
    mode=args[1];FILE_SCOPE,EXPECTED_SET=args[2:4];EXPECTED_BEFORE_MANIFEST=args[14]
    need(all(re.fullmatch('[0-9a-f]{64}',v) for v in (FILE_SCOPE,EXPECTED_SET,EXPECTED_BEFORE_MANIFEST)))
    need(re.fullmatch('[1-9][0-9]?',args[4]));EXPECTED_COUNT=int(args[4]);need(EXPECTED_COUNT<=96)
    sys.argv=[args[0],'check']+args[5:14]
    with contextlib.redirect_stdout(io.StringIO()):restore_main()
    DEADLINE=started+175;FILE_DIRECTORY=FILE_ROOT+'/'+FILE_SCOPE[:32]
    locks=file_locks(mode=='apply')
    try:
        if mode=='plan':
            p=file_observe();file_changes(p)
            sys.stdout.write('FORMAT=VELUM_KNOWN_FILE_PREPARED_V1\nSCOPE='+FILE_SCOPE+'\nDATABASE_LOGICAL='+p[3]+'\nCHANGED='+str(EXPECTED_COUNT)+'\n')
        elif mode=='apply':file_apply()
        elif mode=='return':file_return()
        else:
            entries,logical,mh,desired,previous=file_artifacts()
            fields=[('FORMAT','VELUM_KNOWN_FILE_READ_V1'),('SCOPE',FILE_SCOPE),('MANIFEST',mh),('DATABASE_LOGICAL',logical),('DESIRED',str(desired)),('PREVIOUS',str(previous)),('FILES',str(EXPECTED_COUNT))]
            sys.stdout.write(''.join(k+'='+v+'\n' for k,v in fields))
    finally:
        for fd in reversed(locks):os.close(fd)

if __name__=='__main__':
    try:file_main()
    except BaseException:sys.exit(81)
""".trimIndent()
}

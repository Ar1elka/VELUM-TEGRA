package com.velumtegra.xuimobile.core.ssh
/** Closed explicit read entrypoint. Existing copy helpers are never invoked. */
internal object RecoveryReadinessWorker {
    val source:String=RestoreCompatibilityWorker.source.substringBefore("\nif __name__ == '__main__':")+"\n"+"""
def readiness_lock(path):
    info=file_info(path,True,4096);need(info[3]==0o600)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        need(signature(os.fstat(fd))==info);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return fd
    except BaseException:os.close(fd);raise

def readiness_service():
    names=('LoadState','ActiveState','SubState','MainPID','ControlPID','TriggeredBy','KillMode','ControlGroup','Job','Delegate')
    result=subprocess.run(['/usr/bin/systemctl','show','--no-pager']+['--property='+p for p in names]+['--','x-ui.service'],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,check=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    need(not result.stderr and len(result.stdout)<=2048)
    pairs=[row.split('=',1) for row in result.stdout.decode('ascii').splitlines()]
    need(len(pairs)==len(names) and all(len(p)==2 for p in pairs));f=dict(pairs);need(set(f)==set(names))
    state='UNAVAILABLE'
    if f['LoadState']=='loaded' and f['ControlPID']=='0' and not f['TriggeredBy'] and f['KillMode'] in ('control-group','mixed') and f['Job'] in ('0','') and f['Delegate']=='no' and f['ControlGroup'] in ('','/system.slice/x-ui.service'):
        if f['ActiveState']=='active' and f['SubState']=='running' and re.fullmatch('[1-9][0-9]{0,8}',f['MainPID']):state='REQUIRED'
        elif f['ActiveState']=='inactive' and f['SubState']=='dead' and f['MainPID']=='0' and f['ControlGroup'] in ('','/system.slice/x-ui.service'):
            group='/sys/fs/cgroup/system.slice/x-ui.service'
            if not os.path.lexists(group):state='STOPPED'
            else:
                rootfd,unused=checked(group,directory=True)
                try:
                    names=os.listdir(rootfd);need(len(names)<=128)
                    need(all(not stat.S_ISDIR(os.stat(n,dir_fd=rootfd,follow_symlinks=False).st_mode) for n in names))
                finally:os.close(rootfd)
                fd,unused=checked(group+'/cgroup.procs')
                try:
                    if os.read(fd,4097).strip()==b'':state='STOPPED'
                finally:os.close(fd)
    return state,f

def readiness_database(path,immutable):
    con=connect(path,immutable)
    try:
        con.execute('BEGIN')
        need(con.execute('PRAGMA quick_check').fetchall()==[('ok',)] and con.execute('PRAGMA foreign_key_check').fetchone() is None)
        page=con.execute('PRAGMA page_size').fetchone()[0];need(type(page)is int and page in (512,1024,2048,4096,8192,16384,32768,65536))
        mode=con.execute('PRAGMA journal_mode').fetchone()[0];need(mode in ('delete','wal'))
        rows=con.execute("SELECT key,value FROM settings WHERE key IN ('webPort','webBasePath','webListen') LIMIT 4").fetchall()
        need(2<=len(rows)<=3 and len(dict(rows))==len(rows) and {'webPort','webBasePath'}<=set(dict(rows)))
        need(all(isinstance(k,str) and isinstance(v,str) and len(v.encode())<=1024 for k,v in rows))
        v=dict(rows);raw=json.dumps([v['webPort'],v['webBasePath'],v.get('webListen','')],ensure_ascii=True,separators=(',',':')).encode('ascii')
        return page,mode,hashlib.sha256(raw).hexdigest()
    finally:con.close()

def readiness_main():
    global DEADLINE,ARCH
    started=time.monotonic();need(len(sys.argv)==12)
    operation=sys.argv.pop(1);need(re.fullmatch('[0-9a-f]{64}',operation))
    need(re.fullmatch('0|[1-9][0-9]{0,18}',sys.argv[1]));revision=sys.argv.pop(1)
    sys.argv.insert(1,'check')
    # Only initializes/checks existing source and isolated copy. Never calls the copy entrypoint.
    with contextlib.redirect_stdout(io.StringIO()):restore_main()
    DEADLINE=started+135
    locks=[]
    try:
        locks.append(readiness_lock(ROOT+'/.writer.lock'));locks.append(readiness_lock(RESTORE_ROOT+'/.lock'))
        stamp=restore_source_stamp()
        with contextlib.redirect_stdout(io.StringIO()):restore_verify()
        raw=read_file(DESTINATION+'/inventory.json',65536,True);need(hashlib.sha256(raw).hexdigest()==EXPECTED_INVENTORY)
        inv=json.loads(raw.decode('utf-8'),object_pairs_hook=unique_object);expected={e['path']:e for e in inv['files']}
        source_schema=compatibility_schema(DESTINATION+'/database.sqlite',True)
        source_db=readiness_database(DESTINATION+'/database.sqlite',True);need(source_db[1]=='delete')
        version=compatibility_version();status=readiness_service();db_identity=file_info(DATABASE,True)
        current_schema=compatibility_schema(DATABASE,False);current_db=readiness_database(DATABASE,False)
        old_arch=ARCH;ARCH=version[1]
        try:observed=collect(DATABASE)
        finally:ARCH=old_arch
        digests={};rows=[]
        for path,(secret,groups,info) in sorted(observed[0].items()):
            tick();digest=digest_file(path,268435456,secret);need(file_info(path,secret)==info);digests[path]=digest
            rows.append([path,sorted(groups),info[3],info[4],digest])
        def difference(a,b):
            common=set(a)&set(b)
            changed=sum(1 for p in common if (expected[p]['mode'],expected[p]['bytes'],expected[p]['sha256'])!=(observed[0][p][2][3],observed[0][p][2][4],digests[p]))
            return [len(a),len(b),changed,len(set(b)-set(a)),len(set(a)-set(b))]
        totals=difference(expected,observed[0]);groups={}
        for g in ('RUNTIME','SERVICE','PANEL_TLS','XRAY_TLS','XRAY_DATA'):
            groups[g]=difference({p for p,e in expected.items() if g in e['groups']},{p for p,e in observed[0].items() if g in e[1]})
        source_bytes=sum(e['bytes'] for e in expected.values());current_bytes=sum(e[2][4] for e in observed[0].values())
        wal='ABSENT'
        if os.path.lexists(DATABASE+'-wal'):
            info=file_info(DATABASE+'-wal',True,MAX_DB);wal='PRESENT' if info[4] else 'EMPTY'
        need(current_db[1]=='wal' or wal!='PRESENT')
        # Reobserve actual byte hashes; metadata-only fences cannot detect changed content with forged timestamps.
        for path,(secret,groups_unused,info) in observed[0].items():need(digest_file(path,268435456,secret)==digests[path] and file_info(path,secret)==info)
        old_arch=ARCH;ARCH=version[1]
        try:need(collect(DATABASE)==observed)
        finally:ARCH=old_arch
        need(compatibility_schema(DATABASE,False)==current_schema and readiness_database(DATABASE,False)==current_db)
        need(file_info(DATABASE,True)[:4]==db_identity[:4] and compatibility_version()==version and readiness_service()==status)
        need(restore_source_stamp()==stamp)
        with contextlib.redirect_stdout(io.StringIO()):restore_verify()
        fields=[('FORMAT','VELUM_RECOVERY_READINESS_V1'),('SCOPE',operation),('REVISION',revision),('ARCHIVE',EXPECTED_ARCHIVE),('DATABASE',EXPECTED_DB),('INVENTORY',EXPECTED_INVENTORY),
            ('CURRENT_VERSION',version[0]),('CURRENT_ARCH',version[1]),('SOURCE_SCHEMA',source_schema[0]),('CURRENT_SCHEMA',current_schema[0]),
            ('TOTAL',','.join(map(str,totals))),('SOURCE_BYTES',str(source_bytes)),('CURRENT_BYTES',str(current_bytes)),
            ('ENDPOINT','MATCH' if source_db[2]==current_db[2] else 'DIFFERENT'),('PAGE_SIZE','MATCH' if source_db[0]==current_db[0] else 'DIFFERENT'),
            ('JOURNAL',current_db[1].upper()),('WAL',wal),('QUIESCENCE',status[0]),('CURRENT_SET',hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()),('MIGRATION','UNVERIFIED')]
        fields += [(g,','.join(map(str,groups[g]))) for g in ('RUNTIME','SERVICE','PANEL_TLS','XRAY_TLS','XRAY_DATA')]
        sys.stdout.write(''.join(k+'='+v+'\n' for k,v in fields))
    finally:
        for fd in reversed(locks):os.close(fd)

if __name__ == '__main__':
    try:readiness_main()
    except BaseException:sys.exit(81)
""".trimIndent()
}

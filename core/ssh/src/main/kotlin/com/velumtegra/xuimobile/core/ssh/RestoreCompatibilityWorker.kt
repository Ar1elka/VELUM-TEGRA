package com.velumtegra.xuimobile.core.ssh

/** Fixed read-only comparison; no restored binary, mutation command or schema migration. */
internal object RestoreCompatibilityWorker {
    val source: String = RestoreCheckWorker.source.substringBefore("\nif __name__ == '__main__':") + "\n" + """
# Read-only compatibility appendix. Restored files are never executed.
def compatibility_schema(path, immutable):
    con = connect(path, immutable)
    try:
        con.execute('BEGIN')
        need(con.execute('PRAGMA quick_check').fetchall() == [('ok',)])
        rows = con.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY type,name LIMIT 129").fetchall()
        need(1 <= len(rows) <= 128)
        for kind,name,table,sql in rows:
            need(kind in ('table','index') and isinstance(name,str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,95}',name))
            need(isinstance(table,str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,95}',table))
            need(sql is None or isinstance(sql,str) and len(sql.encode('utf-8')) <= 65536 and 'VIRTUAL TABLE' not in sql.upper())
        values = [con.execute('PRAGMA user_version').fetchone()[0], con.execute('PRAGMA application_id').fetchone()[0], rows]
        raw = json.dumps(values,ensure_ascii=True,separators=(',',':')).encode('ascii'); need(len(raw)<=262144)
        need(any(r[0]=='table' and r[1]=='inbounds' for r in rows))
        count=con.execute('SELECT count(*) FROM (SELECT 1 FROM inbounds LIMIT 257)').fetchone()[0]; need(type(count)is int and 0<=count<=256)
        return hashlib.sha256(raw).hexdigest(),count
    finally: con.close()


def compatibility_version():
    fields, paths = service()
    binary = RUNTIME + '/x-ui'; before = file_info(binary)
    need(before[4]>0 and before[3]&0o100!=0)
    result=subprocess.run([binary,'-v'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},
        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS,(2147483648,2147483648)))
    need(result.returncode==0 and not result.stderr and len(result.stdout)<=96)
    value=result.stdout.decode('ascii').rstrip('\r\n'); value=value[1:] if value.startswith('v') else value
    need(re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',value) and file_info(binary)==before)
    machine=os.uname().machine; need(machine in ('x86_64','aarch64'))
    return value,('AMD64' if machine=='x86_64' else 'ARM64'),before,fields


def compatibility_main():
    global DEADLINE, ARCH
    started=time.monotonic(); operation=sys.argv[1]; need(re.fullmatch('[0-9a-f]{64}',operation))
    sys.argv[1]='check'
    capture=io.StringIO()
    with contextlib.redirect_stdout(capture): restore_main()
    source_stamp=restore_source_stamp()
    DEADLINE=started+115
    raw=read_file(DESTINATION+'/inventory.json',65536,True); need(hashlib.sha256(raw).hexdigest()==EXPECTED_INVENTORY)
    inventory=json.loads(raw.decode('utf-8'),object_pairs_hook=unique_object)
    source_schema,source_count=compatibility_schema(DESTINATION+'/database.sqlite',True)
    version,architecture,binary_before,service_before=compatibility_version()
    target_schema=target_count=None
    try: target_schema,target_count=compatibility_schema(DATABASE,False)
    except (Rejected,OSError,sqlite3.Error): pass
    file_set='UNAVAILABLE'; changed=None
    old_arch=ARCH
    try:
        ARCH=architecture
        before=collect(DATABASE)
        expected={e['path']:e for e in inventory['files']}
        observed={p:sorted(v[1]) for p,v in before[0].items()}
        same={p:e['groups'] for p,e in expected.items()}==observed
        changed=0
        for path,details in before[0].items():
            tick(); digest=digest_file(path,268435456,details[0]); need(file_info(path,details[0])==details[2])
            e=expected.get(path)
            if e is not None and (e['mode']!=details[2][3] or e['bytes']!=details[2][4] or e['sha256']!=digest): changed+=1
        need(collect(DATABASE)==before)
        file_set='MATCH' if same else 'DIFFERENT'
    except (Rejected,OSError,sqlite3.Error,subprocess.SubprocessError): file_set='UNAVAILABLE';changed=None
    finally: ARCH=old_arch
    tick()
    if target_schema is not None: need(compatibility_schema(DATABASE,False)==(target_schema,target_count))
    need(compatibility_version()==(version,architecture,binary_before,service_before) and restore_source_stamp()==source_stamp)
    fields=[('FORMAT','VELUM_RESTORE_COMPARISON_V1'),('SCOPE',operation),('SOURCE_RESTORE',RUN_SCOPE),
      ('SOURCE_ARCHIVE',EXPECTED_ARCHIVE),('SOURCE_DB',EXPECTED_DB),('SOURCE_INVENTORY',EXPECTED_INVENTORY),
      ('CURRENT_VERSION',version),('CURRENT_ARCH',architecture),('SOURCE_SCHEMA',source_schema),
      ('CURRENT_SCHEMA',target_schema or '-'),('FILE_SET',file_set),('CHANGED_FILES',str(changed) if changed is not None else '-'),
      ('SOURCE_INBOUNDS',str(source_count)),('CURRENT_INBOUNDS',str(target_count) if target_count is not None else '-')]
    sys.stdout.write(''.join(k+'='+v+'\n' for k,v in fields))

if __name__ == '__main__':
    try: compatibility_main()
    except BaseException: sys.exit(81)

""".trimIndent()
}

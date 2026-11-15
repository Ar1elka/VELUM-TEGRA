package com.velumtegra.xuimobile.core.ssh
/** Fixed read-only entrypoint. The accepted writer prefix is unchanged and is never dispatched. */
internal object BeforeCopyEvidenceWorker {
    val source:String=WorkingDatabaseRestoreWorker.source.substringBefore("\nif __name__=='__main__':")+"\n"+"""
# Only this entrypoint executes. No mkdir/copy/backup/service mutation is called.
def before_main():
    global DEADLINE
    started=time.monotonic()
    need(len(sys.argv)==13 and sys.argv[1]=='space')
    with contextlib.redirect_stdout(io.StringIO()):working_main()
    DEADLINE=started+135
    lock=working_lock(False)
    try:
        private_dir(WDB_DIRECTORY)
        names=set(os.listdir(WDB_DIRECTORY))
        need(names in ({'before.sqlite','before.json'},{'before.sqlite','before.json','restored.json'}))
        before_path=WDB_DIRECTORY+'/before.sqlite';manifest_path=WDB_DIRECTORY+'/before.json'
        stamp=(file_info(before_path,True,MAX_DB),file_info(manifest_path,True,2048))
        raw=read_file(manifest_path,2048,True)
        before=json.loads(raw.decode('ascii'),object_pairs_hook=unique_object)
        need(set(before)=={'format','scope','source','previousSha256','previousLogicalSha256','previousBytes'})
        need(before['format']=='VELUM_WORKING_DB_BEFORE_V1' and before['scope']==WDB_SCOPE and before['source']==EXPECTED_DB)
        need(type(before['previousBytes'])is int and 1<=before['previousBytes']<=MAX_DB and stamp[0][4]==before['previousBytes'])
        need(all(isinstance(before[k],str) and re.fullmatch('[0-9a-f]{64}',before[k]) for k in ('previousSha256','previousLogicalSha256')))
        need(digest_file(before_path,MAX_DB,True)==before['previousSha256'])
        need(working_logical(before_path,True)==before['previousLogicalSha256'])
        # The private prior DB must contain the exact reviewed endpoint too.
        working_endpoint(before_path,True)
        service_before=working_service();state='ACTIVE' if service_before['ActiveState']=='active' else 'INACTIVE'
        if state=='INACTIVE':working_service(True)
        current='UNAVAILABLE';structure='UNAVAILABLE';completion='PARTIAL';current_digest=None
        final_raw=None;final_stamp=None
        if 'restored.json' in names:
            final_stamp=file_info(WDB_DIRECTORY+'/restored.json',True,2048)
            final_raw=read_file(WDB_DIRECTORY+'/restored.json',2048,True)
        try:
            # Exact accepted archive/isolated source and current known-file comparison.
            capture=io.StringIO()
            with contextlib.redirect_stdout(capture):compatibility_main()
            DEADLINE=started+135
            pairs=[line.split('=') for line in capture.getvalue().splitlines()]
            need(len(pairs)==14 and all(len(p)==2 for p in pairs));proof=dict(pairs)
            prior_schema,unused=compatibility_schema(before_path,True)
            structure='MATCH' if proof['CURRENT_VERSION']==VERSION and proof['CURRENT_ARCH']==ARCH and proof['SOURCE_SCHEMA']==proof['CURRENT_SCHEMA']==prior_schema and proof['FILE_SET']=='MATCH' and proof['CHANGED_FILES']=='0' else 'DIFFERENT'
        except (Rejected,OSError,sqlite3.Error,subprocess.SubprocessError,ValueError):
            structure='UNAVAILABLE'
        DEADLINE=started+135
        # A live panel's current database is deliberately not asserted as stable.
        if state=='INACTIVE':
            try:
                working_endpoint(DATABASE,False)
                current_digest=working_logical(DATABASE)
                current='SAME' if current_digest==before['previousLogicalSha256'] else 'DIFFERENT'
            except (Rejected,OSError,sqlite3.Error,ValueError):current='UNAVAILABLE'
        # COMPLETE means only a matching private completion manifest exists, not current recovery.
        if 'restored.json' in names:
            try:
                final=json.loads(final_raw.decode('ascii'),object_pairs_hook=unique_object)
                expected=dict(before);expected['format']='VELUM_WORKING_DB_RESTORED_V1'
                value=final.get('restoredLogicalSha256');need(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value))
                final_without=dict(final);final_without.pop('restoredLogicalSha256');need(final_without==expected);completion='COMPLETE'
            except (Rejected,OSError,ValueError,KeyError,UnicodeError):pass
        if current_digest is not None:need(working_logical(DATABASE)==current_digest)
        if final_raw is not None:
            need(read_file(WDB_DIRECTORY+'/restored.json',2048,True)==final_raw and file_info(WDB_DIRECTORY+'/restored.json',True,2048)==final_stamp)
        need(working_service()==service_before)
        if state=='INACTIVE':working_service(True)
        need(set(os.listdir(WDB_DIRECTORY))==names and read_file(manifest_path,2048,True)==raw)
        need((file_info(before_path,True,MAX_DB),file_info(manifest_path,True,2048))==stamp)
        need(digest_file(before_path,MAX_DB,True)==before['previousSha256'] and working_logical(before_path,True)==before['previousLogicalSha256'])
        rows=[('FORMAT','VELUM_BEFORE_COPY_V1'),('SCOPE',WDB_SCOPE),('BEFORE_DB_SHA256',before['previousSha256']),
            ('BEFORE_LOGICAL_SHA256',before['previousLogicalSha256']),('BEFORE_BYTES',str(before['previousBytes'])),
            ('SERVICE',state),('CURRENT_DB',current),('STRUCTURE',structure),('COPY_STATE',completion),('STATE','OBSERVED')]
        sys.stdout.write(''.join(k+'='+v+'\n' for k,v in rows))
    finally:os.close(lock)

if __name__=='__main__':
    try:before_main()
    except BaseException:sys.exit(81)
""".trimIndent()
}

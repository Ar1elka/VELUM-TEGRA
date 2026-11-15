#!/usr/bin/env python3
"""Portable regression tests of actual worker functions and SQLite reference queries.

Only systemctl, filesystem probes and subprocess boundaries are stubbed. No SSH,
network access, real systemd changes or access to user credentials is performed.
Run: python tools/test-handoff-regressions.py
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SSH = PROJECT / 'core/ssh/src/main/kotlin/com/velumtegra/xuimobile/core/ssh'


class Rejected(Exception):
    pass


def need(condition):
    if not condition:
        raise Rejected()


def appendix(name):
    return (SSH / (name + '.kt')).read_text(encoding='utf-8').split('"""', 1)[1].rsplit('"""', 1)[0]


def functions(worker, names, **boundary):
    tree = ast.parse(appendix(worker))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in selected} == set(names)
    env = dict(need=need, Rejected=Rejected, re=re, json=json, hashlib=hashlib, **boundary)
    exec(compile(ast.Module(body=selected, type_ignores=[]), worker, 'exec'), env)
    return env


def kotlin_literals(expression):
    # These fixed SQL expressions contain only concatenated Kotlin string literals.
    return ''.join(json.loads(s) for s in re.findall(r'"(?:[^"\\]|\\.)*"', expression))


def reference_sql(active):
    source = (SSH / 'RecoveryFileInventorySshReader.kt').read_text(encoding='utf-8')
    web = kotlin_literals(source.split('private const val WEB_PATH = ', 1)[1].split('\n\n', 1)[0])
    docs = kotlin_literals(source.split('val docs = ', 1)[1].split('\n', 1)[0])
    valid = kotlin_literals(source.split('val valid = ', 1)[1].split('\n', 1)[0])
    method = source.split('fun references(activeConfig: Boolean)', 1)[1]
    expression = method.split('val sql = ', 1)[1].split('// Validate the generated', 1)[0]
    expression = re.sub(r'\+\s*docs\s*\+', '+ "$docs" +', expression)
    sql = kotlin_literals(expression)
    docs = docs.replace('$active', " UNION ALL SELECT CAST(readfile('/usr/local/x-ui/bin/config.json') AS TEXT)" if active else '')
    for key, value in [('docs', docs), ('valid', valid), ('WEB_PATH', web)]:
        sql = sql.replace('$' + key, value)
    assert '$' not in sql
    return sql


class References(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / 'fixture.sqlite')
        self.con = sqlite3.connect(self.db)
        self.con.executescript('CREATE TABLE settings(key TEXT,value TEXT); CREATE TABLE inbounds(settings TEXT,stream_settings TEXT);')
        self.con.execute('INSERT INTO settings VALUES (?,?)', ('xrayTemplateConfig', '{}'))
        self.con.commit()
        self.active = '{}'
        self.env = functions('InstallationBackupWorker', ['unique_object', 'json_object', 'references'],
            connect=lambda path, immutable: sqlite3.connect(path), DATABASE=self.db,
            RUNTIME='/usr/local/x-ui', tick=lambda: None,
            safe=lambda p: isinstance(p, str) and p.startswith('/root/'),
            read_file=lambda *args: self.active.encode())

    def tearDown(self):
        self.con.close()
        self.tmp.cleanup()

    def config(self, doc, template=True):
        self.con.execute('DELETE FROM settings')
        if template:
            self.con.execute('INSERT INTO settings VALUES (?,?)', ('xrayTemplateConfig', json.dumps(doc)))
        self.con.commit()

    def python_refs(self, active=False):
        return self.env['references'](self.db, active)[0]

    def sql_refs(self, active=False):
        con = sqlite3.connect(self.db)
        con.create_function('readfile', 1, lambda path: self.active)
        try:
            # Execute the real SQL with JSON1, including its read-only transaction.
            rows = []
            for statement in reference_sql(active).split(';'):
                if statement.strip():
                    rows.extend(con.execute(statement).fetchall())
            return [row[0] for row in rows if not row[0].startswith('DOCS|')]
        finally:
            con.close()

    def test_url_paths_are_ignored_by_both_inventory_and_archive(self):
        for doc in [
            {'realitySettings': {'spiderX': '/crawl'}},
            *[{key: {'path': '/web'}} for key in ['wsSettings', 'httpupgradeSettings', 'xhttpSettings', 'splithttpSettings', 'httpSettings']],
            {'tcpSettings': {'header': {'request': {'path': ['/one', '/two']}}}},
            {'fallbacks': [{'path': '/fallback', 'dest': 8080}]},
        ]:
            with self.subTest(doc=doc):
                self.config(doc)
                self.assertEqual({}, self.python_refs())
                self.assertEqual([], self.sql_refs())

    def test_absolute_file_and_socket_references_are_still_rejected(self):
        for doc in [{'path': '/root/unknown'}, {'fallbacks': [{'dest': '/run/panel.sock'}]},
                    {'other': '/root/unknown'}, {'wsSettings': {'file': '/root/unknown'}}]:
            with self.subTest(doc=doc):
                self.config(doc)
                with self.assertRaises(Rejected):
                    self.python_refs()
                self.assertTrue(any(row.startswith('UNKNOWN|') for row in self.sql_refs()))
        for value in ['file:/root/private', 'unix:/run/panel.sock', 'fd:3']:
            self.config({'other': value})
            with self.assertRaises(Rejected):
                self.python_refs()
            self.assertTrue(any(r.startswith('UNKNOWN|') for r in self.sql_refs()))

    def test_certificate_and_private_key_remain_dependencies(self):
        self.config({'tlsSettings': {'certificateFile': '/root/cert.pem', 'keyFile': '/root/key.pem'}})
        refs = self.python_refs()
        self.assertEqual([False, {'XRAY_TLS'}], refs['/root/cert.pem'])
        self.assertEqual([True, {'XRAY_TLS'}], refs['/root/key.pem'])
        self.assertEqual({'XRAY_CERT', 'XRAY_KEY'}, {r.split('|')[0] for r in self.sql_refs()})

    def test_missing_template_requires_effective_active_config(self):
        self.config({}, template=False)
        with self.assertRaises(Rejected):
            self.python_refs()
        self.active = json.dumps({'realitySettings': {'spiderX': '/crawl'}})
        self.assertEqual({}, self.python_refs(active=True))
        self.assertEqual([], self.sql_refs(active=True))
        self.active = json.dumps({'other': '/root/unaccounted'})
        with self.assertRaises(Rejected):
            self.python_refs(active=True)
        self.assertTrue(any(r.startswith('UNKNOWN|') for r in self.sql_refs(active=True)))

    def test_duplicate_and_malformed_template_never_look_like_no_dependencies(self):
        for raw in ['{"x":1,"x":2}', 'not-json', '[]']:
            self.con.execute('UPDATE settings SET value=?', (raw,))
            self.con.commit()
            with self.assertRaises((Rejected, ValueError)):
                self.python_refs()


class Services(unittest.TestCase):
    def fields(self, **changes):
        fields = dict(LoadState='loaded', ActiveState='active', SubState='running', MainPID='123',
                      ControlPID='0', TriggeredBy='', KillMode='mixed', ControlGroup='/system.slice/x-ui.service')
        fields.update(changes)
        return fields

    def runner(self, fields):
        return SimpleNamespace(PIPE=-1, run=lambda *args, **kw: SimpleNamespace(
            stdout=''.join(k + '=' + v + '\n' for k, v in fields.items()).encode(), stderr=b''))

    def working(self, fields):
        env = functions('WorkingDatabaseRestoreWorker', ['working_service'], subprocess=self.runner(fields))
        return env['working_service']()

    def test_restore_accepts_only_reviewed_kill_modes(self):
        for mode in ['mixed', 'control-group']:
            self.assertEqual(mode, self.working(self.fields(KillMode=mode))['KillMode'])
        for mode in ['process', 'none', '', 'MIXED']:
            with self.assertRaises(Rejected):
                self.working(self.fields(KillMode=mode))

    def test_busy_or_foreign_service_is_never_accepted(self):
        for changes in [dict(ControlPID='42'), dict(TriggeredBy='x-ui.socket'),
                        dict(ControlGroup='/system.slice/other.service'), dict(LoadState='not-found')]:
            with self.assertRaises(Rejected):
                self.working(self.fields(**changes))

    def test_readiness_accepts_empty_and_zero_job_but_rejects_pending_job(self):
        for job, expected in [('', 'REQUIRED'), ('0', 'REQUIRED'), ('12 /job/12', 'UNAVAILABLE')]:
            for mode in ['mixed', 'control-group', 'process']:
                fields = self.fields(Job=job, Delegate='no', KillMode=mode)
                env = functions('RecoveryReadinessWorker', ['readiness_service'], subprocess=self.runner(fields))
                self.assertEqual(expected if mode != 'process' else 'UNAVAILABLE', env['readiness_service']()[0])

    def test_post_restore_start_return_and_compensated_start_check_jobs(self):
        for worker, name in [('RestoredPanelStartWorker', 'starting_active'),
                             ('CompensatedPanelStartWorker', 'compensated_active'),
                             ('BeforeCopyReturnWorker', 'returning_stopped')]:
            for output in [b'Job=\n', b'Job=0\n', b'Job=12 /job/12\n', b'', b'Job=0\nJob=\n']:
                with self.subTest(worker=worker, output=output):
                    env = functions(worker, [name],
                        working_service=lambda *args, **kw: self.fields(),
                        subprocess=SimpleNamespace(PIPE=-1, run=lambda *args, **kw: SimpleNamespace(stdout=output, stderr=b'')),
                        os=SimpleNamespace(readlink=lambda path: '/usr/local/x-ui/x-ui'), RUNTIME='/usr/local/x-ui')
                    if output in (b'Job=\n', b'Job=0\n'):
                        env[name]()
                    else:
                        with self.assertRaises(Rejected):
                            env[name]()


class VersionMemory(unittest.TestCase):
    def test_version_child_fits_the_restore_worker_hard_limit(self):
        # A child cannot raise an inherited hard limit without CAP_SYS_RESOURCE.
        # Keep the parent soft limit at 512 MiB while permitting the reviewed 2 GiB child.
        parent = re.search(r'RLIMIT_AS,\s*\((\d+),\s*(\d+)\)', appendix('RestoreCheckWorker'))
        soft, hard = map(int, parent.groups())
        limits = []
        resource = SimpleNamespace(RLIMIT_AS=9, setrlimit=lambda kind, pair: limits.append(pair))
        def run(*args, **kw):
            kw['preexec_fn']()
            need(limits[-1][0] <= limits[-1][1] <= hard)
            return SimpleNamespace(returncode=0, stdout=b'v3.11.0\n', stderr=b'')
        env = functions('RestoreCompatibilityWorker', ['compatibility_version'],
            service=lambda: ({}, []), file_info=lambda path: (0, 0, 0, 0o700, 12),
            subprocess=SimpleNamespace(PIPE=-1, run=run), resource=resource,
            os=SimpleNamespace(uname=lambda: SimpleNamespace(machine='x86_64')), RUNTIME='/usr/local/x-ui')
        self.assertEqual('3.11.0', env['compatibility_version']()[0])
        self.assertEqual(536870912, soft)
        self.assertEqual([(2147483648, 2147483648)], limits)


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=2))

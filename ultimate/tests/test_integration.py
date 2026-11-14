"""Cross-module regressions using synthetic assets and a controlled engine stub."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from jeffe import cli
from jeffe.service import private_json, run_job
from jeffe.storage import Workspace


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jeffe-integration-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace_root = self.root / 'workspace'
        self.ws = Workspace(self.workspace_root)
        source, words = self.root / 'input.txt', self.root / 'words.txt'
        source.write_text(hashlib.sha256(b'synthetic-target').hexdigest() + '\n')
        words.write_text('synthetic-miss\nsynthetic-target\n')
        self.hashes = self.ws.ingest(source, 'hashes')
        self.words = self.ws.ingest(words, 'wordlist')
        self.spec = {'schema_version': 1, 'engine': 'john', 'format': 'raw-sha256',
                     'input_id': self.hashes['id'], 'wordlist_id': self.words['id'],
                     'runtime_seconds': 1}

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = cli.main(['--workspace', str(self.workspace_root), *args])
        return result, stdout.getvalue(), stderr.getvalue()

    def valid_auth(self):
        path = self.root / 'auth.json'
        private_json(path, {'principals': [{
            'name': 'existing-admin', 'role': 'admin',
            'token_sha256': hashlib.sha256(b'synthetic-admin-token').hexdigest(),
        }]})
        return path

    def test_invalid_principal_does_not_replace_working_authentication(self):
        auth = self.valid_auth()
        original = auth.read_bytes()
        code, output, errors = self.invoke([
            'auth-add', '--auth', str(auth), '--name', 'invalid name', '--role', 'viewer'])
        self.assertEqual(code, 2)
        self.assertEqual(output, '')
        self.assertEqual(auth.read_bytes(), original)
        self.assertIn('invalid principal name', errors)

    @unittest.skipUnless(os.name == 'posix', 'POSIX file mode validation')
    def test_auth_add_does_not_silently_adopt_public_authentication_file(self):
        auth = self.valid_auth()
        auth.chmod(0o644)
        original = auth.read_bytes()
        code, output, errors = self.invoke([
            'auth-add', '--auth', str(auth), '--name', 'new-user', '--role', 'viewer'])
        self.assertEqual(code, 2)
        self.assertEqual(output, '')
        self.assertEqual(auth.read_bytes(), original)
        self.assertIn('0600', errors)

    def test_john_only_cli_server_omits_absent_optional_engine(self):
        auth = self.valid_auth()
        server = Mock(server_port=8765)
        server.serve_forever.side_effect = KeyboardInterrupt
        with patch('jeffe.cli.shutil.which', return_value=None), \
                patch('jeffe.server.build_server', return_value=server) as build, \
                patch('jeffe.cli.catalog_data', return_value=[]):
            code, output, errors = self.invoke([
                '--john', sys.executable, 'serve', '--auth', str(auth)])
        self.assertEqual(code, 0, errors)
        self.assertEqual(build.call_args.args[4], {'john': sys.executable})
        server.server_close.assert_called_once()
        self.assertIn('listening', output)

    def test_invalid_format_is_rejected_without_persisting_a_job(self):
        for engine, fmt in [('john', 'raw:sha256'), ('hashcat', 'raw-sha256')]:
            with self.subTest(engine=engine, format=fmt):
                before = self.ws.report_summary()['job_count']
                code, output, errors = self.invoke([
                    'create', '--engine', engine, '--format', fmt,
                    '--input-id', self.hashes['id'], '--wordlist-id', self.words['id']])
                self.assertEqual(code, 2)
                self.assertEqual(output, '')
                self.assertEqual(self.ws.report_summary()['job_count'], before)

    def test_second_launch_cannot_execute_a_running_job(self):
        job = self.ws.create_job(self.spec)
        entered, release = threading.Event(), threading.Event()

        def execute(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError('test launch was not released')
            return {'status': 'completed', 'exit_code': 0, 'elapsed_seconds': 0.1,
                    'checkpoint_available': False, 'recovered_records': 1}

        with patch('jeffe.service.engines.execute', side_effect=execute) as engine:
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(run_job, self.workspace_root, job['id'], {'john': sys.executable})
                try:
                    self.assertTrue(entered.wait(5))
                    with self.assertRaisesRegex(ValueError, 'must be queued'):
                        run_job(self.workspace_root, job['id'], {'john': sys.executable})
                finally:
                    release.set()
                outcome = first.result(timeout=5)
            self.assertEqual(engine.call_count, 1)
        self.assertEqual(outcome['job']['status'], 'completed')
        self.assertEqual([e['status'] for e in self.ws.events(job['id'])],
                         ['queued', 'running', 'completed'])

    def test_engine_failure_is_journaled_without_exception_secret(self):
        job = self.ws.create_job(self.spec)
        marker = 'private-engine-diagnostic-marker'
        with patch('jeffe.service.engines.execute', side_effect=RuntimeError(marker)):
            with self.assertRaises(RuntimeError):
                run_job(self.workspace_root, job['id'], {'john': sys.executable})
        self.assertEqual(self.ws.job(job['id'])['status'], 'failed')
        history = self.ws.events(job['id'])
        self.assertEqual(history[-1]['details'], {'error_code': 'execution_failed'})
        self.assertNotIn(marker, json.dumps(history))


if __name__ == '__main__':
    unittest.main()

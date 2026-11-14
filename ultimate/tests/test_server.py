import hashlib
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from jeffe.server import APIError, MAX_UPLOAD, build_server, load_principals


class PrincipalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'auth.json'

    def tearDown(self):
        self.temp.cleanup()

    def write(self, rows):
        self.path.write_text(json.dumps({'principals': rows}))
        self.path.chmod(0o600)

    def row(self, name='operator', role='operator', digest='a' * 64):
        return {'name': name, 'role': role, 'token_sha256': digest}

    def test_valid_private_config(self):
        self.write([self.row()])
        self.assertEqual(load_principals(self.path)[0]['role'], 'operator')

    def test_rejects_duplicate_names_and_tokens(self):
        for rows in ([self.row(), self.row(digest='b' * 64)], [self.row(), self.row(name='other')]):
            with self.subTest(rows=rows):
                self.write(rows)
                with self.assertRaises(ValueError):
                    load_principals(self.path)

    def test_rejects_roles_plaintext_extra_fields_and_bad_digest(self):
        cases = [self.row(role='superuser'), self.row(digest='cleartext'), dict(self.row(), token='secret')]
        for row in cases:
            self.write([row])
            with self.assertRaises(ValueError):
                load_principals(self.path)

    @unittest.skipUnless(os.name == 'posix', 'POSIX permission test')
    def test_rejects_public_auth_file(self):
        self.write([self.row()])
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            load_principals(self.path)

    def test_rejects_symlink_auth_file(self):
        self.write([self.row()])
        alias = self.path.with_name('alias.json')
        alias.symlink_to(self.path)
        with self.assertRaises(ValueError):
            load_principals(alias)


class TeamHTTPTests(unittest.TestCase):
    viewer = 'viewer_' + 'a' * 40
    operator = 'operator_' + 'b' * 40

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'workspace'
        auth = self.root / 'auth.json'
        auth.write_text(json.dumps({'principals': [
            {'name': 'reader', 'role': 'viewer', 'token_sha256': hashlib.sha256(self.viewer.encode()).hexdigest()},
            {'name': 'runner', 'role': 'operator', 'token_sha256': hashlib.sha256(self.operator.encode()).hexdigest()},
        ]}))
        auth.chmod(0o600)
        self.server = build_server('127.0.0.1', 0, self.workspace, auth,
                                   {'john': '/configured/private/john'}, [], [], max_workers=1)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def request(self, method, path, data=None, token=None, raw=False, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        hdrs = dict(headers or {})
        if token:
            hdrs['Authorization'] = 'Bearer ' + token
        if data is not None:
            if raw:
                hdrs.setdefault('Content-Type', 'application/octet-stream')
            else:
                data = json.dumps(data).encode()
                hdrs.setdefault('Content-Type', 'application/json')
        connection.request(method, path, body=data, headers=hdrs)
        response = connection.getresponse()
        body = response.read()
        result = (response.status, dict(response.getheaders()), body)
        connection.close()
        return result

    def upload(self, kind, body):
        status, headers, raw = self.request('POST', '/api/assets?kind=' + kind, body, self.operator, raw=True)
        self.assertEqual(status, 201, raw)
        return json.loads(raw)

    def job(self):
        hashes = self.upload('hashes', b'synthetic-hash\n')
        words = self.upload('wordlist', b'only-synthetic-word\n')
        spec = {'engine': 'john', 'format': 'raw-sha256', 'input_id': hashes['id'],
                'wordlist_id': words['id'], 'runtime_seconds': 5}
        status, _, raw = self.request('POST', '/api/jobs', spec, self.operator)
        self.assertEqual(status, 201, raw)
        return json.loads(raw)

    def test_health_and_authentication(self):
        self.assertEqual(self.request('GET', '/health')[0], 200)
        self.assertEqual(self.request('GET', '/api/summary')[0], 401)
        self.assertEqual(self.request('GET', '/api/summary', token='x' * 40)[0], 401)
        status, headers, raw = self.request('GET', '/api/me', token=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {'name': 'reader', 'role': 'viewer'})
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_viewer_cannot_write(self):
        status, _, raw = self.request('POST', '/api/jobs', {}, self.viewer)
        self.assertEqual(status, 403)
        self.assertNotIn(self.viewer.encode(), raw)

    def test_asset_upload_dedup_and_safe_read_projection(self):
        first = self.upload('hashes', b'SENSITIVE-INPUT\n')
        second = self.upload('hashes', b'SENSITIVE-INPUT\n')
        self.assertEqual(first['id'], second['id'])
        self.assertNotIn('path', first)
        status, _, raw = self.request('GET', '/api/assets', token=self.viewer)
        self.assertEqual(status, 200)
        self.assertNotIn(b'SENSITIVE-INPUT', raw)
        self.assertNotIn(str(self.workspace).encode(), raw)
        self.assertEqual(list((self.workspace / 'uploads').iterdir()), [])

    def test_asset_pagination_is_explicit_and_bounded(self):
        self.upload('hashes', b'first\n')
        self.upload('hashes', b'second\n')
        status, headers, raw = self.request('GET', '/api/assets?limit=1&offset=0', token=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(raw)), 1)
        self.assertEqual(headers['X-Total-Count'], '2')
        self.assertIn('offset=1', headers['Link'])
        self.assertEqual(self.request('GET', '/api/assets?limit=1001', token=self.viewer)[0], 400)

    def test_upload_quota_is_checked_before_reading_and_releases_slots(self):
        with patch('jeffe.server.MAX_ASSET_BYTES', 4):
            self.upload('hashes', b'1234')
            self.assertEqual(self.request('POST', '/api/assets?kind=hashes', b'5', self.operator, raw=True)[0], 413)
        self.assertEqual(self.server._reserved_upload_bytes, 0)
        self.assertEqual(self.server._reserved_upload_count, 0)

    def test_upload_has_total_deadline_and_removes_partial_file(self):
        with patch('jeffe.server.MAX_UPLOAD_SECONDS', 0.1):
            c = http.client.HTTPConnection(*self.server.server_address, timeout=3)
            c.putrequest('POST', '/api/assets?kind=hashes')
            c.putheader('Authorization', 'Bearer ' + self.operator)
            c.putheader('Content-Type', 'application/octet-stream')
            c.putheader('Content-Length', '2')
            c.endheaders(b'1')
            result = c.getresponse()
            self.assertEqual(result.status, 408)
            result.read()
            c.close()
        self.assertEqual(list((self.workspace / 'uploads').iterdir()), [])

    def test_cached_catalog_is_valid_json_and_does_not_require_workspace_queries(self):
        with patch('jeffe.server._workspace', side_effect=AssertionError('unexpected DB work')):
            status, _, raw = self.request('GET', '/api/backlog', token=self.viewer)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), [])

    def test_rejects_unbounded_upload_and_local_file_path_job(self):
        status, _, _ = self.request('POST', '/api/assets?kind=hashes', b'', self.operator,
                                   raw=True, headers={'Content-Length': str(MAX_UPLOAD + 1)})
        self.assertEqual(status, 413)
        status, _, raw = self.request('POST', '/api/jobs', {'engine_path': '/tmp/untrusted'}, self.operator)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)['error']['code'], 'engine_path_forbidden')

    def test_job_creation_safe_projection_and_invalid_resume(self):
        job = self.job()
        self.assertEqual(job['status'], 'queued')
        self.assertNotIn('engine_path', job['spec'])
        status, _, raw = self.request('GET', '/api/jobs/' + job['id'], token=self.viewer)
        self.assertEqual(status, 200)
        self.assertNotIn(b'/configured/private', raw)
        status, _, _ = self.request('POST', '/api/jobs/' + job['id'] + '/resume', {}, self.operator)
        self.assertEqual(status, 409)

    def test_scheduling_is_bounded_and_duplicate_safe(self):
        job = self.job()
        entered, release = threading.Event(), threading.Event()
        def fake_run(*args, **kwargs):
            entered.set()
            release.wait(5)
            return {'status': 'exhausted'}
        with patch('jeffe.server._run_job', side_effect=fake_run) as runner:
            try:
                status, _, raw = self.request('POST', '/api/jobs/' + job['id'] + '/run', {}, self.operator)
                self.assertEqual(status, 202, raw)
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.request('POST', '/api/jobs/' + job['id'] + '/run', {}, self.operator)[0], 409)
                self.assertEqual(runner.call_count, 1)
            finally:
                release.set()

    def test_errors_do_not_disclose_storage_or_auth_secrets(self):
        status, _, raw = self.request('GET', '/api/jobs/' + 'f' * 32, token=self.viewer)
        self.assertEqual(status, 404)
        self.assertNotIn(str(self.workspace).encode(), raw)
        self.assertNotIn(self.viewer.encode(), raw)
        self.assertEqual(self.request('TRACE', '/api/jobs', token=self.viewer)[0], 405)

    def test_queue_rejects_work_beyond_active_plus_sixteen_pending(self):
        release = threading.Event()
        principal = {'name': 'runner', 'role': 'operator'}
        with patch('jeffe.server._run_job', side_effect=lambda *args: release.wait(5)):
            try:
                for index in range(17):
                    self.server.schedule(principal, format(index, '032x'))
                with self.assertRaises(APIError) as error:
                    self.server.schedule(principal, format(17, '032x'))
                self.assertEqual(error.exception.status, 429)
            finally:
                release.set()

    def test_audit_has_identity_without_secrets(self):
        asset = self.upload('hashes', b'A-PRIVATE-PASSWORD-LIKE-FIXTURE\n')
        audit = (self.workspace / 'team-audit.jsonl').read_text()
        self.assertIn('runner', audit)
        self.assertIn(asset['id'], audit)
        self.assertNotIn(self.operator, audit)
        self.assertNotIn('A-PRIVATE-PASSWORD-LIKE-FIXTURE', audit)


if __name__ == '__main__':
    unittest.main()

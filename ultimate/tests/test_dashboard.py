import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from jeffe.dashboard import render_dashboard, render_team_shell, write_dashboard


def payload(document):
    match = re.search(r'<script type="application/json" id="dashboard-data">(.*?)</script>', document, re.S)
    return json.loads(match.group(1))


class DashboardTests(unittest.TestCase):
    def test_private_job_fields_never_reach_snapshot(self):
        secret = 'SENSITIVE-test-password-DO-NOT-PUBLISH'
        document = render_dashboard(
            {'asset_count': 1, 'asset_bytes': 40, 'job_count': 1, 'secret': secret},
            [{'id': 'ab12', 'status': 'completed', 'created_at': '2026-11-14',
              'spec': {'password': secret}, 'path': '/private/' + secret,
              'output': secret, 'result': {'plaintext': secret}}],
            [], [{'id': 1, 'idea': 'Track recovery outcomes.', 'evidence': secret}],
        )
        self.assertNotIn(secret, document)
        self.assertEqual(payload(document)['jobs'], [
            {'id': 'ab12', 'status': 'completed', 'created_at': '2026-11-14'}])

    def test_script_breakout_and_html_attributes_are_escaped(self):
        attack = '</script><script>alert("unexpected")</script><img src=x onerror=alert(1)>'
        document = render_dashboard({}, [{'id': attack, 'status': 'queued'}],
                                    [{'repo': attack, 'description': attack}],
                                    [{'id': 1, 'idea': attack}])
        self.assertNotIn(attack, document)
        self.assertIn('&lt;/script&gt;', document)
        self.assertEqual(payload(document)['backlog'][0]['idea'], attack)
        self.assertIn('\\u003c/script\\u003e', document)
        self.assertEqual(document.count('<script'), 2)

    def test_dangerous_or_credential_bearing_links_are_removed(self):
        rows = [{'repo': 'unsafe', 'url': url, 'sources': [url]}
                for url in ['javascript:alert(1)', 'data:text/html,hello',
                            'file:///private/file', 'https://user:secret@example.com/',
                            'https://example.com:invalid/', 'https://example.com/\nattack']]
        rows.append({'repo': 'safe', 'url': 'https://github.com/example/project',
                     'sources': ['https://github.com/example/project/README.md']})
        parsed = payload(render_dashboard({}, [], rows, []))['integrations']
        for row in parsed[:-1]:
            self.assertEqual(row['url'], '')
            self.assertEqual(row['sources'], [])
        self.assertEqual(parsed[-1]['url'], 'https://github.com/example/project')

    def test_full_tracker_preserves_ids_and_honest_statuses(self):
        backlog = [{'id': i, 'idea': f'Proposal {i}', 'category': 'Planning',
                    'status': 'implemented' if i == 1 else 'partial' if i == 2 else 'planned'}
                   for i in range(1, 1001)]
        document = render_dashboard({'asset_count': 3, 'asset_bytes': 1234, 'job_count': 2}, [], [], backlog)
        rows = payload(document)['backlog']
        self.assertEqual(len(rows), 1000)
        self.assertEqual([row['id'] for row in rows], [str(i) for i in range(1, 1001)])
        self.assertIn('<strong>1 / 1000</strong>', document)
        self.assertIn('1 partial', document)
        self.assertEqual(rows[1]['status'], 'partial')

    def test_absent_status_is_planned_not_implemented(self):
        data = payload(render_dashboard({}, [], [{'repo': 'unreviewed'}], [{'id': 1}]))
        self.assertEqual(data['backlog'][0]['status'], 'planned')
        self.assertEqual(data['integrations'][0]['decision'], 'needs-review')

    def test_placeholder_text_is_not_interpreted_as_template(self):
        document = render_dashboard({}, [], [], [{'id': 1, 'idea': '__ASSETS__ __JOB_FALLBACK__ __DATA__'}])
        self.assertEqual(payload(document)['backlog'][0]['idea'], '__ASSETS__ __JOB_FALLBACK__ __DATA__')

    def test_snapshot_write_is_private_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'new' / 'snapshot.html'
            returned = write_dashboard(path, {}, [], [], [])
            self.assertEqual(returned, path)
            self.assertIn('JEFFE Ultimate', path.read_text())
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            old = path.read_bytes()
            with patch('jeffe.dashboard.os.replace', side_effect=OSError('simulated publication failure')):
                with self.assertRaises(OSError):
                    write_dashboard(path, {'asset_count': 99}, [], [], [])
            self.assertEqual(path.read_bytes(), old)
            self.assertEqual(list(path.parent.glob('.dashboard-*')), [])

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlink support unavailable')
    def test_write_replaces_final_symlink_without_overwriting_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'important.txt'
            target.write_text('preserve original')
            link = Path(directory) / 'dashboard.html'
            link.symlink_to(target)
            write_dashboard(link, {}, [], [], [])
            self.assertFalse(link.is_symlink())
            self.assertEqual(target.read_text(), 'preserve original')

    def test_document_has_no_external_execution_or_network_assets(self):
        document = render_dashboard({}, [], [], [])
        self.assertNotRegex(document, r'<script[^>]+src=')
        self.assertNotRegex(document, r'<link[^>]+href=')
        self.assertIn("connect-src 'none'", document)
        self.assertIn('aria-live="polite"', document)
        self.assertIn('scope="col"', document)

    def test_team_shell_keeps_credentials_in_memory_and_isolates_report(self):
        document = render_team_shell()
        self.assertIn("headers.set('Authorization','Bearer '+accessToken)", document)
        self.assertNotIn('localStorage', document)
        self.assertNotIn('sessionStorage', document)
        self.assertNotIn('document.cookie', document)
        self.assertNotIn('console.log', document)
        self.assertIn('sandbox="allow-scripts"', document)
        self.assertNotIn('allow-same-origin', document)
        self.assertIn("credentials:'omit'", document)
        self.assertIn("connect-src 'self'", document)
        self.assertIn("el('access-token').value=''", document)

    def test_team_shell_uses_explicit_role_aware_api_actions(self):
        document = render_team_shell()
        for endpoint in ['/api/me', '/api/assets', '/api/jobs', '/api/dashboard']:
            self.assertIn(endpoint, document)
        self.assertIn("['operator','admin'].includes(identity.role)", document)
        self.assertIn("['queued','interrupted'].includes(job.status)", document)
        self.assertIn("'Content-Type':'application/octet-stream'", document)
        self.assertIn('n.textContent=value', document)
        self.assertNotIn('innerHTML', document)
        self.assertIn('Creating a job does not start it.', document)


if __name__ == '__main__':
    unittest.main()

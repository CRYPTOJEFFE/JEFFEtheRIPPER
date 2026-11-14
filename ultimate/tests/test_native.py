"""Opt-in tests against an actual John Jumbo executable, using synthetic data.

Set JEFFE_TEST_JOHN to the executable path. These are correctness/lifecycle
checks, not performance benchmarks. No customer files or password data are used.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from jeffe.models import JobSpec
from jeffe.service import run_job
from jeffe.storage import Workspace


NATIVE_JOHN = os.environ.get('JEFFE_TEST_JOHN')
SLOW_FIXTURE = (
    '$6$rounds=5000$jeffe-fixture$'
    'lP1FtNChcAiuCDxXCbNA99rBgeEAZwyUPJnaa/6JhkwVJ4T8aS8e6TP2VRfDk/S4FsHJf/KV2PIRagq/eo7bh0'
)


@unittest.skipUnless(NATIVE_JOHN, 'Set JEFFE_TEST_JOHN to run actual engine checks')
class NativeJohnTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jeffe-native-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace_root = self.root / 'workspace'
        self.ws = Workspace(self.workspace_root)
        if hasattr(self.ws, 'close'):
            self.addCleanup(self.ws.close)
        self.engine = str(Path(NATIVE_JOHN).resolve(strict=True))
        self.env = patch.dict(os.environ, {'OMP_NUM_THREADS': '2'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def job(self, verifier, candidates, fmt='raw-sha256', runtime=3):
        source = self.root / 'synthetic-hashes.txt'
        words = self.root / 'synthetic-wordlist.txt'
        source.write_text(verifier + '\n', encoding='utf-8')
        words.write_text(candidates, encoding='utf-8')
        asset = self.ws.ingest(source, 'hashes')
        wordlist = self.ws.ingest(words, 'wordlist')
        spec = JobSpec('john', fmt, asset['id'], wordlist['id'], runtime).to_dict()
        return self.ws.create_job(spec)

    def run_native(self, job, *, resume=False, engine=None):
        return run_job(self.workspace_root, job['id'],
                       {'john': engine or self.engine}, resume=resume)

    def test_real_synthetic_success_is_private(self):
        secret = 'jeffe-native-success-fixture-5821'
        job = self.job(hashlib.sha256(secret.encode()).hexdigest(),
                       'a-synthetic-miss\n' + secret + '\n')
        result = self.run_native(job)
        self.assertEqual(result['job']['status'], 'completed')
        self.assertEqual(result['outcome']['recovered_records'], 1)
        self.assertFalse(result['outcome']['results_independently_verified'])
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual([e['status'] for e in self.ws.events(job['id'])],
                         ['queued', 'running', 'completed'])

    def test_real_synthetic_exhaustion_is_not_success(self):
        verifier = hashlib.sha256(b'jeffe-target-outside-tiny-fixture').hexdigest()
        job = self.job(verifier, 'synthetic-miss-one\nsynthetic-miss-two\n')
        result = self.run_native(job)
        self.assertEqual(result['job']['status'], 'exhausted')
        self.assertEqual(result['outcome']['recovered_records'], 0)
        self.assertFalse(result['outcome']['checkpoint_available'])

    @staticmethod
    def candidate_counter(checkpoint):
        """Read documented-in-source REC4 fields to prove resumed candidate progress.

        Layout is pinned by src/recovery.c: argc includes the omitted executable,
        followed by 13 status fields; cands low/high are fields 7 and 8.
        The assertion intentionally fails if upstream changes this wire format.
        """
        lines = checkpoint.read_text(encoding='utf-8').splitlines()
        if lines[0] != 'REC4':
            raise AssertionError('Update native fixture parser for changed recovery version')
        arguments = int(lines[1])
        fields = lines[arguments + 1: arguments + 14]
        return int(fields[7], 16) + (int(fields[8], 16) << 32)

    def test_real_checkpoint_resume_and_integrity_guards(self):
        candidates = ''.join(f'jeffe-synthetic-miss-{i:06d}\n' for i in range(100000))
        job = self.job(SLOW_FIXTURE, candidates, fmt='sha512crypt', runtime=1)
        first = self.run_native(job)
        self.assertEqual(first['job']['status'], 'interrupted')
        self.assertTrue(first['outcome']['checkpoint_available'])
        self.assertFalse(first['outcome']['timed_out'], 'John should honor its native runtime cap')
        checkpoint = self.ws.job_dir(job['id']) / 'session.rec'
        before = self.candidate_counter(checkpoint)
        self.assertGreater(before, 0)
        self.assertIn('--max-run-time=1', checkpoint.read_text())

        # A different engine digest must be refused before any resumed process starts.
        changed_engine = self.root / 'changed-john'
        shutil.copy2(self.engine, changed_engine)
        with changed_engine.open('ab') as output:
            output.write(b'changed-test-digest')
        with self.assertRaisesRegex(ValueError, 'original engine'):
            self.run_native(job, resume=True, engine=str(changed_engine))
        self.assertEqual(self.ws.job(job['id'])['status'], 'interrupted')

        # Managed wordlist changes are also refused; restore fixture bytes afterwards.
        wordlist = Path(self.ws.asset(job['spec']['wordlist_id'])['path'])
        original = wordlist.read_bytes()
        wordlist.write_bytes(original + b'extra-synthetic-record\n')
        with self.assertRaises(ValueError):
            self.run_native(job, resume=True)
        self.assertEqual(self.ws.job(job['id'])['status'], 'interrupted')
        wordlist.write_bytes(original)

        second = self.run_native(job, resume=True)
        self.assertEqual(second['job']['status'], 'interrupted')
        self.assertTrue(second['outcome']['checkpoint_available'])
        self.assertFalse(second['outcome']['timed_out'], 'Restored native runtime cap should persist')
        self.assertGreater(self.candidate_counter(checkpoint), before)
        self.assertEqual(second['outcome']['recovered_records'], 0)
        self.assertEqual([e['status'] for e in self.ws.events(job['id'])],
                         ['queued', 'running', 'interrupted', 'running', 'interrupted'])


if __name__ == '__main__':
    unittest.main()

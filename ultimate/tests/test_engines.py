"""Adapter contract tests use synthetic executables, not real engine benchmarks."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from jeffe.engines import build_command, diagnostics, execute, formats


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'hashes; touch unsafe'
        self.words = self.root / 'words $(touch unsafe)'
        self.inputs.write_text('synthetic-record\n')
        self.words.write_text('synthetic-candidate\n')
        self.job = self.root / 'job'
        self.spec = {'engine': 'john', 'format': 'raw-sha256', 'runtime_seconds': 1}

    def fake(self, body):
        path = self.root / 'fake-engine'
        path.write_text('#!' + sys.executable + '\n' + body)
        path.chmod(0o700)
        return str(path)

    def test_command_preserves_literal_paths(self):
        exe = self.fake('pass\n')
        command = build_command(self.spec, self.inputs, self.words, self.job, exe)
        self.assertIn('--wordlist=' + str(self.words), command)
        self.assertEqual(command[-1], str(self.inputs))
        self.assertNotIn('sh', command)
        result = execute(self.spec, self.inputs, self.words, self.job, exe)
        self.assertEqual(result['status'], 'exhausted')
        self.assertFalse((self.root / 'unsafe').exists())

    def test_invalid_configuration(self):
        exe = self.fake('pass\n')
        for patch in ({'format':'--help'}, {'format':'raw-sha256;true'},
                      {'runtime_seconds':0}, {'runtime_seconds':True},
                      {'engine':'shell'}, {'engine':'hashcat','format':'md5'}):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                build_command(dict(self.spec, **patch), self.inputs, self.words, self.job, exe)

    def test_synthetic_recovery_returns_no_plaintext(self):
        exe = self.fake("from pathlib import Path\nPath('results.pot').write_text('synthetic-hash:super-secret-value\\n')\nprint('super-secret-value')\n")
        result = execute(self.spec, self.inputs, self.words, self.job, exe)
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['recovered_records'], 1)
        self.assertNotIn('super-secret-value', json.dumps(result))
        self.assertFalse(result['results_independently_verified'])
        if os.name == 'posix':
            self.assertEqual((self.job / 'results.pot').stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.job.stat().st_mode & 0o777, 0o700)

    def test_failure_is_not_exhaustion(self):
        exe = self.fake('raise SystemExit(9)\n')
        result = execute(self.spec, self.inputs, self.words, self.job, exe)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['exit_code'], 9)

    def test_john_native_abort_exit_is_interrupted(self):
        exe = self.fake("from pathlib import Path\nPath('session.rec').write_text('checkpoint')\nraise SystemExit(2)\n")
        result = execute(self.spec, self.inputs, self.words, self.job, exe)
        self.assertEqual(result['status'], 'interrupted')
        self.assertTrue(result['checkpoint_available'])

    def test_timeout_saves_synthetic_checkpoint(self):
        exe = self.fake("import signal,time\nfrom pathlib import Path\ndef stop(*a):\n Path('session.rec').write_text('synthetic checkpoint')\n raise SystemExit(0)\nsignal.signal(signal.SIGINT,stop)\ntime.sleep(60)\n")
        result = execute(self.spec, self.inputs, self.words, self.job, exe, grace_seconds=.2)
        self.assertEqual(result['status'], 'interrupted')
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['checkpoint_available'])
        self.assertLess(result['elapsed_seconds'], 6)

    def test_resume_uses_engine_saved_arguments(self):
        exe = self.fake('pass\n')
        command = build_command(self.spec, self.inputs, self.words, self.job, exe, resume=True)
        self.assertEqual(command, [exe, '--restore=' + str(self.job / 'session')])
        with self.assertRaises(ValueError):
            execute(self.spec, self.inputs, self.words, self.job, exe, resume=True)

    def test_hashcat_exit_codes_and_paths(self):
        exe = self.fake('raise SystemExit(1)\n')
        spec = dict(self.spec, engine='hashcat', format='1400')
        command = build_command(spec, self.inputs, self.words, self.job, exe)
        self.assertIn('--restore-file-path=' + str(self.job / 'session.restore'), command)
        self.assertEqual(command[-2:], [str(self.inputs), str(self.words)])
        result = execute(spec, self.inputs, self.words, self.job, exe)
        self.assertEqual(result['status'], 'exhausted')

    def test_output_is_capped(self):
        exe = self.fake("import sys\nsys.stdout.write('x' * (3 * 1024 * 1024))\n")
        result = execute(self.spec, self.inputs, self.words, self.job, exe, grace_seconds=.1)
        self.assertEqual(result['status'], 'failed')
        self.assertTrue(result['output_limit_reached'])
        self.assertLessEqual((self.job / 'engine.log').stat().st_size, 2 * 1024 * 1024)

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink protection')
    def test_output_symlink_rejected(self):
        exe = self.fake('pass\n')
        self.job.mkdir()
        target = self.root / 'outside'
        target.write_text('unchanged')
        (self.job / 'results.pot').symlink_to(target)
        with self.assertRaises(ValueError):
            execute(self.spec, self.inputs, self.words, self.job, exe)
        self.assertEqual(target.read_text(), 'unchanged')

    @unittest.skipUnless(os.name == 'posix', 'POSIX hardlink protection')
    def test_output_hardlink_rejected_before_truncation(self):
        exe = self.fake('pass\n')
        self.job.mkdir()
        target = self.root / 'outside'
        target.write_text('unchanged')
        os.link(target, self.job / 'engine.log')
        with self.assertRaises(ValueError):
            execute(self.spec, self.inputs, self.words, self.job, exe)
        self.assertEqual(target.read_text(), 'unchanged')

    @unittest.skipUnless(os.name == 'posix', 'POSIX FIFO protection')
    def test_output_fifo_rejected_without_blocking(self):
        exe = self.fake('pass\n')
        self.job.mkdir()
        os.mkfifo(self.job / 'engine.log')
        with self.assertRaises(ValueError):
            execute(self.spec, self.inputs, self.words, self.job, exe)

    def test_diagnostics_and_format_discovery(self):
        exe = self.fake("import sys\nprint('raw-md5, raw-sha256' if '--list=formats' in sys.argv else 'synthetic-engine 1.0')\n")
        self.assertEqual(formats(exe, 'john'), ['raw-md5', 'raw-sha256'])
        result = diagnostics(exe, 'john')
        self.assertTrue(result['available'])
        self.assertEqual(len(result['sha256']), 64)

    def test_realistic_format_summary_is_not_a_format(self):
        exe = self.fake("print('raw-md5, dynamic_n, raw-sha256\\n400 formats (100 dynamic formats shown as just dynamic_n here)')\n")
        self.assertEqual(formats(exe, 'john'), ['raw-md5', 'raw-sha256'])

    def test_stale_checkpoint_does_not_hide_resume_failure(self):
        exe = self.fake('raise SystemExit(9)\n')
        self.job.mkdir()
        (self.job / 'session.rec').write_text('stale checkpoint')
        result = execute(self.spec, self.inputs, self.words, self.job, exe, resume=True)
        self.assertEqual(result['status'], 'failed')


if __name__ == '__main__':
    unittest.main()

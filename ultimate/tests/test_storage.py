import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from jeffe.models import JobSpec
from jeffe.storage import Workspace


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.workspace = Workspace(self.base / "workspace")

    def tearDown(self):
        self.tmp.cleanup()

    def source(self, name, data):
        path = self.base / name
        path.write_bytes(data)
        return path

    def job(self):
        hashes = self.workspace.ingest(self.source("hashes", b"synthetic-hash\n"))
        words = self.workspace.ingest(self.source("words", b"synthetic-password\n"), "wordlist")
        return self.workspace.create_job(JobSpec("john", "raw-sha256", hashes["id"], words["id"]).to_dict())

    def test_ingest_preserves_bytes_and_deduplicates_by_kind(self):
        content = b"zero\x00\xff\n" * 10000
        source = self.source("input", content)
        a = self.workspace.ingest(source)
        b = self.workspace.ingest(source)
        c = self.workspace.ingest(source, "wordlist")
        self.assertEqual(a["id"], b["id"])
        self.assertNotEqual(a["id"], c["id"])
        self.assertEqual(Path(a["path"]).read_bytes(), content)
        self.assertEqual(a["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(source.read_bytes(), content)
        self.assertEqual(len(self.workspace.list_assets()), 2)
        self.assertEqual(list(self.workspace.staging_dir.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_private_permissions(self):
        a = self.workspace.ingest(self.source("input", b"secret"))
        self.assertEqual(stat.S_IMODE(self.workspace.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(Path(a["path"]).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.workspace.db_path.stat().st_mode), 0o600)

    def test_symlink_source_rejected(self):
        original = self.source("input", b"text")
        link = self.base / "link"
        link.symlink_to(original)
        with self.assertRaises(ValueError):
            self.workspace.ingest(link)

    def test_workspace_symlink_rejected(self):
        link = self.base / "linked"
        link.symlink_to(self.workspace.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            Workspace(link)

    def test_database_symlink_rejected(self):
        other = self.base / "other"
        other.mkdir()
        (other / "workspace.sqlite3").symlink_to(self.workspace.db_path)
        with self.assertRaises(ValueError):
            Workspace(other)

    def test_size_limit_does_not_publish_asset(self):
        with self.assertRaises(ValueError):
            self.workspace.ingest(self.source("large", b"12345"), max_bytes=4)
        self.assertEqual(self.workspace.list_assets(), [])
        self.assertEqual(list(self.workspace.staging_dir.iterdir()), [])

    def test_mutation_during_copy_is_rejected(self):
        source = self.source("changing", b"first")
        original_read = os.read
        changed = False

        def mutating_read(fd, size):
            nonlocal changed
            block = original_read(fd, size)
            if block and not changed:
                changed = True
                source.write_bytes(b"second")
            return block

        with patch("jeffe.storage.os.read", side_effect=mutating_read):
            with self.assertRaisesRegex(ValueError, "changed"):
                self.workspace.ingest(source)
        self.assertEqual(self.workspace.list_assets(), [])
        self.assertEqual(list(self.workspace.staging_dir.iterdir()), [])

    def test_dedup_detects_same_size_corrupted_asset(self):
        source = self.source("input", b"abc")
        asset = self.workspace.ingest(source)
        Path(asset["path"]).write_bytes(b"xyz")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.workspace.ingest(source)

    def test_transitions_and_journal_persist(self):
        job = self.job()
        self.workspace.transition(job["id"], "running")
        self.workspace.transition(job["id"], "interrupted", {"reason": "time_limit"})
        reopened = Workspace(self.workspace.root)
        reopened.transition(job["id"], "running")
        reopened.transition(job["id"], "completed")
        self.assertEqual(reopened.job(job["id"])["status"], "completed")
        self.assertEqual([e["status"] for e in reopened.events(job["id"])],
                         ["queued", "running", "interrupted", "running", "completed"])
        with self.assertRaises(ValueError):
            reopened.transition(job["id"], "running")
        self.assertEqual(len(reopened.events(job["id"])), 5)

    def test_invalid_transitions_do_not_write_events(self):
        job = self.job()
        with self.assertRaises(ValueError):
            self.workspace.transition(job["id"], "completed")
        self.assertEqual(self.workspace.job(job["id"])["status"], "queued")
        self.assertEqual(len(self.workspace.events(job["id"])), 1)
        self.workspace.transition(job["id"], "running")
        self.workspace.transition(job["id"], "failed")
        with self.assertRaises(ValueError):
            self.workspace.transition(job["id"], "running")

    def test_job_path_traversal_rejected(self):
        for value in ("../outside", "a" * 31, "A" * 32):
            with self.assertRaises(ValueError):
                self.workspace.job_dir(value)

    def test_verify_detects_stored_corruption(self):
        asset = self.workspace.ingest(self.source("input", b"abc"))
        self.assertEqual(self.workspace.verify_asset(asset["id"]), asset)
        Path(asset["path"]).write_bytes(b"xyz")
        with self.assertRaises(ValueError):
            self.workspace.verify_asset(asset["id"])

    def test_concurrent_launch_claim_has_one_winner(self):
        job = self.job()

        def claim():
            try:
                self.workspace.transition(job["id"], "running")
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: claim(), range(2)))
        self.assertEqual(sorted(outcomes), [False, True])
        self.assertEqual(len(self.workspace.events(job["id"])), 2)

    def test_concurrent_ingest_has_single_record(self):
        source = self.source("shared", b"shared-input" * 1000)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.workspace.ingest(source), range(2)))
        self.assertEqual(results[0]["id"], results[1]["id"])
        self.assertEqual(len(self.workspace.list_assets()), 1)

    def test_future_schema_is_rejected(self):
        import sqlite3
        with sqlite3.connect(self.workspace.db_path) as conn:
            conn.execute("PRAGMA user_version=2")
        with self.assertRaisesRegex(ValueError, "schema"):
            Workspace(self.workspace.root)

    def test_asset_pagination_is_stable_and_validated(self):
        expected = [self.workspace.ingest(self.source(f"input-{i}", str(i).encode())) for i in range(5)]
        first = self.workspace.list_assets(limit=2)
        second = self.workspace.list_assets(limit=2, offset=2)
        last = self.workspace.list_assets(limit=2, offset=4)
        self.assertEqual([row["id"] for row in first + second + last], [row["id"] for row in expected])
        self.assertEqual(self.workspace.list_assets(limit=2, offset=5), [])
        for kwargs in ({"limit": 0}, {"limit": 1001}, {"limit": True}, {"offset": -1}, {"offset": True}):
            with self.assertRaises(ValueError):
                self.workspace.list_assets(**kwargs)

    def test_summary_never_exposes_job_details(self):
        job = self.job()
        self.workspace.transition(job["id"], "running", {"private": "sensitive-marker"})
        report = self.workspace.report_summary()
        serialized = json.dumps(report)
        for forbidden in ("sensitive-marker", "synthetic-password", "raw-sha256", str(self.base), job["id"]):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(report["asset_count"], 2)
        self.assertEqual(report["jobs_by_status"]["running"], 1)

    def test_model_rejects_unknown_and_unsafe_fields(self):
        valid = JobSpec("john", "raw-sha256", "a" * 32, "b" * 32).to_dict()
        for field, value in [("runtime_seconds", True), ("runtime_seconds", 0), ("runtime_seconds", 3601),
                             ("schema_version", 2), ("format", "--bad"), ("format", "foo bar"),
                             ("input_id", "../x"), ("engine", "shell"), ("engine_path", "a\x00b")]:
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    JobSpec.from_dict({**valid, field: value})
        with self.assertRaises(ValueError):
            JobSpec.from_dict({**valid, "command": "anything"})
        with self.assertRaises(ValueError):
            JobSpec.from_dict({**valid, "format": "raw:sha256"})
        with self.assertRaises(ValueError):
            JobSpec.from_dict({**valid, "engine": "hashcat", "format": "raw-sha256"})
        self.assertEqual(JobSpec.from_dict({**valid, "engine": "hashcat", "format": "1400"}).format, "1400")
        self.assertEqual(JobSpec.from_dict(valid).to_dict(), valid)


if __name__ == "__main__":
    unittest.main()

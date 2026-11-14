"""Private local evidence storage and transactional recovery-job journal.

Assets are never edited through this API. Files are copied, hashed and verified
before publication. Workspace confidentiality relies on the operating-system
account and filesystem permissions; this module does not encrypt files.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import uuid

from .models import JobSpec, validate_id


CHUNK_SIZE = 1024 * 1024
STATES = ("queued", "running", "completed", "exhausted", "interrupted", "failed")
TRANSITIONS = {
    "queued": {"running"},
    "running": {"completed", "exhausted", "interrupted", "failed"},
    "interrupted": {"running"},
    "completed": set(), "exhausted": set(), "failed": set(),
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _private_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Managed directory must not be a symbolic link")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("Managed path must be a directory")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError("Managed directory must belong to the current user")
    path.chmod(0o700)


def _signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _sync_dir(path):
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class Workspace:
    def __init__(self, root):
        raw_root = Path(root).expanduser().absolute()
        # Check every existing component before resolve() can conceal symlinks.
        for component in (raw_root, *raw_root.parents):
            if component.is_symlink():
                raise ValueError("Workspace path must not contain symbolic links")
        self.root = raw_root
        _private_dir(self.root)
        self.assets_dir = self.root / "assets"
        self.jobs_dir = self.root / "jobs"
        self.staging_dir = self.root / "staging"
        for directory in (self.assets_dir, self.jobs_dir, self.staging_dir):
            _private_dir(directory)
        self.db_path = self.root / "workspace.sqlite3"
        try:
            fd = os.open(self.db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            info = self.db_path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Workspace database must be a regular, unlinked file")
        else:
            os.close(fd)
        self.db_path.chmod(0o600)
        with self._connection() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("Unsupported workspace schema version")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY, sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL, kind TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(sha256, kind)
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, status TEXT NOT NULL,
                    spec TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    old_status TEXT, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status);
                CREATE INDEX IF NOT EXISTS jobs_created_id ON jobs(created_at DESC, id DESC);
                DROP INDEX IF EXISTS jobs_created;
                CREATE INDEX IF NOT EXISTS events_job ON events(job_id, seq);
                PRAGMA user_version=1;
            """)

    @contextmanager
    def _connection(self):
        for path in (self.db_path, Path(str(self.db_path) + "-wal"), Path(str(self.db_path) + "-shm")):
            if path.is_symlink():
                raise ValueError("Workspace database files must not be symbolic links")
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _asset_dict(self, row):
        result = dict(row)
        result["path"] = str(self.assets_dir / (validate_id(result["id"]) + ".bin"))
        return result

    def ingest(self, source, kind="hashes", max_bytes=128 * 1024 * 1024):
        if not isinstance(kind, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", kind):
            raise ValueError("Invalid asset kind")
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        source = Path(source)
        before_path = source.lstat()
        if not stat.S_ISREG(before_path.st_mode):
            raise ValueError("Input must be a regular file, not a symlink or device")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(source, flags)
        temp_path = None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or _signature(before) != _signature(before_path):
                raise ValueError("Input file changed before copying")
            if before.st_size > max_bytes:
                raise ValueError("Input exceeds configured size limit")
            digest = hashlib.sha256()
            size = 0
            temp_fd, temp_name = tempfile.mkstemp(prefix="ingest-", dir=self.staging_dir)
            temp_path = Path(temp_name)
            with os.fdopen(temp_fd, "wb") as destination:
                while True:
                    block = os.read(fd, CHUNK_SIZE)
                    if not block:
                        break
                    size += len(block)
                    if size > max_bytes:
                        raise ValueError("Input exceeds configured size limit")
                    digest.update(block)
                    destination.write(block)
                destination.flush()
                os.fsync(destination.fileno())
            after = os.fstat(fd)
            try:
                after_path = source.lstat()
            except FileNotFoundError as exc:
                raise ValueError("Input disappeared during copying") from exc
            if (_signature(before) != _signature(after)
                    or _signature(before) != _signature(after_path)
                    or size != before.st_size):
                raise ValueError("Input file changed during copying")
            hexdigest = digest.hexdigest()
            with self._connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT * FROM assets WHERE sha256=? AND kind=?", (hexdigest, kind)
                ).fetchone()
                if existing:
                    asset = self._asset_dict(existing)
                    target = Path(asset["path"])
                    info = target.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                        raise ValueError("Existing asset is missing or damaged")
                    # A matching size alone does not establish that stored bytes are intact.
                    with target.open("rb") as stored:
                        stored_digest = hashlib.file_digest(stored, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else _file_digest(stored)
                    if stored_digest != hexdigest:
                        raise ValueError("Existing asset digest does not match recorded content")
                    return asset
                asset_id = uuid.uuid4().hex
                target = self.assets_dir / (asset_id + ".bin")
                os.replace(temp_path, target)
                temp_path = None
                _sync_dir(self.assets_dir)
                created_at = _now()
                try:
                    conn.execute("INSERT INTO assets VALUES (?, ?, ?, ?, ?)",
                                 (asset_id, hexdigest, size, kind, created_at))
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
                return {"id": asset_id, "sha256": hexdigest, "size": size,
                        "kind": kind, "created_at": created_at, "path": str(target)}
        finally:
            os.close(fd)
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def asset(self, asset_id):
        validate_id(asset_id)
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if row is None:
            raise KeyError("Unknown asset identifier")
        return self._asset_dict(row)

    def verify_asset(self, asset_id):
        """Verify stored bytes immediately before use; does not expose their contents."""
        asset = self.asset(asset_id)
        path = Path(asset["path"])
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("Stored asset must be a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size != asset["size"]:
                raise ValueError("Stored asset is damaged")
            digest = hashlib.sha256()
            for block in iter(lambda: os.read(fd, CHUNK_SIZE), b""):
                digest.update(block)
            after = os.fstat(fd)
            if (_signature(before) != _signature(after)
                    or _signature(after) != _signature(path.lstat())
                    or digest.hexdigest() != asset["sha256"]):
                raise ValueError("Stored asset failed integrity verification")
        finally:
            os.close(fd)
        return asset

    def list_assets(self, limit=None, offset=0):
        if limit is not None and (type(limit) is not int or not 1 <= limit <= 1000):
            raise ValueError("limit must be an integer between 1 and 1000")
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a nonnegative integer")
        with self._connection() as conn:
            return [self._asset_dict(row) for row in conn.execute(
                "SELECT * FROM assets ORDER BY created_at, id LIMIT ? OFFSET ?",
                (limit if limit is not None else -1, offset))]

    @staticmethod
    def _job_dict(row):
        result = dict(row)
        result["spec"] = json.loads(result["spec"])
        return result

    def create_job(self, spec):
        spec = JobSpec.from_dict(spec).to_dict()
        if self.asset(spec["input_id"])["kind"] != "hashes":
            raise ValueError("Job input must reference a hashes asset")
        if self.asset(spec["wordlist_id"])["kind"] != "wordlist":
            raise ValueError("Job wordlist must reference a wordlist asset")
        job_id = uuid.uuid4().hex
        timestamp = _now()
        with self._connection() as conn:
            conn.execute("INSERT INTO jobs VALUES (?, ?, ?, ?, ?)",
                         (job_id, "queued", json.dumps(spec, sort_keys=True), timestamp, timestamp))
            conn.execute("INSERT INTO events(job_id,old_status,status,created_at,details) VALUES (?,NULL,?,?,?)",
                         (job_id, "queued", timestamp, "{}"))
        return self.job(job_id)

    def job(self, job_id):
        validate_id(job_id)
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError("Unknown job identifier")
        return self._job_dict(row)

    def list_jobs(self, limit=100):
        if type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError("limit must be an integer between 1 and 10000")
        with self._connection() as conn:
            return [self._job_dict(row) for row in conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC, id DESC LIMIT ?", (limit,))]

    def transition(self, job_id, status, details=None):
        validate_id(job_id)
        if status not in STATES:
            raise ValueError("Unknown job status")
        if details is not None and not isinstance(details, dict):
            raise ValueError("Event details must be an object")
        detail_json = json.dumps(details or {}, sort_keys=True, allow_nan=False)
        if len(detail_json.encode("utf-8")) > 65536:
            raise ValueError("Event details exceed size limit")
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise KeyError("Unknown job identifier")
            old_status = row["status"]
            if status not in TRANSITIONS[old_status]:
                raise ValueError("Invalid job transition: " + old_status + " -> " + status)
            timestamp = _now()
            conn.execute("UPDATE jobs SET status=?,updated_at=? WHERE id=?", (status, timestamp, job_id))
            conn.execute("INSERT INTO events(job_id,old_status,status,created_at,details) VALUES (?,?,?,?,?)",
                         (job_id, old_status, status, timestamp, detail_json))
        return self.job(job_id)

    def events(self, job_id):
        self.job(job_id)
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM events WHERE job_id=? ORDER BY seq", (job_id,)).fetchall()
        result = []
        for row in rows:
            event = dict(row)
            event["details"] = json.loads(event["details"])
            result.append(event)
        return result

    def job_dir(self, job_id):
        self.job(job_id)
        directory = self.jobs_dir / job_id
        _private_dir(directory)
        return directory

    def report_summary(self):
        with self._connection() as conn:
            totals = conn.execute("SELECT COUNT(*) AS count,COALESCE(SUM(size),0) AS bytes FROM assets").fetchone()
            kinds = {row["kind"]: row["count"] for row in conn.execute("SELECT kind,COUNT(*) AS count FROM assets GROUP BY kind")}
            statuses = {status: 0 for status in STATES}
            statuses.update({row["status"]: row["count"] for row in conn.execute("SELECT status,COUNT(*) AS count FROM jobs GROUP BY status")})
        return {"schema_version": 1, "asset_count": totals["count"], "asset_bytes": totals["bytes"],
                "job_count": sum(statuses.values()), "jobs_by_status": statuses, "assets_by_kind": kinds}


def _file_digest(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(CHUNK_SIZE), b""):
        digest.update(block)
    return digest.hexdigest()

"""Authenticated, bounded HTTP service for one trusted team's workspace.

The listener is intended to sit behind a TLS reverse proxy. Engine executables
are administrator configuration, never values accepted from API requests.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import stat
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

MAX_UPLOAD = 128 * 1024 * 1024
MAX_JSON = 64 * 1024
MAX_AUTH_FILE = 1024 * 1024
MAX_HTTP_CONNECTIONS = 32
MAX_UPLOADS = 2
MAX_UPLOAD_SECONDS = 120
MAX_ASSET_BYTES = 4 * 1024 * 1024 * 1024
MAX_ASSET_COUNT = 10000
DISK_RESERVE = 64 * 1024 * 1024
ID = re.compile(r"[0-9a-f]{32}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_~.+/-]{32,512}\Z")
SAFE_JOB_FIELDS = ("id", "status", "created_at", "updated_at")
SAFE_SPEC_FIELDS = ("engine", "format", "input_id", "wordlist_id", "runtime_seconds", "schema_version")


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message
        super().__init__(message)


def _utcnow():
    return datetime.now(timezone.utc).isoformat()


def load_principals(path: Path) -> tuple[dict, ...]:
    """Read a private, regular config file containing only token digests."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if Path(path).is_symlink():
        raise ValueError("authentication file must not be a symbolic link")
    with os.fdopen(os.open(path, flags), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_AUTH_FILE:
            raise ValueError("authentication file must be a bounded regular file")
        if os.name == "posix" and info.st_mode & 0o077:
            raise ValueError("authentication file must have mode 0600 or stricter")
        data = json.loads(source.read(MAX_AUTH_FILE + 1))
    if not isinstance(data, dict) or set(data) != {"principals"}:
        raise ValueError("authentication config requires only a principals array")
    principals = data["principals"]
    if not isinstance(principals, list) or not 1 <= len(principals) <= 1000:
        raise ValueError("authentication config requires 1 to 1000 principals")
    names, digests, normalized = set(), set(), []
    for row in principals:
        if not isinstance(row, dict) or set(row) != {"name", "role", "token_sha256"}:
            raise ValueError("principal fields must be name, role, and token_sha256")
        name, role, digest = row["name"], row["role"], row["token_sha256"]
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise ValueError("invalid principal name")
        if role not in ("viewer", "operator", "admin"):
            raise ValueError("invalid principal role")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid token digest")
        if name in names or digest in digests:
            raise ValueError("principal names and token digests must be unique")
        names.add(name)
        digests.add(digest)
        normalized.append({"name": name, "role": role, "token_sha256": digest})
    return tuple(normalized)


@contextmanager
def _workspace(root):
    from .storage import Workspace
    workspace = Workspace(root)
    try:
        yield workspace
    finally:
        close = getattr(workspace, "close", None)
        if close:
            close()


def _safe_job(job):
    result = {key: job[key] for key in SAFE_JOB_FIELDS if key in job}
    spec = job.get("spec", {})
    if isinstance(spec, dict):
        result["spec"] = {key: spec[key] for key in SAFE_SPEC_FIELDS if key in spec}
    return result


def _safe_asset(asset):
    return {key: asset[key] for key in ("id", "sha256", "size", "kind", "created_at") if key in asset}


def _run_job(root, job_id, engine_paths, resume):
    from .service import run_job
    return run_job(root, job_id, engine_paths, resume=resume)


class TeamServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True
    allow_reuse_address = True

    def __init__(self, address, workspace_root, principals, engine_paths, integrations, backlog, max_workers):
        self.workspace_root = Path(workspace_root).resolve()
        self.principals = principals
        self.engine_paths = dict(engine_paths)
        # Catalogs are immutable snapshots for this server process. Cache their
        # encoded representation rather than serializing 1,000 rows per request.
        self._integrations_json = json.dumps(integrations, ensure_ascii=False, separators=(",", ":")).encode()
        self._backlog_json = json.dumps(backlog, ensure_ascii=False, separators=(",", ":")).encode()
        self.integrations = json.loads(self._integrations_json)
        self.backlog = json.loads(self._backlog_json)
        self._state_lock = threading.Lock()
        self._audit_lock = threading.Lock()
        self._pending = set()
        self._closed = False
        self._slots = threading.BoundedSemaphore(max_workers + 16)
        self._http_slots = threading.BoundedSemaphore(MAX_HTTP_CONNECTIONS)
        self._upload_slots = threading.BoundedSemaphore(MAX_UPLOADS)
        self._upload_lock = threading.Lock()
        self._reserved_upload_bytes = 0
        self._reserved_upload_count = 0
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="jeffe-worker")
        self._audit_path = self.workspace_root / "team-audit.jsonl"
        super().__init__(address, TeamHandler)

    def process_request(self, request, client_address):
        if not self._http_slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._http_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._http_slots.release()

    def handle_error(self, request, client_address):
        # HTTP errors already use redacted responses. Never dump request-bearing
        # stack traces to a shared service console.
        pass

    @contextmanager
    def reserve_upload(self, size):
        if not self._upload_slots.acquire(blocking=False):
            raise APIError(429, "uploads_busy", "Too many uploads are active; retry later.")
        reserved = False
        try:
            with self._upload_lock:
                with _workspace(self.workspace_root) as workspace:
                    summary = workspace.report_summary()
                if summary["asset_bytes"] + self._reserved_upload_bytes + size > MAX_ASSET_BYTES:
                    raise APIError(413, "storage_quota", "The team's stored-asset quota would be exceeded.")
                if summary["asset_count"] + self._reserved_upload_count >= MAX_ASSET_COUNT:
                    raise APIError(413, "asset_count_quota", "The team's stored-asset count quota would be exceeded.")
                if shutil.disk_usage(self.workspace_root).free < self._reserved_upload_bytes + size + DISK_RESERVE:
                    raise APIError(507, "insufficient_storage", "Insufficient free space for this upload.")
                self._reserved_upload_bytes += size
                self._reserved_upload_count += 1
                reserved = True
            yield
        finally:
            if reserved:
                with self._upload_lock:
                    self._reserved_upload_bytes -= size
                    self._reserved_upload_count -= 1
            self._upload_slots.release()

    def audit(self, principal, action, subject=None, outcome="accepted"):
        event = {"at": _utcnow(), "actor": principal["name"], "role": principal["role"],
                 "action": action, "outcome": outcome}
        if subject is not None:
            event["subject"] = subject
        payload = (json.dumps(event, separators=(",", ":")) + "\n").encode()
        with self._audit_lock:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self._audit_path, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "ab", closefd=False) as target:
                    target.write(payload)
                    target.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)

    def schedule(self, principal, job_id, resume=False):
        with self._state_lock:
            if self._closed:
                raise APIError(503, "shutting_down", "The server is shutting down.")
            if job_id in self._pending:
                raise APIError(409, "already_scheduled", "This job is already scheduled.")
            if not self._slots.acquire(blocking=False):
                raise APIError(429, "queue_full", "The worker queue is full; retry later.")
            self._pending.add(job_id)
            try:
                self.audit(principal, "resume" if resume else "run", job_id)
                future = self.executor.submit(_run_job, self.workspace_root, job_id, self.engine_paths, resume)
            except Exception:
                self._pending.remove(job_id)
                self._slots.release()
                raise

        def done(completed):
            with self._state_lock:
                self._pending.discard(job_id)
                self._slots.release()
            try:
                outcome = "cancelled" if completed.cancelled() else "returned"
                if not completed.cancelled() and completed.exception() is not None:
                    outcome = "failed"
                self.audit(principal, "worker_finished", job_id, outcome)
            except OSError:
                # Runtime job state remains in SQLite; never print secret-bearing errors.
                pass
        future.add_done_callback(done)

    def server_close(self):
        with self._state_lock:
            self._closed = True
        super().server_close()
        # Active engine runs have a validated runtime and adapter termination grace.
        # Unstarted work is cancelled; queued jobs remain explicit queued records.
        self.executor.shutdown(wait=True, cancel_futures=True)


class TeamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "JEFFE"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, format, *args):
        pass

    def _send(self, status, data, content_type="application/json; charset=utf-8", extra_headers=None):
        body = data if isinstance(data, bytes) else (json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode() if content_type.startswith("application/json") else data.encode())
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'")
        self.send_header("Connection", "close")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, str(value))
        if status == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="JEFFE team"')
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def _error(self, error):
        self._send(error.status, {"error": {"code": error.code, "message": error.message}})

    def _authenticate(self):
        headers = self.headers.get_all("Authorization", [])
        if len(headers) != 1 or not headers[0].startswith("Bearer "):
            raise APIError(401, "unauthorized", "A valid bearer token is required.")
        token = headers[0][7:]
        if not TOKEN.fullmatch(token):
            raise APIError(401, "unauthorized", "A valid bearer token is required.")
        digest = hashlib.sha256(token.encode()).hexdigest()
        found = None
        for principal in self.server.principals:
            if hmac.compare_digest(digest, principal["token_sha256"]):
                found = principal
        if found is None:
            raise APIError(401, "unauthorized", "A valid bearer token is required.")
        return found

    def _length(self, maximum, allow_empty=False):
        if self.headers.get("Transfer-Encoding"):
            raise APIError(400, "transfer_encoding", "Chunked request bodies are not supported.")
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths and allow_empty:
            return 0
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            raise APIError(411, "content_length", "One valid Content-Length header is required.")
        length = int(lengths[0])
        if length > maximum:
            raise APIError(413, "body_too_large", "The request body exceeds the endpoint limit.")
        return length

    def _json(self, allow_empty=False):
        length = self._length(MAX_JSON, allow_empty)
        if not length and allow_empty:
            return {}
        if self.headers.get_content_type() != "application/json":
            raise APIError(415, "content_type", "Use application/json for this endpoint.")
        chunks, remaining, deadline = [], length, time.monotonic() + 30
        while remaining:
            time_left = deadline - time.monotonic()
            if time_left <= 0:
                raise APIError(408, "request_timeout", "The request body exceeded its time limit.")
            self.connection.settimeout(time_left)
            chunk = self.rfile.read1(remaining)
            if not chunk:
                raise APIError(400, "incomplete_body", "The request body was incomplete.")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise APIError(400, "invalid_json", "The request body must be valid JSON.") from None
        if not isinstance(data, dict):
            raise APIError(400, "invalid_json", "The request body must be a JSON object.")
        return data

    def _route(self):
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise APIError(400, "invalid_path", "Use a relative request path.")
        path = parsed.path
        if self.command == "GET" and path == "/health":
            return self._send(200, {"status": "ok"})
        if self.command == "GET" and path == "/":
            from .dashboard import render_team_shell
            return self._send(200, render_team_shell(), "text/html; charset=utf-8")
        principal = self._authenticate()
        if self.command == "GET":
            if path == "/api/me":
                return self._send(200, {"name": principal["name"], "role": principal["role"]})
            if path == "/api/integrations":
                return self._send(200, self.server._integrations_json)
            if path == "/api/backlog":
                return self._send(200, self.server._backlog_json)
            with _workspace(self.server.workspace_root) as workspace:
                if path == "/api/summary":
                    return self._send(200, workspace.report_summary())
                if path == "/api/assets":
                    query = parse_qs(parsed.query, keep_blank_values=True)
                    if set(query) - {"limit", "offset"} or any(len(v) != 1 for v in query.values()):
                        raise APIError(400, "pagination", "Use limit and offset for asset pagination.")
                    try:
                        limit = int(query.get("limit", ["1000"])[0])
                        offset = int(query.get("offset", ["0"])[0])
                    except ValueError:
                        raise APIError(400, "pagination", "Pagination values must be integers.") from None
                    if not 1 <= limit <= 1000 or not 0 <= offset <= 1000000000:
                        raise APIError(400, "pagination", "Asset limit must be 1–1000 and offset nonnegative.")
                    total = workspace.report_summary()["asset_count"]
                    headers = {"X-Total-Count": total, "X-Limit": limit, "X-Offset": offset}
                    if offset + limit < total:
                        headers["Link"] = f'</api/assets?limit={limit}&offset={offset + limit}>; rel="next"'
                    return self._send(200, [_safe_asset(a) for a in workspace.list_assets(limit=limit, offset=offset)], extra_headers=headers)
                if path == "/api/jobs":
                    return self._send(200, [_safe_job(j) for j in workspace.list_jobs(limit=1000)])
                if path == "/api/dashboard":
                    from .dashboard import render_dashboard
                    return self._send(200, render_dashboard(workspace.report_summary(), workspace.list_jobs(limit=1000), self.server.integrations, self.server.backlog), "text/html; charset=utf-8")
                match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})", path)
                if match:
                    return self._send(200, _safe_job(workspace.job(match.group(1))))
            raise APIError(404, "not_found", "The requested resource was not found.")
        if self.command != "POST":
            raise APIError(405, "method_not_allowed", "This method is not supported.")
        if principal["role"] not in ("operator", "admin"):
            self.server.audit(principal, "write_denied", outcome="denied")
            raise APIError(403, "forbidden", "This action requires an operator or administrator.")
        if path == "/api/assets":
            return self._upload(principal, parse_qs(parsed.query, keep_blank_values=True))
        if path == "/api/jobs":
            data = self._json()
            if "engine_path" in data:
                raise APIError(400, "engine_path_forbidden", "Engine paths are administrator configuration.")
            if set(data) - set(SAFE_SPEC_FIELDS):
                raise APIError(400, "unknown_field", "The job contains unsupported fields.")
            if data.get("engine") not in self.server.engine_paths:
                raise APIError(400, "engine_unavailable", "The requested engine is not configured.")
            with _workspace(self.server.workspace_root) as workspace:
                job = workspace.create_job(data)
            self.server.audit(principal, "create_job", job["id"])
            return self._send(201, _safe_job(job))
        match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})/(run|resume)", path)
        if match:
            if self._json(allow_empty=True):
                raise APIError(400, "unexpected_body", "This action does not accept options.")
            job_id, action = match.groups()
            with _workspace(self.server.workspace_root) as workspace:
                job = workspace.job(job_id)
            expected = "interrupted" if action == "resume" else "queued"
            if job["status"] != expected:
                raise APIError(409, "invalid_state", "The job is not in a valid state for this action.")
            self.server.schedule(principal, job_id, resume=action == "resume")
            return self._send(202, {"id": job_id, "status": "scheduled"})
        raise APIError(404, "not_found", "The requested resource was not found.")

    def _upload(self, principal, query):
        if set(query) != {"kind"} or len(query["kind"]) != 1 or query["kind"][0] not in ("hashes", "wordlist"):
            raise APIError(400, "invalid_kind", "Choose kind=hashes or kind=wordlist.")
        if self.headers.get_content_type() != "application/octet-stream":
            raise APIError(415, "content_type", "Upload raw bytes as application/octet-stream.")
        size = self._length(MAX_UPLOAD)
        with self.server.reserve_upload(size):
            return self._store_upload(principal, query["kind"][0], size)

    def _store_upload(self, principal, kind, remaining):
        deadline = time.monotonic() + MAX_UPLOAD_SECONDS
        folder = self.server.workspace_root / "uploads"
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.is_symlink():
            raise APIError(500, "storage_unavailable", "Upload storage is unavailable.")
        folder.chmod(0o700)
        fd, name = tempfile.mkstemp(prefix="upload-", dir=folder)
        try:
            with os.fdopen(fd, "wb") as target:
                while remaining:
                    time_left = deadline - time.monotonic()
                    if time_left <= 0:
                        raise APIError(408, "upload_timeout", "The upload exceeded its total time limit.")
                    self.connection.settimeout(min(30, time_left))
                    chunk = self.rfile.read1(min(1024 * 1024, remaining))
                    if not chunk:
                        raise APIError(400, "incomplete_body", "The request body was incomplete.")
                    target.write(chunk)
                    remaining -= len(chunk)
                target.flush()
                os.fsync(target.fileno())
            with _workspace(self.server.workspace_root) as workspace:
                asset = workspace.ingest(Path(name), kind=kind, max_bytes=MAX_UPLOAD)
            self.server.audit(principal, "import_asset", asset["id"])
            return self._send(201, _safe_asset(asset))
        finally:
            Path(name).unlink(missing_ok=True)

    def _handle(self):
        try:
            self._route()
        except APIError as error:
            self._error(error)
        except KeyError:
            self._error(APIError(404, "not_found", "The requested resource was not found."))
        except (ValueError, TypeError):
            self._error(APIError(400, "invalid_request", "The request contains invalid values."))
        except (TimeoutError, socket.timeout):
            self._error(APIError(408, "request_timeout", "The request timed out."))
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            self._error(APIError(500, "internal_error", "The operation could not be completed."))

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_TRACE = _handle
    do_OPTIONS = _handle
    do_HEAD = _handle


def build_server(host: str, port: int, workspace_root: Path, auth_path: Path,
                 engine_paths: dict, integrations: list, backlog: list,
                 max_workers: int = 1) -> ThreadingHTTPServer:
    """Create an unstarted team server; caller owns serve_forever/shutdown/close."""
    if not isinstance(host, str) or not host:
        raise ValueError("host is required")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("invalid listener port")
    if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 8:
        raise ValueError("worker count must be between 1 and 8")
    if not isinstance(engine_paths, dict) or set(engine_paths) - {"john", "hashcat"}:
        raise ValueError("only John and Hashcat engine configuration is supported")
    if any(not isinstance(value, str) or not value or "\0" in value for value in engine_paths.values()):
        raise ValueError("engine executable paths must be nonempty strings")
    principals = load_principals(Path(auth_path))
    with _workspace(Path(workspace_root)):
        pass
    return TeamServer((host, port), workspace_root, principals, engine_paths, integrations, backlog, max_workers)

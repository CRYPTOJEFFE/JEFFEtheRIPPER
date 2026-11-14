"""Bounded subprocess adapters for locally installed offline recovery engines.

Logs and engine pot files are sensitive and remain in the private job directory.
The return values intentionally contain counts and execution metadata only.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
from typing import Any

MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_PROBE_BYTES = 256 * 1024
_FORMAT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]{0,127}\Z")


def _binary(executable: str) -> Path:
    path = Path(executable).expanduser().resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("Engine must be an executable regular file")
    return path


def _digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def _private_directory(directory: Path) -> Path:
    path = Path(directory).absolute()
    if path.is_symlink():
        raise ValueError("Job directory cannot be a symbolic link")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("Job directory must be a directory")
    if os.name == "posix":
        path.chmod(0o700)
    return path.resolve()


def _private_file(path: Path, *, append: bool = False):
    # Validate before truncation: opening an existing hardlink must not erase a
    # file outside the workspace, and a FIFO must not block before fstat.
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("Engine output destination must be a singly linked regular file")
    if not append:
        os.ftruncate(fd, 0)
    if os.name == "posix":
        os.fchmod(fd, 0o600)
    return os.fdopen(fd, "ab" if append else "wb")


def _signal_group(process: subprocess.Popen, sig: int) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, sig)
        elif sig == signal.SIGINT:
            process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
        elif sig == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except (ProcessLookupError, PermissionError):
        pass


def _stop(process: subprocess.Popen, grace: float) -> None:
    _signal_group(process, signal.SIGINT)
    try:
        process.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    _signal_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        _signal_group(process, getattr(signal, "SIGKILL", signal.SIGTERM))
        process.wait(timeout=max(1.0, grace))


def _run(command: list[str], directory: Path, timeout: float, log_path: Path,
         *, grace: float = 3.0, max_output: int = MAX_LOG_BYTES) -> dict[str, Any]:
    """Drain both output streams without buffering unbounded output in memory."""
    started = time.monotonic()
    exceeded = threading.Event()
    io_failed = threading.Event()
    written = [0]
    options: dict[str, Any] = {"start_new_session": True} if os.name == "posix" else {
        "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    with _private_file(log_path) as log:
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   shell=False, **options)

        def drain() -> None:
            assert process.stdout is not None
            try:
                while True:
                    chunk = process.stdout.read(8192)
                    if not chunk:
                        break
                    remaining = max(0, max_output - written[0])
                    if remaining:
                        saved = chunk[:remaining]
                        log.write(saved)
                        written[0] += len(saved)
                    if len(chunk) > remaining:
                        exceeded.set()
                log.flush()
            except (OSError, ValueError):
                io_failed.set()

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        timed_out = interrupted = False
        try:
            while process.poll() is None:
                if exceeded.is_set() or io_failed.is_set():
                    _stop(process, grace)
                    break
                if time.monotonic() - started >= timeout:
                    timed_out = True
                    _stop(process, grace)
                    break
                time.sleep(0.025)
        except KeyboardInterrupt:
            interrupted = True
            _stop(process, grace)
        finally:
            if process.poll() is None:
                _stop(process, grace)
            # A descendant retaining stdout must not keep an adapter alive.
            reader.join(timeout=max(1.0, grace))
            if reader.is_alive():
                _signal_group(process, signal.SIGTERM)
                reader.join(timeout=max(1.0, grace))
            if reader.is_alive():
                _signal_group(process, getattr(signal, "SIGKILL", signal.SIGTERM))
                reader.join(timeout=1.0)
            if not reader.is_alive() and process.stdout is not None:
                process.stdout.close()
            # The thread is daemonized as a last resort on unsupported platforms.
        return {"exit_code": process.returncode,
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "timed_out": timed_out, "interrupted": interrupted,
                "output_limit_reached": exceeded.is_set(),
                "log_write_failed": io_failed.is_set(), "log_bytes": written[0]}


def _probe(executable: str, engine: str, flag: str) -> tuple[dict[str, Any], str]:
    if engine not in {"john", "hashcat"}:
        raise ValueError("Supported engines are john and hashcat")
    binary = _binary(executable)
    with tempfile.TemporaryDirectory(prefix="jeffe-probe-") as temp:
        directory = _private_directory(Path(temp))
        logfile = directory / "probe.log"
        metadata = _run([str(binary), flag], directory, 10.0, logfile,
                        grace=1.0, max_output=MAX_PROBE_BYTES)
        output = logfile.read_bytes().decode("utf-8", errors="replace")
    metadata.update({"engine": engine, "executable": str(binary),
                     "sha256": _digest(binary),
                     "available": metadata["exit_code"] == 0 and not metadata["timed_out"]
                     and not metadata["output_limit_reached"]})
    return metadata, output


def diagnostics(executable: str, engine: str) -> dict[str, Any]:
    """Probe an explicitly selected installed executable, with a ten-second cap."""
    metadata, output = _probe(executable, engine,
                              "--list=build-info" if engine == "john" else "--version")
    # Build/version output only; never invoke --show or expose job log content.
    metadata["build_info"] = "".join(c for c in output[:16384]
                                     if c in "\n\t" or ord(c) >= 32)
    return metadata


def formats(executable: str, engine: str) -> list[str]:
    """Discover John formats from the installed build; no static support claims."""
    if engine == "hashcat":
        return []  # Numeric modes are explicitly selected; discovery is not implemented.
    metadata, output = _probe(executable, engine, "--list=formats")
    if not metadata["available"]:
        raise RuntimeError("Installed engine format discovery failed")
    result = set()
    # John writes a human summary to stderr, which the bounded runner merges.
    # It also emits dynamic_n as a family placeholder rather than a usable label.
    lines = [line for line in output.splitlines()
             if not re.match(r"\s*\d+\s+formats\b", line)
             and not line.lower().startswith(("warning:", "error:"))]
    for token in re.split(r"[,\s]+", "\n".join(lines)):
        if _FORMAT.fullmatch(token) and not token.isdigit() and token != "dynamic_n":
            result.add(token)
    return sorted(result)


def build_command(spec: dict[str, Any], input_path: Path, wordlist_path: Path,
                  job_dir: Path, engine_path: str, resume: bool = False) -> list[str]:
    """Build an argument vector; filenames are never evaluated as shell text."""
    engine = spec.get("engine")
    if engine not in {"john", "hashcat"}:
        raise ValueError("Supported engines are john and hashcat")
    fmt = str(spec.get("format", ""))
    runtime = spec.get("runtime_seconds", 30)
    if type(runtime) is not int or not 1 <= runtime <= 3600:
        raise ValueError("runtime_seconds must be an integer from 1 to 3600")
    if not _FORMAT.fullmatch(fmt) or (engine == "hashcat" and not fmt.isdigit()):
        raise ValueError("Invalid engine format identifier")
    binary = str(_binary(engine_path))
    directory = Path(job_dir).absolute()
    inputs = Path(input_path).absolute()
    words = Path(wordlist_path).absolute()
    if engine == "john":
        session = str(directory / "session")
        if resume:
            # John persists --max-run-time and all original input/pot options.
            return [binary, "--restore=" + session]
        return [binary, "--format=" + fmt, "--wordlist=" + str(words),
                "--pot=" + str(directory / "results.pot"), "--session=" + session,
                "--max-run-time=" + str(runtime), str(inputs)]
    session = "jeffe-" + hashlib.sha256(str(directory).encode()).hexdigest()[:20]
    common = ["--session=" + session,
              "--restore-file-path=" + str(directory / "session.restore")]
    if resume:
        return [binary, "--restore", *common]
    return [binary, "-m", fmt, "-a", "0", "--runtime=" + str(runtime),
            "--potfile-path=" + str(directory / "results.pot"),
            "--logfile-disable", *common, str(inputs), str(words)]


def _checkpoint(directory: Path, engine: str) -> bool:
    path = directory / ("session.rec" if engine == "john" else "session.restore")
    return path.is_file() and not path.is_symlink() and path.stat().st_size > 0


def _pot_count(path: Path) -> int:
    """Count non-empty records without interpreting or returning recovered values."""
    if not path.exists() or path.is_symlink():
        return 0
    count = 0
    with path.open("rb") as stream:
        for line in stream:
            if line.strip():
                count += 1
    return count


def execute(spec: dict[str, Any], input_path: Path, wordlist_path: Path,
            job_dir: Path, engine_path: str, resume: bool = False,
            *, grace_seconds: float = 3.0) -> dict[str, Any]:
    """Run one bounded offline job; callers own durable state and resume validation.

    A completed state means engine processing ended with reported recovery records;
    it does not assert that every input record was recovered or independently verified.
    """
    if not 0.05 <= grace_seconds <= 30:
        raise ValueError("grace_seconds must be from 0.05 to 30")
    directory = _private_directory(Path(job_dir))
    engine = spec.get("engine")
    for source in (Path(input_path), Path(wordlist_path)):
        if source.is_symlink() or not source.is_file():
            raise ValueError("Engine inputs must be local regular files, not symbolic links")
    for name in ("results.pot", "session.rec", "session.restore", "session.log", "engine.log"):
        candidate = directory / name
        if candidate.is_symlink():
            raise ValueError("Job engine artifacts cannot be symbolic links")
        if candidate.exists():
            info = candidate.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Job engine artifacts must be singly linked regular files")
    command = build_command(spec, input_path, wordlist_path, directory, engine_path, resume)
    if resume and not _checkpoint(directory, engine):
        raise ValueError("No compatible engine checkpoint is available")
    with _private_file(directory / "results.pot", append=True):
        pass
    engine_digest = _digest(Path(command[0]))
    result = _run(command, directory, spec.get("runtime_seconds", 30) + 2.0,
                  directory / "engine.log", grace=grace_seconds)
    checkpoint = _checkpoint(directory, engine)
    count = _pot_count(directory / "results.pot")
    result.update({"engine": engine, "engine_digest": engine_digest,
                   "engine_changed_during_run": engine_digest != _digest(Path(command[0])),
                   "checkpoint_available": checkpoint, "recovered_records": count,
                   "results_independently_verified": False})
    failed_io = (result["output_limit_reached"] or result["log_write_failed"]
                 or result["engine_changed_during_run"])
    if failed_io:
        status = "failed"
    elif result["timed_out"] or result["interrupted"]:
        status = "interrupted"
    elif engine == "hashcat":
        status = {0: "completed", 1: "exhausted", 2: "interrupted", 3: "interrupted",
                  4: "interrupted"}.get(result["exit_code"], "failed")
    elif result["exit_code"] == 0:
        status = "interrupted" if checkpoint else ("completed" if count else "exhausted")
    elif result["exit_code"] == 2:
        # John signals.c:check_abort exits 2 for its native runtime cap and
        # graceful interruption. Error exits must not be confused with this.
        status = "interrupted"
    else:
        status = "failed"
    result["status"] = status
    for name in ("results.pot", "session.rec", "session.restore", "session.log", "engine.log"):
        path = directory / name
        if path.is_file() and not path.is_symlink() and os.name == "posix":
            path.chmod(0o600)
    return result

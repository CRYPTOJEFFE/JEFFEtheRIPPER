"""Application services shared by the CLI and authenticated team server."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from .storage import Workspace
from . import engines


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def private_json(path: Path, value: object) -> None:
    """Atomically replace a private JSON artifact without following its final symlink."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.jeffe-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(value, output, indent=2, ensure_ascii=False)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def catalog_data(name: str) -> list[dict]:
    if name not in {'integrations', 'backlog'}:
        raise ValueError('Unknown catalog')
    path = Path(__file__).parent / 'data' / (name + '.json')
    return json.loads(path.read_text(encoding='utf-8'))


def public_job(job: dict) -> dict:
    result = {k: job[k] for k in ('id', 'status', 'created_at', 'updated_at') if k in job}
    spec = job.get('spec', {})
    result['configuration'] = {k: spec[k] for k in ('engine', 'format', 'input_id', 'wordlist_id', 'runtime_seconds') if k in spec}
    return result


def resolve_engine(value: str | None) -> Path:
    if not value:
        raise ValueError('Engine is not configured; run diagnostics and configure its executable')
    found = shutil.which(value)
    candidate = Path(found or value).expanduser().resolve(strict=True)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ValueError('Configured engine is not an executable file')
    return candidate


def run_job(workspace_root: Path, job_id: str, engine_paths: dict, resume: bool = False) -> dict:
    """Execute only managed local assets, pinning the engine and asset bytes for resume."""
    ws = Workspace(Path(workspace_root))
    try:
        job = ws.job(job_id)
        expected = 'interrupted' if resume else 'queued'
        if job['status'] != expected:
            raise ValueError(f'Job must be {expected} for this operation')
        spec = job['spec']
        binary = resolve_engine(engine_paths.get(spec['engine']))
        source, words = ws.verify_asset(spec['input_id']), ws.verify_asset(spec['wordlist_id'])
        input_path, wordlist_path = Path(source['path']), Path(words['path'])
        directory = ws.job_dir(job_id)
        manifest_path = directory / 'execution.json'
        manifest = {
            'schema_version': 1, 'job_id': job_id, 'spec': spec,
            'engine_sha256': digest_file(binary),
            'input_sha256': source['sha256'], 'wordlist_sha256': words['sha256'],
        }
        if resume:
            if manifest_path.is_symlink() or not manifest_path.is_file():
                raise ValueError('A trusted execution manifest is required to resume')
            if json.loads(manifest_path.read_text()) != manifest:
                raise ValueError('Resume requires the original engine, input bytes and configuration')
        # The transactional lifecycle update claims the job before writing execution state.
        ws.transition(job_id, 'running', {'operation': 'resume' if resume else 'start'})
        try:
            if not resume:
                private_json(manifest_path, manifest)
            result = engines.execute(spec, input_path, wordlist_path, directory, str(binary), resume=resume)
            # Results here are engine-reported counts, not independent cryptographic confirmation.
            result['verification'] = 'engine-reported'
            private_json(directory / 'outcome.json', result)
            ws.transition(job_id, result['status'], {
                'exit_code': result.get('exit_code'),
                'elapsed_seconds': result.get('elapsed_seconds'),
                'checkpoint_available': result.get('checkpoint_available', False),
                'recovered_records': result.get('recovered_records', 0),
                'verification': 'engine-reported',
            })
            return {'job': public_job(ws.job(job_id)), 'outcome': result}
        except BaseException:
            # Never persist exception strings: engine and input errors can contain secrets.
            ws.transition(job_id, 'failed', {'error_code': 'execution_failed'})
            raise
    finally:
        if hasattr(ws, 'close'):
            ws.close()


def recover_orphaned_jobs(workspace_root: Path) -> int:
    """Explicit administrative operation; do not infer process ownership from a reused PID."""
    ws = Workspace(workspace_root)
    try:
        count = 0
        for job in ws.list_jobs(limit=10000):
            if job['status'] == 'running':
                ws.transition(job['id'], 'failed', {'error_code': 'operator_reconciled_orphan'})
                count += 1
        return count
    finally:
        if hasattr(ws, 'close'):
            ws.close()

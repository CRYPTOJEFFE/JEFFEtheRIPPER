# JEFFE Ultimate workbench 0.1.0

A runnable offline password-recovery workbench and authenticated **single-team server** around John Jumbo. The interface records immutable inputs, bounded jobs and private results. Hashcat has an optional adapter; its native binary and GPU behavior have not been validated in this environment.

This release implements a focused subset of the earlier 1,000-proposal catalog. `jeffe/data/backlog.json` accounts for every proposal with an explicit status and evidence. The 51-entry integration catalog contains the original 30 candidates plus 21 unique newly requested links. Catalog inclusion never downloads or executes a project.

## Run from this checkout

Python 3.10+ is required. The application has no third-party runtime Python dependencies. Start in `ultimate/`:

```sh
python -m jeffe --workspace /path/to/private-workspace init
python -m jeffe --john ../run/john diagnose
python -m jeffe --workspace /path/to/private-workspace --john ../run/john demo
```

The demo creates a tiny public synthetic hash/wordlist fixture. It does not use existing user data. To build John from source, follow upstream `doc/INSTALL`; the validation build here used `./configure --disable-opencl --disable-pcap` and `make -j2` in `src/`. That resulting AVX-512 executable targets this host and is not a portable binary release.

## Shared team server

Create one private authentication file and add named users. Each command prints a newly generated token once; keep it private. Only SHA-256 token digests are stored.

```sh
python -m jeffe auth-add --auth /path/to/private/auth.json --name owner --role admin
python -m jeffe auth-add --auth /path/to/private/auth.json --name analyst --role operator
python -m jeffe auth-add --auth /path/to/private/auth.json --name reviewer --role viewer
python -m jeffe --workspace /path/to/private-workspace --john /absolute/path/to/run/john serve --auth /path/to/private/auth.json --host 127.0.0.1 --port 8765 --workers 1
```

Open `http://127.0.0.1:8765` and enter a token. The browser keeps the token in memory, not local storage or URLs. Viewers can read redacted status and reports. Operators and administrators can upload local hash/wordlist files, create jobs, and request bounded execution/resume. Authentication administration is through the local CLI; the admin role does not imply a remote account-management feature. Restart the server after changing/revoking tokens.

For remote team use, keep the application bound to loopback and put an HTTPS reverse proxy in front of it. A sample Caddy configuration is in `deploy/Caddyfile.example`; it is not deployed or tested against a public domain. Run under a dedicated OS account with a private data directory. One server process owns one trusted team's workspace. All members share that team's catalog and job metadata; separate-project/tenant isolation, SSO, MFA, token expiry, distributed workers, and production deployment hardening remain future work.

The worker queue allows 16 waiting jobs plus the configured worker count. Each job has a 1–3,600 second execution budget, followed by bounded signal-handling grace. Server shutdown waits for active bounded jobs; there is no browser cancellation control in this release. A hard process/host crash can leave a durable job marked running; automatic orphan recovery is not implemented. Inspect engine processes and checkpoint artifacts before manually reconciling such a workspace. Queued records survive; scheduling requests are in memory and must be resubmitted after restart.

## Local CLI workflow

```sh
python -m jeffe --workspace /path/to/private-workspace ingest owned-hashes.txt --kind hashes
python -m jeffe --workspace /path/to/private-workspace ingest local-words.txt --kind wordlist
python -m jeffe --workspace /path/to/private-workspace create --engine john --format raw-sha256 --input-id HASH_ASSET_ID --wordlist-id WORDLIST_ASSET_ID --runtime 30
python -m jeffe --workspace /path/to/private-workspace --john ../run/john run JOB_ID
python -m jeffe --workspace /path/to/private-workspace jobs
python -m jeffe --workspace /path/to/private-workspace report --output report.json
python -m jeffe --workspace /path/to/private-workspace dashboard --output dashboard.html
```

Replace uppercase IDs with returned identifiers. `resume JOB_ID` requires an interrupted job, a compatible checkpoint, and the original input/configuration/engine digest. Engine checkpoints and result formats are not interchangeable. Existing `*2john` tools remain part of John; automatic document/archive conversion is not implemented in the workbench yet. Import their locally prepared hash output as a hashes asset.

`catalog --query PDF` searches integration decisions; `backlog --status deferred` exposes unfinished proposals. The dashboard supports searching and filtering the full tracker.

## Data handling and interpretation

- Inputs are copied with streaming SHA-256, size limits, mutation checks and private filesystem permissions. Managed data is **not encrypted at rest**.
- SQLite records job state changes transactionally; per-job execution manifests pin asset and executable digests.
- Engine logs and pot files remain sensitive private files. Public JSON/dashboard responses contain metadata and counts, not recovered plaintext.
- A completed job does not establish that every record was recovered. Results are engine-reported; independent result re-verification is not implemented.
- No target acquisition, live-service credential attacks, wireless attacks, exploit execution, shellcode execution, or autonomous attack agents are connected to this server. Such supplied projects remain catalog references or review candidates.
- File permissions protect against other ordinary OS users, not against administrators or malicious code running as the same service account. Use normal host backup/encryption/access controls as appropriate to your deployment.

## Verify

```sh
python -m unittest discover -s tests -v
JEFFE_TEST_JOHN=/absolute/path/to/run/john OMP_NUM_THREADS=2 python -m unittest discover -s tests -v
python benchmarks/benchmark_storage.py --help
```

The native tests use generated synthetic material. HTTP tests require permission to bind loopback sockets. See `reports/` for exact executed commands, native build limits, performance samples, implementation coverage and the detailed delivery report. Configuration files for CI are provided; local passes do not establish that remote CI has run.

## Licensing

The application follows the repository's GPL-2.0-or-later license. Existing upstream and component notices remain authoritative. No implementation source from the newly supplied third-party projects was copied. Their metadata and review decisions are included with source links; absent/conflicting/noncommercial licenses are recorded rather than treated as compatible.

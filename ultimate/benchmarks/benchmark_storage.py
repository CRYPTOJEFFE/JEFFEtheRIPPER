"""Reproducible before/after benchmark of real Workspace query methods.

The initial recorded experiment ran before and after changing storage.py.
For reproduction with the current code, the before phase restores the original
index layout inside this dedicated synthetic workspace; the after phase uses
the current optimized indexes. Query methods are identical in both layouts.
Setup, schema changes, integrity scans and three warmups are excluded from
timings. This measures metadata queries, not password recovery throughput.

Example (from ultimate):
    python benchmarks/benchmark_storage.py --phase before --workspace /tmp/jeffe-perf --output /tmp/jeffe-performance.json
    python benchmarks/benchmark_storage.py --phase after --workspace /tmp/jeffe-perf --output /tmp/jeffe-performance.json
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from jeffe.models import JobSpec
from jeffe.storage import Workspace
import jeffe.storage


def prepare(workspace, count, phase):
    marker = workspace.root / "benchmark-dataset.json"
    if marker.exists():
        data = json.loads(marker.read_text())
        if data["rows"] != count:
            raise ValueError("Requested row count differs from the existing benchmark dataset")
        return data
    if phase != "before":
        raise ValueError("After measurement requires the original before-phase workspace")
    if workspace.list_jobs() or workspace.list_assets():
        raise ValueError("Refusing to seed a nonempty workspace")
    hash_source = workspace.root / "synthetic-hashes.txt"
    words_source = workspace.root / "synthetic-words.txt"
    hash_source.write_text(hashlib.sha256(b"benchmark-only-not-a-secret").hexdigest() + "\n")
    words_source.write_text("benchmark-only-not-a-secret\n")
    hashes = workspace.ingest(hash_source, "hashes")
    words = workspace.ingest(words_source, "wordlist")
    spec = json.dumps(JobSpec("john", "raw-sha256", hashes["id"], words["id"]).to_dict(), sort_keys=True)
    origin = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # Batch imports commonly share timestamps. This fixture uses 50 jobs per
    # second and explicitly records that distribution rather than claiming it
    # represents every deployment.
    status_cycle = ["completed"] * 50 + ["exhausted"] * 20 + ["queued"] * 15 + ["failed"] * 5 + ["interrupted"] * 5 + ["running"] * 5

    def records():
        for i in range(count):
            stamp = (origin + timedelta(seconds=i // 50)).isoformat()
            yield (f"{i + 1:032x}", status_cycle[i % len(status_cycle)], spec, stamp, stamp)

    with sqlite3.connect(workspace.db_path) as conn:
        conn.executemany("INSERT INTO jobs(id,status,spec,created_at,updated_at) VALUES (?,?,?,?,?)", records())
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    data = {"rows": count, "seed": "deterministic-v1", "jobs_per_timestamp": 50,
            "notes": "Synthetic metadata inserted directly; this fixture measures reads, not job creation or event journaling."}
    marker.write_text(json.dumps(data, indent=2))
    return data


def inspect(workspace):
    digest = hashlib.sha256()
    with sqlite3.connect(workspace.db_path) as conn:
        for row in conn.execute("SELECT id,status,spec,created_at,updated_at FROM jobs ORDER BY id"):
            digest.update(json.dumps(row, separators=(",", ":")).encode())
            digest.update(b"\n")
        plans = {}
        for name, sql in {
            "summary_status_group": "SELECT status,COUNT(*) AS count FROM jobs GROUP BY status",
            "newest_100_jobs": "SELECT * FROM jobs ORDER BY created_at DESC,id DESC LIMIT 100",
        }.items():
            plans[name] = [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + sql)]
        indexes = [dict(name=row[0], sql=row[1]) for row in conn.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='jobs' ORDER BY name")]
    return digest.hexdigest(), plans, indexes


def configure_benchmark_indexes(workspace, phase):
    """Reproduce the original index layout only in a marked benchmark store."""
    if not (workspace.root / "benchmark-dataset.json").is_file():
        raise ValueError("Index comparison requires a dedicated benchmark workspace")
    with sqlite3.connect(workspace.db_path) as conn:
        if phase == "before":
            conn.execute("DROP INDEX IF EXISTS jobs_status")
            conn.execute("DROP INDEX IF EXISTS jobs_created_id")
            conn.execute("CREATE INDEX IF NOT EXISTS jobs_created ON jobs(created_at DESC)")
        else:
            conn.execute("CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS jobs_created_id ON jobs(created_at DESC,id DESC)")
            conn.execute("DROP INDEX IF EXISTS jobs_created")


def environment():
    cpu_model = platform.processor()
    if Path("/proc/cpuinfo").exists():
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    return {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
            "platform": platform.platform(), "cpu_model": cpu_model,
            "logical_cpus": os.cpu_count(),
            "allowed_cpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "timer": "time.perf_counter_ns", "storage_sha256": hashlib.sha256(Path(jeffe.storage.__file__).read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["before", "after"], required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=100000)
    parser.add_argument("--repeats", type=int, default=13)
    args = parser.parse_args()
    if args.rows < 1 or not 7 <= args.repeats <= 15:
        parser.error("rows must be positive; repeats must be between 7 and 15")
    workspace = Workspace(args.workspace)
    dataset = prepare(workspace, args.rows, args.phase)
    configure_benchmark_indexes(workspace, args.phase)
    dataset_digest, plans, indexes = inspect(workspace)
    functions = {"report_summary": workspace.report_summary, "newest_100_jobs": lambda: workspace.list_jobs(limit=100)}
    expected_summary = workspace.report_summary()
    expected_jobs = workspace.list_jobs(limit=100)
    assert expected_summary["job_count"] == args.rows
    assert len(expected_jobs) == min(100, args.rows)
    for _ in range(3):
        for function in functions.values():
            function()
    samples = {key: [] for key in functions}
    for trial in range(args.repeats):
        keys = list(functions)
        if trial % 2:
            keys.reverse()
        for key in keys:
            start = time.perf_counter_ns()
            value = functions[key]()
            elapsed = time.perf_counter_ns() - start
            if key == "report_summary":
                assert value == expected_summary
            else:
                assert value == expected_jobs
            samples[key].append(elapsed / 1_000_000)
    result = {"measured_at_utc": datetime.now(timezone.utc).isoformat(),
              "environment": environment(), "dataset": {**dataset, "sha256": dataset_digest},
              "warmup_calls_per_method": 3, "repeats": args.repeats,
              "plans": plans, "indexes": indexes,
              "samples_ms": samples,
              "median_ms": {key: statistics.median(value) for key, value in samples.items()}}
    report = json.loads(args.output.read_text()) if args.output.exists() else {}
    if args.phase in report:
        raise ValueError("Refusing to overwrite an existing phase; use a separate output file for another experiment")
    if args.phase == "after":
        if "before" not in report or report["before"]["dataset"]["sha256"] != dataset_digest:
            raise ValueError("Before/after data differ or baseline is missing")
        report["comparison"] = {}
        for key, after in result["median_ms"].items():
            before = report["before"]["median_ms"][key]
            report["comparison"][key] = {"before_median_ms": before, "after_median_ms": after,
                "speedup_ratio": before / after, "median_latency_reduction_percent": 100 * (before - after) / before}
    report[args.phase] = result
    report["caveats"] = [
        "Warm-cache, single-machine measurements on synthetic metadata; not password recovery or GPU throughput.",
        "Real Workspace methods include a new SQLite connection per call in both phases; setup, index creation and integrity scans are excluded.",
        "Each trial measures both methods, alternating order; baseline and optimized phases are sequential, not randomized across code versions.",
        "Indexes consume storage and add write/update work; write throughput and other deployments were not benchmarked.",
        "No wall-time thresholds are asserted by the functional tests; shared-host noise can affect samples.",
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"phase": args.phase, "median_ms": result["median_ms"], "plans": plans,
                      "comparison": report.get("comparison")}, indent=2))


if __name__ == "__main__":
    main()

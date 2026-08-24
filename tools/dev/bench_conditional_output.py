#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


METRIC_PATTERN = re.compile(
    rb"\[BENCH\] scenario=\S+ iterations=\d+ output_bytes=(\d+) "
    rb"reserves=(\d+) grow=(\d+) max_request=(\d+) max_cap=(\d+) max_view=(\d+)"
)
RSS_PATTERN = re.compile(rb"\[BENCH-TIME\] peak_rss_kb=(\d+)")


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample_set_sha256(repo_root, paths):
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(repo_root).as_posix()
        digest.update((relative + "\n").encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def git_value(repo_root, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(repo_root), *arguments], text=True
    ).strip()


def invoke_runner(command, arguments):
    started = time.perf_counter()
    result = subprocess.run(
        ["/usr/bin/time", "-f", "[BENCH-TIME] peak_rss_kb=%M", *command, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    wall_time_ms = (time.perf_counter() - started) * 1000.0
    return result, wall_time_ms


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", required=True)
    parser.add_argument("--runner-prefix", default="")
    parser.add_argument("--manifest", default="testdata/bench/conditional_output/manifest.json")
    parser.add_argument("--expected", default="testdata/bench/conditional_output/expected-sha256.json")
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--iterations-per-run", type=int, default=1000)
    parser.add_argument("--output-root", default="out/artifacts/bench")
    parser.add_argument("--target-architecture", required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--compiler-version", required=True)
    parser.add_argument("--cflags", required=True)
    parser.add_argument("--commit")
    parser.add_argument("--source-version")
    args = parser.parse_args()
    if args.repetitions < 5 or args.warmup < 1 or args.iterations_per_run < 1:
        parser.error("repetitions must be >= 5; warmup and iterations-per-run must be >= 1")

    repo_root = Path(__file__).resolve().parents[2]
    runner = (repo_root / args.runner).resolve()
    manifest_path = (repo_root / args.manifest).resolve()
    expected_path = (repo_root / args.expected).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    expected = json.loads(expected_path.read_text(encoding="utf-8-sig"))
    fixtures = []
    for entry in manifest["fixtures"]:
        fixtures.append({
            **entry,
            "path": (manifest_path.parent / entry["file"]).resolve(),
        })

    sample_hash = sample_set_sha256(
        repo_root, [manifest_path, *(fixture["path"] for fixture in fixtures)]
    )
    if sample_hash != expected["sampleSetSha256"]:
        raise RuntimeError("[bench] sample-set SHA changed; update expectations explicitly")

    cases = []
    for scenario in ("raw", "title", "grep", "fold", "fold-unique"):
        for fixture in fixtures:
            cases.append((f"{scenario}/{fixture['id']}", scenario, [fixture]))
    cases.append(("batch/all", "batch", fixtures))

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = (repo_root / args.output_root / timestamp).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [*shlex.split(args.runner_prefix), str(runner)]
    raw_rows = []
    summary_rows = []

    for case_id, scenario, case_fixtures in cases:
        runner_args = ["--scenario", scenario, "--iterations", str(args.iterations_per_run)]
        for fixture in case_fixtures:
            runner_args.extend(("--fixture", str(fixture["path"])))
        if len(case_fixtures) == 1:
            runner_args.extend(("--query", case_fixtures[0]["query"], "--rir", case_fixtures[0]["rir"]))

        warmup_result = None
        for _ in range(args.warmup):
            warmup_result, _ = invoke_runner(command, runner_args)
            if warmup_result.returncode != 0:
                raise RuntimeError(f"[bench] warm-up failed: {case_id}: {warmup_result.stderr.decode(errors='replace')}")
        output_hash = hashlib.sha256(warmup_result.stdout).hexdigest()
        if expected["cases"].get(case_id) != output_hash:
            raise RuntimeError(f"[bench] frozen output mismatch: {case_id}")

        case_rows = []
        fixture_bytes = sum(fixture["path"].stat().st_size for fixture in case_fixtures)
        query_count = len(case_fixtures) * args.iterations_per_run
        for run_index in range(1, args.repetitions + 1):
            result, wall_time_ms = invoke_runner(command, runner_args)
            if result.returncode != 0:
                raise RuntimeError(f"[bench] measured run failed: {case_id}: {result.stderr.decode(errors='replace')}")
            if hashlib.sha256(result.stdout).hexdigest() != output_hash:
                raise RuntimeError(f"[bench] non-deterministic output: {case_id} run={run_index}")
            metric = METRIC_PATTERN.search(result.stderr)
            rss = RSS_PATTERN.search(result.stderr)
            if not metric or not rss:
                raise RuntimeError(f"[bench] metrics missing: {case_id} run={run_index}")
            values = [int(value) for value in metric.groups()]
            row = {
                "case_id": case_id,
                "scenario": scenario,
                "run": run_index,
                "iterations": args.iterations_per_run,
                "queries": query_count,
                "wall_time_ms": round(wall_time_ms, 3),
                "output_bytes": values[0],
                "peak_rss_kb": int(rss.group(1)),
                "reserves": values[1],
                "grow": values[2],
                "max_request": values[3],
                "max_cap": values[4],
                "max_view": values[5],
                "throughput_qps": round(query_count / (wall_time_ms / 1000.0), 3),
                "scan_bytes": fixture_bytes * args.iterations_per_run,
                "stdout_sha256": output_hash,
            }
            raw_rows.append(row)
            case_rows.append(row)

        summary_rows.append({
            "case_id": case_id,
            "scenario": scenario,
            "repetitions": args.repetitions,
            "iterations_per_run": args.iterations_per_run,
            "queries_per_run": query_count,
            "wall_time_median_ms": round(percentile([row["wall_time_ms"] for row in case_rows], 0.5), 3),
            "wall_time_p95_ms": round(percentile([row["wall_time_ms"] for row in case_rows], 0.95), 3),
            "throughput_median_qps": round(percentile([row["throughput_qps"] for row in case_rows], 0.5), 3),
            "output_bytes": case_rows[0]["output_bytes"],
            "peak_rss_kb": max(row["peak_rss_kb"] for row in case_rows),
            "reserves": case_rows[0]["reserves"],
            "grow": case_rows[0]["grow"],
            "max_request": case_rows[0]["max_request"],
            "max_cap": case_rows[0]["max_cap"],
            "max_view": case_rows[0]["max_view"],
            "scan_bytes": case_rows[0]["scan_bytes"],
            "stdout_sha256": output_hash,
        })
        print(f"[bench] PASS case={case_id}")

    for filename, rows in (("raw.csv", raw_rows), ("summary.csv", summary_rows)):
        with (output_dir / filename).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    metadata = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "commit": args.commit or git_value(repo_root, "rev-parse", "HEAD"),
        "gitDescribe": args.source_version or git_value(repo_root, "describe", "--tags", "--always", "--dirty"),
        "runner": str(runner),
        "runnerSha256": sha256_file(runner),
        "benchmarkScriptSha256": sha256_file(Path(__file__)),
        "sampleSetSha256": sample_hash,
        "repetitions": args.repetitions,
        "warmup": args.warmup,
        "iterationsPerRun": args.iterations_per_run,
        "targetArchitecture": args.target_architecture,
        "compiler": args.compiler,
        "compilerVersion": args.compiler_version,
        "cflags": args.cflags,
        "os": platform.platform(),
        "processorCount": os.cpu_count(),
        "runnerPrefix": args.runner_prefix,
        "results": summary_rows,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[bench] PASS cases={len(cases)} output={output_dir}")


if __name__ == "__main__":
    main()
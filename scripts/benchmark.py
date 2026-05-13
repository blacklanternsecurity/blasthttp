#!/usr/bin/env python3
"""
Benchmark comparing blasthttp against Go / C / Python HTTP clients.

Drives a workload of N requests at fixed worker count W against a local
HTTP server, mirroring the style of blastdns/scripts/benchmark.py.

Every implementation runs against the same workload and the same
effective concurrency cap:
  - blasthttp-cli     : target/release/blasthttp -l urls.txt -c W
  - blasthttp-python  : BlastHTTP().request_batch(configs, concurrency=W)
  - python-httpx      : W asyncio tasks pulling from asyncio.Queue
  - go-stdlib         : W goroutines pulling from a channel (subprocess)
  - c-libcurl         : W libcurl easy handles on a multi handle (subprocess)

Requires:
  - target/release/blasthttp    (cargo build --release)
  - target/bench/{server,client-go,client-c}  (make -C scripts/bench)
  - Python deps: httpx, tabulate, uvloop, and the blasthttp module
"""

import argparse
import asyncio
import contextlib
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import uvloop
from tabulate import tabulate

from blasthttp import BatchConfig, BlastHTTP


REPO_ROOT = Path(__file__).resolve().parent.parent
BENCH_DIR = REPO_ROOT / "target" / "bench"
BLASTHTTP_CLI = REPO_ROOT / "target" / "release" / "blasthttp"
BENCH_SERVER = BENCH_DIR / "server"
BENCH_GO_CLIENT = BENCH_DIR / "client-go"
BENCH_C_CLIENT = BENCH_DIR / "client-c"


# =============================================================================
# Bundled Go server lifecycle
# =============================================================================


def _wait_for_port(host, port, timeout=5.0):
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        with contextlib.suppress(OSError):
            with socket.create_connection((host, port), timeout=0.25):
                return True
        time.sleep(0.05)
    return False


@contextlib.contextmanager
def local_server(addr):
    """Start the bundled Go server on `addr` (host:port); stop it on exit."""
    if not BENCH_SERVER.exists():
        raise RuntimeError(
            f"Server binary not found at {BENCH_SERVER}. Run: make -C {BENCH_DIR.relative_to(REPO_ROOT).parent}/bench"
        )
    host, port = addr.split(":")
    port = int(port)
    proc = subprocess.Popen(
        [str(BENCH_SERVER), "-addr", addr],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not _wait_for_port(host, port, timeout=5.0):
            proc.terminate()
            raise RuntimeError(f"Server never became ready on {addr}")
        yield f"http://{addr}/"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()


# =============================================================================
# Subprocess helper
# =============================================================================


def _count_json_results(stdout):
    """Count success/failure lines in a JSON-per-line stdout blob.

    Success lines have a numeric "status"; failure lines have "error".
    """
    success = 0
    errors = 0
    for line in stdout.splitlines():
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "error" in obj:
            errors += 1
        else:
            success += 1
    return success, errors


def _run_subprocess_benchmark(binary, urls, workers):
    """Write URLs to a temp file, run `binary <urls-file> <workers>`, parse JSON."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, dir=REPO_ROOT) as urls_file:
        urls_file.write("\n".join(urls))
        urls_file.write("\n")
        urls_path = urls_file.name

    try:
        start = time.perf_counter()
        result = subprocess.run(
            [str(binary), urls_path, str(workers)],
            capture_output=True,
            text=True,
        )
        total_time = time.perf_counter() - start

        if result.returncode != 0:
            raise RuntimeError(f"{binary} exited {result.returncode}: {result.stderr[-500:]}")
        success, errors = _count_json_results(result.stdout)
        qps = len(urls) / total_time if total_time > 0 else 0
        return total_time, qps, success, errors
    finally:
        Path(urls_path).unlink(missing_ok=True)


# =============================================================================
# blasthttp CLI
# =============================================================================


def benchmark_blasthttp_cli(urls, workers, rate_limit=None):
    if not BLASTHTTP_CLI.exists():
        raise RuntimeError(f"{BLASTHTTP_CLI} missing (cargo build --release)")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, dir=REPO_ROOT) as urls_file:
        urls_file.write("\n".join(urls))
        urls_file.write("\n")
        urls_path = urls_file.name

    try:
        argv = [str(BLASTHTTP_CLI), "-l", urls_path, "-c", str(workers)]
        if rate_limit is not None:
            argv += ["--rate-limit", str(rate_limit)]

        start = time.perf_counter()
        result = subprocess.run(argv, capture_output=True, text=True)
        total_time = time.perf_counter() - start

        if result.returncode != 0:
            raise RuntimeError(f"blasthttp failed: {result.stderr[-500:]}")

        # blasthttp emits rich JSON per response — collapse to success/error.
        success = errors = 0
        for line in result.stdout.splitlines():
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" in obj:
                errors += 1
            else:
                success += 1
        qps = len(urls) / total_time if total_time > 0 else 0
        return total_time, qps, success, errors
    finally:
        Path(urls_path).unlink(missing_ok=True)


# =============================================================================
# blasthttp Python
# =============================================================================


async def benchmark_blasthttp_python(urls, workers, rate_limit=None):
    client = BlastHTTP()
    configs = [BatchConfig(url) for url in urls]

    start = time.perf_counter()
    results = await client.request_batch(configs, concurrency=workers, rate_limit=rate_limit)
    total_time = time.perf_counter() - start

    success = sum(1 for r in results if r.success)
    errors = len(results) - success
    qps = len(urls) / total_time if total_time > 0 else 0
    return total_time, qps, success, errors


async def benchmark_blasthttp_python_stream(urls, workers, rate_limit=None):
    client = BlastHTTP()
    configs = [BatchConfig(url) for url in urls]

    success = 0
    errors = 0
    start = time.perf_counter()
    async for batch in client.request_batch_stream(configs, concurrency=workers, rate_limit=rate_limit):
        for r in batch:
            if r.success:
                success += 1
            else:
                errors += 1
    total_time = time.perf_counter() - start

    qps = len(urls) / total_time if total_time > 0 else 0
    return total_time, qps, success, errors


# =============================================================================
# httpx
# =============================================================================


async def _httpx_worker(client, queue, counts):
    while True:
        url = await queue.get()
        if url is None:
            queue.task_done()
            break
        try:
            resp = await client.get(url)
            await resp.aread()
            if 200 <= resp.status_code < 400:
                counts[0] += 1
            else:
                counts[1] += 1
        except Exception:
            counts[1] += 1
        queue.task_done()


async def benchmark_httpx(urls, workers):
    limits = httpx.Limits(
        max_connections=workers,
        max_keepalive_connections=workers,
    )
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        queue = asyncio.Queue(maxsize=workers * 2)
        counts = [0, 0]  # [success, errors]

        start = time.perf_counter()
        worker_tasks = [asyncio.create_task(_httpx_worker(client, queue, counts)) for _ in range(workers)]

        for url in urls:
            await queue.put(url)
        for _ in range(workers):
            await queue.put(None)

        await queue.join()
        await asyncio.gather(*worker_tasks)

        total_time = time.perf_counter() - start
        qps = len(urls) / total_time if total_time > 0 else 0
        return total_time, qps, counts[0], counts[1]


# =============================================================================
# Go & C subprocess wrappers
# =============================================================================


def benchmark_go_stdlib(urls, workers):
    if not BENCH_GO_CLIENT.exists():
        raise RuntimeError(f"{BENCH_GO_CLIENT} missing (make -C scripts/bench)")
    return _run_subprocess_benchmark(BENCH_GO_CLIENT, urls, workers)


def benchmark_c_libcurl(urls, workers):
    if not BENCH_C_CLIENT.exists():
        raise RuntimeError(f"{BENCH_C_CLIENT} missing (make -C scripts/bench)")
    return _run_subprocess_benchmark(BENCH_C_CLIENT, urls, workers)


# =============================================================================
# Output
# =============================================================================


def print_table(results, baseline):
    baseline_qps = results.get(baseline, (0, 1, 0, 0))[1] if baseline in results else 0

    rows = []
    for name, (total_time, qps, success, errors) in sorted(results.items(), key=lambda x: -x[1][1]):
        multiplier = (qps / baseline_qps) if baseline_qps > 0 else 0
        rows.append(
            [
                name,
                f"{total_time:.3f}s",
                f"{qps:,.0f}",
                f"{success:,}",
                f"{errors:,}",
                f"{multiplier:.2f}x" if baseline_qps > 0 else "-",
            ]
        )

    headers = ["Library", "Time", "QPS", "Success", "Failed", f"vs {baseline}"]
    print(tabulate(rows, headers=headers, tablefmt="github"))


def generate_urls(num, target, pattern):
    """Build a URL list. Default pattern = same URL N times (maximum reuse)."""
    if pattern == "same":
        return [target] * num
    elif pattern == "unique":
        # Each request hits /<n>
        sep = "" if target.endswith("/") else "/"
        return [f"{target}{sep}{i}" for i in range(num)]
    else:
        raise ValueError(f"unknown URL pattern: {pattern}")


# =============================================================================
# Main
# =============================================================================

ENGINES = [
    "blasthttp-cli",
    "blasthttp-cli-200k",
    "blasthttp-python",
    "blasthttp-python-200k",
    "blasthttp-python-stream",
    "blasthttp-python-stream-200k",
    "httpx",
    "go",
    "c",
]

RATE_LIMITED_RPS = 200_000


async def main():
    parser = argparse.ArgumentParser(description="Benchmark blasthttp vs Go/C/Python HTTP clients")
    parser.add_argument("-n", "--num-queries", type=int, default=20_000, help="Number of requests")
    parser.add_argument("-w", "--num-workers", type=int, default=100, help="Concurrent workers")
    parser.add_argument(
        "--target",
        default=None,
        help="Target URL. If unset, a bundled Go server is started on 127.0.0.1:8080.",
    )
    parser.add_argument(
        "--pattern",
        choices=["same", "unique"],
        default="same",
        help="URL pattern: 'same' URL N times, or 'unique' paths /0../N-1",
    )
    parser.add_argument("--only", choices=ENGINES, help="Run only one engine")
    parser.add_argument(
        "--baseline",
        choices=ENGINES,
        default="httpx",
        help="Baseline engine for the multiplier column",
    )
    args = parser.parse_args()

    # Set up target (bundled server unless user supplied --target).
    server_ctx = contextlib.nullcontext(args.target)
    if args.target is None:
        server_ctx = local_server("127.0.0.1:8080")

    with server_ctx as target:
        urls = generate_urls(args.num_queries, target, args.pattern)

        print("## HTTP Client Benchmark")
        print()
        print(f"- **Requests:** {args.num_queries:,}")
        print(f"- **Workers:** {args.num_workers}")
        print(f"- **Target:** {target}")
        print(f"- **URL pattern:** {args.pattern}")
        print()

        results = {}

        def run(name):
            return args.only is None or args.only == name

        if run("blasthttp-cli"):
            print("Running blasthttp-cli...", file=sys.stderr, flush=True)
            results["blasthttp-cli"] = benchmark_blasthttp_cli(urls, args.num_workers)

        if run("blasthttp-cli-200k"):
            print("Running blasthttp-cli-200k...", file=sys.stderr, flush=True)
            results["blasthttp-cli-200k"] = benchmark_blasthttp_cli(
                urls, args.num_workers, rate_limit=RATE_LIMITED_RPS
            )

        if run("blasthttp-python"):
            print("Running blasthttp-python...", file=sys.stderr, flush=True)
            results["blasthttp-python"] = await benchmark_blasthttp_python(urls, args.num_workers)

        if run("blasthttp-python-200k"):
            print("Running blasthttp-python-200k...", file=sys.stderr, flush=True)
            results["blasthttp-python-200k"] = await benchmark_blasthttp_python(
                urls, args.num_workers, rate_limit=RATE_LIMITED_RPS
            )

        if run("blasthttp-python-stream"):
            print("Running blasthttp-python-stream...", file=sys.stderr, flush=True)
            results["blasthttp-python-stream"] = await benchmark_blasthttp_python_stream(urls, args.num_workers)

        if run("blasthttp-python-stream-200k"):
            print("Running blasthttp-python-stream-200k...", file=sys.stderr, flush=True)
            results["blasthttp-python-stream-200k"] = await benchmark_blasthttp_python_stream(
                urls, args.num_workers, rate_limit=RATE_LIMITED_RPS
            )

        if run("httpx"):
            print("Running httpx...", file=sys.stderr, flush=True)
            results["httpx"] = await benchmark_httpx(urls, args.num_workers)

        if run("go"):
            print("Running go-stdlib...", file=sys.stderr, flush=True)
            results["go"] = benchmark_go_stdlib(urls, args.num_workers)

        if run("c"):
            print("Running c-libcurl...", file=sys.stderr, flush=True)
            results["c"] = benchmark_c_libcurl(urls, args.num_workers)

        print()
        print("### Results")
        print()
        print_table(results, baseline=args.baseline)


if __name__ == "__main__":
    uvloop.install()
    asyncio.run(main())

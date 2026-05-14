"""Pytest-asyncio tests for `BlastHTTP.request_batch_stream`.

Exercises the streaming batch iterator (`PyBatchResultIterator.__anext__`)
against a local asyncio HTTP server that delays responses based on the URL
path so we can drive completion timing and verify the 200ms timeout flushes
partial batches.
"""

import asyncio
import re

import blasthttp
import pytest_asyncio


@pytest_asyncio.fixture
async def delay_server():
    """Minimal HTTP/1.1 server on an ephemeral port.

    Responds 200 OK after sleeping `ms` milliseconds, where `ms` is parsed
    from a `GET /delay/<ms>` request line. Sends `Connection: close` so we
    don't have to deal with keep-alive bookkeeping.

    Yields the port; tears down on cleanup.
    """

    async def handle(reader, writer):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                data += chunk
            request_line = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
            m = re.match(r"[A-Z]+ /delay/(\d+) ", request_line)
            ms = int(m.group(1)) if m else 0
            if ms > 0:
                await asyncio.sleep(ms / 1000)
            body = b"ok"
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n"
                b"\r\n" + body
            )
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


async def test_stream_yields_batches_of_batchresults(delay_server):
    """Smoke test: each yielded item is a `list[BatchResult]` and totals match."""
    port = delay_server
    client = blasthttp.BlastHTTP()
    configs = [blasthttp.BatchConfig(f"http://127.0.0.1:{port}/delay/0") for _ in range(10)]

    total = 0
    async for batch in client.request_batch_stream(configs, concurrency=10):
        assert isinstance(batch, list)
        assert all(isinstance(r, blasthttp.BatchResult) for r in batch)
        total += len(batch)

    assert total == 10


async def test_stream_completes_in_completion_order(delay_server):
    """A slow request doesn't block faster peers behind it in the input list."""
    port = delay_server
    client = blasthttp.BlastHTTP()
    # Slow first, then fast — completion order must invert dispatch order.
    urls = [f"http://127.0.0.1:{port}/delay/300"] + [f"http://127.0.0.1:{port}/delay/0"] * 5
    configs = [blasthttp.BatchConfig(u) for u in urls]

    completed = []
    async for batch in client.request_batch_stream(configs, concurrency=6):
        for r in batch:
            completed.append(r.url)

    # The 5 fast requests must complete before the single slow one.
    assert completed[-1].endswith("/delay/300"), f"got order: {completed}"


async def test_stream_timeout_flushes_partial_batches(delay_server):
    """The 200ms `__anext__` timeout splits results into separate batches
    when completions come in temporally distinct clusters.

    Setup: 60 requests in three completion clusters — 20 immediate,
    20 at ~300ms, 20 at ~600ms. All dispatched concurrently.

    Expected batch boundaries (mirrors blastdns's test_batch_timeout_triggers):
      - __anext__ #1: 20 fast results pile up at ~T+5ms; loop awaits;
        first slow result arrives at ~T+300ms; push (batch=21); elapsed
        ≥ 200ms → flush → batch of 21.
      - __anext__ #2 starts at ~T+300ms: 19 remaining cluster-B results
        arrive immediately; loop awaits; first cluster-C result at
        ~T+600ms; push (batch=20); elapsed ≥ 200ms → flush → batch of 20.
      - __anext__ #3 starts at ~T+600ms: 19 remaining cluster-C results
        arrive immediately; stream ends → batch of 19.
    """
    port = delay_server
    client = blasthttp.BlastHTTP()

    urls = (
        [f"http://127.0.0.1:{port}/delay/0"] * 20
        + [f"http://127.0.0.1:{port}/delay/300"] * 20
        + [f"http://127.0.0.1:{port}/delay/600"] * 20
    )
    configs = [blasthttp.BatchConfig(u) for u in urls]

    batch_sizes = []
    async for batch in client.request_batch_stream(configs, concurrency=60):
        batch_sizes.append(len(batch))

    assert sum(batch_sizes) == 60, f"expected 60 results, got {batch_sizes}"
    assert batch_sizes == [21, 20, 19], f"expected timeout to flush as [21, 20, 19], got {batch_sizes}"


async def test_stream_no_timeout_under_load(delay_server):
    """When results arrive faster than the 200ms timeout, the iterator
    should drain into one batch (or hit the 1000-item ceiling), not
    fragment uselessly. Verifies we don't have a pathological flush
    every poll."""
    port = delay_server
    client = blasthttp.BlastHTTP()
    configs = [blasthttp.BatchConfig(f"http://127.0.0.1:{port}/delay/0") for _ in range(50)]

    batch_sizes = []
    async for batch in client.request_batch_stream(configs, concurrency=50):
        batch_sizes.append(len(batch))

    assert sum(batch_sizes) == 50
    # 50 fast results in well under 200ms — should land in a single batch.
    assert len(batch_sizes) == 1, f"expected 1 batch, got sizes {batch_sizes}"

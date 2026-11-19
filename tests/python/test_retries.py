"""`retry_statuses` through the Python surface: 429 is retried by default, after
its `Retry-After`, and an empty list hands every status back to the caller."""

import asyncio

import pytest_asyncio

import blasthttp


@pytest_asyncio.fixture
async def rate_limited():
    """Answers the first request with a 429 asking for one second, then 200.
    Yields the URL and the list of requests it saw."""
    seen = []

    async def handle(reader, writer):
        try:
            while await reader.readuntil(b"\r\n") != b"\r\n":
                pass
            seen.append(1)
            if len(seen) == 1:
                writer.write(b"HTTP/1.1 429 X\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        finally:
            writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    async with srv:
        yield f"http://127.0.0.1:{srv.sockets[0].getsockname()[1]}/", seen


RETRY = {"retries": 1, "retry_wait_min_ms": 10, "retry_wait_max_ms": 10_000}


async def test_a_429_is_retried_by_default(rate_limited):
    url, seen = rate_limited
    r = await blasthttp.BlastHTTP().request(url, **RETRY)
    assert (r.status, len(seen)) == (200, 2)


async def test_no_retry_statuses_hands_the_429_back(rate_limited):
    url, seen = rate_limited
    r = await blasthttp.BlastHTTP().request(url, retry_statuses=[], **RETRY)
    assert (r.status, len(seen)) == (429, 1)


async def test_batch_config_takes_retry_statuses(rate_limited):
    url, seen = rate_limited
    config = blasthttp.BatchConfig(url, retry_statuses=[], **RETRY)
    assert config.retry_statuses == []
    [result] = await blasthttp.BlastHTTP().request_batch([config])
    assert (result.response.status, len(seen)) == (429, 1)


async def test_download_takes_retry_statuses(rate_limited, tmp_path):
    url, seen = rate_limited
    await blasthttp.BlastHTTP().download(url, str(tmp_path / "out"), retries=1, retry_statuses=[])
    assert len(seen) == 1

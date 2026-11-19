"""`concurrency` on the batch calls: a number caps one call, and a
`ConcurrencyLimit` caps every call it is passed to, together."""

import asyncio

import pytest
import pytest_asyncio

import blasthttp
from blasthttp.mock import BlasthttpMock


@pytest_asyncio.fixture
async def slow_server():
    """Answers each request after 0.2s. Yields its port and a record of how
    many connections it had open at once."""
    state = {"now": 0, "most": 0}

    async def handle(reader, writer):
        state["now"] += 1
        state["most"] = max(state["most"], state["now"])
        try:
            while await reader.readuntil(b"\r\n") != b"\r\n":
                pass
            await asyncio.sleep(0.2)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        finally:
            state["now"] -= 1
            writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    async with srv:
        yield srv.sockets[0].getsockname()[1], state


def configs(port, batch):
    return [blasthttp.BatchConfig(f"http://127.0.0.1:{port}/{batch}{i}") for i in range(4)]


async def drain(client, configs, concurrency):
    n = 0
    async for chunk in client.request_batch_stream(configs, concurrency=concurrency):
        n += len(chunk)
    return n


async def test_a_shared_limit_caps_every_call_holding_it(slow_server):
    port, state = slow_server
    client = blasthttp.BlastHTTP()
    limit = blasthttp.ConcurrencyLimit(2)
    done = await asyncio.gather(
        drain(client, configs(port, "a"), limit),
        drain(client, configs(port, "b"), limit),
    )
    assert done == [4, 4]
    assert state["most"] == 2


async def test_a_number_caps_only_its_own_call(slow_server):
    port, state = slow_server
    client = blasthttp.BlastHTTP()
    done = await asyncio.gather(
        drain(client, configs(port, "a"), 2),
        drain(client, configs(port, "b"), 2),
    )
    assert done == [4, 4]
    assert state["most"] == 4


async def test_request_batch_takes_a_shared_limit(slow_server):
    port, state = slow_server
    client = blasthttp.BlastHTTP()
    limit = blasthttp.ConcurrencyLimit(1)
    results = await client.request_batch(configs(port, "a"), concurrency=limit)
    assert [r.response.status for r in results] == [200] * 4
    assert state["most"] == 1


def test_a_limit_reports_its_size_and_refuses_zero():
    assert blasthttp.ConcurrencyLimit(3).size == 3
    with pytest.raises(ValueError):
        blasthttp.ConcurrencyLimit(0)


async def test_the_mock_takes_a_shared_limit():
    mock = BlasthttpMock()
    mock.add_response(url="http://mocked.test/", status_code=200, text="ok")
    results = await mock.request_batch(
        [blasthttp.BatchConfig("http://mocked.test/")], concurrency=blasthttp.ConcurrencyLimit(2)
    )
    assert results[0].response.status == 200

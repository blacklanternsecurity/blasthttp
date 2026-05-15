"""Tests for httpx-style `files=` multipart/form-data encoding."""

import re

import pytest

from blasthttp.mock import BlasthttpMock, MockRequest, MockResponse


@pytest.mark.asyncio
async def test_files_plain_field_with_none_filename():
    """`(None, value)` becomes a plain form field — no filename, no default Content-Type."""
    captured = {}

    async def cb(req: MockRequest):
        captured["content"] = bytes(req.content)
        captured["headers"] = dict(req.headers)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    await mock.request(
        "http://x/",
        method="POST",
        files={"action": (None, "delete")},
    )

    body = captured["content"]
    ct = captured["headers"]["Content-Type"]
    boundary = ct.split("boundary=", 1)[1]
    assert ct.startswith("multipart/form-data; boundary=")

    expected = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="action"\r\n\r\ndelete\r\n--{boundary}--\r\n'
    ).encode()
    assert body == expected


@pytest.mark.asyncio
async def test_files_file_part_with_filename_and_content_type():
    """`(filename, content, content_type)` becomes a proper file part."""
    captured = {}

    async def cb(req: MockRequest):
        captured["content"] = bytes(req.content)
        captured["headers"] = dict(req.headers)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    await mock.request(
        "http://x/",
        method="POST",
        files={
            "upload": ("blob", b"\x00\x01\x02hello", "application/octet-stream"),
        },
    )

    body = captured["content"]
    boundary = captured["headers"]["Content-Type"].split("boundary=", 1)[1]
    expected = (
        (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="upload"; filename="blob"\r\n'
            "Content-Type: application/octet-stream\r\n"
            "\r\n"
        ).encode()
        + b"\x00\x01\x02hello"
        + f"\r\n--{boundary}--\r\n".encode()
    )
    assert body == expected


@pytest.mark.asyncio
async def test_files_default_content_type_for_file_part():
    """A 2-tuple with a non-None filename defaults Content-Type to application/octet-stream."""
    captured = {}

    async def cb(req: MockRequest):
        captured["content"] = bytes(req.content)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    await mock.request("http://x/", method="POST", files={"f": ("name.txt", "data")})
    assert b"Content-Type: application/octet-stream" in captured["content"]


@pytest.mark.asyncio
async def test_files_mixed_fields_and_file_telerik_shape():
    """
    Real-world shape from the telerik probe: most fields are
    (None, str) form fields, plus one (filename, bytes, content_type) file part.
    """
    captured = {}

    async def cb(req: MockRequest):
        captured["content"] = bytes(req.content)
        captured["headers"] = dict(req.headers)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    await mock.request(
        "http://x/",
        method="POST",
        files={
            "rauPostData": (None, "encrypted-blob"),
            "file": ("blob", b"\xe1\xda\xf4\x8a", "application/octet-stream"),
            "fileName": (None, "df8dbc7a"),
            "metadata": (None, '{"TotalChunks":1}'),
        },
    )

    body = captured["content"]
    ct = captured["headers"]["Content-Type"]
    assert ct.startswith("multipart/form-data; boundary=")
    boundary = ct.split("boundary=", 1)[1]

    # Expected ordering matches dict insertion order.
    parts = body.split(f"--{boundary}".encode())
    # split yields [preamble, part1, part2, ..., terminator]
    assert parts[0] == b""
    assert parts[-1] == b"--\r\n"
    body_parts = parts[1:-1]
    assert len(body_parts) == 4

    assert b'name="rauPostData"' in body_parts[0]
    assert b"encrypted-blob" in body_parts[0]
    assert b'filename="blob"' in body_parts[1]
    assert b"\xe1\xda\xf4\x8a" in body_parts[1]
    assert b'name="fileName"' in body_parts[2]
    assert b'name="metadata"' in body_parts[3]
    assert b'{"TotalChunks":1}' in body_parts[3]


@pytest.mark.asyncio
async def test_files_and_body_rejected():
    """Passing both `body=` and `files=` raises ValueError instead of silently picking one."""
    mock = BlasthttpMock()

    async def cb(req: MockRequest):
        return MockResponse(status_code=200, text="ok")

    mock.add_callback(cb, url="http://x/")

    with pytest.raises(ValueError, match="both body= and files="):
        await mock.request(
            "http://x/",
            method="POST",
            body="ignored",
            files={"k": (None, "v")},
        )


@pytest.mark.asyncio
async def test_files_respects_caller_content_type():
    """Caller-supplied Content-Type wins (useful for forcing a specific boundary)."""
    captured = {}

    async def cb(req: MockRequest):
        captured["headers"] = dict(req.headers)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    await mock.request(
        "http://x/",
        method="POST",
        headers={"Content-Type": "multipart/form-data; boundary=fixed"},
        files={"k": (None, "v")},
    )

    assert captured["headers"]["Content-Type"] == "multipart/form-data; boundary=fixed"


@pytest.mark.asyncio
async def test_files_extra_headers():
    """4-tuple lets the caller add per-part headers."""
    captured = {}

    async def cb(req: MockRequest):
        captured["content"] = bytes(req.content)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    await mock.request(
        "http://x/",
        method="POST",
        files={
            "f": ("a.txt", "x", "text/plain", {"X-Custom": "yep"}),
        },
    )

    assert b"X-Custom: yep" in captured["content"]


@pytest.mark.asyncio
async def test_files_quotes_disposition_special_chars():
    """Filenames with quotes/backslashes/newlines get percent-encoded."""
    captured = {}

    async def cb(req: MockRequest):
        captured["content"] = bytes(req.content)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    await mock.request(
        "http://x/",
        method="POST",
        files={"f": ('na"me\\with\r\nbreaks', "x")},
    )

    assert b'filename="na%22me%5Cwith%0D%0Abreaks"' in captured["content"]


@pytest.mark.asyncio
async def test_files_dict_invalid_value_raises():
    """A 1-tuple is invalid (httpx requires 2-4 elements)."""
    mock = BlasthttpMock()
    mock.add_response(url="http://x/", text="ok")
    with pytest.raises(TypeError, match="2-4 elements"):
        await mock.request("http://x/", method="POST", files={"f": ("solo",)})


@pytest.mark.asyncio
async def test_body_accepts_bytes():
    """`body=` now accepts raw bytes, not just str."""
    captured = {}

    async def cb(req: MockRequest):
        captured["content"] = bytes(req.content)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")
    await mock.request("http://x/", method="POST", body=b"\x00\x01\x02")
    assert captured["content"] == b"\x00\x01\x02"


@pytest.mark.asyncio
async def test_batch_config_accepts_bytes_body():
    """BatchConfig(body=bytes) — closes parity with BlastHTTP.request(body=bytes)."""
    captured = {}

    async def cb(req):
        captured["content"] = bytes(req.content)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    import blasthttp

    cfg = blasthttp.BatchConfig("http://x/", method="POST", body=b"\x00\x01\x02")
    await mock.request_batch([cfg])

    assert captured["content"] == b"\x00\x01\x02"


@pytest.mark.asyncio
async def test_batch_config_accepts_str_body():
    """BatchConfig(body=str) still works after the bytes widening."""
    captured = {}

    async def cb(req):
        captured["content"] = bytes(req.content)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    import blasthttp

    cfg = blasthttp.BatchConfig("http://x/", method="POST", body="hello")
    await mock.request_batch([cfg])

    assert captured["content"] == b"hello"


@pytest.mark.asyncio
async def test_batch_config_files_multipart():
    """BatchConfig(files=...) sends multipart through the batch path."""
    captured = {}

    async def cb(req):
        captured["content"] = bytes(req.content)
        captured["headers"] = dict(req.headers)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    import blasthttp

    cfg = blasthttp.BatchConfig(
        "http://x/",
        method="POST",
        files={"field": (None, "value"), "f": ("blob", b"\x00\x01", "application/octet-stream")},
    )
    await mock.request_batch([cfg])

    ct = captured["headers"]["Content-Type"]
    assert ct.startswith("multipart/form-data; boundary=")
    assert b'name="field"' in captured["content"]
    assert b'filename="blob"' in captured["content"]
    assert b"\x00\x01" in captured["content"]


@pytest.mark.asyncio
async def test_batch_config_files_multipart_via_stream():
    """BatchConfig(files=...) works through request_batch_stream."""
    captured = {}

    async def cb(req):
        captured["content"] = bytes(req.content)
        captured["headers"] = dict(req.headers)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    import blasthttp

    cfg = blasthttp.BatchConfig(
        "http://x/",
        method="POST",
        files={"field": (None, "value")},
    )
    async for _result in mock.request_batch_stream([cfg]):
        pass

    ct = captured["headers"]["Content-Type"]
    assert ct.startswith("multipart/form-data; boundary=")
    assert b'name="field"' in captured["content"]


@pytest.mark.asyncio
async def test_batch_config_body_and_files_rejected():
    """BatchConfig with both body= and files= raises ValueError through the batch path."""
    mock = BlasthttpMock()

    async def cb(req):
        return MockResponse(status_code=200, text="ok")

    mock.add_callback(cb, url="http://x/")

    import blasthttp

    cfg = blasthttp.BatchConfig(
        "http://x/",
        method="POST",
        body=b"\xaa\xbb",
        files={"field": (None, "value")},
    )
    with pytest.raises(ValueError, match="both body= and files="):
        async for _ in mock.request_batch_stream([cfg]):
            pass


@pytest.mark.asyncio
async def test_batch_config_caller_content_type_wins():
    """Caller-supplied Content-Type in BatchConfig.headers wins over auto-injected boundary."""
    captured = {}

    async def cb(req):
        captured["headers"] = dict(req.headers)
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    mock.add_callback(cb, url="http://x/")

    import blasthttp

    cfg = blasthttp.BatchConfig(
        "http://x/",
        method="POST",
        headers=[("Content-Type", "multipart/form-data; boundary=fixed")],
        files={"k": (None, "v")},
    )
    await mock.request_batch([cfg])

    assert captured["headers"]["Content-Type"] == "multipart/form-data; boundary=fixed"


@pytest.mark.asyncio
async def test_boundary_is_unique_per_request():
    """Each request generates a fresh boundary so concurrent uploads don't collide."""
    boundaries = []

    async def cb(req: MockRequest):
        ct = dict(req.headers)["Content-Type"]
        boundaries.append(ct.split("boundary=", 1)[1])
        return MockResponse(status_code=200, text="ok")

    mock = BlasthttpMock()
    for _ in range(5):
        mock.add_callback(cb, url=re.compile(r"http://x/"))

    for _ in range(5):
        await mock.request("http://x/", method="POST", files={"k": (None, "v")})

    assert len(set(boundaries)) == 5

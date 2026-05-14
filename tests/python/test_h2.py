"""Pytest coverage for the `blasthttp.h2` Python surface.

Exercises HPACK encoder/decoder, frame builders, and the `build_probe`
high-level helper. All tests are pure-CPU — no network — so they
run in milliseconds and catch PyO3-binding drift early.
"""

from blasthttp import h2


# ── module surface ────────────────────────────────────────────────────


def test_module_exports_key_symbols():
    """Contract guard — any refactor that renames or drops these
    symbols silently breaks downstream code (e.g. badhttp)."""
    for name in (
        "Header",
        "Decoder",
        "PREFACE",
        "FRAME_HEADERS",
        "FRAME_DATA",
        "FRAME_SETTINGS",
        "FRAME_CONTINUATION",
        "FRAME_RST_STREAM",
        "FRAME_GOAWAY",
        "FLAG_END_HEADERS",
        "FLAG_END_STREAM",
        "FLAG_ACK",
        "encode_headers",
        "build_headers_frame",
        "build_data_frame",
        "build_settings_frame",
        "build_probe",
    ):
        assert hasattr(h2, name), f"blasthttp.h2.{name} missing"


def test_preface_matches_rfc_9113():
    assert h2.PREFACE == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# ── HPACK encode/decode roundtrip ────────────────────────────────────


def test_encode_decode_roundtrip_canonical_headers():
    """Canonical request pseudo-headers + a regular header → encode →
    decode via a fresh Decoder. The HPACK block must come back
    byte-identical on the names and values."""
    headers = [
        h2.Header(":method", "GET"),
        h2.Header(":path", "/"),
        h2.Header(":authority", "example.com"),
        h2.Header(":scheme", "https"),
        h2.Header("user-agent", "blasthttp-test"),
    ]
    block = h2.encode_headers(headers)
    decoded = h2.Decoder().decode(block)

    decoded_str = [(n.decode("latin-1"), v.decode("latin-1")) for n, v in decoded]
    assert decoded_str == [
        (":method", "GET"),
        (":path", "/"),
        (":authority", "example.com"),
        (":scheme", "https"),
        ("user-agent", "blasthttp-test"),
    ]


def test_decoder_preserves_dynamic_table_across_calls():
    """Per RFC 7541, decoder state must persist across calls on the
    same Decoder instance. A second block can reference entries the
    first block added to the dynamic table."""
    dec = h2.Decoder()
    # First block adds `custom-key: custom-value` to the dynamic table.
    block_a = h2.encode_headers([h2.Header("custom-key", "custom-value")])
    dec.decode(block_a)
    # Second block reuses the same pair — a healthy decoder should
    # reconstruct it from the dynamic table (no error, correct output).
    block_b = h2.encode_headers([h2.Header("custom-key", "custom-value")])
    out = dec.decode(block_b)
    assert out == [(b"custom-key", b"custom-value")]


def test_permissive_crlf_in_value_round_trips():
    """The whole reason blasthttp's HPACK exists: allow emitting bytes
    a strict encoder would refuse. CRLF in header value is the probe
    material for H2-to-H1 CRLF injection. Encoder must accept, decoder
    must return exact bytes back."""
    evil = "bogus\r\nX-Smuggled: yes"
    block = h2.encode_headers(
        [
            h2.Header(":method", "GET"),
            h2.Header(":path", "/"),
            h2.Header(":authority", "example.com"),
            h2.Header(":scheme", "https"),
            h2.Header(
                "x-injected",
                evil,
                allow_invalid_value=True,
                huffman_value=False,
            ),
        ]
    )
    decoded = h2.Decoder().decode(block)
    # Find the injected header — its value must be preserved verbatim,
    # CRLF and all.
    found = [(n, v) for n, v in decoded if n == b"x-injected"]
    assert len(found) == 1
    assert found[0][1] == evil.encode("latin-1")


# ── Frame builders ───────────────────────────────────────────────────


def _parse_frame_header(frame):
    """Decode the 9-byte H2 frame header into
    (length, type, flags, stream_id)."""
    assert len(frame) >= 9
    length = int.from_bytes(frame[0:3], "big")
    ftype = frame[3]
    flags = frame[4]
    sid = int.from_bytes(frame[5:9], "big") & 0x7FFFFFFF
    return length, ftype, flags, sid


def test_settings_frame_empty_is_well_formed():
    frame = h2.build_settings_frame()
    length, ftype, flags, sid = _parse_frame_header(frame)
    assert ftype == h2.FRAME_SETTINGS
    assert sid == 0  # SETTINGS is always stream 0
    assert flags == 0  # no ACK
    assert length == 0  # empty SETTINGS payload
    assert len(frame) == 9  # header only


def test_settings_frame_ack_sets_ack_flag():
    frame = h2.build_settings_frame(ack=True)
    _, ftype, flags, _ = _parse_frame_header(frame)
    assert ftype == h2.FRAME_SETTINGS
    assert flags & h2.FLAG_ACK


def test_headers_frame_default_flags():
    block = h2.encode_headers([h2.Header(":method", "GET")])
    frame = h2.build_headers_frame(block, stream_id=1)
    length, ftype, flags, sid = _parse_frame_header(frame)
    assert ftype == h2.FRAME_HEADERS
    assert sid == 1
    # Default per blasthttp signature: end_headers=True, end_stream=False.
    assert flags & h2.FLAG_END_HEADERS
    assert not (flags & h2.FLAG_END_STREAM)
    assert length == len(block)


def test_headers_frame_end_stream_flag():
    block = h2.encode_headers([h2.Header(":method", "GET")])
    frame = h2.build_headers_frame(block, stream_id=3, end_stream=True)
    _, _, flags, _ = _parse_frame_header(frame)
    assert flags & h2.FLAG_END_STREAM


def test_data_frame_carries_payload():
    payload = b"hello body bytes"
    frame = h2.build_data_frame(payload, stream_id=1, end_stream=True)
    length, ftype, flags, sid = _parse_frame_header(frame)
    assert ftype == h2.FRAME_DATA
    assert sid == 1
    assert flags & h2.FLAG_END_STREAM
    assert length == len(payload)
    assert frame[9:] == payload


# ── build_probe high-level helper ────────────────────────────────────


def test_build_probe_emits_preface_then_settings_then_headers():
    """build_probe is the one-shot builder for a full H2 request probe.
    Order matters: preface first, then a SETTINGS frame (our side's),
    then the HEADERS for stream 1."""
    probe = h2.build_probe(
        [
            h2.Header(":method", "GET"),
            h2.Header(":path", "/"),
            h2.Header(":authority", "example.com"),
            h2.Header(":scheme", "https"),
        ]
    )
    assert probe.startswith(h2.PREFACE)
    after_preface = probe[len(h2.PREFACE) :]
    # First frame past the preface is SETTINGS.
    _, ftype1, _, sid1 = _parse_frame_header(after_preface)
    assert ftype1 == h2.FRAME_SETTINGS
    assert sid1 == 0
    # Skip SETTINGS frame → next frame is HEADERS on stream 1.
    settings_total = 9 + int.from_bytes(after_preface[0:3], "big")
    rest = after_preface[settings_total:]
    _, ftype2, _, sid2 = _parse_frame_header(rest)
    assert ftype2 == h2.FRAME_HEADERS
    assert sid2 == 1


def test_build_probe_appends_data_frame_when_body_given():
    """When a body is passed, build_probe emits preface + SETTINGS +
    HEADERS (no END_STREAM) + DATA (END_STREAM). That's the shape the
    H2 smuggling detectors depend on."""
    probe = h2.build_probe(
        [
            h2.Header(":method", "POST"),
            h2.Header(":path", "/"),
            h2.Header(":authority", "example.com"),
            h2.Header(":scheme", "https"),
            h2.Header("content-length", "5"),
        ],
        body=b"hello",
    )
    assert probe.startswith(h2.PREFACE)
    # Walk the frames — expect SETTINGS, HEADERS, DATA in order.
    pos = len(h2.PREFACE)
    frame_types = []
    while pos < len(probe):
        length, ftype, _flags, _sid = _parse_frame_header(probe[pos:])
        frame_types.append(ftype)
        pos += 9 + length
    assert frame_types == [
        h2.FRAME_SETTINGS,
        h2.FRAME_HEADERS,
        h2.FRAME_DATA,
    ]

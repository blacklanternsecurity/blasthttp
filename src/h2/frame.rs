//! HTTP/2 frame builders (RFC 9113).
//!
//! Every H2 frame has a 9-byte header:
//!   - 24-bit length (big-endian)
//!   - 8-bit type
//!   - 8-bit flags
//!   - 1 reserved bit (MUST be 0) + 31-bit stream identifier
//!
//! Followed by `length` bytes of type-specific payload.
//!
//! Builders in this module return the full frame bytes (header +
//! payload) ready for wire transmission. Callers concatenate the
//! bytes they need in whatever order — we don't enforce frame
//! ordering since research probes often deliberately misorder.

/// Connection preface — the client-to-server magic string MUST be
/// the very first thing a client sends on a new HTTP/2 connection.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ── Frame type codes (RFC 9113 §11.2) ───────────────────────────
pub const FRAME_DATA: u8 = 0x00;
pub const FRAME_HEADERS: u8 = 0x01;
pub const FRAME_PRIORITY: u8 = 0x02;
pub const FRAME_RST_STREAM: u8 = 0x03;
pub const FRAME_SETTINGS: u8 = 0x04;
pub const FRAME_PUSH_PROMISE: u8 = 0x05;
pub const FRAME_PING: u8 = 0x06;
pub const FRAME_GOAWAY: u8 = 0x07;
pub const FRAME_WINDOW_UPDATE: u8 = 0x08;
pub const FRAME_CONTINUATION: u8 = 0x09;

// ── Flag bits (overlap across frame types per spec) ────────────
pub const FLAG_END_STREAM: u8 = 0x01; // DATA, HEADERS
pub const FLAG_ACK: u8 = 0x01; // SETTINGS, PING (same bit, different name)
pub const FLAG_END_HEADERS: u8 = 0x04; // HEADERS, CONTINUATION, PUSH_PROMISE
pub const FLAG_PADDED: u8 = 0x08; // DATA, HEADERS, PUSH_PROMISE
pub const FLAG_PRIORITY: u8 = 0x20; // HEADERS

// ── SETTINGS identifiers (RFC 9113 §6.5.2) ─────────────────────
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x01;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x02;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x03;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x04;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x05;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x06;

/// Build a raw frame header + payload. Exposed both for our own
/// internal use and as a "final escape hatch" researcher-level
/// primitive: any unusual frame type, flags, or stream id combination
/// can be crafted by hand without touching the typed builders.
pub fn build_raw_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    assert!(len < (1 << 24), "frame payload exceeds 24-bit length");
    let mut out = Vec::with_capacity(9 + len);
    // 24-bit length, big-endian
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    // type, flags
    out.push(frame_type);
    out.push(flags);
    // R bit (0) + 31-bit stream id, big-endian
    let sid = stream_id & 0x7FFF_FFFF;
    out.push(((sid >> 24) & 0xFF) as u8);
    out.push(((sid >> 16) & 0xFF) as u8);
    out.push(((sid >> 8) & 0xFF) as u8);
    out.push((sid & 0xFF) as u8);
    out.extend_from_slice(payload);
    out
}

/// SETTINGS frame (RFC 9113 §6.5). Caller supplies (id, value) pairs.
/// When empty, emits a zero-length SETTINGS frame (all defaults).
/// Set `ack=true` for a SETTINGS ACK (must be zero-length).
pub fn build_settings_frame(settings: &[(u16, u32)], ack: bool) -> Vec<u8> {
    let flags = if ack { FLAG_ACK } else { 0 };
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for &(id, val) in settings {
        payload.push((id >> 8) as u8);
        payload.push(id as u8);
        payload.extend_from_slice(&val.to_be_bytes());
    }
    build_raw_frame(FRAME_SETTINGS, flags, 0, &payload)
}

/// HEADERS frame.
///
/// `header_block` is the HPACK-encoded header block fragment (from
/// `hpack::encode_headers()`). If `end_headers=false`, the caller is
/// responsible for emitting one or more CONTINUATION frames next.
/// `padding` 0 = no PADDED flag; >0 adds a PAD_LENGTH byte and
/// `padding` zero bytes.
/// `priority` attaches legacy-priority info (dep_stream, weight,
/// exclusive); prepends PRIORITY fields to the payload and sets the
/// PRIORITY flag.
pub struct HeadersFrameOpts<'a> {
    pub header_block: &'a [u8],
    pub stream_id: u32,
    pub end_stream: bool,
    pub end_headers: bool,
    pub padding: u8,
    pub priority: Option<(u32, u8, bool)>,
}

pub fn build_headers_frame(opts: HeadersFrameOpts<'_>) -> Vec<u8> {
    let mut payload = Vec::new();
    if opts.padding > 0 {
        payload.push(opts.padding);
    }
    if let Some((dep, weight, exclusive)) = opts.priority {
        let mut dep_word = dep & 0x7FFF_FFFF;
        if exclusive {
            dep_word |= 0x8000_0000;
        }
        payload.extend_from_slice(&dep_word.to_be_bytes());
        payload.push(weight);
    }
    payload.extend_from_slice(opts.header_block);
    // Padding bytes.
    payload.resize(payload.len() + opts.padding as usize, 0);
    let mut flags = 0u8;
    if opts.end_stream {
        flags |= FLAG_END_STREAM;
    }
    if opts.end_headers {
        flags |= FLAG_END_HEADERS;
    }
    if opts.padding > 0 {
        flags |= FLAG_PADDED;
    }
    if opts.priority.is_some() {
        flags |= FLAG_PRIORITY;
    }
    build_raw_frame(FRAME_HEADERS, flags, opts.stream_id, &payload)
}

/// CONTINUATION frame. Used when a HEADERS (or PUSH_PROMISE) block
/// is split across multiple frames.
pub fn build_continuation_frame(header_block: &[u8], stream_id: u32, end_headers: bool) -> Vec<u8> {
    let flags = if end_headers { FLAG_END_HEADERS } else { 0 };
    build_raw_frame(FRAME_CONTINUATION, flags, stream_id, header_block)
}

/// DATA frame.
pub fn build_data_frame(data: &[u8], stream_id: u32, end_stream: bool, padding: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    if padding > 0 {
        payload.push(padding);
    }
    payload.extend_from_slice(data);
    payload.resize(payload.len() + padding as usize, 0);
    let mut flags = 0u8;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    if padding > 0 {
        flags |= FLAG_PADDED;
    }
    build_raw_frame(FRAME_DATA, flags, stream_id, &payload)
}

pub fn build_window_update_frame(increment: u32, stream_id: u32) -> Vec<u8> {
    let payload = increment.to_be_bytes();
    build_raw_frame(FRAME_WINDOW_UPDATE, 0, stream_id, &payload)
}

pub fn build_ping_frame(data: [u8; 8], ack: bool) -> Vec<u8> {
    let flags = if ack { FLAG_ACK } else { 0 };
    build_raw_frame(FRAME_PING, flags, 0, &data)
}

pub fn build_rst_stream_frame(stream_id: u32, error_code: u32) -> Vec<u8> {
    build_raw_frame(FRAME_RST_STREAM, 0, stream_id, &error_code.to_be_bytes())
}

pub fn build_goaway_frame(last_stream_id: u32, error_code: u32, debug_data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + debug_data.len());
    payload.extend_from_slice(&(last_stream_id & 0x7FFF_FFFF).to_be_bytes());
    payload.extend_from_slice(&error_code.to_be_bytes());
    payload.extend_from_slice(debug_data);
    build_raw_frame(FRAME_GOAWAY, 0, 0, &payload)
}

pub fn build_priority_frame(
    stream_id: u32,
    dep_stream: u32,
    weight: u8,
    exclusive: bool,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5);
    let mut dep_word = dep_stream & 0x7FFF_FFFF;
    if exclusive {
        dep_word |= 0x8000_0000;
    }
    payload.extend_from_slice(&dep_word.to_be_bytes());
    payload.push(weight);
    build_raw_frame(FRAME_PRIORITY, 0, stream_id, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_frame_length_encoding() {
        // 1-byte payload: length field = 0x000001.
        let f = build_raw_frame(FRAME_DATA, 0, 1, b"x");
        assert_eq!(f[0], 0x00);
        assert_eq!(f[1], 0x00);
        assert_eq!(f[2], 0x01);
        assert_eq!(f[3], FRAME_DATA);
        assert_eq!(f[4], 0);
        assert_eq!(&f[5..9], &[0, 0, 0, 1]); // stream_id=1
        assert_eq!(&f[9..], b"x");
    }

    #[test]
    fn settings_frame_empty_is_9_bytes() {
        let f = build_settings_frame(&[], false);
        assert_eq!(f.len(), 9);
        assert_eq!(f[3], FRAME_SETTINGS);
        assert_eq!(f[4], 0);
    }

    #[test]
    fn settings_frame_ack_sets_flag() {
        let f = build_settings_frame(&[], true);
        assert_eq!(f[4], FLAG_ACK);
    }

    #[test]
    fn settings_frame_encodes_pairs() {
        // Two settings: HEADER_TABLE_SIZE=4096, MAX_FRAME_SIZE=16384.
        let f = build_settings_frame(
            &[
                (SETTINGS_HEADER_TABLE_SIZE, 4096),
                (SETTINGS_MAX_FRAME_SIZE, 16384),
            ],
            false,
        );
        // Length = 12 bytes (6 per setting × 2).
        assert_eq!(f[2], 12);
        // First setting: id=0x0001, value=0x00001000
        assert_eq!(&f[9..15], &[0x00, 0x01, 0x00, 0x00, 0x10, 0x00]);
        // Second: id=0x0005, value=0x00004000
        assert_eq!(&f[15..21], &[0x00, 0x05, 0x00, 0x00, 0x40, 0x00]);
    }

    #[test]
    fn headers_frame_end_stream_and_end_headers() {
        let f = build_headers_frame(HeadersFrameOpts {
            header_block: b"xx",
            stream_id: 1,
            end_stream: true,
            end_headers: true,
            padding: 0,
            priority: None,
        });
        assert_eq!(f[3], FRAME_HEADERS);
        assert_eq!(f[4], FLAG_END_STREAM | FLAG_END_HEADERS);
        assert_eq!(&f[9..], b"xx");
    }

    #[test]
    fn headers_frame_with_padding() {
        let f = build_headers_frame(HeadersFrameOpts {
            header_block: b"x",
            stream_id: 1,
            end_stream: false,
            end_headers: true,
            padding: 3,
            priority: None,
        });
        assert_eq!(f[4] & FLAG_PADDED, FLAG_PADDED);
        // Payload: [pad_length=3, 0x78='x', 0, 0, 0]
        assert_eq!(&f[9..], &[3, b'x', 0, 0, 0]);
    }

    #[test]
    fn data_frame_default() {
        let f = build_data_frame(b"hello", 1, true, 0);
        assert_eq!(f[3], FRAME_DATA);
        assert_eq!(f[4], FLAG_END_STREAM);
        assert_eq!(&f[9..], b"hello");
    }

    #[test]
    fn rst_stream_frame_encoding() {
        let f = build_rst_stream_frame(1, 8);
        assert_eq!(f[3], FRAME_RST_STREAM);
        assert_eq!(&f[9..], &[0, 0, 0, 8]);
    }

    #[test]
    fn goaway_frame_encoding() {
        let f = build_goaway_frame(7, 1, b"debug");
        assert_eq!(f[3], FRAME_GOAWAY);
        assert_eq!(&f[9..13], &[0, 0, 0, 7]); // last_stream_id
        assert_eq!(&f[13..17], &[0, 0, 0, 1]); // error_code
        assert_eq!(&f[17..], b"debug");
    }
}

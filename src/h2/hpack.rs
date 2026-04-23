//! Permissive HPACK encoder (RFC 7541).
//!
//! Write-only. Takes `Header` values with permissiveness knobs and
//! emits a header-block-fragment byte string suitable for placement
//! in a HEADERS or CONTINUATION frame payload.
//!
//! What we DO implement:
//!   - Literal header field with incremental indexing (§6.2.1)
//!   - Literal header field without indexing (§6.2.2)
//!   - Literal header field never indexed (§6.2.3)
//!   - Variable-length integer encoding (§5.1), with optional
//!     deliberate "bloat" bytes for fuzzing
//!   - String literal encoding (§5.2), Huffman or raw, per caller
//!     choice or auto-shortest
//!   - Static-table name references (indexed name + literal value)
//!
//! What we explicitly DON'T do:
//!   - Dynamic table state tracking on the encoder side. Each call
//!     produces a header block that starts from a virtual empty
//!     dynamic table. Real HTTP/2 decoders track it per-connection,
//!     but since we only control one probe per connection (and don't
//!     reuse encoders across probes), a stateless encoder is fine
//!     and avoids a whole class of subtle cross-probe bugs.
//!   - Validation of header names/values BEYOND what our permissive
//!     knobs gate. The caller is responsible for what they send.
//!
//! Reference table indices (RFC 7541 Appendix A) live in
//! [`static_table`] for the name lookup when `force_static_index`
//! is in play.

use super::header::{Header, Indexing};
use super::huffman;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("header name is empty")]
    EmptyName,
    #[error(
        "invalid characters in header value (CRLF, NUL, or other \
         RFC 9113 §8.2.1-prohibited bytes); set allow_invalid_value \
         to emit anyway"
    )]
    InvalidValue,
    #[error(
        "invalid characters in header name (uppercase, space, or \
         control chars); set allow_invalid_name to emit anyway"
    )]
    InvalidName,
    #[error("length_bloat out of range (must be 0..=3): {0}")]
    BloatOutOfRange(u8),
    #[error("force_static_index out of range (must be 1..=61): {0}")]
    StaticIndexOutOfRange(u8),
}

/// Encode a list of headers into an HPACK header-block-fragment.
///
/// Stateless: ignores the dynamic table entirely on the encoder
/// side (equivalent to assuming a fresh connection every call).
pub fn encode_headers(headers: &[Header]) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    for h in headers {
        encode_one(h, &mut out)?;
    }
    Ok(out)
}

fn encode_one(h: &Header, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if h.name.is_empty() && h.force_static_index.is_none() {
        return Err(EncodeError::EmptyName);
    }
    if h.length_bloat_name > 3 {
        return Err(EncodeError::BloatOutOfRange(h.length_bloat_name));
    }
    if h.length_bloat_value > 3 {
        return Err(EncodeError::BloatOutOfRange(h.length_bloat_value));
    }
    if !h.allow_invalid_name && h.force_static_index.is_none() && !is_name_valid(&h.name) {
        return Err(EncodeError::InvalidName);
    }
    if !h.allow_invalid_value && !is_value_valid(&h.value) {
        return Err(EncodeError::InvalidValue);
    }

    // The first byte's prefix pattern encodes BOTH the representation
    // choice (with/without/never) and, if the name is by reference
    // to an existing table entry, the start of the index. §6.2.
    let (prefix_pattern, prefix_bits) = match h.indexing {
        Indexing::With => (0b0100_0000u8, 6u32), // 01xxxxxx, 6-bit index
        Indexing::Without => (0b0000_0000, 4),   // 0000xxxx, 4-bit index
        Indexing::Never => (0b0001_0000, 4),     // 0001xxxx, 4-bit index
    };

    // Name: indexed (references static or dynamic table) or literal.
    let name_index: u32 = match h.force_static_index {
        Some(idx) => {
            if !(1..=61).contains(&idx) {
                return Err(EncodeError::StaticIndexOutOfRange(idx));
            }
            idx as u32
        }
        None => 0, // 0 signals "literal name follows"
    };

    // Emit the prefix-encoded integer for the name index.
    write_integer(out, name_index, prefix_bits, prefix_pattern, 0);

    // If the name was literal (index 0), emit the string literal next.
    if name_index == 0 {
        write_string(out, &h.name, h.huffman_name, h.length_bloat_name);
    }

    // Value is always a string literal.
    write_string(out, &h.value, h.huffman_value, h.length_bloat_value);

    Ok(())
}

/// Write an HPACK variable-length integer (RFC 7541 §5.1) into `out`.
///
/// - `value`: the integer to encode
/// - `n`: the prefix size in bits (e.g. 4 for `Without`, 6 for
///   `With`, 7 for string-length prefixes)
/// - `prefix_pattern`: high bits of the first byte (the
///   representation prefix, already shifted into place). The low
///   `n` bits of the first byte come from the integer encoding.
/// - `bloat`: emit this many extra continuation bytes of value zero
///   (with the high bit clear on the last) to produce a deliberate
///   overlong encoding. 0 = RFC-compliant minimum length.
fn write_integer(out: &mut Vec<u8>, value: u32, n: u32, prefix_pattern: u8, bloat: u8) {
    let max_prefix = (1u32 << n) - 1; // e.g. n=5 -> 31
    if value < max_prefix {
        // Fits directly in the n-bit prefix, no continuation needed.
        // `bloat` is silently ignored in this path: HPACK integer
        // encoding has no well-defined way to "pad" a value that
        // fits in the prefix (there's no continuation byte stream
        // to inject 0x80 filler into). Callers who want to probe
        // bloat must use values large enough to overflow the prefix.
        out.push(prefix_pattern | (value as u8));
        return;
    }
    // First byte: prefix_pattern + all-ones prefix, signaling
    // "continuation follows".
    out.push(prefix_pattern | (max_prefix as u8));
    let mut remaining = value - max_prefix;
    while remaining >= 128 {
        out.push(((remaining & 0x7F) as u8) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
    // Bloat: append N extra zero-value continuation bytes before the
    // real terminator, then move the terminator back. The spec allows
    // any number of continuation bytes; decoders MAY or MAY NOT accept
    // arbitrary bloat. This is the "length_bloat" fuzzing knob.
    for _ in 0..bloat {
        // Insert a 0x80 (continuation byte, value 0) immediately
        // before the last byte (which had the high bit clear).
        let last = out.pop().unwrap();
        out.push(0x80);
        out.push(last);
    }
}

/// Write an HPACK string literal (RFC 7541 §5.2) into `out`.
///
/// - `huffman`: Some(true) = force Huffman, Some(false) = force raw,
///   None = pick whichever is shorter.
/// - `length_bloat`: extra bytes on the length prefix integer.
fn write_string(out: &mut Vec<u8>, data: &[u8], huffman: Option<bool>, length_bloat: u8) {
    let use_huffman = match huffman {
        Some(h) => h,
        None => huffman::encoded_len(data) < data.len(),
    };
    let (encoded, h_flag) = if use_huffman {
        (huffman::encode(data), 0x80u8)
    } else {
        (data.to_vec(), 0x00)
    };
    // String length: 7-bit prefix, high bit is the Huffman flag.
    write_integer(out, encoded.len() as u32, 7, h_flag, length_bloat);
    out.extend_from_slice(&encoded);
}

/// Name validity per RFC 9113 §8.2.1 (HTTP/2 field-name rules):
/// must be non-empty, no uppercase, no control chars, no special
/// separators. Pseudo-headers starting with `:` are allowed because
/// pseudo-header tokens are themselves valid lowercase field names.
fn is_name_valid(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    // First byte: may be `:` for pseudo-headers, otherwise must be
    // a lowercase token character.
    let first = name[0];
    if first == b':' {
        if name.len() == 1 {
            return false;
        }
    } else if !is_lowercase_token_char(first) {
        return false;
    }
    // Remaining: all must be lowercase token chars (no `:` allowed
    // after the first position).
    for &b in &name[1..] {
        if !is_lowercase_token_char(b) {
            return false;
        }
    }
    true
}

/// RFC 7230 token chars, restricted to lowercase ASCII per RFC 9113.
fn is_lowercase_token_char(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z'
        | b'0'..=b'9'
        | b'!' | b'#' | b'$' | b'%' | b'&' | b'\''
        | b'*' | b'+' | b'-' | b'.' | b'^' | b'_'
        | b'`' | b'|' | b'~'
    )
}

/// Value validity per RFC 9113 §8.2.1: no NUL, CR, or LF. Other
/// control characters are technically allowed in header values by
/// the field-value grammar but we stay strict.
fn is_value_valid(value: &[u8]) -> bool {
    !value.iter().any(|&b| b == 0x00 || b == 0x0A || b == 0x0D)
}

// ── HPACK decoder ───────────────────────────────────────────────────
//
// Stateful decoder (dynamic-table-aware) for reading HPACK-encoded
// header blocks off the wire. Complements the stateless encoder
// above. Used by response parsers that need to materialize a
// server's HEADERS frames back into (name, value) pairs.
//
// Static table per RFC 7541 Appendix A (indices 1..=61). Dynamic
// table entries start at index 62 and push existing dynamic entries
// up. Size is bounded by `max_table_size`; the peer can change this
// via SETTINGS_HEADER_TABLE_SIZE or via an in-stream dynamic-table-
// size-update signal (§6.3).

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("unexpected end of input at position {0}")]
    UnexpectedEof(usize),
    #[error("HPACK integer overflow (continuation bytes exceed u32 range)")]
    IntegerOverflow,
    #[error("invalid table index {0}")]
    InvalidIndex(u32),
    #[error("dynamic-table-size-update of {0} exceeds peer-announced max {1}")]
    TableSizeTooLarge(u32, u32),
    #[error("Huffman decode failed: {0}")]
    Huffman(#[from] super::huffman::HuffmanError),
}

/// HPACK static table — entries 1..=61 per RFC 7541 Appendix A.
/// Index 0 is unused (HPACK indices are 1-based).
#[rustfmt::skip]
const STATIC_TABLE: &[(&[u8], &[u8])] = &[
    (b":authority", b""),
    (b":method", b"GET"),                    (b":method", b"POST"),
    (b":path", b"/"),                        (b":path", b"/index.html"),
    (b":scheme", b"http"),                   (b":scheme", b"https"),
    (b":status", b"200"),                    (b":status", b"204"),
    (b":status", b"206"),                    (b":status", b"304"),
    (b":status", b"400"),                    (b":status", b"404"),
    (b":status", b"500"),                    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),  (b"accept-language", b""),
    (b"accept-ranges", b""),                 (b"accept", b""),
    (b"access-control-allow-origin", b""),   (b"age", b""),
    (b"allow", b""),                         (b"authorization", b""),
    (b"cache-control", b""),                 (b"content-disposition", b""),
    (b"content-encoding", b""),              (b"content-language", b""),
    (b"content-length", b""),                (b"content-location", b""),
    (b"content-range", b""),                 (b"content-type", b""),
    (b"cookie", b""),                        (b"date", b""),
    (b"etag", b""),                          (b"expect", b""),
    (b"expires", b""),                       (b"from", b""),
    (b"host", b""),                          (b"if-match", b""),
    (b"if-modified-since", b""),             (b"if-none-match", b""),
    (b"if-range", b""),                      (b"if-unmodified-since", b""),
    (b"last-modified", b""),                 (b"link", b""),
    (b"location", b""),                      (b"max-forwards", b""),
    (b"proxy-authenticate", b""),            (b"proxy-authorization", b""),
    (b"range", b""),                         (b"referer", b""),
    (b"refresh", b""),                       (b"retry-after", b""),
    (b"server", b""),                        (b"set-cookie", b""),
    (b"strict-transport-security", b""),     (b"transfer-encoding", b""),
    (b"user-agent", b""),                    (b"vary", b""),
    (b"via", b""),                           (b"www-authenticate", b""),
];

/// One decoded (name, value) pair. Both are raw bytes (HPACK doesn't
/// constrain header encoding to UTF-8).
pub type DecodedHeader = (Vec<u8>, Vec<u8>);

/// HPACK decoder with persistent dynamic-table state. Create once
/// per connection (not per request) since HPACK's whole point is
/// that the dynamic table is shared across a connection's request
/// stream.
pub struct Decoder {
    /// Front is the most-recently-added entry (logical index 62;
    /// later additions push this index up). Back is the oldest,
    /// evicted first when we exceed `max_table_size`.
    dynamic_table: std::collections::VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Sum of (name.len + value.len + 32) for all dynamic entries.
    /// Bounded by `max_table_size`.
    dynamic_table_size: u32,
    /// Upper bound on the dynamic table's byte size, per the peer's
    /// SETTINGS_HEADER_TABLE_SIZE (default 4096).
    max_table_size: u32,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            dynamic_table: std::collections::VecDeque::new(),
            dynamic_table_size: 0,
            max_table_size: 4096,
        }
    }

    pub fn with_max_table_size(max: u32) -> Self {
        let mut d = Self::new();
        d.max_table_size = max;
        d
    }

    /// Decode an HPACK header-block-fragment into (name, value) pairs.
    /// Mutates internal dynamic-table state as needed; call on the
    /// same decoder instance for all HEADERS/CONTINUATION frames on
    /// one connection.
    pub fn decode_headers(&mut self, block: &[u8]) -> Result<Vec<DecodedHeader>, DecodeError> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                // Indexed Header Field (§6.1) — 1xxxxxxx
                let (idx, new_pos) = read_integer(block, pos, 7)?;
                pos = new_pos;
                out.push(self.lookup_index(idx)?);
            } else if b & 0xC0 == 0x40 {
                // Literal with Incremental Indexing (§6.2.1) — 01xxxxxx
                let (idx, new_pos) = read_integer(block, pos, 6)?;
                pos = new_pos;
                let name = if idx == 0 {
                    let (s, p) = read_string(block, pos)?;
                    pos = p;
                    s
                } else {
                    self.lookup_index(idx)?.0
                };
                let (value, p) = read_string(block, pos)?;
                pos = p;
                self.add_to_dynamic_table(name.clone(), value.clone());
                out.push((name, value));
            } else if b & 0xE0 == 0x20 {
                // Dynamic Table Size Update (§6.3) — 001xxxxx
                let (new_size, new_pos) = read_integer(block, pos, 5)?;
                pos = new_pos;
                if new_size > self.max_table_size {
                    return Err(DecodeError::TableSizeTooLarge(
                        new_size,
                        self.max_table_size,
                    ));
                }
                self.resize_table(new_size);
            } else {
                // Literal without Indexing (§6.2.2) — 0000xxxx
                // OR Literal Never Indexed (§6.2.3) — 0001xxxx
                let (idx, new_pos) = read_integer(block, pos, 4)?;
                pos = new_pos;
                let name = if idx == 0 {
                    let (s, p) = read_string(block, pos)?;
                    pos = p;
                    s
                } else {
                    self.lookup_index(idx)?.0
                };
                let (value, p) = read_string(block, pos)?;
                pos = p;
                out.push((name, value));
            }
        }
        Ok(out)
    }

    fn lookup_index(&self, idx: u32) -> Result<(Vec<u8>, Vec<u8>), DecodeError> {
        if idx == 0 {
            return Err(DecodeError::InvalidIndex(0));
        }
        if (idx as usize) <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[(idx - 1) as usize];
            return Ok((n.to_vec(), v.to_vec()));
        }
        // Dynamic table: dynamic index 62 = front of deque (most recent).
        let dyn_idx = (idx as usize) - 1 - STATIC_TABLE.len();
        match self.dynamic_table.get(dyn_idx) {
            Some((n, v)) => Ok((n.clone(), v.clone())),
            None => Err(DecodeError::InvalidIndex(idx)),
        }
    }

    fn add_to_dynamic_table(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry_size = (name.len() + value.len() + 32) as u32;
        // Single entry bigger than the whole table → table cleared
        // and entry NOT inserted (RFC 7541 §4.4).
        if entry_size > self.max_table_size {
            self.dynamic_table.clear();
            self.dynamic_table_size = 0;
            return;
        }
        // Evict from back (oldest) until room.
        while self.dynamic_table_size + entry_size > self.max_table_size {
            if let Some((n, v)) = self.dynamic_table.pop_back() {
                self.dynamic_table_size -= (n.len() + v.len() + 32) as u32;
            } else {
                break;
            }
        }
        self.dynamic_table.push_front((name, value));
        self.dynamic_table_size += entry_size;
    }

    fn resize_table(&mut self, new_size: u32) {
        self.max_table_size = new_size;
        while self.dynamic_table_size > new_size {
            if let Some((n, v)) = self.dynamic_table.pop_back() {
                self.dynamic_table_size -= (n.len() + v.len() + 32) as u32;
            } else {
                break;
            }
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Read an HPACK variable-length integer from `buf[pos..]` with an
/// `n`-bit prefix. Returns (value, new_pos).
fn read_integer(buf: &[u8], pos: usize, n: u32) -> Result<(u32, usize), DecodeError> {
    if pos >= buf.len() {
        return Err(DecodeError::UnexpectedEof(pos));
    }
    let max_prefix = (1u32 << n) - 1;
    let first = (buf[pos] as u32) & max_prefix;
    if first < max_prefix {
        return Ok((first, pos + 1));
    }
    // Continuation bytes: value = max_prefix + sum(byte_i & 0x7F) * 128^i
    let mut value = max_prefix;
    let mut shift: u32 = 0;
    let mut p = pos + 1;
    loop {
        if p >= buf.len() {
            return Err(DecodeError::UnexpectedEof(p));
        }
        let b = buf[p];
        p += 1;
        let contribution = ((b & 0x7F) as u32)
            .checked_shl(shift)
            .ok_or(DecodeError::IntegerOverflow)?;
        value = value
            .checked_add(contribution)
            .ok_or(DecodeError::IntegerOverflow)?;
        if b & 0x80 == 0 {
            return Ok((value, p));
        }
        shift = shift.checked_add(7).ok_or(DecodeError::IntegerOverflow)?;
    }
}

/// Read an HPACK string literal from `buf[pos..]`. Returns
/// (decoded bytes, new_pos).
fn read_string(buf: &[u8], pos: usize) -> Result<(Vec<u8>, usize), DecodeError> {
    if pos >= buf.len() {
        return Err(DecodeError::UnexpectedEof(pos));
    }
    let huffman = buf[pos] & 0x80 != 0;
    let (length, new_pos) = read_integer(buf, pos, 7)?;
    let end = new_pos + (length as usize);
    if end > buf.len() {
        return Err(DecodeError::UnexpectedEof(end));
    }
    let raw = &buf[new_pos..end];
    let bytes = if huffman {
        super::huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((bytes, end))
}

#[cfg(test)]
mod decoder_tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── Integer read tests ───────────────────────────────────────

    #[test]
    fn read_integer_example_c_1_1() {
        // 10 in 5-bit prefix: 0x0a
        assert_eq!(read_integer(&[0x0a], 0, 5).unwrap(), (10, 1));
    }

    #[test]
    fn read_integer_example_c_1_2() {
        // 1337 in 5-bit prefix: 0x1f 0x9a 0x0a
        assert_eq!(read_integer(&[0x1f, 0x9a, 0x0a], 0, 5).unwrap(), (1337, 3));
    }

    #[test]
    fn read_integer_example_c_1_3() {
        // 42 in 8-bit prefix: 0x2a
        assert_eq!(read_integer(&[0x2a], 0, 8).unwrap(), (42, 1));
    }

    // ── RFC 7541 §C.2 canonical header-field examples ────────────

    #[test]
    fn c_2_1_literal_with_incremental_indexing() {
        // custom-key: custom-header, literal name + value (raw)
        let block = hex("400a637573746f6d2d6b65790d637573746f6d2d686561646572");
        let mut d = Decoder::new();
        let out = d.decode_headers(&block).unwrap();
        assert_eq!(
            out,
            vec![(b"custom-key".to_vec(), b"custom-header".to_vec())]
        );
        // Must have been added to dynamic table.
        assert_eq!(d.dynamic_table.len(), 1);
    }

    #[test]
    fn c_2_2_literal_without_indexing() {
        // :path: /sample/path, name indexed (4 = :path), value literal raw
        let block = hex("040c2f73616d706c652f70617468");
        let mut d = Decoder::new();
        let out = d.decode_headers(&block).unwrap();
        assert_eq!(out, vec![(b":path".to_vec(), b"/sample/path".to_vec())]);
        // Without-indexing form does NOT add to dynamic table.
        assert_eq!(d.dynamic_table.len(), 0);
    }

    #[test]
    fn c_2_3_literal_never_indexed() {
        // password: secret, both literal raw
        let block = hex("100870617373776f726406736563726574");
        let mut d = Decoder::new();
        let out = d.decode_headers(&block).unwrap();
        assert_eq!(out, vec![(b"password".to_vec(), b"secret".to_vec())]);
        assert_eq!(d.dynamic_table.len(), 0);
    }

    #[test]
    fn c_2_4_indexed_header_field() {
        // :method: GET — static table entry 2, wire form 0x82
        let block = hex("82");
        let mut d = Decoder::new();
        let out = d.decode_headers(&block).unwrap();
        assert_eq!(out, vec![(b":method".to_vec(), b"GET".to_vec())]);
    }

    // ── RFC 7541 §C.3 multi-request sequence exercises the dyn table ──

    #[test]
    fn c_3_1_first_request() {
        // :method: GET, :scheme: http, :path: /, :authority: www.example.com
        let block = hex("828684410f7777772e6578616d706c652e636f6d");
        let mut d = Decoder::new();
        let out = d.decode_headers(&block).unwrap();
        assert_eq!(
            out,
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ]
        );
        // One dynamic entry added (from the incremental-indexing literal).
        assert_eq!(d.dynamic_table.len(), 1);
        assert_eq!(d.dynamic_table[0].0, b":authority");
        assert_eq!(d.dynamic_table[0].1, b"www.example.com");
    }

    // ── RFC 7541 §C.4 Huffman examples ───────────────────────────

    #[test]
    fn c_4_1_first_request_huffman() {
        // :method: GET, :scheme: http, :path: /,
        // :authority: www.example.com (Huffman-encoded)
        let block = hex("828684418cf1e3c2e5f23a6ba0ab90f4ff");
        let mut d = Decoder::new();
        let out = d.decode_headers(&block).unwrap();
        assert_eq!(
            out,
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ]
        );
    }

    // ── Round-trip against our own encoder ───────────────────────

    #[test]
    fn round_trip_strict_encoder_decoder() {
        let headers = vec![
            Header {
                name: b":method".to_vec(),
                value: b"POST".to_vec(),
                indexing: Indexing::With,
                huffman_name: Some(false),
                huffman_value: Some(false),
                allow_invalid_value: false,
                allow_invalid_name: false,
                length_bloat_name: 0,
                length_bloat_value: 0,
                force_static_index: None,
            },
            Header::new("content-type", "text/html; charset=utf-8"),
            Header::new("x-custom-header", "hello"),
        ];
        let encoded = encode_headers(&headers).unwrap();
        let mut d = Decoder::new();
        let decoded = d.decode_headers(&encoded).unwrap();
        assert_eq!(
            decoded,
            vec![
                (b":method".to_vec(), b"POST".to_vec()),
                (
                    b"content-type".to_vec(),
                    b"text/html; charset=utf-8".to_vec()
                ),
                (b"x-custom-header".to_vec(), b"hello".to_vec()),
            ]
        );
    }

    #[test]
    fn dynamic_table_eviction() {
        let mut d = Decoder::with_max_table_size(100);
        // Add entries until eviction happens.
        d.add_to_dynamic_table(b"a".repeat(30), b"v".repeat(30));
        d.add_to_dynamic_table(b"b".repeat(30), b"v".repeat(30));
        assert_eq!(d.dynamic_table.len(), 1); // first entry evicted
    }

    #[test]
    fn single_oversized_entry_clears_table() {
        let mut d = Decoder::with_max_table_size(100);
        d.add_to_dynamic_table(b"a".to_vec(), b"v".to_vec());
        assert_eq!(d.dynamic_table.len(), 1);
        // Entry size = 30 + 30 + 32 = 92 (fits)
        // Now add one that's 200 bytes — clears table, doesn't insert.
        d.add_to_dynamic_table(b"x".repeat(100), b"y".repeat(100));
        assert_eq!(d.dynamic_table.len(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── Integer encoding (RFC 7541 §C.1) ─────────────────────────

    #[test]
    fn integer_example_c_1_1() {
        // Encode 10 using 5-bit prefix (result: 0x0a in lower bits of
        // first byte). Prefix pattern 0 (no flags). Length: 1 byte.
        let mut out = Vec::new();
        write_integer(&mut out, 10, 5, 0, 0);
        assert_eq!(out, vec![10]);
    }

    #[test]
    fn integer_example_c_1_2() {
        // Encode 1337 using 5-bit prefix: overflow first byte, then
        // two continuation bytes. Expected: 0x1f, 0x9a, 0x0a (3 bytes).
        let mut out = Vec::new();
        write_integer(&mut out, 1337, 5, 0, 0);
        assert_eq!(out, vec![0x1f, 0x9a, 0x0a]);
    }

    #[test]
    fn integer_example_c_1_3() {
        // Encode 42 with 8-bit prefix: fits directly. 42 == 0x2a.
        let mut out = Vec::new();
        write_integer(&mut out, 42, 8, 0, 0);
        assert_eq!(out, vec![0x2a]);
    }

    // ── String encoding ──────────────────────────────────────────

    #[test]
    fn string_raw_custom_key() {
        // "custom-key" encoded raw (huffman=Some(false)): length 10,
        // prefix bit 0 -> first byte 0x0a, then 10 ASCII bytes.
        let mut out = Vec::new();
        write_string(&mut out, b"custom-key", Some(false), 0);
        assert_eq!(&out[0..1], &[0x0a]);
        assert_eq!(&out[1..], b"custom-key");
    }

    #[test]
    fn string_huffman_auto_picks_shorter() {
        // Auto mode: www.example.com Huffman-encodes to 12 bytes
        // (shorter than 15 raw), so the auto path picks Huffman.
        let mut out = Vec::new();
        write_string(&mut out, b"www.example.com", None, 0);
        // First byte: 0x8c = 0x80 (huffman flag) | 0x0c (length 12)
        assert_eq!(out[0], 0x8c);
        assert_eq!(&out[1..], &hex("f1e3c2e5f23a6ba0ab90f4ff")[..]);
    }

    // ── Full header block: RFC 7541 §C.2 examples ────────────────

    #[test]
    fn rfc7541_c_2_1_literal_with_indexing() {
        // "custom-key: custom-header" via literal with indexing,
        // literal name & value (both raw). Expected bytes:
        // 40 0a 63 75 73 74 6f 6d 2d 6b 65 79 0d 63 75 73 74 6f 6d 2d 68 65 61 64 65 72
        // Our encoder defaults pick auto-shortest. Force raw so we
        // match the RFC's worked example byte-for-byte.
        let h = Header {
            name: b"custom-key".to_vec(),
            value: b"custom-header".to_vec(),
            indexing: Indexing::With,
            huffman_name: Some(false),
            huffman_value: Some(false),
            allow_invalid_value: false,
            allow_invalid_name: false,
            length_bloat_name: 0,
            length_bloat_value: 0,
            force_static_index: None,
        };
        let out = encode_headers(&[h]).unwrap();
        assert_eq!(
            out,
            hex("400a637573746f6d2d6b65790d637573746f6d2d686561646572")
        );
    }

    #[test]
    fn rfc7541_c_2_2_literal_without_indexing() {
        // ":path: /sample/path" via literal without indexing,
        // referencing static table entry 4 (:path). Expected:
        // 04 0c 2f 73 61 6d 70 6c 65 2f 70 61 74 68
        let h = Header {
            name: b":path".to_vec(),
            value: b"/sample/path".to_vec(),
            indexing: Indexing::Without,
            huffman_name: None,
            huffman_value: Some(false),
            allow_invalid_value: false,
            allow_invalid_name: false,
            length_bloat_name: 0,
            length_bloat_value: 0,
            force_static_index: Some(4),
        };
        let out = encode_headers(&[h]).unwrap();
        assert_eq!(out, hex("040c2f73616d706c652f70617468"));
    }

    #[test]
    fn rfc7541_c_2_3_literal_never_indexed() {
        // "password: secret" via never-indexed, literal name & value.
        // Expected: 10 08 70 61 73 73 77 6f 72 64 06 73 65 63 72 65 74
        let h = Header {
            name: b"password".to_vec(),
            value: b"secret".to_vec(),
            indexing: Indexing::Never,
            huffman_name: Some(false),
            huffman_value: Some(false),
            allow_invalid_value: false,
            allow_invalid_name: false,
            length_bloat_name: 0,
            length_bloat_value: 0,
            force_static_index: None,
        };
        let out = encode_headers(&[h]).unwrap();
        assert_eq!(out, hex("100870617373776f726406736563726574"));
    }

    // ── Permissive knobs ─────────────────────────────────────────

    #[test]
    fn rejects_invalid_value_by_default() {
        let h = Header::new("x-foo", "has\r\ncrlf");
        let err = encode_headers(&[h]).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidValue));
    }

    #[test]
    fn allow_invalid_value_emits_crlf() {
        let mut h = Header::new("x-foo", "has\r\ncrlf");
        h.allow_invalid_value = true;
        h.huffman_value = Some(false);
        let out = encode_headers(&[h]).unwrap();
        assert!(out.windows(2).any(|w| w == b"\r\n"));
    }

    #[test]
    fn rejects_uppercase_name_by_default() {
        let h = Header::new("X-Foo", "val");
        assert!(matches!(
            encode_headers(&[h]).unwrap_err(),
            EncodeError::InvalidName
        ));
    }

    #[test]
    fn allow_invalid_name_emits_uppercase() {
        let mut h = Header::new("X-Foo", "val");
        h.allow_invalid_name = true;
        h.huffman_name = Some(false);
        h.huffman_value = Some(false);
        let out = encode_headers(&[h]).unwrap();
        // Name literal starts after the prefix byte; "X-Foo" is 5B.
        // Prefix 0x40 (With + index 0) then length 0x05 then b"X-Foo"
        // then value. First 7 bytes: 40 05 58 2d 46 6f 6f
        assert_eq!(&out[..7], b"\x40\x05X-Foo");
    }

    #[test]
    fn pseudo_headers_always_allowed() {
        // ":method" name starts with `:` — valid without allow_invalid_name.
        let h = Header::new(":method", "GET");
        assert!(encode_headers(&[h]).is_ok());
    }

    #[test]
    fn length_bloat_adds_continuation_bytes() {
        // Bloat only affects integers that already overflow the prefix.
        // Build a value long enough that its length encoding overflows
        // the 7-bit string-length prefix (>= 127 bytes).
        let long_value = "a".repeat(200);
        let mut h = Header::new("x", long_value.clone());
        h.huffman_name = Some(false);
        h.huffman_value = Some(false);
        let no_bloat = encode_headers(&[h.clone()]).unwrap();
        h.length_bloat_value = 2;
        let bloated = encode_headers(&[h]).unwrap();
        assert_eq!(bloated.len(), no_bloat.len() + 2);
    }

    #[test]
    fn small_integer_bloat_is_ignored_not_panic() {
        // Asking for bloat on a value that fits in the prefix is a
        // caller error but we shouldn't crash — just emit the
        // canonical form.
        let mut h = Header::new("x", "y");
        h.huffman_name = Some(false);
        h.huffman_value = Some(false);
        h.length_bloat_value = 2;
        let out = encode_headers(&[h]).unwrap();
        // Value "y" length 1 < 127, bloat ignored. Length byte is 0x01.
        // Layout: [0x40 (With+idx 0), 0x01, 'x', 0x01, 'y']
        assert_eq!(out, b"\x40\x01x\x01y");
    }
}

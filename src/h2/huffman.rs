//! HPACK Huffman code table (RFC 7541 Appendix B).
//!
//! Fixed per the spec: a 256-entry table mapping each byte value plus
//! the EOS (end-of-stream, 256) to a (code, code_length) pair. Used
//! only for encoding; decoding is not needed for our write-only
//! permissive encoder (we decode responses via Python `hpack`).

/// Huffman-encode `input` bytes using the HPACK static Huffman table.
/// Pads to a whole byte with 1-bits (per spec). Returns the encoded
/// bytes.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;
    for &b in input {
        let (code, code_len) = HUFFMAN_TABLE[b as usize];
        bit_buf = (bit_buf << code_len) | code as u64;
        bits_in_buf += code_len;
        while bits_in_buf >= 8 {
            bits_in_buf -= 8;
            out.push(((bit_buf >> bits_in_buf) & 0xFF) as u8);
        }
    }
    // Pad with 1-bits (the EOS-like prefix padding, per RFC 7541 §5.2).
    if bits_in_buf > 0 {
        let pad = 8 - bits_in_buf;
        bit_buf = (bit_buf << pad) | ((1u64 << pad) - 1);
        out.push((bit_buf & 0xFF) as u8);
    }
    out
}

/// Huffman-encoded length for `input`, in bytes. Used to decide
/// whether plaintext or Huffman encoding is shorter when a caller
/// passes `huffman: None`.
pub fn encoded_len(input: &[u8]) -> usize {
    let mut bits: usize = 0;
    for &b in input {
        bits += HUFFMAN_TABLE[b as usize].1 as usize;
    }
    bits.div_ceil(8)
}

/// Decode HPACK Huffman-encoded bytes back to raw. Uses the lazily-
/// built binary prefix tree. Per RFC 7541 §5.2, a byte-boundary EOS
/// padding (up to 7 bits of 1s) is ignored at the end; any longer
/// all-ones tail or an embedded EOS-symbol (length 30) is a decode
/// error.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, HuffmanError> {
    let tree = huffman_tree();
    let mut out = Vec::with_capacity(input.len());
    let mut node_idx = 0usize;
    let mut bits_consumed_in_byte = 0u32;
    let mut byte_pos = 0usize;
    while byte_pos < input.len() {
        let b = input[byte_pos];
        let bit = (b >> (7 - bits_consumed_in_byte)) & 1;
        node_idx = if bit == 0 {
            tree[node_idx].left
        } else {
            tree[node_idx].right
        };
        bits_consumed_in_byte += 1;
        if bits_consumed_in_byte == 8 {
            bits_consumed_in_byte = 0;
            byte_pos += 1;
        }
        let node = &tree[node_idx];
        if let Some(sym) = node.symbol {
            if sym == 256 {
                // EOS symbol embedded in the stream — per RFC must
                // not appear, decoder error.
                return Err(HuffmanError::EosInStream);
            }
            out.push(sym as u8);
            node_idx = 0;
        }
    }
    // Trailing partial byte must be all-1s padding (prefix of EOS).
    // Walking internal nodes on pure 1-bits is fine up to 7 bits.
    // If we end on an internal node after >7 bits of padding, error.
    if node_idx != 0 {
        let node = &tree[node_idx];
        if node.all_ones_depth > 7 || !node.prefix_of_eos {
            return Err(HuffmanError::BadPadding);
        }
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum HuffmanError {
    #[error("Huffman EOS symbol appeared in the input stream")]
    EosInStream,
    #[error("invalid Huffman padding at end of input")]
    BadPadding,
}

/// Single node of the Huffman decode tree. Leaves carry a symbol.
/// Internal nodes track `all_ones_depth` (how deep a chain of 1-bit
/// steps we've walked) and `prefix_of_eos` (whether the path from
/// the root to this node is a prefix of the 30-bit EOS code) so the
/// decoder can accept trailing ≤7 bits of 1s as EOS-prefix padding
/// and reject anything else.
#[derive(Clone, Copy)]
struct HuffNode {
    left: usize,         // 0-bit child (default 0 = self-loop for leaves)
    right: usize,        // 1-bit child
    symbol: Option<u32>, // Some(byte) for leaves, Some(256) for EOS, None for internal
    all_ones_depth: u32,
    prefix_of_eos: bool,
}

use std::sync::OnceLock;

static HUFFMAN_TREE: OnceLock<Vec<HuffNode>> = OnceLock::new();

fn huffman_tree() -> &'static [HuffNode] {
    HUFFMAN_TREE.get_or_init(|| {
        let mut tree: Vec<HuffNode> = vec![HuffNode {
            left: 0,
            right: 0,
            symbol: None,
            all_ones_depth: 0,
            prefix_of_eos: true,
        }];
        // Insert all 256 byte symbols.
        for (sym, &(code, code_len)) in HUFFMAN_TABLE.iter().enumerate() {
            insert_symbol(&mut tree, code, code_len, sym as u32);
        }
        // Insert EOS (256, code=0x3fff_ffff, 30 bits).
        insert_symbol(&mut tree, 0x3fff_ffff, 30, 256);
        tree
    })
}

fn insert_symbol(tree: &mut Vec<HuffNode>, code: u32, code_len: u32, symbol: u32) {
    let mut idx = 0usize;
    for i in (0..code_len).rev() {
        let bit = (code >> i) & 1;
        let parent_all_ones_depth = tree[idx].all_ones_depth;
        let parent_prefix_eos = tree[idx].prefix_of_eos;
        let next = if bit == 0 {
            if tree[idx].left != 0 {
                tree[idx].left
            } else {
                let new_idx = tree.len();
                tree.push(HuffNode {
                    left: 0,
                    right: 0,
                    symbol: None,
                    all_ones_depth: 0,
                    prefix_of_eos: false,
                });
                tree[idx].left = new_idx;
                new_idx
            }
        } else if tree[idx].right != 0 {
            tree[idx].right
        } else {
            let new_idx = tree.len();
            tree.push(HuffNode {
                left: 0,
                right: 0,
                symbol: None,
                all_ones_depth: parent_all_ones_depth + 1,
                prefix_of_eos: parent_prefix_eos,
            });
            tree[idx].right = new_idx;
            new_idx
        };
        idx = next;
    }
    tree[idx].symbol = Some(symbol);
}

/// Huffman codes for each 8-bit byte value (0..=255) plus EOS (256,
/// 30 bits long, not emitted in practice). Transcribed verbatim from
/// RFC 7541 Appendix B.
///
/// Each entry: (code, code_length_in_bits).
///
/// The code value is right-justified in a u32 — high bits are zero.
#[rustfmt::skip]
const HUFFMAN_TABLE: [(u32, u32); 256] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6),     (0x3f8, 10),    (0x3f9, 10),    (0xffa, 12),
    (0x1ff9, 13),  (0x15, 6),      (0xf8, 8),      (0x7fa, 11),
    (0x3fa, 10),   (0x3fb, 10),    (0xf9, 8),      (0x7fb, 11),
    (0xfa, 8),     (0x16, 6),      (0x17, 6),      (0x18, 6),
    (0x0, 5),      (0x1, 5),       (0x2, 5),       (0x19, 6),
    (0x1a, 6),     (0x1b, 6),      (0x1c, 6),      (0x1d, 6),
    (0x1e, 6),     (0x1f, 6),      (0x5c, 7),      (0xfb, 8),
    (0x7ffc, 15),  (0x20, 6),      (0xffb, 12),    (0x3fc, 10),
    (0x1ffa, 13),  (0x21, 6),      (0x5d, 7),      (0x5e, 7),
    (0x5f, 7),     (0x60, 7),      (0x61, 7),      (0x62, 7),
    (0x63, 7),     (0x64, 7),      (0x65, 7),      (0x66, 7),
    (0x67, 7),     (0x68, 7),      (0x69, 7),      (0x6a, 7),
    (0x6b, 7),     (0x6c, 7),      (0x6d, 7),      (0x6e, 7),
    (0x6f, 7),     (0x70, 7),      (0x71, 7),      (0x72, 7),
    (0xfc, 8),     (0x73, 7),      (0xfd, 8),      (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13),   (0x3ffc, 14),   (0x22, 6),
    (0x7ffd, 15),  (0x3, 5),       (0x23, 6),      (0x4, 5),
    (0x24, 6),     (0x5, 5),       (0x25, 6),      (0x26, 6),
    (0x27, 6),     (0x6, 5),       (0x74, 7),      (0x75, 7),
    (0x28, 6),     (0x29, 6),      (0x2a, 6),      (0x7, 5),
    (0x2b, 6),     (0x76, 7),      (0x2c, 6),      (0x8, 5),
    (0x9, 5),      (0x2d, 6),      (0x77, 7),      (0x78, 7),
    (0x79, 7),     (0x7a, 7),      (0x7b, 7),      (0x7ffe, 15),
    (0x7fc, 11),   (0x3ffd, 14),   (0x1ffd, 13),   (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20),  (0xfffe8, 20),
    (0x3fffd3, 22),(0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22),(0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23),(0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24),(0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24),(0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23),(0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22),(0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22),(0x1fffdd, 21), (0xfffe9, 20),  (0x3fffdb, 22),
    (0x3fffdc, 22),(0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23),(0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21),(0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21),(0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23),(0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23),(0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26),(0x3ffffe1, 26),(0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22),(0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26),(0x3ffffe3, 26),(0x3ffffe4, 26),(0x7ffffde, 27),
    (0x7ffffdf, 27),(0x3ffffe5, 26),(0xfffff1, 24),(0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26),(0x7ffffe0, 27),
    (0x7ffffe1, 27),(0x3ffffe7, 26),(0x7ffffe2, 27),(0xfffff2, 24),
    (0x1fffe4, 21),(0x1fffe5, 21), (0x3ffffe8, 26),(0x3ffffe9, 26),
    (0xffffffd, 28),(0x7ffffe3, 27),(0x7ffffe4, 27),(0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20),  (0x1fffe6, 21),
    (0x3fffe9, 22),(0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22),(0x3fffeb, 22), (0x1ffffee, 25),(0x1ffffef, 25),
    (0xfffff4, 24),(0xfffff5, 24), (0x3ffffea, 26),(0x7ffff4, 23),
    (0x3ffffeb, 26),(0x7ffffe6, 27),(0x3ffffec, 26),(0x3ffffed, 26),
    (0x7ffffe7, 27),(0x7ffffe8, 27),(0x7ffffe9, 27),(0x7ffffea, 27),
    (0x7ffffeb, 27),(0xffffffe, 28),(0x7ffffec, 27),(0x7ffffed, 27),
    (0x7ffffee, 27),(0x7ffffef, 27),(0x7fffff0, 27),(0x3ffffee, 26),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_encodes_to_empty() {
        assert_eq!(encode(b""), b"");
        assert_eq!(encoded_len(b""), 0);
    }

    #[test]
    fn rfc7541_c_4_1_www_example_com() {
        // RFC 7541 §C.4.1: "www.example.com" Huffman-encoded is
        // f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff (12 bytes).
        let expected = hex("f1e3c2e5f23a6ba0ab90f4ff");
        assert_eq!(encode(b"www.example.com"), expected);
        assert_eq!(encoded_len(b"www.example.com"), expected.len());
    }

    #[test]
    fn rfc7541_c_4_2_no_cache() {
        // "no-cache" -> a8 eb 10 64 9c bf (6 bytes).
        let expected = hex("a8eb10649cbf");
        assert_eq!(encode(b"no-cache"), expected);
    }

    #[test]
    fn rfc7541_c_4_3_custom_key_and_value() {
        // "custom-key" -> 25 a8 49 e9 5b a9 7d 7f (8 bytes).
        assert_eq!(encode(b"custom-key"), hex("25a849e95ba97d7f"));
        // "custom-value" -> 25 a8 49 e9 5b b8 e8 b4 bf (9 bytes).
        assert_eq!(encode(b"custom-value"), hex("25a849e95bb8e8b4bf"));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decode_empty_input() {
        assert_eq!(decode(b"").unwrap(), b"");
    }

    #[test]
    fn decode_rfc7541_c_4_1_www_example_com() {
        let encoded = hex("f1e3c2e5f23a6ba0ab90f4ff");
        assert_eq!(decode(&encoded).unwrap(), b"www.example.com");
    }

    #[test]
    fn decode_rfc7541_c_4_2_no_cache() {
        assert_eq!(decode(&hex("a8eb10649cbf")).unwrap(), b"no-cache");
    }

    #[test]
    fn decode_rfc7541_c_4_3_custom_key_and_value() {
        assert_eq!(decode(&hex("25a849e95ba97d7f")).unwrap(), b"custom-key");
        assert_eq!(decode(&hex("25a849e95bb8e8b4bf")).unwrap(), b"custom-value");
    }

    #[test]
    fn decode_round_trip_all_byte_values() {
        // Every byte 0x00..=0xFF.
        let input: Vec<u8> = (0..=255u8).collect();
        let encoded = encode(&input);
        assert_eq!(decode(&encoded).unwrap(), input);
    }

    #[test]
    fn decode_accepts_eos_prefix_padding() {
        // "a" = 0x03, 5 bits → one byte with 3 bits of padding.
        let encoded = encode(b"a");
        assert_eq!(decode(&encoded).unwrap(), b"a");
    }
}

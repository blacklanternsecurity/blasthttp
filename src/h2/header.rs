//! Header entry type with all permissiveness knobs.
//!
//! Each knob corresponds to one axis of real-world HPACK/HTTP/2
//! implementation variation. Most have safe defaults that match
//! what a spec-conformant encoder would produce. Opt in explicitly
//! to probe weak decoders / validators.

/// Which HPACK literal representation to use for a header.
///
/// See RFC 7541 §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Indexing {
    /// Literal with incremental indexing. Adds the (name, value) to
    /// the dynamic table so later requests can reference it.
    /// Wire form: `01xxxxxx` prefix.
    #[default]
    With,
    /// Literal without indexing. Does not modify the dynamic table.
    /// Wire form: `0000xxxx` prefix.
    Without,
    /// Literal never-indexed. Must not be cached by intermediaries.
    /// Wire form: `0001xxxx` prefix.
    Never,
}

/// One (name, value) pair plus encoding knobs.
///
/// Fields with `Option<bool>` use `None` to mean "auto" — the encoder
/// chooses whatever is spec-conformant or shortest. `Some(true)` and
/// `Some(false)` force the choice.
#[derive(Debug, Clone)]
pub struct Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub indexing: Indexing,
    /// Force Huffman encoding on the name string: `Some(true)` always
    /// uses Huffman, `Some(false)` always uses plaintext, `None`
    /// chooses whichever is shorter.
    pub huffman_name: Option<bool>,
    /// Same for the value string.
    pub huffman_value: Option<bool>,
    /// If `true`, skip RFC 9113 §8.2.1 validation of the value (CRLF,
    /// NUL, etc.). Required for smuggling/tunneling primitives.
    pub allow_invalid_value: bool,
    /// If `true`, skip name validation (uppercase, spaces, control
    /// chars). Pseudo-headers starting with `:` are always allowed
    /// regardless of this flag.
    pub allow_invalid_name: bool,
    /// Extra bytes of "bloat" on the HPACK integer that encodes the
    /// NAME string length. Valid range 0..=3. HPACK integers are
    /// variable-length but a deliberate overlong form is tolerated
    /// by some decoders and rejected by others — useful for probing.
    pub length_bloat_name: u8,
    /// Same for the VALUE string length integer.
    pub length_bloat_value: u8,
    /// If `Some(idx)`, force-emit as a literal that *references the
    /// static table entry at `idx` for the name* (indices 1..=61
    /// per RFC 7541 Appendix A). The actual `name` field is ignored
    /// when this is set. Some decoders accept references even when
    /// the caller-supplied value doesn't match the indexed entry's
    /// typical use.
    pub force_static_index: Option<u8>,
}

impl Header {
    /// Convenience constructor matching the most common "just a header"
    /// use. All permissiveness knobs default to their safe values.
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            indexing: Indexing::default(),
            huffman_name: None,
            huffman_value: None,
            allow_invalid_value: false,
            allow_invalid_name: false,
            length_bloat_name: 0,
            length_bloat_value: 0,
            force_static_index: None,
        }
    }
}

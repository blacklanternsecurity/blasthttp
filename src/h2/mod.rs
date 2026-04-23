//! Permissive HTTP/2 probe construction.
//!
//! Write-only. Builds H2 frames and HPACK header blocks with
//! explicit knobs for every real-world HTTP/2 implementation
//! variation we want to probe: CRLF in values, uppercase header
//! names, Huffman forcing, integer bloat, CONTINUATION splitting,
//! padding, priority, static-table references, etc. Each knob
//! defaults to the spec-compliant safe behavior, so passing the
//! minimum `Header::new(name, value)` produces valid H2 — the
//! permissiveness is strictly opt-in.
//!
//! Response decoding is NOT provided here. Clients parse server
//! responses with whatever decoder they already have (in our case,
//! Python `hpack` for normal-response parsing in badhttp). Our
//! job is to emit wire bytes the caller asked for, nothing more.
//!
//! ## Module layout
//! - [`header`] — `Header` struct + the permissiveness knobs
//! - [`huffman`] — RFC 7541 Appendix B Huffman table (encoder only)
//! - [`hpack`] — header-block-fragment encoder (stateless, no
//!   dynamic table tracking — see module docs for rationale)
//! - [`frame`] — HTTP/2 frame builders for every frame type
//! - [`probe`] — high-level [`probe::build_probe`] that assembles
//!   preface + settings + headers [+ body] for the common single-
//!   request case

pub mod frame;
pub mod header;
pub mod hpack;
pub mod huffman;
pub mod probe;

// Re-export the types most callers need.
pub use header::{Header, Indexing};
pub use hpack::EncodeError;
pub use probe::{ProbeOpts, build_probe};

//! High-level `build_probe()` convenience for the common "one H2
//! request per connection" use.
//!
//! Assembles: PREFACE + SETTINGS + HEADERS (+ optional CONTINUATION
//! splits) + optional DATA. Exposes the frame-level knobs that matter
//! for research without forcing callers to glue frames by hand. For
//! anything weirder (interleaved streams, misordered frames, custom
//! types) use the Tier 2 primitives in `frame` directly.

use super::frame::{
    HeadersFrameOpts, PREFACE, build_continuation_frame, build_data_frame, build_headers_frame,
    build_settings_frame,
};
use super::header::Header;
use super::hpack::{self, EncodeError};

/// Options for [`build_probe`]. Every field has a sensible default
/// matching spec-compliant one-shot requests; opt in to the weirder
/// shapes deliberately.
pub struct ProbeOpts {
    /// Include the 24-byte PREFACE at the start. Almost always `true`.
    pub send_preface: bool,
    /// Override the preface bytes. When set, used INSTEAD OF the
    /// standard preface (so `send_preface` must also be `true`).
    /// Useful only for probing servers that tolerate non-standard
    /// preface bytes.
    pub preface_override: Option<Vec<u8>>,
    /// SETTINGS frame payload. Empty vec = empty SETTINGS. `None` =
    /// omit the SETTINGS frame entirely (malformed, some stacks
    /// tolerate).
    pub settings: Option<Vec<(u16, u32)>>,
    /// Stream ID for the request. Normally 1. Even IDs are
    /// server-initiated (invalid for client) but useful for probing
    /// stream-ID validation.
    pub stream_id: u32,
    /// Request body. If `None`, the HEADERS frame gets END_STREAM.
    /// If `Some`, a DATA frame follows with END_STREAM.
    pub body: Option<Vec<u8>>,
    /// When set, split the encoded header block so the HEADERS frame
    /// carries only the first N bytes and the remainder goes in one
    /// or more CONTINUATION frames. Set to `Some(1)` to test
    /// CONTINUATION handling in decoders.
    pub split_headers_after: Option<usize>,
    /// HEADERS frame padding (PAD_LENGTH byte + N zero bytes).
    pub pad_headers: u8,
    /// DATA frame padding (only meaningful if `body` is set).
    pub pad_data: u8,
    /// Legacy priority info attached to the HEADERS frame.
    pub priority: Option<(u32, u8, bool)>,
    /// When `true`, override the auto-picked HEADERS frame's
    /// END_STREAM flag to `false` even when no body is present.
    /// Useful for probing decoders that expect END_STREAM on
    /// body-less requests.
    pub force_no_end_stream_on_headers: bool,
    /// Raw frame bytes inserted BEFORE the HEADERS frame, after
    /// preface+settings. Escape hatch for injecting arbitrary frame
    /// sequences.
    pub extra_frames_before_headers: Vec<u8>,
    /// Raw frame bytes inserted AFTER all request frames.
    pub extra_frames_after: Vec<u8>,
}

impl Default for ProbeOpts {
    fn default() -> Self {
        Self {
            send_preface: true,
            preface_override: None,
            settings: Some(Vec::new()),
            stream_id: 1,
            body: None,
            split_headers_after: None,
            pad_headers: 0,
            pad_data: 0,
            priority: None,
            force_no_end_stream_on_headers: false,
            extra_frames_before_headers: Vec::new(),
            extra_frames_after: Vec::new(),
        }
    }
}

/// Assemble a full H2 probe (preface + SETTINGS + HEADERS [+ body])
/// ready to send over a raw_connect connection.
pub fn build_probe(headers: &[Header], opts: &ProbeOpts) -> Result<Vec<u8>, EncodeError> {
    let header_block = hpack::encode_headers(headers)?;
    let mut out = Vec::new();

    if opts.send_preface {
        match &opts.preface_override {
            Some(p) => out.extend_from_slice(p),
            None => out.extend_from_slice(PREFACE),
        }
    }
    if let Some(settings) = &opts.settings {
        out.extend_from_slice(&build_settings_frame(settings, false));
    }

    out.extend_from_slice(&opts.extra_frames_before_headers);

    let has_body = opts.body.is_some();
    let end_stream_on_headers = if opts.force_no_end_stream_on_headers {
        false
    } else {
        !has_body
    };

    // Split the header block into HEADERS [+ CONTINUATION(s)] if the
    // caller asked. The first frame is HEADERS; subsequent frames are
    // CONTINUATION. Only the LAST frame carries END_HEADERS.
    if let Some(split_after) = opts.split_headers_after {
        let split = split_after.min(header_block.len());
        let (first, rest) = header_block.split_at(split);
        let more_coming = !rest.is_empty();
        out.extend_from_slice(&build_headers_frame(HeadersFrameOpts {
            header_block: first,
            stream_id: opts.stream_id,
            end_stream: end_stream_on_headers,
            end_headers: !more_coming,
            padding: opts.pad_headers,
            priority: opts.priority,
        }));
        if more_coming {
            // One CONTINUATION with the rest. (Finer-grained splits
            // are callable via `frame::build_continuation_frame`
            // directly.)
            out.extend_from_slice(&build_continuation_frame(rest, opts.stream_id, true));
        }
    } else {
        out.extend_from_slice(&build_headers_frame(HeadersFrameOpts {
            header_block: &header_block,
            stream_id: opts.stream_id,
            end_stream: end_stream_on_headers,
            end_headers: true,
            padding: opts.pad_headers,
            priority: opts.priority,
        }));
    }

    if let Some(body) = &opts.body {
        out.extend_from_slice(&build_data_frame(body, opts.stream_id, true, opts.pad_data));
    }

    out.extend_from_slice(&opts.extra_frames_after);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::frame::{self, FRAME_CONTINUATION, FRAME_DATA, FRAME_HEADERS, FRAME_SETTINGS};

    fn default_headers() -> Vec<Header> {
        vec![
            Header::new(":method", "GET"),
            Header::new(":path", "/"),
            Header::new(":authority", "example.com"),
            Header::new(":scheme", "https"),
        ]
    }

    #[test]
    fn default_probe_has_preface_settings_headers() {
        let out = build_probe(&default_headers(), &ProbeOpts::default()).unwrap();
        // Starts with preface.
        assert_eq!(&out[..frame::PREFACE.len()], frame::PREFACE);
        // Immediately after preface: SETTINGS frame (type 0x04).
        let after_preface = &out[frame::PREFACE.len()..];
        assert_eq!(after_preface[3], FRAME_SETTINGS);
        // Skip SETTINGS header (9) + payload (0) = 9 bytes. Next:
        // HEADERS frame.
        let after_settings = &after_preface[9..];
        assert_eq!(after_settings[3], FRAME_HEADERS);
    }

    #[test]
    fn probe_with_body_emits_data_frame() {
        let opts = ProbeOpts {
            body: Some(b"hello".to_vec()),
            ..ProbeOpts::default()
        };
        let out = build_probe(&default_headers(), &opts).unwrap();
        // Scan for DATA frame.
        let mut found_data = false;
        let mut i = frame::PREFACE.len();
        while i < out.len() {
            let ftype = out[i + 3];
            let payload_len =
                ((out[i] as usize) << 16) | ((out[i + 1] as usize) << 8) | (out[i + 2] as usize);
            if ftype == FRAME_DATA {
                found_data = true;
                assert_eq!(&out[i + 9..i + 9 + payload_len], b"hello");
                break;
            }
            i += 9 + payload_len;
        }
        assert!(found_data);
    }

    #[test]
    fn split_headers_emits_continuation() {
        let opts = ProbeOpts {
            split_headers_after: Some(2),
            ..ProbeOpts::default()
        };
        let out = build_probe(&default_headers(), &opts).unwrap();
        // Scan frames; first non-SETTINGS frame must be HEADERS, second
        // must be CONTINUATION.
        let mut frame_types = Vec::new();
        let mut i = frame::PREFACE.len();
        while i + 9 <= out.len() {
            let payload_len =
                ((out[i] as usize) << 16) | ((out[i + 1] as usize) << 8) | (out[i + 2] as usize);
            frame_types.push(out[i + 3]);
            i += 9 + payload_len;
        }
        assert_eq!(frame_types[0], FRAME_SETTINGS);
        assert_eq!(frame_types[1], FRAME_HEADERS);
        assert_eq!(frame_types[2], FRAME_CONTINUATION);
    }

    #[test]
    fn skipping_settings_omits_frame() {
        let opts = ProbeOpts {
            settings: None,
            ..ProbeOpts::default()
        };
        let out = build_probe(&default_headers(), &opts).unwrap();
        let after_preface = &out[frame::PREFACE.len()..];
        // No SETTINGS frame — first frame right after preface is HEADERS.
        assert_eq!(after_preface[3], FRAME_HEADERS);
    }
}

// httpx-style `files=` multipart/form-data encoding for the Python
// bindings. Mirrors httpx so existing call sites keep working
// unchanged after migrating to blasthttp.
//
// Accepted shapes per dict value:
//   bytes / str / int / float / bool                 -> plain form field
//   (filename, content)                              -> file part if filename is not None, else plain field
//   (filename, content, content_type)                -> file part with explicit Content-Type
//   (filename, content, content_type, headers_dict)  -> file part with extra headers

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PySequence, PyString, PyTuple};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

/// Build a multipart/form-data body from an httpx-style `files=` dict.
/// Returns `(boundary, body_bytes)`. The caller is responsible for
/// setting `Content-Type: multipart/form-data; boundary=<boundary>`.
pub fn build_multipart(files: &Bound<'_, PyAny>) -> PyResult<(String, Vec<u8>)> {
    let dict = files
        .cast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("files must be a dict mapping field name to content"))?;

    let boundary = random_boundary();
    let mut body = Vec::with_capacity(256);

    for (name_obj, value_obj) in dict.iter() {
        let name: String = name_obj
            .extract()
            .map_err(|_| PyTypeError::new_err("files dict keys must be strings"))?;
        write_part(&mut body, &boundary, &name, &value_obj)?;
    }

    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"--\r\n");
    Ok((boundary, body))
}

fn write_part(
    body: &mut Vec<u8>,
    boundary: &str,
    field_name: &str,
    value: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let part = parse_value(value)?;

    body.extend_from_slice(b"--");
    body.extend_from_slice(boundary.as_bytes());
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(b"Content-Disposition: form-data; name=\"");
    body.extend_from_slice(quote_header(field_name).as_bytes());
    body.extend_from_slice(b"\"");
    if let Some(ref filename) = part.filename {
        body.extend_from_slice(b"; filename=\"");
        body.extend_from_slice(quote_header(filename).as_bytes());
        body.extend_from_slice(b"\"");
    }
    body.extend_from_slice(b"\r\n");

    if let Some(ref ct) = part.content_type {
        body.extend_from_slice(b"Content-Type: ");
        body.extend_from_slice(ct.as_bytes());
        body.extend_from_slice(b"\r\n");
    } else if part.filename.is_some() {
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    }

    for (k, v) in &part.extra_headers {
        body.extend_from_slice(k.as_bytes());
        body.extend_from_slice(b": ");
        body.extend_from_slice(v.as_bytes());
        body.extend_from_slice(b"\r\n");
    }

    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(&part.content);
    body.extend_from_slice(b"\r\n");
    Ok(())
}

struct ParsedPart {
    filename: Option<String>,
    content_type: Option<String>,
    content: Vec<u8>,
    extra_headers: Vec<(String, String)>,
}

fn parse_value(value: &Bound<'_, PyAny>) -> PyResult<ParsedPart> {
    // Tuple/list of 2-4 elements: (filename, content[, content_type[, headers]])
    if let Ok(seq) = value.cast::<PyTuple>() {
        return parse_sequence(seq.as_sequence());
    }
    if let Ok(seq) = value.cast::<PyList>() {
        return parse_sequence(seq.as_sequence());
    }
    // Scalar — treat as a plain form field value.
    Ok(ParsedPart {
        filename: None,
        content_type: None,
        content: coerce_content(value)?,
        extra_headers: Vec::new(),
    })
}

fn parse_sequence(seq: &Bound<'_, PySequence>) -> PyResult<ParsedPart> {
    let len = seq.len()?;
    if !(2..=4).contains(&len) {
        return Err(PyTypeError::new_err(
            "files value tuple must have 2-4 elements: (filename, content[, content_type[, headers]])",
        ));
    }

    let filename_obj = seq.get_item(0)?;
    let filename: Option<String> =
        if filename_obj.is_none() {
            None
        } else {
            Some(filename_obj.extract().map_err(|_| {
                PyTypeError::new_err("files tuple filename must be a string or None")
            })?)
        };

    let content = coerce_content(&seq.get_item(1)?)?;

    let content_type: Option<String> = if len >= 3 {
        let ct_obj = seq.get_item(2)?;
        if ct_obj.is_none() {
            None
        } else {
            Some(ct_obj.extract().map_err(|_| {
                PyTypeError::new_err("files tuple content_type must be a string or None")
            })?)
        }
    } else {
        None
    };

    let mut extra_headers = Vec::new();
    if len == 4 {
        let h_obj = seq.get_item(3)?;
        if !h_obj.is_none() {
            let h_dict = h_obj
                .cast::<PyDict>()
                .map_err(|_| PyTypeError::new_err("files tuple headers must be a dict or None"))?;
            for (k, v) in h_dict.iter() {
                let k: String = k.extract()?;
                let v: String = v.extract()?;
                extra_headers.push((k, v));
            }
        }
    }

    Ok(ParsedPart {
        filename,
        content_type,
        content,
        extra_headers,
    })
}

fn coerce_content(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if value.is_none() {
        return Ok(Vec::new());
    }
    if let Ok(b) = value.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(s) = value.cast::<PyString>() {
        return Ok(s.to_str()?.as_bytes().to_vec());
    }
    // Fall back to str() for numbers/bools so callers can mix types like httpx does.
    let s = value.str()?;
    Ok(s.to_str()?.as_bytes().to_vec())
}

/// Replace characters that would break the Content-Disposition quoted string.
/// Mirrors httpx (which percent-encodes the same set of chars).
fn quote_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("%5C"),
            '"' => out.push_str("%22"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            _ => out.push(c),
        }
    }
    out
}

/// 32-char hex boundary, seeded from `RandomState` (OS entropy on
/// construction) plus a process-wide counter. Not cryptographically
/// strong — just unique enough that collision with body content is
/// vanishingly unlikely.
fn random_boundary() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut h1 = RandomState::new().build_hasher();
    h1.write_u64(counter);
    let v1 = h1.finish();

    let mut h2 = RandomState::new().build_hasher();
    h2.write_u64(counter ^ v1);
    let v2 = h2.finish();

    format!("blasthttp-boundary-{:016x}{:016x}", v1, v2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_is_unique() {
        let a = random_boundary();
        let b = random_boundary();
        assert_ne!(a, b);
        assert!(a.starts_with("blasthttp-boundary-"));
        assert_eq!(a.len(), "blasthttp-boundary-".len() + 32);
    }

    #[test]
    fn quote_header_escapes_break_chars() {
        assert_eq!(quote_header(r#"a"b\c"#), "a%22b%5Cc");
        assert_eq!(quote_header("line1\r\nline2"), "line1%0D%0Aline2");
        assert_eq!(quote_header("plain.txt"), "plain.txt");
    }
}

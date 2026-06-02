// Integration tests for the `--no-proxy` CLI flag.
//
// These spawn the compiled `blasthttp` binary against a local origin server
// and a hit-counting HTTP proxy, then assert (via the response body and the
// proxy's hit counter) whether each request went through the proxy or
// connected directly. This is the one no_proxy surface the library-level
// tests don't exercise: the CLI arg -> build_config -> effective_proxy path.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// Spawn a minimal HTTP/1.1 server that answers every request with `body`.
/// If `counter` is set, it's incremented once per accepted connection, which
/// is how we tell whether the proxy was hit. Returns the bound port. The listener
/// thread is detached and lives for the rest of the test process.
fn spawn_server(body: &'static str, counter: Option<Arc<AtomicUsize>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if let Some(ref c) = counter {
                c.fetch_add(1, Ordering::SeqCst);
            }
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            // Drain the request head so the client isn't writing into a
            // half-closed socket when we reply.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            while let Ok(n) = stream.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16384 {
                    break;
                }
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

/// Run the CLI against `url` through `proxy` with the given `--no-proxy`
/// entries, returning combined stdout+stderr.
fn run_cli(url: &str, proxy: &str, no_proxy: &[&str]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blasthttp"));
    cmd.arg(url).arg("-x").arg(proxy);
    for entry in no_proxy {
        cmd.arg("--no-proxy").arg(entry);
    }
    cmd.arg("-vv"); // include the response body in the JSON output
    let output = cmd.output().expect("failed to run blasthttp binary");
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
}

/// Fresh origin + proxy per case so the hit counter is isolated. When
/// `expect_direct`, the request must reach the origin (`TARGET_DIRECT`) and
/// never touch the proxy; otherwise it must go through the proxy.
fn assert_routing(no_proxy: &[&str], expect_direct: bool) {
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let target_port = spawn_server("TARGET_DIRECT", None);
    let proxy_port = spawn_server("VIA_PROXY", Some(proxy_hits.clone()));

    let url = format!("http://127.0.0.1:{target_port}/foo");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let out = run_cli(&url, &proxy, no_proxy);

    if expect_direct {
        assert!(
            out.contains("TARGET_DIRECT"),
            "expected direct connection, got: {out}"
        );
        assert_eq!(
            proxy_hits.load(Ordering::SeqCst),
            0,
            "proxy should have been bypassed"
        );
    } else {
        assert!(
            out.contains("VIA_PROXY"),
            "expected proxied connection, got: {out}"
        );
        assert_eq!(
            proxy_hits.load(Ordering::SeqCst),
            1,
            "proxy should have been used once"
        );
    }
}

#[test]
fn no_exclusion_uses_proxy() {
    assert_routing(&[], false);
}

#[test]
fn exact_ip_bypasses_proxy() {
    assert_routing(&["127.0.0.1"], true);
}

#[test]
fn non_matching_cidr_uses_proxy() {
    assert_routing(&["10.0.0.0/8"], false);
}

#[test]
fn matching_cidr_bypasses_proxy() {
    assert_routing(&["127.0.0.0/8"], true);
}

#[test]
fn wildcard_bypasses_proxy() {
    assert_routing(&["*"], true);
}

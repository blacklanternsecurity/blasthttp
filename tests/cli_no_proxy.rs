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

/// Listener core: bind a loopback socket on `bind_host`, then for every
/// accepted connection bump `counter` (if set), drain the request head, and
/// write the fixed `response`. The thread is detached and lives for the rest of
/// the test process. Returns the bound port. `counter` is how we tell whether a
/// given host was actually connected to.
fn spawn_raw(bind_host: &str, response: String, counter: Option<Arc<AtomicUsize>>) -> u16 {
    let listener = TcpListener::bind(format!("{bind_host}:0")).unwrap();
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
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

/// HTTP/1.1 server on `bind_host` that answers every request with a 200 + `body`.
fn spawn_server(bind_host: &str, body: &str, counter: Option<Arc<AtomicUsize>>) -> u16 {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    spawn_raw(bind_host, response, counter)
}

/// HTTP/1.1 server on `bind_host` that 302-redirects every request to `location`.
fn spawn_redirect_server(
    bind_host: &str,
    location: &str,
    counter: Option<Arc<AtomicUsize>>,
) -> u16 {
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    spawn_raw(bind_host, response, counter)
}

/// Run the CLI against `url` through `proxy` with the given `--no-proxy`
/// entries, returning combined stdout+stderr. When `follow`, pass `-L` so
/// redirects are followed (each hop re-evaluates the proxy decision).
fn run_cli(url: &str, proxy: &str, no_proxy: &[&str], follow: bool) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blasthttp"));
    cmd.arg(url).arg("-x").arg(proxy);
    for entry in no_proxy {
        cmd.arg("--no-proxy").arg(entry);
    }
    if follow {
        cmd.arg("-L");
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
    let target_port = spawn_server("127.0.0.1", "TARGET_DIRECT", None);
    let proxy_port = spawn_server("127.0.0.1", "VIA_PROXY", Some(proxy_hits.clone()));

    let url = format!("http://127.0.0.1:{target_port}/foo");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let out = run_cli(&url, &proxy, no_proxy, false);

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

// The proxy decision must be re-made on every redirect hop, not frozen at the
// first URL. Two distinct loopback IPs give the two hops distinct host strings
// so a single `--no-proxy` entry can exclude one but not the other.

/// Case A — start on an excluded host (direct), which redirects onto a host
/// that is *not* excluded. The post-redirect hop must go through the proxy.
/// With the decision frozen at hop 1 it stayed direct, leaking the redirected
/// request straight out instead of through the proxy.
#[test]
fn redirect_onto_proxied_host_uses_proxy() {
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    // Reached only if the post-redirect hop wrongly stays direct.
    let target_port = spawn_server("127.0.0.1", "TARGET_DIRECT", None);
    // Excluded first host (127.0.0.2) redirects to the non-excluded host.
    let redirect_port = spawn_redirect_server(
        "127.0.0.2",
        &format!("http://127.0.0.1:{target_port}/next"),
        None,
    );
    let proxy_port = spawn_server("127.0.0.1", "VIA_PROXY", Some(proxy_hits.clone()));

    let url = format!("http://127.0.0.2:{redirect_port}/start");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let out = run_cli(&url, &proxy, &["127.0.0.2"], true);

    assert!(
        out.contains("VIA_PROXY"),
        "post-redirect hop should have been proxied, got: {out}"
    );
    assert!(
        !out.contains("TARGET_DIRECT"),
        "post-redirect hop must not connect directly, got: {out}"
    );
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        1,
        "the proxied (second) hop should have hit the proxy exactly once"
    );
}

/// Case B — start on a proxied host whose response redirects onto an excluded
/// host. The post-redirect hop must connect directly. With the decision frozen
/// at hop 1 it kept using the proxy, which here re-serves the redirect and
/// loops until the redirect limit instead of reaching the excluded host.
#[test]
fn redirect_onto_no_proxy_host_connects_direct() {
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let direct_hits = Arc::new(AtomicUsize::new(0));
    // Excluded redirect target — reached only via a direct connection.
    let target_port = spawn_server("127.0.0.2", "TARGET_DIRECT", Some(direct_hits.clone()));
    // The proxy redirects every request to the excluded host.
    let proxy_port = spawn_redirect_server(
        "127.0.0.1",
        &format!("http://127.0.0.2:{target_port}/next"),
        Some(proxy_hits.clone()),
    );

    // Start host (127.0.0.1) is not excluded -> hop 1 is proxied.
    let url = format!("http://127.0.0.1:{proxy_port}/start");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let out = run_cli(&url, &proxy, &["127.0.0.2"], true);

    assert!(
        out.contains("TARGET_DIRECT"),
        "post-redirect hop should have reached the excluded host directly, got: {out}"
    );
    assert_eq!(
        direct_hits.load(Ordering::SeqCst),
        1,
        "the excluded host should have been connected to directly exactly once"
    );
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        1,
        "the proxy should only have served the first hop, not the redirect loop"
    );
}

#[test]
fn no_proxy_without_proxy_errors() {
    // --no-proxy is meaningless without -x; the CLI should reject it up front
    // rather than silently ignore it. Validation runs before any connection, so
    // the unreachable URL is never dialed.
    let output = Command::new(env!("CARGO_BIN_EXE_blasthttp"))
        .arg("http://127.0.0.1:1/")
        .arg("--no-proxy")
        .arg("127.0.0.1")
        .output()
        .expect("failed to run blasthttp binary");

    assert!(
        !output.status.success(),
        "expected non-zero exit when --no-proxy is used without --proxy"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no_proxy") && stderr.contains("no proxy is configured"),
        "expected a no_proxy-without-proxy error, got: {stderr}"
    );
}

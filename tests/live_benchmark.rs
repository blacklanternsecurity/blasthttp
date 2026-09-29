// Live measurement against real services. Opt-in, never part of CI.
//
//     cargo test --test live_benchmark -- --ignored --nocapture
//
// Everything here needs the network and some of it needs third-party services
// that rate-limit, go away, or change behaviour between runs. None of that
// belongs in a gate. These print a scorecard and assert only that the
// measurement itself worked, because an assertion like "we are not blocked"
// would fail for reasons entirely outside this repository.
//
// The deterministic gates live in fingerprint_baseline.rs (what we send),
// ja4_conformance.rs (whether our JA4 agrees with everyone else's) and
// antibot_classify.rs (how outcomes are read). Those run offline in CI.

mod support;

use blasthttp::client::HttpClient;
use blasthttp::client::hyper::HyperClient;
use blasthttp::config::RequestConfig;
use support::antibot::{Outcome, ResponseFacts, classify};
use support::tls_server::{TlsServerConfig, TlsTestServer};

fn config(url: &str) -> RequestConfig {
    let mut c = RequestConfig::new(url.to_string());
    c.verify_certs = Some(false);
    c.timeout_seconds = Some(30);
    c.follow_redirects = Some(true);
    c
}

async fn fetch(url: &str) -> Option<(u16, Vec<(String, String)>, String)> {
    let client = HyperClient::new();
    match client.send(&config(url)).await {
        Ok(r) => {
            let body = r.body().to_string();
            Some((r.status, r.headers.clone(), body))
        }
        Err(e) => {
            println!("    request failed: {}", e.message);
            None
        }
    }
}

/// Our own ClientHello, captured locally, addressed by hostname so SNI is sent
/// and the result is directly comparable with what a remote service computes.
async fn local_ja4() -> String {
    let server = TlsTestServer::start(TlsServerConfig::default()).await;
    let url = format!("https://localhost:{}/", server.addr.port());

    let client = HyperClient::new();
    let _ = client.send(&config(&url)).await;

    let hello = server
        .hello
        .lock()
        .expect("hello slot poisoned")
        .clone()
        .expect("no ClientHello captured");
    server.shutdown().await;

    support::ja4::ja4(&hello)
}

#[tokio::test]
#[ignore = "needs network; run with --ignored"]
async fn live_ja4_agrees_with_a_remote_observer() {
    // Cross-checks the whole capture path. Our local reading and a third
    // party's should describe the same client, since it is the same client.
    // A mismatch means either the capture is wrong or something between us and
    // them is rewriting the handshake, and both are worth knowing.
    let local = local_ja4().await;
    println!("\n  local JA4:  {}", local);

    let Some((status, _, body)) = fetch("https://tls.peet.ws/api/all").await else {
        println!("  remote observer unreachable, skipping comparison");
        return;
    };
    assert_eq!(status, 200, "fingerprint service did not answer");

    let parsed: serde_json::Value = serde_json::from_str(&body).expect("expected JSON");
    let remote = parsed["tls"]["ja4"].as_str().unwrap_or("(absent)");
    println!("  remote JA4: {}", remote);

    // Not an assertion either way. JA4 implementations genuinely disagree:
    // one handshake shown to seven services produced three different JA3s and
    // two different JA4s.
    //
    // One divergence here is known and expected. The JA4 header is fixed
    // width and the spec caps both counts at 99; our legacy list is 105
    // suites, so we print `99` where peet.ws prints `105`. The two hash
    // segments match exactly, which says the underlying reading is the same
    // and only the rendering differs. A stealth profile at 15 suites makes it
    // go away.
    if local == remote {
        println!("  agree");
    } else {
        let (l, r) = (local.split('_').next(), remote.split('_').next());
        if local.split('_').skip(1).eq(remote.split('_').skip(1)) {
            println!("  headers differ ({:?} vs {:?}), hashes agree", l, r);
            println!("  (expected while our cipher count is over the 99 cap)");
        } else {
            println!("  hashes differ, worth investigating which of us is wrong");
        }
    }
}

#[tokio::test]
#[ignore = "needs network; run with --ignored"]
async fn live_fingerprint_prevalence() {
    // The check nothing else provides: does our ClientHello occur in real
    // traffic at all? A profile can match a published JA4 exactly and still be
    // a shape no real client emits, and no signature comparison catches that.
    //
    // Measured 2026-09-28: before the legacy cipher work our hello had been
    // seen 903 times across roughly 17B observations; after, it does not
    // appear at all. A real Chrome sits above 450M.
    let Some((_, _, body)) = fetch("https://tls.tlsfingerprint.io/api/client-fingerprint").await
    else {
        println!("  fingerprint database unreachable, skipping");
        return;
    };

    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            println!("  unexpected response shape, skipping");
            return;
        }
    };
    let Some(id) = parsed["norm_hex_id"].as_str() else {
        println!("  no norm_hex_id in response, skipping");
        return;
    };

    println!("\n  our ClientHello id: {}", id);

    let url = format!(
        "https://tlsfingerprint.io/api/tls/fingerprints/{}/exists",
        id
    );
    let Some((_, _, seen)) = fetch(&url).await else {
        return;
    };

    let parsed: serde_json::Value = serde_json::from_str(&seen).unwrap_or_default();
    match parsed["total"].as_u64() {
        Some(n) => println!("  observed {} times in real traffic", n),
        None => println!("  never observed in real traffic (the loudest signal we emit)"),
    }
}

#[tokio::test]
#[ignore = "needs network; run with --ignored"]
async fn live_block_scorecard() {
    // One GET per target, classified structurally.
    //
    // Target choice is deliberate. The scrapingcourse pages exist to be
    // scraped against. akamai.com is the vendor's own property and the
    // clearest discriminator we have: it refused blasthttp and served a
    // Chrome-impersonating client 219KB from the same address in the same
    // minute. cloudflare.com is a control that should always pass.
    //
    // Do not grow this into a list of ordinary commercial sites, and do not
    // put it on a schedule.
    let targets = [
        ("cloudflare.com (control)", "https://www.cloudflare.com/"),
        ("akamai.com", "https://www.akamai.com/"),
        (
            "scrapingcourse cf-challenge",
            "https://www.scrapingcourse.com/cloudflare-challenge",
        ),
        (
            "scrapingcourse antibot",
            "https://www.scrapingcourse.com/antibot-challenge",
        ),
    ];

    println!();
    let mut through = 0;
    for (label, url) in targets {
        let outcome = match fetch(url).await {
            Some((status, headers, body)) => classify(&ResponseFacts {
                status,
                headers: &headers,
                body: &body,
            }),
            None => Outcome::Error,
        };
        if outcome.got_through() {
            through += 1;
        }
        println!("  {:32} {:?}", label, outcome);
    }
    println!("\n  got through: {}/{}", through, targets.len());
    println!("  (the JS challenge tier is out of reach for any HTTP client,");
    println!("   curl_cffi included, so the scrapingcourse pages are expected");
    println!("   to stay unreachable until something executes JavaScript)");
}

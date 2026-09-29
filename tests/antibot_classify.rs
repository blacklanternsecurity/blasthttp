// The outcome classifier, against real captured responses.
//
// Fixtures are trimmed from responses actually observed on 2026-09-28, not
// invented. The Akamai one in particular is the exact page `www.akamai.com`
// returned to blasthttp while returning 200 with real content to a
// Chrome-impersonating client from the same address in the same minute. That
// pair is the clearest single measurement of the problem this effort exists to
// fix, so it is worth having as a regression fixture.

use blasthttp::antibot::{Outcome, ResponseFacts, Vendor, classify};

fn hdrs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn facts<'a>(status: u16, headers: &'a [(String, String)], body: &'a str) -> ResponseFacts<'a> {
    ResponseFacts {
        status,
        headers,
        body,
    }
}

// ── Real captures ─────────────────────────────────────────────────

/// Exactly what www.akamai.com served blasthttp, 366 bytes, reproduced 3/3.
const AKAMAI_DENIED: &str = concat!(
    "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\n \n",
    "You don't have permission to access \"http&#58;&#47;&#47;www&#46;akamai&#46;com&#47;\" ",
    "on this server.<P>\nReference&#32;&#35;18&#46;d3952a17&#46;1790609813&#46;f486746\n",
    "<P>https&#58;&#47;&#47;errors&#46;edgesuite&#46;net&#47;18&#46;d3952a17&#46;1790609813&#46;f486746\n",
    "</BODY>\n</HTML>\n"
);

#[test]
fn test_akamai_access_denied_is_a_block() {
    // These are the headers www.akamai.com actually returned, not a plausible
    // set. Two things about them broke the first version of the classifier and
    // are the reason this fixture is verbatim:
    //
    //   - there is no `server` header at all, so a rule requiring
    //     `server: AkamaiGHost` never fired
    //   - the body entity-encodes its own punctuation, so a search for
    //     `errors.edgesuite.net` never matched `errors&#46;edgesuite&#46;net`
    //
    // Both were caught by running the live benchmark, which classified this
    // exact response as Blocked(Unknown).
    let h = hdrs(&[
        ("mime-version", "1.0"),
        ("content-type", "text/html"),
        ("content-length", "368"),
        ("server-timing", "cdn-cache; desc=HIT"),
        (
            "server-timing",
            "ak_p; desc=\"1790644996525_35083629_828334756_15_11554_9_12_-\";dur=1",
        ),
        ("x-akam-sw-version", "0.5.0"),
        ("akamai-grn", "0.6d551702.1790644996.315f62a4"),
        (
            "set-cookie",
            "akaas_production=2147483647~rv=32~id=e124a124de5a16eb7688b22c80f8e95d;",
        ),
    ]);
    assert_eq!(
        classify(&facts(403, &h, AKAMAI_DENIED)),
        Outcome::Blocked(Vendor::Akamai)
    );
}

#[test]
fn test_akamai_block_detected_without_a_server_header() {
    // Narrower version of the above: the edge markers alone have to carry it.
    let h = hdrs(&[("akamai-grn", "0.6d551702.1790644996.315f62a4")]);
    assert_eq!(
        classify(&facts(
            403,
            &h,
            "<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD></HTML>"
        )),
        Outcome::Blocked(Vendor::Akamai)
    );
}

#[test]
fn test_entity_encoded_edgesuite_still_matches() {
    // No Akamai headers whatsoever, just the encoded error page body.
    let h = hdrs(&[("content-type", "text/html")]);
    assert_eq!(
        classify(&facts(403, &h, AKAMAI_DENIED)),
        Outcome::Blocked(Vendor::Akamai)
    );
}

#[test]
fn test_akamai_session_cookie_on_success_is_present() {
    // The other half of the same comparison: through, and handed a session.
    let h = hdrs(&[
        ("server", "AkamaiNetStorage"),
        (
            "set-cookie",
            "_abck=A7F1...~0~YAAQ...; Path=/; Domain=.akamai.com",
        ),
        ("set-cookie", "bm_sz=8C2...; Path=/"),
    ]);
    let outcome = classify(&facts(200, &h, "<html><body>real content</body></html>"));
    assert_eq!(outcome, Outcome::Present(Vendor::Akamai));
    assert!(outcome.got_through());
}

#[test]
fn test_cloudflare_managed_challenge() {
    // nowsecure.nl and the scrapingcourse challenge pages both answer this
    // way. curl_cffi does not pass it either: this tier wants JavaScript, and
    // no amount of fingerprint work reaches it.
    let h = hdrs(&[
        ("server", "cloudflare"),
        ("cf-mitigated", "challenge"),
        ("cf-ray", "a423d7b45e21b0e8-ATL"),
    ]);
    assert_eq!(
        classify(&facts(403, &h, "<html>Just a moment...</html>")),
        Outcome::Challenge(Vendor::Cloudflare)
    );
}

#[test]
fn test_cloudflare_waf_block_is_not_a_challenge() {
    // A plain WAF refusal carries no cf-mitigated header. Calling it a
    // challenge would suggest a JS tier that is not actually there.
    let h = hdrs(&[("server", "cloudflare"), ("cf-ray", "a423d7b45e21b0e8-ATL")]);
    let outcome = classify(&facts(403, &h, "<html>error 1020</html>"));
    assert!(
        matches!(outcome, Outcome::Blocked(_)),
        "expected a block, got {:?}",
        outcome
    );
    assert_ne!(outcome, Outcome::Challenge(Vendor::Cloudflare));
}

#[test]
fn test_cloudflare_bm_cookie_on_success_is_present() {
    // www.cloudflare.com sets __cf_bm on an ordinary 200.
    let h = hdrs(&[
        ("server", "cloudflare"),
        ("set-cookie", "__cf_bm=hNs8cwmP7rgTn3Us...; Path=/; Secure"),
    ]);
    assert_eq!(
        classify(&facts(200, &h, "<html>content</html>")),
        Outcome::Present(Vendor::Cloudflare)
    );
}

#[test]
fn test_akamai_sec_cpt_428_is_its_own_outcome() {
    // Fires after _abck has already passed, and answers 428 rather than 403.
    // Folding it into "blocked" would hide that we got further than usual.
    let h = hdrs(&[
        ("server", "AkamaiGHost"),
        ("set-cookie", "sec_cpt=abc123; Path=/"),
    ]);
    assert_eq!(
        classify(&facts(428, &h, r#"{"chlg_duration":30,"difficulty":5}"#)),
        Outcome::Challenge(Vendor::Akamai)
    );
}

// ── The false positives that caught the first pass ────────────────

#[test]
fn test_vendor_homepages_are_not_challenges() {
    // Every one of these scored CHALLENGE on the first attempt, purely
    // because a body grep found the vendor's own name in its marketing copy.
    // A vendor homepage is a terrible probe and the classifier must not be
    // fooled by one.
    for (host, body) in [
        (
            "datadome.co",
            "<html><h1>DataDome</h1><p>DataDome protects against bots. \
             Learn why DataDome is trusted.</p></html>",
        ),
        (
            "imperva.com",
            "<html><h1>Imperva</h1><p>Imperva Incapsula delivers \
             application security.</p></html>",
        ),
        (
            "kasada.io",
            "<html><h1>Kasada</h1><p>Kasada stops bots cold.</p></html>",
        ),
        (
            "humansecurity.com",
            "<html><p>HUMAN, formerly PerimeterX, defends against bots.</p></html>",
        ),
    ] {
        let h = hdrs(&[("content-type", "text/html")]);
        assert_eq!(
            classify(&facts(200, &h, body)),
            Outcome::Ok,
            "{} marketing copy was misread as a protection response",
            host
        );
    }
}

#[test]
fn test_reference_number_alone_is_not_akamai() {
    // Plenty of error pages carry a reference number. Without the edgesuite
    // host or the AkamaiGHost server header it means nothing.
    let h = hdrs(&[("server", "nginx")]);
    let outcome = classify(&facts(
        403,
        &h,
        "<html><h1>Access Denied</h1><p>Reference #12345</p></html>",
    ));
    assert_eq!(outcome, Outcome::Blocked(Vendor::Unknown));
}

// ── Ordinary responses ────────────────────────────────────────────

#[test]
fn test_plain_success_is_ok() {
    let h = hdrs(&[("server", "nginx"), ("content-type", "text/html")]);
    let outcome = classify(&facts(200, &h, "<html><body>hello</body></html>"));
    assert_eq!(outcome, Outcome::Ok);
    assert!(outcome.got_through());
}

#[test]
fn test_ordinary_404_is_not_a_block() {
    // A missing page is a real answer from the origin, and counting it as a
    // block would make an ordinary scan look like it was being refused.
    let h = hdrs(&[("server", "nginx")]);
    assert_eq!(classify(&facts(404, &h, "not found")), Outcome::Error);
}

#[test]
fn test_unidentified_refusal_reports_unknown_vendor() {
    // Better to say a block happened and admit we cannot name who did it than
    // to guess a vendor.
    let h = hdrs(&[("server", "nginx")]);
    let outcome = classify(&facts(403, &h, "forbidden"));
    assert_eq!(outcome, Outcome::Blocked(Vendor::Unknown));
    assert!(!outcome.got_through());
}

#[test]
fn test_product_cookie_with_refusal_still_counts_as_blocked() {
    // Setting a session cookie while refusing is still a refusal.
    let h = hdrs(&[
        ("server", "cloudflare"),
        ("set-cookie", "__cf_bm=xyz; Path=/"),
    ]);
    let outcome = classify(&facts(403, &h, "<html>denied</html>"));
    assert_eq!(outcome, Outcome::Blocked(Vendor::Cloudflare));
    assert!(!outcome.got_through());
}

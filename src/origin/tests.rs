//! Unit tests of `origin`.

use super::*;
use axum::http::HeaderValue;

fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(*name, HeaderValue::from_static(value));
    }
    map
}

#[test]
fn fetch_metadata_decides_when_present() {
    assert!(is_same_origin(&headers(&[("sec-fetch-site", "same-origin")])));
    for site in ["cross-site", "same-site", "none"] {
        let mut map = headers(&[("origin", "https://lanlord.example"), ("host", "lanlord.example")]);
        map.insert("sec-fetch-site", HeaderValue::from_static(site));
        assert!(!is_same_origin(&map), "{site}");
    }
}

#[test]
fn origin_must_match_the_host_without_fetch_metadata() {
    assert!(is_same_origin(&headers(&[
        ("origin", "https://lanlord.example"),
        ("host", "lanlord.example")
    ])));
    assert!(is_same_origin(&headers(&[
        ("origin", "http://127.0.0.1:8090"),
        ("host", "127.0.0.1:8090")
    ])));
    assert!(!is_same_origin(&headers(&[
        ("origin", "https://evil.example"),
        ("host", "lanlord.example")
    ])));
    assert!(
        !is_same_origin(&headers(&[("host", "lanlord.example")])),
        "no origin"
    );
    assert!(!is_same_origin(&headers(&[
        ("origin", "null"),
        ("host", "lanlord.example")
    ])));
}

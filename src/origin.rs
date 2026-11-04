//! Protection against cross-site requests: changes are only accepted from lanlord's own pages.

use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Checks that a request comes from a page of the same origin.
///
/// Browsers send `Sec-Fetch-Site` on every request; if it is there, it must be `same-origin`. Older browsers
/// only send `Origin`, which then must match the `Host` header.
#[must_use]
pub fn is_same_origin(headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return site == "same-origin";
    }
    let origin = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok());
    let host = headers.get(header::HOST).and_then(|value| value.to_str().ok());
    match (origin, host) {
        (Some(origin), Some(host)) => origin
            .split_once("://")
            .is_some_and(|(_, authority)| authority.eq_ignore_ascii_case(host)),
        _ => false,
    }
}

/// Rejects every request that changes something (not `GET` or `HEAD`) from another origin.
pub async fn same_origin_only(request: Request, next: Next) -> Response {
    let reads_only = matches!(*request.method(), Method::GET | Method::HEAD);
    if reads_only || is_same_origin(request.headers()) {
        next.run(request).await
    } else {
        (StatusCode::FORBIDDEN, "Cross-site request rejected").into_response()
    }
}

#[cfg(test)]
mod tests {
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
}

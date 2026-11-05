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
mod tests;

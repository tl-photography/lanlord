//! Unit tests of `auth`.

#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn passwords_are_hashed_and_verified() {
    let hash = hash_password("correct horse battery").unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(verify(&hash, "correct horse battery"));
    assert!(!verify(&hash, "wrong horse battery"));
    assert!(!verify("not a hash", "correct horse battery"));
    assert!(hash_password("too short").is_err());
}

#[test]
fn sessions_expire_and_can_be_removed() {
    let sessions = Sessions::default();
    let token = sessions.create().unwrap();
    assert_eq!(token.len(), 64);
    assert!(sessions.is_valid(&token));
    assert!(!sessions.is_valid("guess"));
    sessions.remove(&token);
    assert!(!sessions.is_valid(&token));
    sessions.tokens.lock().unwrap().insert(
        "old".to_owned(),
        Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
    );
    assert!(!sessions.is_valid("old"));
}

#[test]
fn failed_logins_slow_down_the_next_attempt() {
    let sessions = Sessions::default();
    assert_eq!(sessions.delay(), Duration::ZERO);
    sessions.record(false);
    assert_eq!(sessions.delay(), Duration::from_secs(1));
    sessions.record(false);
    assert_eq!(sessions.delay(), Duration::from_secs(2));
    for _ in 0..10 {
        sessions.record(false);
    }
    assert_eq!(sessions.delay(), MAX_DELAY);
    sessions.record(true);
    assert_eq!(sessions.delay(), Duration::ZERO);
}

#[test]
fn the_session_cookie_is_found_among_others() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("a=1; lanlord_session=abc; b=2"),
    );
    assert_eq!(cookie_token(&headers), Some("abc"));
    headers.insert(header::COOKIE, HeaderValue::from_static("lanlord_sessionx=abc"));
    assert_eq!(cookie_token(&headers), None);
}

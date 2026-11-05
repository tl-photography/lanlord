//! Login with one password: the Argon2id hash in `password.hash` in the data directory, sessions in memory.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use askama::Template;
use axum::Form;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

use crate::devices::{Error, write_private};
use crate::{AppState, server_error};

/// Name of the session cookie.
const COOKIE: &str = "lanlord_session";
/// How long a login lasts.
const SESSION_LIFETIME: Duration = Duration::from_hours(12);
/// Shortest password that is accepted.
pub const MIN_PASSWORD_LENGTH: usize = 12;
/// Longest wait after failed logins.
const MAX_DELAY: Duration = Duration::from_secs(30);

/// Paths that work without a login: the login itself, the health check and what the login page needs.
const PUBLIC_PATHS: [&str; 5] = ["/login", "/healthz", "/style.css", "/favicon.svg", "/logo.svg"];

/// Sessions and failed attempts, kept in memory; a restart logs everybody out.
#[derive(Default)]
pub(crate) struct Sessions {
    tokens: Mutex<HashMap<String, Instant>>,
    failures: Mutex<u32>,
}

/// Hashes a password with Argon2id and a random salt.
///
/// # Errors
///
/// If the password is shorter than [`MIN_PASSWORD_LENGTH`] characters or cannot be hashed.
pub fn hash_password(password: &str) -> Result<String, Error> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(Error::Invalid(format!(
            "the password needs at least {MIN_PASSWORD_LENGTH} characters"
        )));
    }
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|error| Error::Invalid(format!("cannot hash the password: {error}")))
}

/// Saves the hash of a new password, readable for the owner only.
///
/// # Errors
///
/// If the password is too short or the file cannot be written.
pub fn save_password(path: &Path, password: &str) -> Result<(), Error> {
    write_private(path, &format!("{}\n", hash_password(password)?))
}

fn verify(hash: &str, password: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), hash.trim())
        .is_ok()
}

fn new_token() -> Option<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).ok()?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    Some(token)
}

fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
}

impl Sessions {
    fn is_valid(&self, token: &str) -> bool {
        let Ok(mut tokens) = self.tokens.lock() else {
            return false;
        };
        let now = Instant::now();
        tokens.retain(|_, expires| *expires > now);
        tokens.contains_key(token)
    }

    fn create(&self) -> Option<String> {
        let token = new_token()?;
        self.tokens
            .lock()
            .ok()?
            .insert(token.clone(), Instant::now() + SESSION_LIFETIME);
        Some(token)
    }

    fn remove(&self, token: &str) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.remove(token);
        }
    }

    /// The wait before checking a login, doubling with each failed attempt in a row.
    fn delay(&self) -> Duration {
        let failures = self.failures.lock().map_or(0, |failures| *failures);
        if failures == 0 {
            return Duration::ZERO;
        }
        let seconds = 1u64.checked_shl(failures.min(6) - 1).unwrap_or(u64::MAX);
        Duration::from_secs(seconds).min(MAX_DELAY)
    }

    fn record(&self, success: bool) {
        if let Ok(mut failures) = self.failures.lock() {
            *failures = if success { 0 } else { failures.saturating_add(1) };
        }
    }
}

/// Lets requests through that have a valid session or go to a public path; sends the rest to the login.
pub async fn require_login(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let public = PUBLIC_PATHS.contains(&path);
    let logged_in = !state.inner.login_required
        || cookie_token(request.headers()).is_some_and(|token| state.inner.sessions.is_valid(token));
    if public || logged_in {
        next.run(request).await
    } else {
        Redirect::to("/login").into_response()
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: String,
    has_password: bool,
}

fn login_page(state: &AppState, status: StatusCode, error: String) -> Response {
    let page = LoginPage {
        error,
        has_password: state.inner.password_path.exists(),
    };
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(error) => server_error(&error),
    }
}

/// The login form.
pub async fn form(State(state): State<AppState>) -> Response {
    login_page(&state, StatusCode::OK, String::new())
}

/// Field of the login form.
#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
}

/// Checks the password and starts a session.
pub async fn login(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    tokio::time::sleep(state.inner.sessions.delay()).await;
    let Ok(hash) = tokio::fs::read_to_string(&state.inner.password_path).await else {
        return login_page(&state, StatusCode::FORBIDDEN, "No password is set yet".to_owned());
    };
    let password = form.password;
    let valid = tokio::task::spawn_blocking(move || verify(&hash, &password))
        .await
        .unwrap_or(false);
    state.inner.sessions.record(valid);
    if !valid {
        return login_page(&state, StatusCode::UNAUTHORIZED, "Wrong password".to_owned());
    }
    let Some(token) = state.inner.sessions.create() else {
        return server_error(&"cannot create a session");
    };
    let cookie = format!(
        "{COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        SESSION_LIFETIME.as_secs()
    );
    let mut response = Redirect::to("/").into_response();
    match HeaderValue::from_str(&cookie) {
        Ok(value) => {
            response.headers_mut().insert(header::SET_COOKIE, value);
            response
        }
        Err(error) => server_error(&error),
    }
}

/// Ends the session.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers) {
        state.inner.sessions.remove(token);
    }
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("lanlord_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"),
    );
    response
}

#[cfg(test)]
mod tests {
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
}

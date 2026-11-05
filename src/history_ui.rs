//! The history page: the newest entries of the change log.

use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};

use crate::history::{self, Entry};
use crate::{AppState, server_error};

/// How many entries the page shows.
const SHOWN: usize = 500;

#[derive(Template)]
#[template(path = "history.html")]
struct HistoryPage {
    nav: &'static str,
    entries: Vec<Entry>,
    shown: usize,
}

/// Shows the newest changes first.
pub async fn list(State(state): State<AppState>) -> Response {
    let page = HistoryPage {
        nav: "history",
        entries: history::read_newest(&state.inner.history_path, SHOWN),
        shown: SHOWN,
    };
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => server_error(&error),
    }
}

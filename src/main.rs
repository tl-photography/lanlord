//! Starts the web interface, or checks it with `lanlord healthcheck` (for the container health check).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
const DEFAULT_DATA: &str = "/data";

fn listen_address() -> String {
    std::env::var("LANLORD_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
}

/// Asks `/healthz` on the local port, without curl in the image.
fn healthcheck() -> ExitCode {
    let Ok(listen) = listen_address().parse::<SocketAddr>() else {
        return ExitCode::FAILURE;
    };
    let target = SocketAddr::from(([127, 0, 0, 1], listen.port()));
    let Ok(mut stream) = TcpStream::connect_timeout(&target, Duration::from_secs(3)) else {
        return ExitCode::FAILURE;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    if stream.write_all(b"GET /healthz HTTP/1.0\r\n\r\n").is_err() {
        return ExitCode::FAILURE;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    if response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200") {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Asks for a new password twice and saves its hash in the data directory.
fn set_password() -> ExitCode {
    let data_dir = std::env::var("LANLORD_DATA").unwrap_or_else(|_| DEFAULT_DATA.to_owned());
    let path = std::path::Path::new(&data_dir).join("password.hash");
    let first = rpassword::prompt_password("New password: ");
    let second = rpassword::prompt_password("Repeat it: ");
    let (Ok(first), Ok(second)) = (first, second) else {
        eprintln!("cannot read the password, run with docker exec -it");
        return ExitCode::FAILURE;
    };
    if first != second {
        eprintln!("the passwords differ");
        return ExitCode::FAILURE;
    }
    match lanlord::auth::save_password(&path, &first) {
        Ok(()) => {
            println!("password saved in {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// Waits for Ctrl-C or SIGTERM (sent by `docker stop`).
async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("healthcheck") => return healthcheck(),
        Some("set-password") => return set_password(),
        _ => {}
    }

    tracing_subscriber::fmt::init();
    let data_dir = std::env::var("LANLORD_DATA").unwrap_or_else(|_| DEFAULT_DATA.to_owned());
    let state = match lanlord::AppState::load(std::path::Path::new(&data_dir)) {
        Ok(state) => state,
        Err(error) => {
            tracing::error!("cannot start: {error}");
            return ExitCode::FAILURE;
        }
    };
    let listen = listen_address();
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("cannot listen on {listen}: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("listening on {listen}");
    if let Err(error) = axum::serve(listener, lanlord::app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("server stopped: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

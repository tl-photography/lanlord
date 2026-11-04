//! Starts the web interface, or checks it with `lanlord healthcheck` (for the container health check).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

const DEFAULT_LISTEN: &str = "0.0.0.0:8080";

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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return healthcheck();
    }

    tracing_subscriber::fmt::init();
    let listen = listen_address();
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("cannot listen on {listen}: {error}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!("listening on {listen}");
    if let Err(error) = axum::serve(listener, lanlord::app())
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("server stopped: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

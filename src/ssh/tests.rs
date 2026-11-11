//! Unit tests of `ssh`, against a small SSH server in the test.

use super::*;
use russh::keys::PrivateKey;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::server::{self, Auth, ChannelOpenHandle, Msg};
use russh::{Channel, ChannelId};
use tokio::net::TcpListener;

const USER: &str = "lanlord";
const PASSWORD: &str = "secret";

fn host_key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

fn fingerprint(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// Answers a few fixed commands.
#[derive(Default)]
struct Device {
    channels: Vec<Channel<Msg>>,
}

impl server::Handler for Device {
    type Error = russh::Error;

    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = Result<Auth, Self::Error>> + Send {
        std::future::ready(Ok(if user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        }))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.push(channel);
        reply.accept().await;
        Ok(())
    }

    fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(answer(channel, command, session))
    }
}

/// Answers one command: `report` prints, `fail` exits with 3, `flood` prints too much, anything else exits without
/// a status.
fn answer(channel: ChannelId, command: &[u8], session: &mut server::Session) -> Result<(), russh::Error> {
    session.channel_success(channel)?;
    match command {
        b"report" => {
            session.data(channel, &b"out\n"[..])?;
            session.extended_data(channel, STDERR, &b"err\n"[..])?;
            session.exit_status_request(channel, 0)?;
        }
        b"fail" => session.exit_status_request(channel, 3)?,
        b"flood" => {
            session.data(channel, vec![b'x'; MAX_OUTPUT_BYTES + 1])?;
            session.exit_status_request(channel, 0)?;
        }
        _ => {}
    }
    session.eof(channel)?;
    session.close(channel)
}

/// Starts the device on a free port and returns the port.
async fn device(key: PrivateKey) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::ZERO,
        ..server::Config::default()
    });
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, socket, Device::default()).await {
                    let _ = running.await;
                }
            });
        }
    });
    port
}

fn login<'a>(port: u16, password: &'a str, host_key: &'a str) -> Login<'a> {
    Login {
        host: "127.0.0.1",
        port,
        user: USER,
        password,
        host_key,
    }
}

#[tokio::test]
async fn runs_commands_and_returns_what_they_print() {
    let key = host_key(1);
    let pinned = fingerprint(&key);
    let session = Session::connect(&login(device(key).await, PASSWORD, &pinned))
        .await
        .unwrap();
    let cases: [(&str, Result<Output, &str>); 4] = [
        (
            "report",
            Ok(Output {
                status: 0,
                stdout: "out\n".to_owned(),
                stderr: "err\n".to_owned(),
            }),
        ),
        (
            "fail",
            Ok(Output {
                status: 3,
                ..Output::default()
            }),
        ),
        ("flood", Err("bytes of output")),
        ("silent", Err("without an exit status")),
    ];
    for (command, expected) in cases {
        match (session.run(command).await, expected) {
            (Ok(output), Ok(expected)) => assert_eq!(output, expected, "{command}"),
            (Err(error), Err(part)) => assert!(error.contains(part), "{command}: {error}"),
            (result, expected) => panic!("{command}: {result:?}, expected {expected:?}"),
        }
    }
    session.close().await;
}

#[tokio::test]
async fn refuses_a_wrong_host_key_or_password() {
    let key = host_key(1);
    let pinned = fingerprint(&key);
    let other = fingerprint(&host_key(2));
    let port = device(key).await;
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cases = [
        (
            "other host key",
            login(port, PASSWORD, &other),
            "not the pinned one",
        ),
        ("wrong password", login(port, "wrong", &pinned), "login refused"),
        ("nothing listening", login(closed, PASSWORD, &pinned), ""),
    ];
    for (case, login, part) in cases {
        match Session::connect(&login).await {
            Ok(_) => panic!("{case}: connected"),
            Err(error) => assert!(error.contains(part), "{case}: {error}"),
        }
    }
}

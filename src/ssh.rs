//! SSH for the plugins: one library behind one module, so every plugin that reaches a device over SSH logs in the
//! same way. lanlord logs in with a password and trusts only the pinned host key of the device.

use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};

/// Longest time to log in, and to run one command.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Largest output of one command that is read.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// The stream of the standard error output in an SSH channel.
const STDERR: u32 = 1;

/// Where and as whom to log in.
pub struct Login<'a> {
    /// Host name or address of the device.
    pub host: &'a str,
    /// SSH port, usually 22.
    pub port: u16,
    /// User name.
    pub user: &'a str,
    /// Password, read from its file in the data directory.
    pub password: &'a str,
    /// SHA-256 fingerprint of the host key as `ssh-keygen -l` prints it: `SHA256:` and base64.
    pub host_key: &'a str,
}

/// What a command returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit status, 0 for success.
    pub status: u32,
    /// Standard output.
    pub stdout: String,
    /// Standard error output.
    pub stderr: String,
}

/// Accepts only the pinned host key.
struct Pinned {
    host_key: String,
}

impl client::Handler for Pinned {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        std::future::ready(Ok(fingerprint == self.host_key))
    }
}

/// A logged-in connection to one device.
pub struct Session {
    handle: Handle<Pinned>,
}

impl Session {
    /// Connects and logs in.
    ///
    /// # Errors
    ///
    /// A message if the device cannot be reached, its host key is not the pinned one or the login is refused.
    pub async fn connect(login: &Login<'_>) -> Result<Self, String> {
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(TIMEOUT),
            ..client::Config::default()
        });
        let pinned = Pinned {
            host_key: login.host_key.trim().to_owned(),
        };
        let address = (login.host, login.port);
        let mut handle =
            within(client::connect(config, address, pinned))
                .await?
                .map_err(|error| match error {
                    russh::Error::UnknownKey => "the host key is not the pinned one".to_owned(),
                    error => error.to_string(),
                })?;
        let answer = within(handle.authenticate_password(login.user, login.password))
            .await?
            .map_err(|error| error.to_string())?;
        if !answer.success() {
            return Err("login refused".to_owned());
        }
        Ok(Self { handle })
    }

    /// Runs one command and waits for it to end.
    ///
    /// # Errors
    ///
    /// A message if the command cannot be started, its output is larger than [`MAX_OUTPUT_BYTES`] or it ends
    /// without an exit status.
    pub async fn run(&self, command: &str) -> Result<Output, String> {
        within(self.collect(command)).await?
    }

    async fn collect(&self, command: &str) -> Result<Output, String> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|error| error.to_string())?;
        channel
            .exec(true, command)
            .await
            .map_err(|error| error.to_string())?;
        let (mut stdout, mut stderr, mut status) = (Vec::new(), Vec::new(), None);
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: STDERR } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
            if stdout.len() + stderr.len() > MAX_OUTPUT_BYTES {
                return Err(format!("{command}: more than {MAX_OUTPUT_BYTES} bytes of output"));
            }
        }
        let status = status.ok_or_else(|| format!("{command}: ended without an exit status"))?;
        Ok(Output {
            status,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    /// Logs out.
    pub async fn close(self) {
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

/// Waits at most [`TIMEOUT`].
async fn within<T>(work: impl Future<Output = T>) -> Result<T, String> {
    tokio::time::timeout(TIMEOUT, work)
        .await
        .map_err(|_| format!("no answer within {} s", TIMEOUT.as_secs()))
}

#[cfg(test)]
mod tests;

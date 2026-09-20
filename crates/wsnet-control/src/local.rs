//! The local-only transport: a Windows named pipe, or a Unix socket.
//!
//! USAGE.md section 2 makes the management channel a Unix domain socket (a named
//! pipe on Windows) reachable by the current OS user, and DESIGN.md section 7.6
//! repeats that the CLI must never be given a public management API. This module
//! therefore has no code path that can open a network listener: a `SocketAddr`
//! never appears, and the endpoint type it accepts cannot hold one.
//!
//! The two halves here are the same on both platforms wherever the platform
//! allows it: exactly one implementation of the connection loop, and one client
//! request method, with only `bind`, `serve`, and `connect` differing.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::endpoint::{Endpoint, EndpointError};
use crate::error::ControlError;
use crate::frame::{decode_body, encode_body, read_frame, write_frame};
use crate::wire::{ErrorCode, Request, Response};
use crate::ControlHandler;

#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Win32 `ERROR_ACCESS_DENIED`.
///
/// Named here rather than pulled from a Windows binding crate: the workspace does
/// not depend on one, and these two codes are the entire surface this module needs.
#[cfg(windows)]
const ERROR_ACCESS_DENIED: i32 = 5;

/// Win32 `ERROR_PIPE_BUSY`: every instance of the pipe is connected.
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;

/// How long a client waits for a free pipe instance before giving up.
#[cfg(windows)]
const PIPE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Delay between pipe-instance retries.
#[cfg(windows)]
const PIPE_BUSY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(10);

/// A local control server.
///
/// One server serves one endpoint and any number of concurrent connections;
/// USAGE.md section 2 shows several independent CLI invocations (`status`,
/// `services list`, `forward add`) against one running daemon.
pub struct ControlServer {
    endpoint: Endpoint,
    #[cfg(windows)]
    listener: NamedPipeServer,
    #[cfg(unix)]
    listener: UnixListener,
}

impl ControlServer {
    /// Creates the control endpoint.
    ///
    /// On Windows the pipe is created as the first instance with remote clients
    /// refused. `FILE_FLAG_FIRST_PIPE_INSTANCE` is what keeps a second daemon from
    /// sharing the name: it turns the collision into `ERROR_ACCESS_DENIED`, which
    /// is reported here as [`EndpointError::InUse`] rather than as a permissions
    /// bug. The pipe inherits the process's default DACL, so only the creating user
    /// can open it.
    #[cfg(windows)]
    pub async fn bind(endpoint: &Endpoint) -> Result<Self, ControlError> {
        let listener = create_instance(endpoint, true)?;
        Ok(ControlServer {
            endpoint: endpoint.clone(),
            listener,
        })
    }

    /// Creates the control endpoint.
    ///
    /// An existing path is accepted only when it is a socket owned by this
    /// process and nobody is listening on it; anything else is refused instead of
    /// unlinked, so a daemon never destroys another user's file. The socket is
    /// created with mode 0600 as USAGE.md section 2 requires. Note the narrow
    /// window between `bind` and `set_permissions`, where the file exists with the
    /// process umask: it is closed by keeping the socket in a directory only this
    /// user can traverse (`$XDG_RUNTIME_DIR`), which is why that location is
    /// preferred over a shared temporary directory.
    #[cfg(unix)]
    pub async fn bind(endpoint: &Endpoint) -> Result<Self, ControlError> {
        use std::io::ErrorKind;
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        use std::path::PathBuf;

        let path = PathBuf::from(endpoint.os_name());
        prepare_directory(&path).await?;
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) => {
                if !metadata.file_type().is_socket() {
                    return Err(EndpointError::NotASocket(endpoint.to_string()).into());
                }
                if metadata.uid() != process_uid(&path).await? {
                    return Err(EndpointError::NotOwned {
                        path: endpoint.to_string(),
                        owner: metadata.uid(),
                    }
                    .into());
                }
                // A socket nobody answers on is left over from a crashed daemon;
                // a live one must keep its endpoint.
                if UnixStream::connect(&path).await.is_ok() {
                    return Err(EndpointError::InUse(endpoint.to_string()).into());
                }
                tokio::fs::remove_file(&path).await?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&path)?;
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
        Ok(ControlServer {
            endpoint: endpoint.clone(),
            listener,
        })
    }

    /// The endpoint this server is serving.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Serves connections until the endpoint itself fails.
    ///
    /// Each connection is handled by its own task, and a connection that ends
    /// badly (a client that dies mid-frame, for instance) only ends that task.
    #[cfg(windows)]
    pub async fn serve<H: ControlHandler>(self, handler: H) -> Result<(), ControlError> {
        let ControlServer {
            endpoint,
            mut listener,
        } = self;
        let handler = Arc::new(handler);
        loop {
            if let Err(error) = listener.connect().await {
                return Err(ControlError::Io(error));
            }
            // Publish the next instance before this one is handed to a task.
            // Without this a second CLI running at the same moment would see
            // ERROR_PIPE_BUSY, and USAGE.md section 2 expects several concurrent
            // `wsnet` invocations against one daemon.
            let connected = std::mem::replace(&mut listener, create_instance(&endpoint, false)?);
            let handler = Arc::clone(&handler);
            tokio::spawn(handle_connection(connected, handler));
        }
    }

    /// Serves connections until the endpoint itself fails.
    ///
    /// The socket's mode is the access control: only the owning user can connect.
    /// There is no peer-credential check here because the standard library
    /// exposes none portably, which is another reason the file mode is set
    /// strictly at bind time.
    #[cfg(unix)]
    pub async fn serve<H: ControlHandler>(self, handler: H) -> Result<(), ControlError> {
        let handler = Arc::new(handler);
        loop {
            let (connection, _peer) = self.listener.accept().await?;
            let handler = Arc::clone(&handler);
            tokio::spawn(handle_connection(connection, handler));
        }
    }
}

/// A client for the local control endpoint, used by the `wsnet` CLI.
pub struct ControlClient {
    endpoint: Endpoint,
    #[cfg(windows)]
    connection: NamedPipeClient,
    #[cfg(unix)]
    connection: UnixStream,
}

impl ControlClient {
    /// Opens the control endpoint.
    ///
    /// A pipe whose instances are all connected is retried briefly rather than
    /// failing immediately, because that state is transient: the daemon publishes
    /// the next instance as soon as it accepts. Every other failure is returned
    /// as-is, so "no daemon is running" stays distinguishable from "the daemon
    /// refused me".
    #[cfg(windows)]
    pub async fn connect(endpoint: &Endpoint) -> Result<Self, ControlError> {
        let name = endpoint.os_name();
        let deadline = std::time::Instant::now() + PIPE_BUSY_TIMEOUT;
        loop {
            match ClientOptions::new().open(&name) {
                Ok(connection) => {
                    return Ok(ControlClient {
                        endpoint: endpoint.clone(),
                        connection,
                    })
                }
                Err(error)
                    if error.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(PIPE_BUSY_RETRY_DELAY).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Opens the control endpoint.
    #[cfg(unix)]
    pub async fn connect(endpoint: &Endpoint) -> Result<Self, ControlError> {
        let connection = UnixStream::connect(endpoint.os_name()).await?;
        Ok(ControlClient {
            endpoint: endpoint.clone(),
            connection,
        })
    }

    /// The endpoint this client is connected to.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Sends one request and waits for its answer.
    ///
    /// The connection is kept open, so several requests can share one CLI run.
    /// A refusal by the daemon comes back as [`Response::Error`], not as an error
    /// from this method.
    pub async fn request(&mut self, request: Request) -> Result<Response, ControlError> {
        let body = encode_body(&request)?;
        write_frame(&mut self.connection, &body).await?;
        match read_frame(&mut self.connection).await? {
            Some(body) => Ok(decode_body(&body)?),
            // The daemon went away mid-exchange. Reporting a fabricated or empty
            // answer would hide a real failure from the CLI.
            None => Err(ControlError::Closed),
        }
    }
}

/// Handles requests on one connection until the peer stops talking.
async fn handle_connection<C, H>(mut connection: C, handler: Arc<H>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: ControlHandler,
{
    loop {
        let body = match read_frame(&mut connection).await {
            Ok(Some(body)) => body,
            // A CLI that closes between frames is an ordinary exit, not a fault.
            Ok(None) => return,
            Err(error) => {
                tracing::debug!(%error, "control connection ended while reading a frame");
                return;
            }
        };
        let response = match decode_body::<Request>(&body) {
            Ok(request) => handler.handle(request).await,
            Err(error) => {
                tracing::warn!(%error, "control client sent an undecodable request");
                // A body that did not decode leaves the stream unsynchronised, so
                // answer once and close instead of guessing where the next frame
                // begins.
                let response = Response::error(ErrorCode::BadRequest, error.to_string());
                let _ = write_response(&mut connection, &response).await;
                return;
            }
        };
        if let Err(error) = write_response(&mut connection, &response).await {
            tracing::debug!(%error, "control connection ended while writing a response");
            return;
        }
    }
}

/// Encodes and writes one answer.
async fn write_response<C>(connection: &mut C, response: &Response) -> Result<(), ControlError>
where
    C: AsyncWrite + Unpin,
{
    let body = encode_body(response)?;
    write_frame(connection, body.as_slice()).await
}

/// Creates one named-pipe instance.
#[cfg(windows)]
fn create_instance(endpoint: &Endpoint, first: bool) -> Result<NamedPipeServer, ControlError> {
    ServerOptions::new()
        .first_pipe_instance(first)
        // Remote clients are off by default in the Win32 API; asking explicitly
        // keeps USAGE.md section 2's "local only" true even if a future default
        // changes.
        .reject_remote_clients(true)
        .create(endpoint.os_name())
        .map_err(|error| {
            if first && error.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                EndpointError::InUse(endpoint.to_string()).into()
            } else {
                ControlError::Io(error)
            }
        })
}

/// Creates the socket's directory when it does not exist, as 0700.
///
/// An existing directory is left alone: it belongs to the operator (a shared
/// `/tmp`, for instance), and tightening someone else's directory would be worse
/// than the risk it removes.
#[cfg(unix)]
async fn prepare_directory(path: &std::path::Path) -> Result<(), ControlError> {
    use std::os::unix::fs::PermissionsExt;

    let Some(directory) = path.parent() else {
        return Ok(());
    };
    if directory.as_os_str().is_empty() {
        return Ok(());
    }
    if tokio::fs::symlink_metadata(directory).await.is_err() {
        tokio::fs::create_dir_all(directory).await?;
        tokio::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(())
}

/// This process's own user id, read back from a file it just created.
///
/// The standard library has no `geteuid`, and the workspace has no platform-sys
/// crate, so identity is taken from a probe file: whoever created it is us. The
/// probe lives beside the socket because binding a socket requires write access to
/// that directory anyway.
#[cfg(unix)]
async fn process_uid(socket: &std::path::Path) -> Result<u32, ControlError> {
    use std::os::unix::fs::MetadataExt;

    let directory = socket.parent().unwrap_or_else(|| std::path::Path::new("."));
    let probe = directory.join(format!(".wsnet-control-uid-{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&probe)?;
    let uid = file.metadata()?.uid();
    drop(file);
    let _ = std::fs::remove_file(&probe);
    Ok(uid)
}

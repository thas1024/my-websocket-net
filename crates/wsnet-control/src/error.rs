//! The crate's error type.

use crate::endpoint::EndpointError;
use crate::frame::FrameError;

/// Anything that can go wrong between the management CLI and the local daemon.
///
/// A refusal *by the daemon* is not an error here: it travels as
/// [`Response::Error`](crate::Response::Error) so the CLI can print the reason.
/// These variants mean the exchange itself failed.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// The local endpoint could not be bound, opened, read, or written.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The peer sent bytes that are not a legal control frame.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The endpoint name or the existing endpoint file is unusable.
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    /// The peer closed the connection before answering a request.
    #[error("control connection closed before a response arrived")]
    Closed,
}

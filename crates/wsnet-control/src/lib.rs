//! Local management IPC for a running wsnet node (USAGE.md sections 1, 2, 5, 7).
//!
//! USAGE.md section 1 gives the management CLI one job: control the running
//! `wsnet` through local IPC only. USAGE.md section 2 lists exactly what that CLI
//! may do (`wsnet status`, `wsnet services list`, `wsnet forward add|list|remove`)
//! and states the rule this crate exists to enforce: the CLI reaches the same
//! user's daemon over a Unix domain socket (a named pipe on Windows), the IPC
//! file defaults to read/write for the current OS user only, and the control
//! interface must never be bound to a public TCP port. DESIGN.md section 7.6
//! repeats it for the same reason.
//!
//! Those rules are structural here rather than documentary:
//!
//! * [`ControlServer::bind`] and [`ControlClient::connect`] accept an
//!   [`Endpoint`], which can only be built from a pipe name or a socket path.
//!   No constructor in this crate accepts a `SocketAddr`, so a public TCP
//!   management listener is not expressible through this API at all.
//! * [`default_endpoint`] derives a per-user name; on Unix the socket is created
//!   with mode 0600 inside a 0700 directory, and on Windows the pipe is created
//!   as a first instance with remote clients refused.
//! * Every frame is length-prefixed JSON bounded by [`MAX_CONTROL_FRAME`], and
//!   the bound is checked before a body buffer is allocated (DESIGN.md section
//!   4.1: bound the length before allocating or decoding).
//!
//! The daemon implements [`ControlHandler`]; the CLI uses
//! [`ControlClient::request`]. Both halves speak the same [`Request`] and
//! [`Response`] types, so the CLI and the static configuration cannot drift into
//! two different notions of a forward (USAGE.md section 12 asks for exactly that
//! agreement).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod endpoint;
mod error;
mod frame;
mod local;
mod wire;

use std::future::Future;
use std::pin::Pin;

pub use crate::endpoint::{default_endpoint, user_slug, Endpoint, EndpointError};
pub use crate::error::ControlError;
pub use crate::frame::{
    decode_body, decode_message, encode_body, encode_message, frame_length, read_frame,
    write_frame, FrameError, MAX_CONTROL_FRAME,
};
pub use crate::local::{ControlClient, ControlServer};
pub use crate::wire::{
    Counters, DaemonState, ErrorCode, ErrorResponse, ForwardInfo, ForwardListReport, ForwardSpec,
    ForwardState, HubSession, Request, Response, ServiceDescriptor, ServicesReport, ServiceState,
    SessionState, StatusReport,
};

/// A boxed, `Send` future, the shape every [`ControlHandler`] answer takes.
///
/// The alias is public because implementors must be able to name the return type
/// of [`ControlHandler::handle`] explicitly.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a node does with a management request.
///
/// The daemon owns the state a request touches (listeners, Hub sessions,
/// in-memory forwards), so the control layer only carries requests in and
/// answers out; it never inspects or caches node state itself. USAGE.md section 2
/// keeps dynamic forwards in memory only, which is why [`Request::ForwardAdd`] is
/// a request to a live process rather than a configuration write.
///
/// Implementations must be `Send + Sync + 'static` because one handler is shared
/// by every connection the daemon is serving at once.
pub trait ControlHandler: Send + Sync + 'static {
    /// Answers one request.
    ///
    /// The handler is always called with a well-formed [`Request`]: framing and
    /// JSON decoding failures are rejected by the server before this runs. A
    /// refusal must be reported as [`Response::error`], not by dropping the
    /// connection, so that the CLI can print the reason (USAGE.md section 7
    /// requires a local reason for a failed forward).
    fn handle(&self, request: Request) -> BoxFuture<'static, Response>;
}

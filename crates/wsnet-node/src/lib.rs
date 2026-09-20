#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! The wsnet node client: hub sessions, carriers, SOCKS5, and Local Forward.
//!
//! A node is built from a [`wsnet_config::ClientConfig`] and owns three things:
//!
//! * one [`HubSession`] per configured `[[servers]]` entry, each of which
//!   authenticates (DESIGN.md section 5.1), binds at least one carrier pair
//!   (section 5.3), registers its published services with `Hello`, and only then
//!   becomes `Ready` for business traffic (section 6.1);
//! * the inbound SOCKS5 listener of DESIGN.md section 9.3, whose handler maps a
//!   SOCKS request onto a hub `Open` and keeps a domain target unresolved so the
//!   exit resolves it (section 7.1);
//! * the `[[forwards]]` Local Forward listeners of section 7.6, driven by the
//!   same hub sessions.
//!
//! Two seams keep the interesting behaviour testable without a live Hub:
//!
//! * [`HubTransport`] is everything the node needs from one Hub's plumbing. The
//!   shipped [`HttpTransport`] speaks `POST /m` for authentication and uplink
//!   plus `GET /e` SSE for downlink; a test can supply its own.
//! * [`FlowOpener`] is what the local entry points call to obtain a remote
//!   stream, so the SOCKS5 and Local Forward layers never touch a session
//!   directly.
//!
//! The node never logs a pre-shared key or a session key. Secrets are loaded from
//! the configured `secret_file` (or injected through [`NodeOptions`]) and only
//! ever handed to the handshake.

use std::future::Future;
use std::pin::Pin;

pub mod carrier;
pub mod endpoint;
pub mod forward;
pub mod health;
pub mod http;
pub mod hub;
pub mod node;
pub mod select;
pub mod socks;
pub mod stream;

pub use carrier::{CarrierIo, CarrierKind};
pub use endpoint::{BoundSession, HubEndpoint, HubTransport, TransportFactory};
pub use forward::ForwardBridge;
pub use health::HealthTracker;
pub use http::{HttpTransport, HttpTransportFactory};
pub use hub::HubSession;
pub use node::{FlowOpener, Node, NodeError, NodeOptions, NodeRuntime};
pub use select::{select_hub, Candidate, HubChoice, ServiceDirectory};
pub use socks::{destination_for, SocksBridge};
pub use stream::SessionStream;

/// A boxed, `Send`, borrowing future.
///
/// The transport and opener seams are object safe through this alias; an
/// `async fn` in a trait would leave them unusable behind `dyn`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Current UTC time in whole seconds, which is what the handshake signs.
pub(crate) fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// A monotonic millisecond counter for the operation table.
pub(crate) fn now_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Locks a bookkeeping mutex, recovering the value if an unrelated task panicked.
pub(crate) fn lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

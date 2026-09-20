//! The SOCKS5 entry point (DESIGN.md sections 7.1 and 9.3).
//!
//! The handler is deliberately thin: it turns a SOCKS request into the strict
//! `Open` destination union and hands it to a [`FlowOpener`]. Two rules are
//! encoded here rather than left to the caller:
//!
//! * a `SocksTarget::Domain` stays a domain (section 7.1: "域名原样交给出口解析，
//!   客户端不为远端代理偷偷本地解析"), so the node never resolves a name it was
//!   asked to proxy;
//! * a failure is mapped onto an RFC 1928 reply code instead of a reason, so the
//!   local policy stays unobservable through the proxy's own error paths
//!   (section 9.1).

use std::sync::Arc;

use tracing::debug;

use wsnet_routing::{Destination, Proto};
use wsnet_socks::{
    BoxDuplex, BoxFuture as HandlerFuture, SocksError, SocksHandler, SocksRequest, SocksTarget,
    UdpControl,
};

use crate::node::{FlowOpener, NodeError};
use crate::select::HubChoice;

/// The `Open` destination a SOCKS5 request asks for.
///
/// A domain target is passed through verbatim: the exit resolves it, and the
/// local node must not, or `curl --socks5-hostname` would leak the application's
/// DNS lookups to the node's own resolver.
pub fn destination_for(request: &SocksRequest) -> Destination {
    let host = match &request.target {
        SocksTarget::Domain(name) => name.clone(),
        SocksTarget::Ip(ip) => ip.to_string(),
    };
    Destination::address(host, request.port)
}

/// Serves inbound SOCKS5 connections out of hub sessions.
pub struct SocksBridge {
    opener: Arc<dyn FlowOpener>,
}

impl SocksBridge {
    /// Builds a handler that opens flows through `opener`.
    pub fn new(opener: Arc<dyn FlowOpener>) -> Self {
        SocksBridge { opener }
    }
}

impl SocksHandler for SocksBridge {
    /// Opens one CONNECT through a hub session.
    ///
    /// The returned stream is only handed back after the remote `OpenResult` and
    /// `Ready` completed, which is what USAGE.md section 7 step 2 requires before
    /// any local byte is forwarded.
    fn connect(
        &self,
        request: SocksRequest,
    ) -> HandlerFuture<'static, Result<BoxDuplex, SocksError>> {
        let opener = Arc::clone(&self.opener);
        Box::pin(async move {
            let destination = destination_for(&request);
            match opener
                .open_flow(destination, Proto::Tcp, Vec::new(), HubChoice::Auto)
                .await
            {
                Ok(stream) => Ok(Box::new(stream) as BoxDuplex),
                Err(error) => {
                    // The reason stays local (section 9.1); the client only sees
                    // the RFC 1928 code.
                    debug!(error = %error, "socks5 connect failed");
                    Err(reply_for(&error))
                }
            }
        })
    }

    /// Answers a UDP ASSOCIATE with the RFC's "command not supported".
    ///
    /// This node does not carry datagrams yet, so claiming an association would
    /// be a success the node cannot back (DESIGN.md section 7.4 is not
    /// implemented here); the listener therefore also disables it up front.
    fn udp_associate(
        &self,
        mut control: UdpControl,
    ) -> HandlerFuture<'static, Result<(), SocksError>> {
        Box::pin(async move {
            while control.recv().await.is_some() {}
            Err(SocksError::UdpDisabled)
        })
    }
}

/// The client-facing reply code for a failed flow.
fn reply_for(error: &NodeError) -> SocksError {
    match error {
        NodeError::Offline(_) | NodeError::NoHub | NodeError::UnknownHub { .. } => {
            SocksError::ConnectRefused
        }
        NodeError::Denied(_) => SocksError::ConnectRefused,
        other => SocksError::Handler(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Section 7.1: a domain must reach the exit unresolved.
    #[test]
    fn a_domain_target_stays_a_domain() {
        let request = SocksRequest {
            target: SocksTarget::Domain("example.com".to_string()),
            port: 443,
        };
        assert_eq!(
            destination_for(&request),
            Destination::address("example.com", 443)
        );
    }

    /// An address the application already resolved is forwarded as an IP literal,
    /// because the original name cannot be recovered (USAGE.md section 3.2).
    #[test]
    fn an_ip_target_becomes_an_ip_destination() {
        let request = SocksRequest {
            target: SocksTarget::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
            port: 80,
        };
        assert_eq!(
            destination_for(&request),
            Destination::address("192.0.2.7", 80)
        );
    }

    /// Section 9.1: only a bounded, reason-free code reaches the client.
    #[test]
    fn failures_map_onto_reply_codes() {
        assert!(matches!(
            reply_for(&NodeError::Offline("publisher is not ready".into())),
            SocksError::ConnectRefused
        ));
        assert!(matches!(
            reply_for(&NodeError::Denied("acl".into())),
            SocksError::ConnectRefused
        ));
        assert!(matches!(
            reply_for(&NodeError::NotReady),
            SocksError::Handler(_)
        ));
    }
}

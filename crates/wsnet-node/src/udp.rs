//! The SOCKS5 UDP association, mapped onto tunnel routes (DESIGN.md section 7.4).
//!
//! Section 7.4 splits this in two, and the split is what shapes the code:
//!
//! * the *association* belongs to the SOCKS5 TCP control connection — it is
//!   registered when that connection opens and torn down when it closes;
//! * every distinct target inside one association gets its own **route**, which is
//!   a `Proto::Udp` stream on a hub session, and responses are only forwarded for a
//!   target the association actually mapped.
//!
//! So this module is a small mapping table with one task per route. The mapping
//! lives here rather than in `wsnet-forward`'s association table because the key is
//! different: a Local Forward keys on the local source tuple with a fixed
//! destination, while a SOCKS5 association is one client with up to
//! `MAX_UDP_TARGETS_PER_ASSOCIATION` destinations.
//!
//! Everything the SOCKS5 server can check on its own — source address, port
//! locking, `FRAG != 0`, header shape, payload size, queue TTL — is already checked
//! before a [`UdpDatagram`] arrives here, so this module never re-implements it.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, trace};

use wsnet_limits::MAX_UDP_TARGETS_PER_ASSOCIATION;
use wsnet_routing::Proto;
use wsnet_session::DatagramFields;
use wsnet_socks::{
    Counter, SocksRequest, SocksTarget, UdpControl, UdpDatagram, UdpReply, UdpReplySender,
};

use crate::node::FlowOpener;
use crate::select::HubChoice;
use crate::socks::destination_for;
use crate::stream::SessionStream;

/// How often idle routes are reaped.
///
/// Section 7.4 allows the mapping to be reclaimed when it goes idle, and the
/// reclamation is what keeps a long-lived association from accumulating sockets it
/// no longer uses. The sweep is coarse because the cost of holding a route for one
/// extra interval is a socket, while a per-datagram timer would be a timer per
/// target.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// One association's mapping from a client target to the route that serves it.
pub struct UdpAssociation {
    association_id: u64,
    opener: Arc<dyn FlowOpener>,
    replies: UdpReplySender,
    /// How long a route may go unused before it is reclaimed (section 7.4).
    idle_timeout: Duration,
    routes: BTreeMap<(String, u16), Route>,
}

/// One route: the channel its datagrams travel on, and when it was last used.
struct Route {
    datagrams: mpsc::UnboundedSender<UdpDatagram>,
    last_used: Instant,
}

impl UdpAssociation {
    /// Builds the mapping for one association.
    pub fn new(
        control: &UdpControl,
        opener: Arc<dyn FlowOpener>,
        idle_timeout: Duration,
    ) -> Self {
        UdpAssociation {
            association_id: control.association_id(),
            opener,
            replies: control.reply_sender(),
            idle_timeout,
            routes: BTreeMap::new(),
        }
    }

    /// Number of live routes, for tests and diagnostics.
    pub fn routes(&self) -> usize {
        self.routes.len()
    }

    /// Serves the association until its control connection ends.
    ///
    /// `recv` reports the end of the association by returning `None` (the server
    /// closes the datagram channel at the same moment it signals `closed`), so the
    /// loop needs no second borrow of the control to observe it.
    pub async fn run(mut self, mut control: UdpControl) {
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tokio::select! {
                datagram = control.recv() => match datagram {
                    Some(datagram) => self.dispatch(datagram),
                    None => break,
                },
                _ = sweep.tick() => self.reap(),
            }
        }
        // Dropping the mapping closes every route's channel, which is what ends the
        // route tasks and their tunnel streams (section 7.4: the association and its
        // targets are reclaimed together).
        debug!(association = self.association_id, "socks5: udp association ended");
    }

    /// Hands one client datagram to its target's route, opening it on first use.
    fn dispatch(&mut self, datagram: UdpDatagram) {
        let key = route_key(&datagram.target, datagram.port);
        if !self.routes.contains_key(&key) {
            // Section 7.4 caps the targets one association may track; the cap is a
            // refusal to grow, never a silent eviction of a live mapping.
            if self.routes.len() >= MAX_UDP_TARGETS_PER_ASSOCIATION {
                self.replies.count(Counter::UdpTargetLimitDropped);
                debug!(
                    association = self.association_id,
                    limit = MAX_UDP_TARGETS_PER_ASSOCIATION,
                    "socks5: udp association is at its target limit"
                );
                return;
            }
            match self.open_route(&datagram) {
                Some(route) => {
                    self.routes.insert(key.clone(), route);
                }
                None => return,
            }
        }
        if let Some(route) = self.routes.get_mut(&key) {
            route.last_used = Instant::now();
            if route.datagrams.send(datagram).is_err() {
                // The route task ended, which only happens when its tunnel stream
                // did; dropping the mapping lets the next datagram open a new one
                // rather than blackholing this target.
                self.routes.remove(&key);
            }
        }
    }

    /// Starts the task that serves one target, or reports why it could not.
    ///
    /// The route's `Open` happens *inside* the task, so a hub round trip never
    /// stalls the association loop: datagrams for this target simply queue until
    /// the route is ready, and section 7.4's queue budgets are what bound that wait.
    /// A target that cannot be opened costs only its own datagrams.
    fn open_route(&self, datagram: &UdpDatagram) -> Option<Route> {
        let (tx, rx) = mpsc::unbounded_channel();
        let opener = Arc::clone(&self.opener);
        let replies = self.replies.clone();
        let association_id = self.association_id;
        let target = datagram.target.clone();
        let port = datagram.port;
        // The destination union is built the same way a CONNECT builds it, so a
        // domain stays a domain and the exit resolves it (section 7.1).
        let destination = destination_for(&SocksRequest {
            target: target.clone(),
            port,
        });

        tokio::spawn(async move {
            let mut stream = match opener
                .open_flow(destination, Proto::Udp, Vec::new(), HubChoice::Auto)
                .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    debug!(%error, "socks5: cannot open a udp route");
                    return;
                }
            };
            serve_route(&mut stream, rx, &replies, association_id, target, port).await;
        });

        Some(Route {
            datagrams: tx,
            last_used: Instant::now(),
        })
    }

    /// Drops routes that have gone unused for longer than the idle timeout.
    fn reap(&mut self) {
        let idle = self.idle_timeout;
        self.routes
            .retain(|_, route| route.last_used.elapsed() < idle);
    }
}

/// The address of one client target, as the client wrote it.
///
/// A domain and the address it resolves to are deliberately *different* keys: the
/// client asked for a name, the exit resolved it, and collapsing the two here would
/// let one mapping serve a destination the client never named.
fn host_of(target: &SocksTarget) -> String {
    match target {
        SocksTarget::Domain(name) => name.clone(),
        SocksTarget::Ip(ip) => ip.to_string(),
    }
}

/// The mapping key for one client target.
fn route_key(target: &SocksTarget, port: u16) -> (String, u16) {
    (host_of(target), port)
}

/// Moves one route's datagrams in both directions until either half ends.///
/// The two halves are the channel the association feeds and the tunnel stream, so
/// this is where section 7.4's answers are matched: a datagram whose response
/// carries another association is dropped rather than delivered to this client.
async fn serve_route(
    stream: &mut SessionStream,
    mut datagrams: mpsc::UnboundedReceiver<UdpDatagram>,
    replies: &UdpReplySender,
    association_id: u64,
    target: SocksTarget,
    port: u16,
) {
    let stream_id = stream.stream_id();
    let sender = stream.datagram_sender();
    let mut next_id: u64 = 0;

    loop {
        tokio::select! {
            datagram = datagrams.recv() => {
                let Some(datagram) = datagram else {
                    // The association dropped this route.
                    return;
                };
                let now = Instant::now();
                if datagram.is_expired(now) {
                    // Section 7.4: a datagram that spent its whole queue budget is
                    // dropped, never sent late.
                    replies.count(Counter::UdpTtlExpiredDropped);
                    continue;
                }
                let Some(datagram_id) = next_id.checked_add(1) else {
                    // Section 4.1 forbids reusing a datagram id, so the route ends
                    // instead of wrapping.
                    debug!(stream_id, "socks5: a udp route exhausted its datagram ids");
                    return;
                };
                next_id = datagram_id;
                let fields = DatagramFields {
                    stream_id,
                    association_id,
                    datagram_id,
                    host: host_of(&datagram.target),
                    port: datagram.port,
                    remaining_ttl_ms: datagram
                        .remaining_ttl(now)
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                };
                if let Err(error) = sender.send(fields, &datagram.payload) {
                    debug!(stream_id, %error, "socks5: cannot send a datagram into the tunnel");
                    return;
                }
            }
            incoming = stream.recv_datagram() => match incoming {
                Some((fields, payload)) => {
                    // Section 7.4: only this association's responses may be
                    // delivered, and a response that cannot name its source address
                    // cannot be rewritten into a SOCKS5 UDP header at all.
                    if fields.association_id != association_id {
                        replies.count(Counter::UdpUnmappedReplyDropped);
                        continue;
                    }
                    let Ok(ip) = fields.host.parse::<IpAddr>() else {
                        replies.count(Counter::UdpUnexpectedSourceDropped);
                        trace!(stream_id, host = %fields.host, "socks5: dropping a reply with a non-address source");
                        continue;
                    };
                    let source = SocketAddr::new(ip, fields.port);
                    let reply = UdpReply::new(target.clone(), port, source, payload);
                    if replies.send(reply).await.is_err() {
                        return;
                    }
                }
                None => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A domain and the address it resolves to must not share a route: the client
    /// asked for a name, and collapsing the two would let one mapping serve a
    /// destination the client never named (section 7.4's per-target mapping).
    #[test]
    fn a_domain_and_an_address_are_different_routes() {
        let domain = SocksTarget::Domain("example.com".to_string());
        let address = SocksTarget::Ip("192.0.2.7".parse().expect("an ip literal"));
        assert_eq!(route_key(&domain, 53), ("example.com".to_string(), 53));
        assert_eq!(route_key(&address, 53), ("192.0.2.7".to_string(), 53));
        assert_ne!(route_key(&domain, 53), route_key(&address, 53));
        // The port is part of the key, so one host on two ports is two routes.
        assert_ne!(route_key(&address, 53), route_key(&address, 5353));
    }
}

//! Local Forward: the opener that binds a listener to a hub `Open`.
//!
//! `wsnet_forward::ForwardManager` owns the local listeners and the lifecycle
//! table of USAGE.md section 7; this module is the piece it calls once a local
//! connection has been accepted. Two of its behaviours come from the design:
//!
//! * the destination is opened as the strict union member it was configured as,
//!   so a `ServiceTarget` is resolved by the publishing node, never by the
//!   caller (DESIGN.md section 7.6);
//! * a lifecycle verdict is passed through as such —`OFFLINE` and `DENIED` move
//!   the forward's observable state and never turn into a direct connection
//!   (USAGE.md section 8).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use wsnet_forward::{
    BoxDuplex, BoxFuture as ForwardFuture, ForwardError, ForwardOpener, ForwardSpec,
};
use wsnet_routing::{Destination, Proto};

use crate::lock;
use crate::node::{FlowOpener, NodeError};
use crate::select::HubChoice;
use crate::BoxFuture;

/// Opens Local Forward flows through hub sessions.
pub struct ForwardBridge {
    opener: Arc<dyn FlowOpener>,
    /// Per-destination Hub pin, because `ForwardOpener::open` carries no Hub.
    ///
    /// The `hub` field of a `[[forwards]]` entry is validated by the forward
    /// manager but never handed to the opener, so the node records the mapping
    /// when it builds the listeners.
    hubs: Mutex<HashMap<Vec<u8>, HubChoice>>,
}

impl ForwardBridge {
    /// Builds an opener that uses automatic Hub selection for everything.
    pub fn new(opener: Arc<dyn FlowOpener>) -> Self {
        ForwardBridge {
            opener,
            hubs: Mutex::new(HashMap::new()),
        }
    }

    /// Pins `destination` to `hub`.
    pub fn with_hub(self, destination: &Destination, hub: HubChoice) -> Self {
        lock(&self.hubs).insert(destination.canonical_bytes(), hub);
        self
    }

    /// The configured Hub choice for a destination.
    pub fn hub_for(&self, destination: &Destination) -> HubChoice {
        lock(&self.hubs)
            .get(&destination.canonical_bytes())
            .cloned()
            .unwrap_or_default()
    }
}

impl ForwardOpener for ForwardBridge {
    fn open(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
    ) -> ForwardFuture<'static, Result<BoxDuplex, ForwardError>> {
        let opener = Arc::clone(&self.opener);
        let hub = self.hub_for(&destination);
        let open: BoxFuture<'static, Result<crate::SessionStream, NodeError>> =
            opener.open_flow(destination, proto, via, hub);
        Box::pin(async move {
            match open.await {
                Ok(stream) => Ok(Box::new(stream) as BoxDuplex),
                // The two stable verdicts of the USAGE.md section 7 table keep
                // their identity so the listener can fail new connections fast.
                Err(NodeError::Offline(reason)) => Err(ForwardError::Offline { reason }),
                Err(NodeError::Denied(reason)) => Err(ForwardError::Denied { reason }),
                Err(error) => Err(ForwardError::RemoteOpen {
                    reason: error.to_string(),
                }),
            }
        })
    }
}

/// The Local Forward specification for one `[[forwards]]` entry.
///
/// The field set mirrors USAGE.md section 5.1 exactly, so a static
/// `[[forwards]]` entry and a dynamic `forward add` produce the same internal
/// target.
pub fn spec_of(forward: &wsnet_config::ForwardConfig) -> Option<ForwardSpec> {
    let destination = forward.destination.clone()?;
    Some(
        ForwardSpec::new(
            forward.name.clone(),
            forward.listen.clone(),
            forward.proto,
            destination,
        )
        .with_hub(forward.hub.clone())
        .with_via(forward.via.clone())
        .with_allow_from(forward.allow_from.clone()),
    )
}

/// The Hub choice a `[[forwards]]` entry names.
pub fn choice_of(hub: &str) -> HubChoice {
    if hub == "auto" {
        HubChoice::Auto
    } else {
        HubChoice::Hub(hub.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionStream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Records what the node was asked to open, so the mapping can be observed.
    struct Recorder {
        destination: Mutex<Option<Destination>>,
        choice: Mutex<Option<HubChoice>>,
        calls: AtomicUsize,
    }

    impl Recorder {
        fn new() -> Arc<Self> {
            Arc::new(Recorder {
                destination: Mutex::new(None),
                choice: Mutex::new(None),
                calls: AtomicUsize::new(0),
            })
        }
    }

    impl FlowOpener for Recorder {
        fn open_flow(
            &self,
            destination: Destination,
            _proto: Proto,
            _via: Vec<String>,
            choice: HubChoice,
        ) -> BoxFuture<'static, Result<SessionStream, NodeError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *lock(&self.destination) = Some(destination);
            *lock(&self.choice) = Some(choice);
            Box::pin(async { Err(NodeError::Offline("no hub".to_string())) })
        }
    }

    /// Section 7.6: the configured `hub` and `via` reach the opener unchanged.
    #[tokio::test]
    async fn the_pinned_hub_reaches_the_opener() {
        let recorder = Recorder::new();
        let bridge = ForwardBridge::new(recorder.clone()).with_hub(
            &Destination::service("client-a", "web"),
            HubChoice::Hub("hub-b".to_string()),
        );
        let result = bridge
            .open(
                Destination::service("client-a", "web"),
                Proto::Tcp,
                vec!["client-b".to_string()],
            )
            .await;
        assert!(matches!(result, Err(ForwardError::Offline { .. })));
        assert_eq!(recorder.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            lock(&recorder.choice).clone(),
            Some(HubChoice::Hub("hub-b".to_string()))
        );
        assert_eq!(
            lock(&recorder.destination).clone(),
            Some(Destination::service("client-a", "web"))
        );
    }

    /// USAGE.md section 8: a missing Hub becomes `OFFLINE`, never a direct
    /// connection.
    #[test]
    fn an_unknown_hub_maps_to_remote_open() {
        let recorder = Recorder::new();
        let bridge = ForwardBridge::new(recorder);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime.block_on(async {
            bridge
                .open(
                    Destination::service("client-a", "web"),
                    Proto::Tcp,
                    Vec::new(),
                )
                .await
                .err()
                .unwrap()
        });
        assert!(matches!(error, ForwardError::Offline { .. }));
    }

    /// The spec built from a `[[forwards]]` entry keeps every documented field.
    #[test]
    fn a_forward_config_becomes_the_documented_spec() {
        let config = wsnet_config::ForwardConfig {
            name: "a-web".to_string(),
            listen: "127.0.0.1:18080".to_string(),
            proto: Proto::Tcp,
            hub: "hub-b".to_string(),
            via: vec!["client-b".to_string()],
            allow_from: Vec::new(),
            destination: Some(Destination::service("client-a", "web")),
        };
        let spec = spec_of(&config).unwrap();
        assert_eq!(spec.name, "a-web");
        assert_eq!(spec.listen, "127.0.0.1:18080");
        assert_eq!(spec.hub, "hub-b");
        assert_eq!(spec.via, vec!["client-b".to_string()]);
        assert_eq!(spec.destination, Destination::service("client-a", "web"));
        assert_eq!(choice_of("auto"), HubChoice::Auto);
        assert_eq!(choice_of("hub-b"), HubChoice::Hub("hub-b".to_string()));

        let mut missing = config;
        missing.destination = None;
        assert!(spec_of(&missing).is_none());
    }
}

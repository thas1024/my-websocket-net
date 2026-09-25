//! Local Forward lifecycle over real loopback sockets.
//!
//! These cover the guarantees USAGE.md section 7 and DESIGN.md section 7.6 make
//! about a listener, which the unit tests alone cannot show because they all
//! involve a real client, a real accept, and real timing:
//!
//! * `listen = "127.0.0.1:0"` yields a usable OS-assigned port (USAGE section 12).
//! * One `Open` per accepted connection, carrying the configured destination.
//! * **Nothing is forwarded before the remote open succeeds** (USAGE section 7
//!   step 1), and a failed open closes the local connection instead of inventing
//!   a response (step 4).
//! * Duplicate name and duplicate resolved listen are rejected atomically.
//! * A non-loopback listener requires an explicit allowlist, and the allowlist is
//!   enforced before the opener is consulted.
//! * `OFFLINE`/`DENIED` fast-fail rather than silently falling back to direct.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use wsnet_forward::{
    BoxDuplex, BoxFuture, ForwardError, ForwardManager, ForwardOpener, ForwardSpec, ForwardState,
};
use wsnet_routing::{Destination, Proto};

/// Deadline for one loopback exchange in these tests.
///
/// These are *hang detectors*, not latency assertions: every behavioural claim is
/// made by the bytes and the dial counts, so a generous deadline only distinguishes
/// "wrong" from "stuck". A short one instead made the suite flaky whenever the
/// machine was loaded, because a loopback `connect` that the kernel completes
/// immediately can still wait behind a starved scheduler.
const CONNECT_DEADLINE_SECS: u64 = 15;

/// How long to let a freshly spawned accept loop reach its first `poll`.
///
/// The listener is already bound when the manager returns (so a client is never
/// refused), but the task that accepts must be scheduled before a connection is
/// observed. Left generous for the same reason as the deadline above.
const SETTLE: Duration = Duration::from_millis(200);

/// How a stub opener should behave.
#[derive(Clone)]
enum Mode {
    /// Hand the caller one end of an in-memory duplex and echo whatever it says.
    Serve,
    /// Wait before serving, so a test can prove nothing is forwarded early.
    ServeAfter(Duration),
    /// Fail the remote open.
    Fail,
}

/// Records every `open` call so a test can assert on dial counts.
struct StubOpener {
    calls: AtomicUsize,
    seen: Mutex<Vec<(Destination, Proto, Vec<String>)>>,
    mode: Mode,
}

impl StubOpener {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(StubOpener {
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            mode,
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<(Destination, Proto, Vec<String>)> {
        self.seen.lock().expect("seen mutex").clone()
    }
}

impl ForwardOpener for StubOpener {
    fn open(
        &self,
        destination: Destination,
        proto: Proto,
        via: Vec<String>,
    ) -> BoxFuture<'static, Result<BoxDuplex, ForwardError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .expect("seen mutex")
            .push((destination, proto, via));
        let mode = self.mode.clone();

        Box::pin(async move {
            match mode {
                Mode::Fail => Err(ForwardError::RemoteOpen {
                    reason: "stub refused".into(),
                }),
                Mode::ServeAfter(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(echo_peer())
                }
                Mode::Serve => Ok(echo_peer()),
            }
        })
    }
}

/// Returns one end of an in-memory duplex that echoes everything written to it.
///
/// The returned end stands in for the remote target, so a test can prove that
/// bytes actually traverse the forward.
fn echo_peer() -> BoxDuplex {
    let (near, mut far) = tokio::io::duplex(8 * 1024);
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        loop {
            match far.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if far.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    Box::new(near)
}

/// Adds a forward and starts accepting on it.
async fn running_manager(
    spec: ForwardSpec,
    opener: Arc<StubOpener>,
) -> (Arc<ForwardManager>, watch::Sender<bool>, SocketAddr) {
    let mut manager = ForwardManager::new(opener);
    let handle = manager.add(spec).expect("forward should bind");
    let addr = handle.listen_addr();
    let manager = Arc::new(manager);
    let (tx, rx) = watch::channel(false);
    let runner = Arc::clone(&manager);
    tokio::spawn(async move { runner.run(rx).await });
    // Give the accept loop a moment to start before a client connects.
    tokio::time::sleep(SETTLE).await;
    (manager, tx, addr)
}

fn service_spec(name: &str) -> ForwardSpec {
    ForwardSpec::new(
        name,
        "127.0.0.1:0",
        Proto::Tcp,
        Destination::service("client-a", "web"),
    )
}

/// USAGE.md section 12: `listen = ":0"` reports the real port, and it is usable.
#[tokio::test]
async fn port_zero_reports_a_usable_address() {
    let opener = StubOpener::new(Mode::Serve);
    let (_manager, _tx, addr) = running_manager(service_spec("a-web"), Arc::clone(&opener)).await;

    assert_ne!(addr.port(), 0, "the OS-assigned port must be reported");
    let mut client = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed");

    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), client.read_exact(&mut echoed))
        .await
        .expect("read timed out")
        .expect("read failed");
    assert_eq!(&echoed, b"ping");
    assert_eq!(opener.calls(), 1, "exactly one Open per accepted connection");
}

/// The opener must receive the configured destination and chain, not a guess.
#[tokio::test]
async fn the_opener_receives_the_configured_destination() {
    let opener = StubOpener::new(Mode::Serve);
    let spec = ForwardSpec::new(
        "a-ssh",
        "127.0.0.1:0",
        Proto::Tcp,
        Destination::node_address("client-a", "127.0.0.1", 22),
    )
    .with_hub("hub-a")
    .with_via(vec!["client-b".into()]);

    let (_manager, _tx, addr) = running_manager(spec, Arc::clone(&opener)).await;
    let _client = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    let seen = opener.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].0,
        Destination::node_address("client-a", "127.0.0.1", 22)
    );
    assert_eq!(seen[0].1, Proto::Tcp);
    assert_eq!(seen[0].2, vec!["client-b".to_string()]);
}

/// USAGE.md section 7 step 1: the local socket is not read, and nothing is
/// forwarded, until the protected `Open` is confirmed.
#[tokio::test]
async fn nothing_is_forwarded_before_the_open_resolves() {
    let opener = StubOpener::new(Mode::ServeAfter(Duration::from_millis(400)));
    let (_manager, _tx, addr) = running_manager(service_spec("slow"), Arc::clone(&opener)).await;

    let mut client = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    client.write_all(b"early bytes").await.unwrap();

    // The opener has not resolved, so the echo peer cannot have answered.
    let mut buffer = [0u8; 16];
    let early = timeout(Duration::from_millis(120), client.read(&mut buffer)).await;
    assert!(
        early.is_err(),
        "bytes were forwarded before the remote open completed"
    );

    // Once it resolves, the same bytes traverse the forward.
    let n = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), client.read(&mut buffer))
        .await
        .expect("read timed out after the open resolved")
        .expect("read failed");
    assert_eq!(&buffer[..n], b"early bytes");
}

/// USAGE.md section 7 step 4: a failed open closes the local connection and the
/// reason stays local; no HTTP response or other fiction is produced.
#[tokio::test]
async fn a_failed_open_closes_the_local_connection() {
    let opener = StubOpener::new(Mode::Fail);
    let (manager, _tx, addr) = running_manager(service_spec("failing"), Arc::clone(&opener)).await;

    let mut client = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();

    let mut buffer = [0u8; 16];
    let read = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), client.read(&mut buffer))
        .await
        .expect("read timed out")
        .expect("read failed");
    assert_eq!(read, 0, "the client must see a clean close, not data");

    let handle = manager.handle("failing").expect("handle");
    assert_eq!(handle.open_attempts(), 1);
    assert!(
        handle.last_failure().is_some(),
        "the failure reason must be recorded locally"
    );
}

/// A duplicate name and a duplicate resolved address are refused, and a refused
/// add leaves the manager untouched.
#[tokio::test]
async fn duplicate_name_and_listen_are_rejected_atomically() {
    let opener = StubOpener::new(Mode::Serve);
    let mut manager = ForwardManager::new(Arc::clone(&opener) as Arc<dyn ForwardOpener>);

    let first = manager.add(service_spec("a-web")).unwrap();
    let first_addr = first.listen_addr();

    let duplicate_name = manager.add(service_spec("a-web"));
    assert!(matches!(
        duplicate_name,
        Err(ForwardError::DuplicateName { .. })
    ));

    let same_addr = ForwardSpec::new(
        "other",
        first_addr.to_string(),
        Proto::Tcp,
        Destination::service("client-a", "web"),
    );
    assert!(matches!(
        manager.add(same_addr),
        Err(ForwardError::DuplicateListen { .. })
    ));

    assert_eq!(manager.list().len(), 1, "a rejected add must change nothing");
}

/// USAGE.md section 12: a non-loopback listener without an allowlist is refused
/// at startup, before any socket is bound.
#[tokio::test]
async fn a_non_loopback_listener_requires_an_allowlist() {
    let opener = StubOpener::new(Mode::Serve);
    let mut manager = ForwardManager::new(Arc::clone(&opener) as Arc<dyn ForwardOpener>);

    let exposed = ForwardSpec::new(
        "exposed",
        "0.0.0.0:0",
        Proto::Tcp,
        Destination::service("client-a", "web"),
    );
    match manager.add(exposed) {
        Err(ForwardError::AllowListRequired { .. }) => {}
        other => panic!("expected AllowListRequired, got {other:?}"),
    }
    assert!(manager.list().is_empty());

    // With an explicit allowlist the same listener is accepted.
    let allowed = ForwardSpec::new(
        "allowed",
        "0.0.0.0:0",
        Proto::Tcp,
        Destination::service("client-a", "web"),
    )
    .with_allow_from(vec!["127.0.0.1/32".to_string()]);
    assert!(manager.add(allowed).is_ok());
}

/// A peer outside the allowlist is refused without consulting the opener, so a
/// misconfigured exposure cannot reach the target.
#[tokio::test]
async fn a_peer_outside_the_allowlist_never_reaches_the_opener() {
    let opener = StubOpener::new(Mode::Serve);
    let mut manager = ForwardManager::new(Arc::clone(&opener) as Arc<dyn ForwardOpener>);

    // An allowlist that deliberately excludes the loopback peer used below.
    let spec = ForwardSpec::new(
        "restricted",
        "0.0.0.0:0",
        Proto::Tcp,
        Destination::service("client-a", "web"),
    )
    .with_allow_from(vec!["10.0.0.0/8".to_string()]);
    let handle = manager.add(spec).unwrap();
    let addr = handle.listen_addr();

    let manager = Arc::new(manager);
    let (tx, rx) = watch::channel(false);
    let runner = Arc::clone(&manager);
    tokio::spawn(async move { runner.run(rx).await });
    tokio::time::sleep(SETTLE).await;

    // The listener is bound to 0.0.0.0, so connect through loopback.
    let dial = SocketAddr::from(([127, 0, 0, 1], addr.port()));
    let mut client = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(dial))
        .await
        .expect("connect timed out")
        .expect("connect failed");
    let mut buffer = [0u8; 4];
    let read = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), client.read(&mut buffer))
        .await
        .expect("read timed out")
        .expect("read failed");
    assert_eq!(read, 0, "a refused peer must be closed");
    assert_eq!(
        opener.calls(),
        0,
        "the opener must not run for a refused peer"
    );
    let _ = tx;
}

/// `OFFLINE` and `DENIED` must fast-fail. The design is explicit that a denied or
/// offline forward must not silently fall back to a direct connection.
#[tokio::test]
async fn offline_and_denied_fast_fail_without_dialling() {
    for (state, label) in [
        (ForwardState::Offline, "offline"),
        (ForwardState::Denied, "denied"),
    ] {
        let opener = StubOpener::new(Mode::Serve);
        let (manager, _tx, addr) =
            running_manager(service_spec(label), Arc::clone(&opener)).await;
        manager.set_state(label, state).unwrap();

        let mut client = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr))
            .await
            .unwrap()
            .unwrap();
        let mut buffer = [0u8; 4];
        let read = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), client.read(&mut buffer))
            .await
            .expect("read timed out")
            .expect("read failed");
        assert_eq!(read, 0, "{label} must close the local connection");
        assert_eq!(opener.calls(), 0, "{label} must not dial");
        assert_eq!(manager.state(label), Some(state));
    }
}

/// Recovery is for *new* connections only: while a forward is offline nothing is
/// dialled, and once it is ready again a fresh connection works.
#[tokio::test]
async fn recovery_applies_to_new_connections_only() {
    let opener = StubOpener::new(Mode::Serve);
    let (manager, _tx, addr) = running_manager(service_spec("recover"), Arc::clone(&opener)).await;

    manager.set_state("recover", ForwardState::Offline).unwrap();
    let mut refused = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    let mut buffer = [0u8; 4];
    assert_eq!(refused.read(&mut buffer).await.unwrap(), 0);
    assert_eq!(opener.calls(), 0);

    manager.set_state("recover", ForwardState::Ready).unwrap();
    let mut client = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    client.write_all(b"hi").await.unwrap();
    let mut echoed = [0u8; 2];
    timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), client.read_exact(&mut echoed))
        .await
        .expect("read timed out")
        .expect("read failed");
    assert_eq!(&echoed, b"hi");
    assert_eq!(opener.calls(), 1);
}

/// Removing a forward stops new connections, and the name becomes reusable.
#[tokio::test]
async fn remove_stops_accepting_and_frees_the_name() {
    let opener = StubOpener::new(Mode::Serve);

    // A live manager: removal must stop the listener from dialling.
    let (manager, _tx, addr) = running_manager(service_spec("gone"), Arc::clone(&opener)).await;
    assert!(manager.remove("gone").is_ok());
    assert!(manager.listen_addr("gone").is_none());

    // A connect to the old address is either refused outright or accepted and
    // immediately closed; either way the opener must not run.
    if let Ok(Ok(mut client)) = timeout(Duration::from_secs(CONNECT_DEADLINE_SECS), TcpStream::connect(addr)).await {
        let mut buffer = [0u8; 4];
        let _ = timeout(Duration::from_millis(300), client.read(&mut buffer)).await;
    }
    assert_eq!(opener.calls(), 0, "a removed forward must not dial");

    // Name reuse and the double-remove error are checked on a manager we own, so
    // that `add`/`remove` can take `&mut self`.
    let mut owned = ForwardManager::new(Arc::clone(&opener) as Arc<dyn ForwardOpener>);
    assert!(owned.add(service_spec("gone")).is_ok());
    assert!(owned.remove("gone").is_ok());
    assert!(matches!(
        owned.remove("gone"),
        Err(ForwardError::UnknownForward { .. })
    ));
    // And the name can be taken again after both removals.
    assert!(owned.add(service_spec("gone")).is_ok());
}

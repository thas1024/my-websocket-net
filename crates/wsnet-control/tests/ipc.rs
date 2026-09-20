//! End-to-end tests for the local management channel.
//!
//! Everything here goes through the real platform transport (a named pipe on
//! Windows, a Unix socket elsewhere), because the transport is where the
//! local-only policy is enforced and a mock would not exercise it. Every await is
//! wrapped in a timeout so a bug fails the suite instead of hanging it.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use wsnet_control::{
    decode_body, decode_message, default_endpoint, encode_body, encode_message, frame_length,
    read_frame, user_slug, BoxFuture, ControlClient, ControlError, ControlHandler, ControlServer,
    Counters, DaemonState, Endpoint, ErrorCode, ForwardInfo, ForwardListReport, ForwardSpec,
    ForwardState, FrameError, HubSession, Request, Response, ServiceDescriptor, ServicesReport,
    ServiceState, SessionState, StatusReport, MAX_CONTROL_FRAME,
};
use wsnet_routing::{Destination, Proto};

/// Long enough for a loaded CI machine, short enough to fail rather than hang.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs a control exchange under a timeout.
async fn with_timeout<F>(future: F) -> F::Output
where
    F: Future,
{
    tokio::time::timeout(EXCHANGE_TIMEOUT, future)
        .await
        .expect("the control exchange must finish inside the timeout")
}

/// A unique endpoint per test, so tests can run in parallel.
fn test_endpoint(label: &str) -> Endpoint {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    let name = format!("wsnet-control-test-{}-{label}-{unique}", std::process::id());
    Endpoint::new(platform_endpoint(&name)).expect("the test endpoint name must be valid")
}

/// Named pipes use a bare name; Unix sockets live in a private temp directory.
#[cfg(windows)]
fn platform_endpoint(name: &str) -> String {
    name.to_string()
}

/// Named pipes use a bare name; Unix sockets live in a private temp directory.
#[cfg(unix)]
fn platform_endpoint(name: &str) -> String {
    let directory = std::env::temp_dir().join(format!("wsnet-control-tests-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("the test temp directory must be creatable");
    directory
        .join(format!("{name}.sock"))
        .to_string_lossy()
        .into_owned()
}

/// The raw platform connection, used to send frames a well-behaved client never
/// would.
#[cfg(windows)]
type RawConnection = tokio::net::windows::named_pipe::NamedPipeClient;
/// The raw platform connection, used to send frames a well-behaved client never
/// would.
#[cfg(unix)]
type RawConnection = tokio::net::UnixStream;

/// Opens a raw connection to an endpoint, bypassing [`ControlClient`].
async fn raw_connect(endpoint: &Endpoint) -> RawConnection {
    #[cfg(windows)]
    {
        tokio::net::windows::named_pipe::ClientOptions::new()
            .open(endpoint.os_name())
            .expect("the raw pipe client must open")
    }
    #[cfg(unix)]
    {
        tokio::net::UnixStream::connect(endpoint.os_name())
            .await
            .expect("the raw socket client must open")
    }
}

fn spec(name: &str) -> ForwardSpec {
    ForwardSpec {
        name: name.into(),
        listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        proto: Proto::Tcp,
        hub: "auto".into(),
        via: Vec::new(),
        destination: Destination::service("client-a", "web"),
    }
}

fn status_report() -> StatusReport {
    StatusReport {
        daemon: DaemonState::Running,
        node_id: "client-a".into(),
        uptime_secs: 42,
        hubs: vec![HubSession {
            hub_id: "hub-a".into(),
            state: SessionState::Ready,
        }],
        counters: Counters {
            bytes_sent: 1,
            bytes_received: 2,
            streams_open: 3,
            forwards_active: 0,
            services_published: 0,
            control_requests: 0,
        },
    }
}

/// A handler that answers every request successfully.
struct Stub;

impl ControlHandler for Stub {
    fn handle(&self, request: Request) -> BoxFuture<'static, Response> {
        Box::pin(async move {
            match request {
                Request::Status => Response::Status(status_report()),
                Request::ServicesList { .. } => Response::Services(ServicesReport {
                    services: Vec::new(),
                }),
                Request::ForwardList => Response::ForwardList(ForwardListReport {
                    forwards: Vec::new(),
                }),
                Request::ForwardAdd { spec } => Response::ForwardAdded {
                    listen: spec.listen,
                    name: spec.name,
                },
                Request::ForwardRemove { name } => Response::ForwardRemoved { name },
            }
        })
    }
}

/// A handler that refuses everything, as the daemon does for an unknown forward.
struct Refuser;

impl ControlHandler for Refuser {
    fn handle(&self, request: Request) -> BoxFuture<'static, Response> {
        Box::pin(async move {
            let name = match request {
                Request::ForwardRemove { name } => name,
                _ => "unexpected".into(),
            };
            Response::error(ErrorCode::NotFound, format!("no forward named {name}"))
        })
    }
}

/// A handler that only answers once two requests are in flight at the same time.
///
/// This is what makes the concurrency test meaningful: a server that handled
/// connections one after another would never release either request and the test
/// would time out.
struct Rendezvous {
    barrier: Arc<tokio::sync::Barrier>,
}

impl ControlHandler for Rendezvous {
    fn handle(&self, _request: Request) -> BoxFuture<'static, Response> {
        let barrier = Arc::clone(&self.barrier);
        Box::pin(async move {
            barrier.wait().await;
            Response::ForwardList(ForwardListReport {
                forwards: Vec::new(),
            })
        })
    }
}

#[tokio::test]
async fn a_status_request_round_trips_over_the_real_transport() {
    let endpoint = test_endpoint("status");
    let server = ControlServer::bind(&endpoint).await.unwrap();
    let serving = tokio::spawn(server.serve(Stub));

    let mut client = with_timeout(ControlClient::connect(&endpoint))
        .await
        .unwrap();
    let response = with_timeout(client.request(Request::Status)).await.unwrap();
    assert_eq!(response, Response::Status(status_report()));

    // The connection stays usable for a second command in the same CLI run.
    let again = with_timeout(client.request(Request::ForwardList)).await.unwrap();
    assert_eq!(
        again,
        Response::ForwardList(ForwardListReport {
            forwards: Vec::new()
        })
    );

    serving.abort();
}

#[tokio::test]
async fn every_request_variant_round_trips_over_the_transport() {
    let endpoint = test_endpoint("variants");
    let server = ControlServer::bind(&endpoint).await.unwrap();
    let serving = tokio::spawn(server.serve(Stub));

    let mut client = with_timeout(ControlClient::connect(&endpoint))
        .await
        .unwrap();
    let requests = vec![
        Request::Status,
        Request::ServicesList {
            hub: Some("hub-a".into()),
            node: None,
        },
        Request::ServicesList {
            hub: None,
            node: Some("client-a".into()),
        },
        Request::ForwardList,
        Request::ForwardAdd { spec: spec("a-web") },
        Request::ForwardRemove {
            name: "a-web".into(),
        },
    ];
    for request in requests {
        let response = with_timeout(client.request(request.clone()))
            .await
            .unwrap_or_else(|error| panic!("{request:?} failed: {error}"));
        assert!(!response.is_error(), "{request:?} was refused: {response:?}");
    }

    serving.abort();
}

#[tokio::test]
async fn two_clients_are_served_concurrently() {
    let endpoint = test_endpoint("concurrent");
    let server = ControlServer::bind(&endpoint).await.unwrap();
    let serving = tokio::spawn(server.serve(Rendezvous {
        barrier: Arc::new(tokio::sync::Barrier::new(2)),
    }));

    let mut first = with_timeout(ControlClient::connect(&endpoint))
        .await
        .unwrap();
    let mut second = with_timeout(ControlClient::connect(&endpoint))
        .await
        .unwrap();
    let (first_response, second_response) = with_timeout(async {
        tokio::join!(
            first.request(Request::Status),
            second.request(Request::Status),
        )
    })
    .await;

    assert_eq!(
        first_response.unwrap(),
        Response::ForwardList(ForwardListReport {
            forwards: Vec::new()
        })
    );
    assert_eq!(
        second_response.unwrap(),
        Response::ForwardList(ForwardListReport {
            forwards: Vec::new()
        })
    );

    serving.abort();
}

#[tokio::test]
async fn a_handler_refusal_reaches_the_client() {
    let endpoint = test_endpoint("refusal");
    let server = ControlServer::bind(&endpoint).await.unwrap();
    let serving = tokio::spawn(server.serve(Refuser));

    let mut client = with_timeout(ControlClient::connect(&endpoint))
        .await
        .unwrap();
    let response = with_timeout(client.request(Request::ForwardRemove {
        name: "a-web".into(),
    }))
    .await
    .unwrap();
    match response {
        Response::Error(error) => {
            assert_eq!(error.code, ErrorCode::NotFound);
            assert!(error.message.contains("a-web"));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    // A refusal is an answer, not a broken connection.
    let after = with_timeout(client.request(Request::ForwardRemove {
        name: "b-web".into(),
    }))
    .await
    .unwrap();
    assert!(after.is_error());

    serving.abort();
}

#[tokio::test]
async fn a_client_that_dies_mid_frame_does_not_stop_the_server() {
    let endpoint = test_endpoint("mid-frame");
    let server = ControlServer::bind(&endpoint).await.unwrap();
    let serving = tokio::spawn(server.serve(Stub));

    let body = encode_body(&Request::Status).unwrap();
    let mut dying = raw_connect(&endpoint).await;
    dying
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    dying.write_all(&body[..body.len() / 2]).await.unwrap();
    dying.flush().await.unwrap();
    drop(dying);

    let mut client = with_timeout(ControlClient::connect(&endpoint))
        .await
        .unwrap();
    let response = with_timeout(client.request(Request::ForwardList))
        .await
        .unwrap();
    assert_eq!(
        response,
        Response::ForwardList(ForwardListReport {
            forwards: Vec::new()
        })
    );

    serving.abort();
}

#[tokio::test]
async fn a_client_that_declares_a_hostile_frame_does_not_stop_the_server() {
    let endpoint = test_endpoint("hostile-frame");
    let server = ControlServer::bind(&endpoint).await.unwrap();
    let serving = tokio::spawn(server.serve(Stub));

    let mut hostile = raw_connect(&endpoint).await;
    hostile.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    hostile.flush().await.unwrap();
    drop(hostile);

    let mut client = with_timeout(ControlClient::connect(&endpoint))
        .await
        .unwrap();
    assert!(with_timeout(client.request(Request::Status)).await.is_ok());

    serving.abort();
}

#[tokio::test]
async fn an_undecodable_request_is_answered_and_then_closed() {
    let endpoint = test_endpoint("garbage");
    let server = ControlServer::bind(&endpoint).await.unwrap();
    let serving = tokio::spawn(server.serve(Stub));

    let mut garbage = raw_connect(&endpoint).await;
    let body = b"{\"request\":\"launch_missiles\"}".to_vec();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    garbage.write_all(&frame).await.unwrap();
    garbage.flush().await.unwrap();

    let answer = with_timeout(read_frame(&mut garbage)).await.unwrap();
    let answer = answer.expect("the server must answer a bad request before closing");
    match decode_body::<Response>(&answer).unwrap() {
        Response::Error(error) => assert_eq!(error.code, ErrorCode::BadRequest),
        other => panic!("expected a bad-request refusal, got {other:?}"),
    }
    // The stream is unsynchronised after a bad body, so the server closes it.
    assert!(with_timeout(read_frame(&mut garbage)).await.unwrap().is_none());

    serving.abort();
}

#[tokio::test]
async fn a_second_server_cannot_share_the_endpoint() {
    let endpoint = test_endpoint("single-daemon");
    let first = ControlServer::bind(&endpoint).await.unwrap();
    let second = ControlServer::bind(&endpoint).await;
    assert!(
        matches!(second, Err(ControlError::Endpoint(_))),
        "a second daemon must not be able to serve the same endpoint"
    );
    assert_eq!(first.endpoint(), &endpoint);
    drop(first);
}

#[test]
fn default_endpoint_is_stable_and_names_the_user() {
    let first = default_endpoint().expect("the environment must identify the current user");
    let second = default_endpoint().expect("the environment must identify the current user");
    assert_eq!(first, second);

    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .expect("the environment must identify the current user");
    assert!(
        first.as_str().contains(&user_slug(&user)),
        "`{first}` does not carry the user identity"
    );
    assert!(!first.as_str().is_empty());

    // Windowed rendering must still be a local endpoint, never an address.
    assert!(first.os_name().contains(&user_slug(&user)));
}

#[tokio::test]
async fn an_oversized_length_prefix_is_refused_before_allocating() {
    let declared = u32::MAX.to_be_bytes();
    assert_eq!(
        frame_length(declared).unwrap_err(),
        FrameError::TooLarge {
            actual: u32::MAX as usize,
            limit: MAX_CONTROL_FRAME
        }
    );
    // Nothing but the prefix was sent, so a reader that allocated the declared
    // body would be asking for 4 GiB here.
    let mut hostile: &[u8] = &declared;
    assert!(matches!(
        read_frame(&mut hostile).await.unwrap_err(),
        ControlError::Frame(FrameError::TooLarge { .. })
    ));
}

#[tokio::test]
async fn a_truncated_frame_is_refused() {
    let frame = encode_message(&Request::Status).unwrap();
    let mut short: &[u8] = &frame[..frame.len() - 1];
    assert!(matches!(
        read_frame(&mut short).await.unwrap_err(),
        ControlError::Frame(FrameError::Truncated { .. })
    ));
    assert_eq!(
        decode_message::<Request>(&frame[..3]).unwrap_err(),
        FrameError::Truncated { field: "length" }
    );
}

#[tokio::test]
async fn trailing_bytes_are_refused() {
    let mut frame = encode_message(&Request::Status).unwrap();
    frame.push(b'x');
    assert_eq!(
        decode_message::<Request>(&frame).unwrap_err(),
        FrameError::TrailingData(1)
    );
}

#[tokio::test]
async fn invalid_utf8_is_refused() {
    let body = [0xf0u8, 0x28, 0x8c, 0x28];
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    assert_eq!(
        decode_message::<Request>(&frame).unwrap_err(),
        FrameError::InvalidUtf8
    );
}

#[tokio::test]
async fn empty_input_is_refused_without_panicking() {
    assert!(matches!(
        decode_message::<Request>(&[]).unwrap_err(),
        FrameError::Truncated { .. }
    ));
    assert_eq!(
        decode_body::<Request>(&[]).unwrap_err(),
        FrameError::Empty
    );
    let mut empty: &[u8] = &[];
    assert!(read_frame(&mut empty).await.unwrap().is_none());
    assert_eq!(
        frame_length(0u32.to_be_bytes()).unwrap_err(),
        FrameError::Empty
    );
}

#[tokio::test]
async fn garbage_bodies_are_refused_without_panicking() {
    for body in [
        &b""[..],
        &b"\xff\xfe"[..],
        &b"{"[..],
        &b"[]"[..],
        &b"null"[..],
        &[0u8; 64][..],
    ] {
        assert!(decode_body::<Request>(body).is_err(), "{body:?} was accepted");
    }
    // A body larger than the bound is refused even though it is valid JSON.
    let oversized = format!("\"{}\"", "x".repeat(MAX_CONTROL_FRAME));
    assert!(matches!(
        decode_body::<Request>(oversized.as_bytes()).unwrap_err(),
        FrameError::TooLarge { .. }
    ));
}

#[test]
fn every_request_variant_round_trips_through_the_codec() {
    for request in [
        Request::Status,
        Request::ServicesList {
            hub: None,
            node: None,
        },
        Request::ServicesList {
            hub: Some("hub-a".into()),
            node: Some("client-a".into()),
        },
        Request::ForwardList,
        Request::ForwardAdd { spec: spec("a-web") },
        Request::ForwardRemove {
            name: "a-web".into(),
        },
    ] {
        let frame = encode_message(&request).unwrap();
        assert_eq!(decode_message::<Request>(&frame).unwrap(), request);
    }
}

#[test]
fn every_response_variant_round_trips_through_the_codec() {
    for response in [
        Response::Status(status_report()),
        Response::Services(ServicesReport {
            services: vec![ServiceDescriptor {
                hub: "hub-a".into(),
                node: "client-a".into(),
                name: "web".into(),
                proto: Proto::Tcp,
                revision: 3,
                state: ServiceState::Ready,
            }],
        }),
        Response::ForwardList(ForwardListReport {
            forwards: vec![ForwardInfo {
                spec: spec("a-web"),
                resolved_listen: "127.0.0.1:18080".parse().unwrap(),
                state: ForwardState::Bound,
            }],
        }),
        Response::ForwardAdded {
            name: "a-web".into(),
            listen: "127.0.0.1:18080".parse().unwrap(),
        },
        Response::ForwardRemoved {
            name: "a-web".into(),
        },
        Response::error(ErrorCode::Denied, "connect_service is not permitted"),
    ] {
        let frame = encode_message(&response).unwrap();
        assert_eq!(decode_message::<Response>(&frame).unwrap(), response);
    }
}

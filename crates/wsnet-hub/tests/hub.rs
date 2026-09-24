//! End-to-end Hub tests over a real loopback listener.
//!
//! Everything here goes through the HTTP surface DESIGN.md section 11 fixes, so
//! the tests exercise the same bytes nginx would forward: a POST batch, an SSE
//! subscription, and a WebSocket upgrade. Each test body runs inside a deadline so
//! a bug cannot hang the suite.
//!
//! The client is deliberately small and explicit rather than a general HTTP
//! library, for two reasons: the assertions that matter here are about *bytes*
//! (section 9.1 requires a replayed `Auth`, an unknown node, and a bad MAC to be
//! indistinguishable), and a hand-written client leaves no doubt about what was
//! sent.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wsnet_config::{ServerConfig, ServerSection};
use wsnet_crypto::{open, seal, Direction, EnvelopeContext, PacketNoAllocator, Psk, SessionKeys};
use wsnet_hub::{
    binding_mac, body_hash, BindProof, BindTarget, Hub, NodeSecrets, ProfilePaths,
    BIND_PROOF_HEADER,
};
use wsnet_limits::{
    FAILURE_MAX_BODY, MAX_CARRIER_RECORD, MAX_HTTP_BODY, MAX_POST_BATCH_BYTES, MAX_SITE_RESOURCE,
    MAX_SSE_EVENT,
};
use wsnet_protocol::{Canonical, MessageKind, Record};
use wsnet_routing::{AclAction, AclRule, Destination, Proto};
use wsnet_session::{
    auth_mac, session_keys, verify_authok, AuthFields, AuthOkFields, HelloFields, HelloOkFields,
    OpenFields, OpenResultFields, OpenStatus, ServiceRegistration,
};
use wsnet_transport::{post, profile, sse};

const HUB_ID: &str = "hub-a";
const NODE_ID: &str = "client-a";
const KEY_ID: &str = "a-1";
const LISTEN: &str = "127.0.0.1:8443";
const PAGE_PATH: &str = "/transport/page";

fn psk() -> Psk {
    Psk::from_bytes([0x42; 32])
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Runs a test body under a hard deadline.
async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .expect("the test did not finish inside its deadline")
}

// ---------------------------------------------------------------------------
// Hub under test
// ---------------------------------------------------------------------------

struct TestServer {
    hub: Arc<Hub>,
    addr: SocketAddr,
}

async fn start_with(acl: Vec<AclRule>, relay_allow: Vec<&str>) -> TestServer {
    start_with_profiles(acl, relay_allow, None).await
}

async fn start_with_profiles(
    acl: Vec<AclRule>,
    relay_allow: Vec<&str>,
    profiles: Option<ProfilePaths>,
) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = ServerConfig {
        server: ServerSection {
            hub_id: HUB_ID.to_string(),
            listen: LISTEN.to_string(),
            relay_allow: relay_allow
                .into_iter()
                .map(|node| node.to_string())
                .collect(),
            ..ServerSection::default()
        },
        nodes: Vec::new(),
        acl,
    };
    let secrets = NodeSecrets::new().with(NODE_ID, KEY_ID, psk());
    let hub = Arc::new(match profiles {
        Some(profiles) => Hub::with_profiles(config, secrets, profiles).unwrap(),
        None => Hub::new(config, secrets).unwrap(),
    });
    let serving = Arc::clone(&hub);
    tokio::spawn(async move {
        let _ = serving.serve(listener).await;
    });
    TestServer { hub, addr }
}

fn rule(caller: &str, action: AclAction, node: Option<&str>, service: Option<&str>) -> AclRule {
    AclRule {
        caller: caller.to_string(),
        action,
        allow: true,
        node: node.map(|value| value.to_string()),
        service: service.map(|value| value.to_string()),
        host_cidr: None,
        ports: None,
        proto: None,
    }
}

// ---------------------------------------------------------------------------
// A minimal HTTP/1.1 client
// ---------------------------------------------------------------------------

struct RawConn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl RawConn {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect to the hub");
        RawConn {
            stream,
            buf: Vec::new(),
        }
    }

    async fn write(&mut self, bytes: &[u8]) {
        self.write_lossy(bytes).await.expect("write request");
    }

    async fn write_lossy(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes).await
    }

    /// Reads once; `false` means the peer closed.
    async fn fill(&mut self) -> bool {
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk).await {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                true
            }
        }
    }

    fn position(&self, needle: &[u8]) -> Option<usize> {
        find(&self.buf, needle)
    }

    /// Fills until `needle` is present, returning everything up to and including
    /// it and leaving the rest buffered.
    async fn read_until(&mut self, needle: &[u8]) -> Option<Vec<u8>> {
        loop {
            if let Some(at) = self.position(needle) {
                let end = at + needle.len();
                let taken = self.buf[..end].to_vec();
                self.buf.drain(..end);
                return Some(taken);
            }
            if !self.fill().await {
                return None;
            }
        }
    }

    /// Reads exactly `len` bytes, refilling as needed.
    async fn read_exactly(&mut self, len: usize) -> Option<Vec<u8>> {
        while self.buf.len() < len {
            if !self.fill().await {
                return None;
            }
        }
        let taken = self.buf[..len].to_vec();
        self.buf.drain(..len);
        Some(taken)
    }

    async fn read_to_eof(&mut self) -> Vec<u8> {
        while self.fill().await {}
        std::mem::take(&mut self.buf)
    }

    /// Fills until `needle` is present or `budget` elapses.
    async fn wait_for(&mut self, needle: &[u8], budget: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            if self.position(needle).is_some() {
                return true;
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            match tokio::time::timeout(left, self.fill()).await {
                Ok(true) => {}
                _ => return self.position(needle).is_some(),
            }
        }
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    raw: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_chunked(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = find(&body[cursor..], b"\r\n") {
        let line_end = cursor + relative;
        let size_text = String::from_utf8_lossy(&body[cursor..line_end]);
        let Ok(size) = usize::from_str_radix(size_text.trim(), 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        if start + size > body.len() {
            out.extend_from_slice(&body[start..]);
            break;
        }
        out.extend_from_slice(&body[start..start + size]);
        cursor = start + size + 2;
    }
    out
}

fn parse_response(raw: Vec<u8>) -> HttpResponse {
    let split = find(&raw, b"\r\n\r\n").expect("response head is terminated");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    let body = &raw[split + 4..];
    let chunked = headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        decode_chunked(body)
    } else {
        body.to_vec()
    };
    HttpResponse {
        status,
        headers,
        body,
        raw,
    }
}

/// Sends one request with `Connection: close` and reads the whole reply.
async fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut conn = RawConn::connect(addr).await;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    conn.write(head.as_bytes()).await;
    if !body.is_empty() {
        conn.write(body).await;
    }
    parse_response(conn.read_to_eof().await)
}

/// The same, but tolerating a peer that refuses the request mid-write.
///
/// A body past the read bound makes the Hub answer (and close) before the client
/// has finished writing, so a write error is itself evidence of the refusal and
/// must not panic the test.
async fn http_request_or_refused(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> Option<HttpResponse> {
    let mut conn = RawConn::connect(addr).await;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    if conn.write_lossy(head.as_bytes()).await.is_err() {
        return None;
    }
    if !body.is_empty() && conn.write_lossy(body).await.is_err() {
        // Fall through: a response may still be readable.
    }
    let raw = conn.read_to_eof().await;
    // A reply that never got a header is not a reply at all.
    find(&raw, b"\r\n\r\n")?;
    Some(parse_response(raw))
}

// ---------------------------------------------------------------------------
// The node side of a session
// ---------------------------------------------------------------------------

/// The `Auth` bootstrap message, as the node would build it.
fn auth_fields(node_id: &str, nonce: [u8; 32]) -> AuthFields {
    AuthFields {
        version: 1,
        hub_id: HUB_ID.to_string(),
        key_id: KEY_ID.to_string(),
        node_id: node_id.to_string(),
        attempt_id: [0x11; 16],
        ts: now_secs(),
        nonce,
        capabilities: vec![
            "flow.credit".to_string(),
            "carrier.post".to_string(),
            "carrier.ws".to_string(),
            "carrier.sse".to_string(),
        ],
    }
}

/// A node's local view of the session the Hub just created.
struct NodeSession {
    keys: SessionKeys,
    ctx: EnvelopeContext,
    alloc: PacketNoAllocator,
    session_id: [u8; 16],
    epoch: [u8; 16],
    expires_at: i64,
}

/// Every carrier path's encoder, mirroring section 4.3 and section 6.4.
fn encode_for_path(path: &str, envelopes: &[Vec<u8>]) -> Vec<u8> {
    match path {
        "/m" => post::encode(envelopes).unwrap(),
        "/transport/script" => profile::TemplateProfile::JS.encode(envelopes).unwrap(),
        "/transport/style" => profile::TemplateProfile::CSS.encode(envelopes).unwrap(),
        "/transport/api" => profile::json::encode(envelopes).unwrap(),
        _ => profile::TemplateProfile::HTML.encode(envelopes).unwrap(),
    }
}

fn node_from_authok(response: &HttpResponse, fields: &AuthFields, mac: &[u8; 32]) -> NodeSession {
    let envelopes = post::decode(&response.body).expect("the reply is a POST batch");
    assert_eq!(envelopes.len(), 1, "AuthOk is answered with one record");
    let record = Record::decode(&envelopes[0]).expect("the reply is a record");
    assert_eq!(record.kind, MessageKind::AuthOk);
    verify_authok(&psk(), &fields.attempt_id, mac, &record.metadata)
        .expect("the node must be able to verify AuthOk");
    let (authok, _) = AuthOkFields::from_canonical(&record.metadata).expect("AuthOk metadata");
    let keys = session_keys(&psk(), fields, &authok);
    NodeSession {
        ctx: EnvelopeContext::new(HUB_ID, authok.session_id, authok.session_epoch),
        keys,
        alloc: PacketNoAllocator::new(),
        session_id: authok.session_id,
        epoch: authok.session_epoch,
        expires_at: authok.expires_at,
    }
}

async fn authenticate(server: &TestServer) -> NodeSession {
    let fields = auth_fields(NODE_ID, [0x22; 32]);
    let mac = auth_mac(&psk(), &fields);
    let record = Record::new(MessageKind::Auth, fields.to_canonical(&mac));
    let body = encode_for_path("/m", &[record.encode().unwrap()]);
    let response = http_request(server.addr, "POST", "/m", &[], &body).await;
    assert_eq!(response.status, 200, "authentication failed: {response:?}");
    node_from_authok(&response, &fields, &mac)
}

impl NodeSession {
    fn seal(&self, kind: MessageKind, metadata: Canonical, payload: Vec<u8>) -> Vec<u8> {
        let record = if payload.is_empty() && !kind.carries_payload() {
            Record::new(kind, metadata)
        } else {
            Record::with_payload(kind, metadata, payload)
        };
        let plaintext = record.encode().unwrap();
        let packet_no = self.alloc.allocate().unwrap();
        seal(
            self.keys.message_key(Direction::ClientToServer),
            &self.ctx,
            Direction::ClientToServer,
            packet_no,
            &plaintext,
        )
        .unwrap()
    }

    fn open_envelope(&self, envelope: &[u8]) -> Record {
        let opened = open(
            self.keys.message_key(Direction::ServerToClient),
            &self.ctx,
            Direction::ServerToClient,
            envelope,
        )
        .expect("the hub reply must open with the derived keys");
        Record::decode(&opened.plaintext).expect("the hub reply is a record")
    }

    /// Every record in a `/m` response, opened with the session keys.
    fn reply_records(&self, response: &HttpResponse) -> Vec<Record> {
        post::decode(&response.body)
            .expect("the reply is a POST batch")
            .iter()
            .map(|envelope| self.open_envelope(envelope))
            .collect()
    }

    fn proof_with_expiry(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        tag: u8,
        expires_at: i64,
    ) -> String {
        let target = BindTarget {
            method,
            path,
            hub_id: HUB_ID,
            session_id: self.session_id,
            session_epoch: self.epoch,
            channel_id: [tag; 16],
            bind_nonce: [tag; 16],
            body_hash: body_hash(body),
            expires_at,
        };
        let mac = binding_mac(self.keys.bind_key(), &target);
        BindProof {
            session_id: self.session_id,
            channel_id: [tag; 16],
            bind_nonce: [tag; 16],
            expires_at,
            mac,
        }
        .encode()
    }

    fn proof(&self, method: &str, path: &str, body: &[u8], tag: u8) -> String {
        let expires_at = (now_secs() + 20).min(self.expires_at);
        self.proof_with_expiry(method, path, body, tag, expires_at)
    }

    /// A bound POST of sealed records, encoded for the path's carrier.
    async fn post_sealed(
        &self,
        server: &TestServer,
        path: &str,
        envelopes: Vec<Vec<u8>>,
        tag: u8,
    ) -> HttpResponse {
        let body = encode_for_path(path, &envelopes);
        let proof = self.proof("POST", path, &body, tag);
        http_request(
            server.addr,
            "POST",
            path,
            &[(BIND_PROOF_HEADER, proof.as_str())],
            &body,
        )
        .await
    }

    async fn hello(
        &self,
        server: &TestServer,
        services: Vec<ServiceRegistration>,
        tag: u8,
    ) -> HttpResponse {
        let hello = HelloFields {
            request_id: [0x31; 16],
            services,
            capabilities: vec!["flow.credit".to_string()],
        };
        let envelope = self.seal(MessageKind::Hello, hello.to_canonical(), Vec::new());
        self.post_sealed(server, "/m", vec![envelope], tag).await
    }

    async fn register(&self, server: &TestServer, services: Vec<ServiceRegistration>, tag: u8) {
        let response = self.hello(server, services, tag).await;
        assert_eq!(response.status, 200);
        let records = self.reply_records(&response);
        let hello_ok = records
            .iter()
            .find(|record| record.kind == MessageKind::HelloOk)
            .expect("Hello must be answered with HelloOk");
        let fields = HelloOkFields::from_canonical(&hello_ok.metadata).unwrap();
        assert_eq!(fields.request_id, [0x31; 16]);
    }

    async fn open(
        &self,
        server: &TestServer,
        destination: Destination,
        via: Vec<&str>,
        tag: u8,
    ) -> OpenResultFields {
        let records = self.open_reply(server, destination, via, tag).await;
        let result = records
            .iter()
            .find(|record| record.kind == MessageKind::OpenResult)
            .expect("Open must be answered with OpenResult");
        OpenResultFields::from_canonical(&result.metadata).unwrap()
    }

    /// Every record one bound `Open` produced, whatever they are.
    ///
    /// An `Open` that resolves to a node-terminated leg (section 7.6) is not
    /// answered in this reply: the Hub first opens a stream on the publishing
    /// node's session and answers only once that node reports both halves, so a
    /// bridged `Open` has no `OpenResult` here while every refusal has one.
    async fn open_reply(
        &self,
        server: &TestServer,
        destination: Destination,
        via: Vec<&str>,
        tag: u8,
    ) -> Vec<Record> {
        let open = OpenFields {
            request_id: [0x41; 16],
            stream_id: 1,
            proto: Proto::Tcp,
            destination,
            via: via.into_iter().map(|hop| hop.to_string()).collect(),
        };
        let envelope = self.seal(MessageKind::Open, open.to_canonical(), Vec::new());
        let response = self.post_sealed(server, "/m", vec![envelope], tag).await;
        assert_eq!(response.status, 200, "a bound Open must be accepted");
        self.reply_records(&response)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The handshake, and that the derived keys really are the session keys.
#[tokio::test]
async fn post_auth_returns_authok_and_the_derived_keys_verify_a_follow_up_record() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let node = authenticate(&server).await;

        let hello = HelloFields {
            request_id: [0x31; 16],
            services: vec![ServiceRegistration {
                name: "web".to_string(),
                proto: Proto::Tcp,
                target: "127.0.0.1:8080".to_string(),
            }],
            capabilities: vec!["flow.credit".to_string()],
        };
        let envelope = node.seal(MessageKind::Hello, hello.to_canonical(), Vec::new());
        let response = node.post_sealed(&server, "/m", vec![envelope], 1).await;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("cache-control"),
            Some("no-store"),
            "business responses must not be cached (section 11)"
        );

        let records = node.reply_records(&response);
        assert_eq!(records.len(), 1, "Hello is answered with one record");
        assert_eq!(records[0].kind, MessageKind::HelloOk);
        assert_eq!(
            records[0].metadata.get_str("request_id").unwrap(),
            "31".repeat(16)
        );
        assert!(server.hub.is_node_registered(NODE_ID));
        assert_eq!(server.hub.registered_services(NODE_ID), vec!["web"]);
    })
    .await;
}

/// Section 9.1: the appearance of a failed authentication must not depend on which
/// check failed.
#[tokio::test]
async fn a_replay_an_unknown_node_and_a_bad_mac_are_byte_identical() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;

        let fields = auth_fields(NODE_ID, [0x22; 32]);
        let mac = auth_mac(&psk(), &fields);
        let record = Record::new(MessageKind::Auth, fields.to_canonical(&mac));
        let body = encode_for_path("/m", &[record.encode().unwrap()]);

        let accepted = http_request(server.addr, "POST", "/m", &[], &body).await;
        assert_eq!(accepted.status, 200);

        // The same `Auth` again: a replay, whatever carrier it arrives on.
        let replayed = http_request(server.addr, "POST", "/m", &[], &body).await;

        let ghost_fields = auth_fields("ghost-node", [0x23; 32]);
        let ghost_mac = auth_mac(&psk(), &ghost_fields);
        let ghost = Record::new(MessageKind::Auth, ghost_fields.to_canonical(&ghost_mac));
        let ghost_body = encode_for_path("/m", &[ghost.encode().unwrap()]);
        let unknown = http_request(server.addr, "POST", "/m", &[], &ghost_body).await;

        let forged_fields = auth_fields(NODE_ID, [0x24; 32]);
        let forged = Record::new(MessageKind::Auth, forged_fields.to_canonical(&[0u8; 32]));
        let forged_body = encode_for_path("/m", &[forged.encode().unwrap()]);
        let bad_mac = http_request(server.addr, "POST", "/m", &[], &forged_body).await;

        assert_eq!(replayed.status, 404);
        assert_eq!(unknown.status, 404);
        assert_eq!(bad_mac.status, 404);
        assert_eq!(
            replayed.raw, unknown.raw,
            "a replay must be indistinguishable from an unknown node"
        );
        assert_eq!(
            unknown.raw, bad_mac.raw,
            "an unknown node must be indistinguishable from a bad MAC"
        );
        assert_eq!(replayed.header("cache-control"), Some("no-store"));
        assert!(replayed.body.len() <= FAILURE_MAX_BODY);
        // Nothing was registered by any of the three failures.
        assert!(!server.hub.is_node_registered(NODE_ID));
        assert!(!server.hub.is_node_registered("ghost-node"));
    })
    .await;
}

/// Section 4.4: a `bind_nonce` is single use, a proof expires, and a proof is
/// bound to the path it was made for.
#[tokio::test]
async fn bind_proofs_cannot_be_replayed_expired_or_moved_between_paths() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let node = authenticate(&server).await;
        let empty = post::encode(&[]).unwrap();

        let proof = node.proof("POST", "/m", &empty, 0x01);
        let first = http_request(
            server.addr,
            "POST",
            "/m",
            &[(BIND_PROOF_HEADER, proof.as_str())],
            &empty,
        )
        .await;
        assert_eq!(first.status, 200, "the first use of a proof is accepted");

        let replayed = http_request(
            server.addr,
            "POST",
            "/m",
            &[(BIND_PROOF_HEADER, proof.as_str())],
            &empty,
        )
        .await;
        assert_eq!(replayed.status, 404, "a bind nonce is single use");

        let expired = node.proof_with_expiry("POST", "/m", &empty, 0x02, now_secs() - 1);
        let expired_response = http_request(
            server.addr,
            "POST",
            "/m",
            &[(BIND_PROOF_HEADER, expired.as_str())],
            &empty,
        )
        .await;
        assert_eq!(expired_response.status, 404);

        let too_long = node.proof_with_expiry("POST", "/m", &empty, 0x03, now_secs() + 600);
        let too_long_response = http_request(
            server.addr,
            "POST",
            "/m",
            &[(BIND_PROOF_HEADER, too_long.as_str())],
            &empty,
        )
        .await;
        assert_eq!(too_long_response.status, 404);

        // A proof made for a profile path cannot be used on `/m`...
        let page_body = encode_for_path(PAGE_PATH, &[]);
        let page_proof = node.proof("POST", PAGE_PATH, &page_body, 0x04);
        let moved = http_request(
            server.addr,
            "POST",
            "/m",
            &[(BIND_PROOF_HEADER, page_proof.as_str())],
            &page_body,
        )
        .await;
        assert_eq!(moved.status, 404);

        // ...but it works on the path it was made for, so the refusal above was
        // the path binding rather than a blanket rejection.
        let page = http_request(
            server.addr,
            "POST",
            PAGE_PATH,
            &[(BIND_PROOF_HEADER, page_proof.as_str())],
            &page_body,
        )
        .await;
        assert_eq!(page.status, 200);
        assert_eq!(
            page.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(page.header("cache-control"), Some("no-store"));
    })
    .await;
}

/// Section 4.4: an unauthenticated `/m` carries exactly one `Auth`.
#[tokio::test]
async fn an_unauthenticated_batch_must_carry_exactly_one_auth() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let fields = auth_fields(NODE_ID, [0x25; 32]);
        let mac = auth_mac(&psk(), &fields);
        let record = Record::new(MessageKind::Auth, fields.to_canonical(&mac));

        let two = encode_for_path("/m", &[record.encode().unwrap(), record.encode().unwrap()]);
        let response = http_request(server.addr, "POST", "/m", &[], &two).await;
        assert_eq!(response.status, 404);

        // A single non-Auth record is refused as well.
        let ping = Record::new(MessageKind::Ping, Canonical::empty_object());
        let wrong_kind = encode_for_path("/m", &[ping.encode().unwrap()]);
        let response = http_request(server.addr, "POST", "/m", &[], &wrong_kind).await;
        assert_eq!(response.status, 404);
        assert!(!server.hub.is_node_registered(NODE_ID));
    })
    .await;
}

/// Section 5.3: `HelloOk` is the business barrier.
#[tokio::test]
async fn an_open_before_hello_ok_is_refused_and_hello_ok_lifts_the_barrier() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let node = authenticate(&server).await;

        let open = OpenFields {
            request_id: [0x41; 16],
            stream_id: 1,
            proto: Proto::Tcp,
            destination: Destination::address("example.com", 443),
            via: Vec::new(),
        };
        let envelope = node.seal(MessageKind::Open, open.to_canonical(), Vec::new());
        let response = node.post_sealed(&server, "/m", vec![envelope], 1).await;
        let records = node.reply_records(&response);
        assert!(
            records
                .iter()
                .any(|record| record.kind == MessageKind::Reset),
            "an early Open must be reset, not answered: {records:?}"
        );
        assert!(!records
            .iter()
            .any(|record| record.kind == MessageKind::OpenResult));
        assert!(!server.hub.is_node_registered(NODE_ID));

        // Registering lifts the barrier, and the same Open is now answered.
        node.register(&server, Vec::new(), 2).await;
        assert!(server.hub.is_node_registered(NODE_ID));
        let result = node
            .open(
                &server,
                Destination::address("example.com", 443),
                Vec::new(),
                3,
            )
            .await;
        assert_eq!(
            result.status,
            OpenStatus::Denied,
            "an empty ACL denies everything (section 9.3)"
        );
        assert!(result.detail.contains("acl"), "{}", result.detail);
    })
    .await;
}

/// Section 7.6: a named service needs a matching ACL rule.
#[tokio::test]
async fn a_service_without_an_acl_rule_is_denied_and_nothing_is_dialled() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let node = authenticate(&server).await;
        node.register(
            &server,
            vec![ServiceRegistration {
                name: "web".to_string(),
                proto: Proto::Tcp,
                target: "127.0.0.1:8080".to_string(),
            }],
            1,
        )
        .await;

        let result = node
            .open(&server, Destination::service(NODE_ID, "web"), Vec::new(), 2)
            .await;
        assert_eq!(result.status, OpenStatus::Denied);
        assert_eq!(result.detail, "no acl rule permits this access");
        // The service is published, which proves the refusal came from the ACL
        // and not from a missing registration.
        assert_eq!(server.hub.registered_services(NODE_ID), vec!["web"]);
    })
    .await;
}

/// Section 7.6: with its own rule a published service resolves to the publishing
/// node's leg, and a service rule still grants no raw address access.
#[tokio::test]
async fn a_service_with_a_rule_resolves_and_a_service_rule_grants_no_raw_access() {
    within(async {
        let server = start_with(
            vec![rule(
                NODE_ID,
                AclAction::ConnectService,
                Some(NODE_ID),
                Some("web"),
            )],
            Vec::new(),
        )
        .await;
        let node = authenticate(&server).await;
        node.register(
            &server,
            vec![ServiceRegistration {
                name: "web".to_string(),
                proto: Proto::Tcp,
                target: "127.0.0.1:8080".to_string(),
            }],
            1,
        )
        .await;

        // The rule resolves the service, so the Hub bridges the leg to the
        // publishing node instead of refusing it: the answer comes only once
        // that node reports both halves, so this reply carries no
        // `OpenResult`. A refusal would have answered here.
        let records = node
            .open_reply(&server, Destination::service(NODE_ID, "web"), Vec::new(), 2)
            .await;
        assert!(
            !records
                .iter()
                .any(|record| record.kind == MessageKind::OpenResult),
            "a bridged Open must not be answered before the publishing node answers"
        );

        // The same rule must not admit a raw address in that node's view.
        let raw = node
            .open(
                &server,
                Destination::node_address(NODE_ID, "127.0.0.1", 22),
                Vec::new(),
                3,
            )
            .await;
        assert_eq!(raw.status, OpenStatus::Denied);
    })
    .await;
}

/// Section 7.6: `NodeAddressTarget` is denied until its own rule allows it.
#[tokio::test]
async fn a_node_address_target_needs_its_own_rule() {
    within(async {
        // Denied with no rule at all.
        let no_rules = start_with(Vec::new(), Vec::new()).await;
        let node = authenticate(&no_rules).await;
        node.register(&no_rules, Vec::new(), 1).await;
        let denied = node
            .open(
                &no_rules,
                Destination::node_address(NODE_ID, "127.0.0.1", 22),
                Vec::new(),
                2,
            )
            .await;
        assert_eq!(denied.status, OpenStatus::Denied);

        // Admitted with a dedicated `connect_node_address` rule.
        let server = start_with(
            vec![rule(
                NODE_ID,
                AclAction::ConnectNodeAddress,
                Some(NODE_ID),
                None,
            )],
            Vec::new(),
        )
        .await;
        let node = authenticate(&server).await;
        node.register(&server, Vec::new(), 1).await;
        // Its own rule admits the address, so the leg is bridged to the named
        // node and the answer waits for that node (section 7.6).
        let allowed = node
            .open_reply(
                &server,
                Destination::node_address(NODE_ID, "127.0.0.1", 22),
                Vec::new(),
                2,
            )
            .await;
        assert!(
            !allowed
                .iter()
                .any(|record| record.kind == MessageKind::OpenResult),
            "its own rule must admit the address into a bridge"
        );
    })
    .await;
}

/// Section 7.1: loops, duplicates, and over-long chains are refused, and a valid
/// chain is still validated rather than silently ignored.
#[tokio::test]
async fn via_chains_are_validated_and_never_silently_ignored() {
    within(async {
        let server = start_with(
            vec![
                rule(NODE_ID, AclAction::ConnectAddress, None, None),
                rule(NODE_ID, AclAction::Relay, Some("hop1"), None),
                rule(NODE_ID, AclAction::Relay, Some("hop2"), None),
                rule(NODE_ID, AclAction::Relay, Some("hop3"), None),
                rule(NODE_ID, AclAction::Relay, Some("hop4"), None),
                rule(NODE_ID, AclAction::Relay, Some("hop5"), None),
            ],
            vec!["hop1", "hop2", "hop3", "hop4", "hop5"],
        )
        .await;
        let node = authenticate(&server).await;
        node.register(&server, Vec::new(), 1).await;

        let looped = node
            .open(
                &server,
                Destination::address("example.com", 443),
                vec![NODE_ID],
                2,
            )
            .await;
        assert_eq!(looped.status, OpenStatus::Denied);
        assert!(looped.detail.contains("loop"), "{}", looped.detail);

        let duplicated = node
            .open(
                &server,
                Destination::address("example.com", 443),
                vec!["hop1", "hop1"],
                3,
            )
            .await;
        assert_eq!(duplicated.status, OpenStatus::Denied);
        assert!(
            duplicated.detail.contains("repeat"),
            "{}",
            duplicated.detail
        );

        let too_long = node
            .open(
                &server,
                Destination::address("example.com", 443),
                vec!["hop1", "hop2", "hop3", "hop4", "hop5"],
                4,
            )
            .await;
        assert_eq!(too_long.status, OpenStatus::Denied);
        assert!(too_long.detail.contains("budget"), "{}", too_long.detail);

        // A valid, fully permitted chain is refused rather than dialled: the Hub
        // never silently drops the intermediate hops.
        let relayed = node
            .open(
                &server,
                Destination::address("example.com", 443),
                vec!["hop1"],
                5,
            )
            .await;
        assert_eq!(relayed.status, OpenStatus::Refused);
        assert!(relayed.detail.contains("multi-hop"), "{}", relayed.detail);
    })
    .await;
}

/// A relay chain needs both gates of section 9.3.
#[tokio::test]
async fn a_chain_needs_relay_allow_and_a_relay_rule() {
    within(async {
        // `relay_allow` permits the hop, but no `relay` ACL rule exists.
        let server = start_with(
            vec![rule(NODE_ID, AclAction::ConnectAddress, None, None)],
            vec!["hop1"],
        )
        .await;
        let node = authenticate(&server).await;
        node.register(&server, Vec::new(), 1).await;
        let result = node
            .open(
                &server,
                Destination::address("example.com", 443),
                vec!["hop1"],
                2,
            )
            .await;
        assert_eq!(result.status, OpenStatus::Denied);
        assert!(result.detail.contains("relaying"), "{}", result.detail);

        // Without `relay_allow` the same chain is refused earlier still.
        let server = start_with(
            vec![
                rule(NODE_ID, AclAction::ConnectAddress, None, None),
                rule(NODE_ID, AclAction::Relay, Some("hop1"), None),
            ],
            Vec::new(),
        )
        .await;
        let node = authenticate(&server).await;
        node.register(&server, Vec::new(), 1).await;
        let result = node
            .open(
                &server,
                Destination::address("example.com", 443),
                vec!["hop1"],
                2,
            )
            .await;
        assert_eq!(result.status, OpenStatus::Denied);
        assert!(result.detail.contains("relay_allow"), "{}", result.detail);
    })
    .await;
}

/// Section 6.4: the configured profile paths are carriers in their own right.
#[tokio::test]
async fn profile_paths_accept_their_own_encoding() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let node = authenticate(&server).await;

        for (tag, (path, content_type)) in [
            (PAGE_PATH, "text/html; charset=utf-8"),
            ("/transport/script", "application/javascript"),
            ("/transport/style", "text/css; charset=utf-8"),
            ("/transport/api", "application/json"),
        ]
        .into_iter()
        .enumerate()
        {
            let body = encode_for_path(path, &[]);
            let proof = node.proof("POST", path, &body, 0x40 + tag as u8);
            let response = http_request(
                server.addr,
                "POST",
                path,
                &[(BIND_PROOF_HEADER, proof.as_str())],
                &body,
            )
            .await;
            assert_eq!(response.status, 200, "{path} refused a bound request");
            assert_eq!(
                response.header("content-type"),
                Some(content_type),
                "{path}"
            );
            assert_eq!(response.header("cache-control"), Some("no-store"), "{path}");
        }
    })
    .await;
}

/// Section 9.3: the Hub backend refuses to bind anywhere but loopback.
#[tokio::test]
async fn a_non_loopback_listen_is_refused_at_construction() {
    within(async {
        for listen in ["0.0.0.0:8443", "192.168.10.4:8443", "[::]:8443"] {
            let config = ServerConfig {
                server: ServerSection {
                    listen: listen.to_string(),
                    ..ServerSection::default()
                },
                ..ServerConfig::default()
            };
            let error = Hub::new(config, NodeSecrets::new().with(NODE_ID, KEY_ID, psk()))
                .expect_err("a non-loopback listen must be refused");
            assert!(error.to_string().contains("loopback"), "{listen}: {error}");
        }
    })
    .await;
}

/// Section 4.4: a WebSocket peer authenticates with one Text `Auth`, and only
/// then does the carrier accept Binary records.
#[tokio::test]
async fn a_websocket_bootstrap_authenticates_on_a_text_frame_then_carries_binary_records() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let mut socket = WebSocketClient::connect(server.addr, "/w").await;

        // The bootstrap frame is the unsealed Auth record, hex-encoded so that the
        // Text frame stays valid UTF-8.
        let fields = auth_fields(NODE_ID, [0x33; 32]);
        let mac = auth_mac(&psk(), &fields);
        let record = Record::new(MessageKind::Auth, fields.to_canonical(&mac));
        socket
            .send_text(&hex::encode(record.encode().unwrap()))
            .await;

        let (opcode, payload) = socket.read_frame().await.expect("an AuthOk frame");
        assert_eq!(opcode, OPCODE_TEXT);
        let authok_record = Record::decode(&hex::decode(&payload).unwrap()).unwrap();
        assert_eq!(authok_record.kind, MessageKind::AuthOk);
        verify_authok(&psk(), &fields.attempt_id, &mac, &authok_record.metadata).unwrap();
        let (authok, _) = AuthOkFields::from_canonical(&authok_record.metadata).unwrap();
        let node = NodeSession {
            ctx: EnvelopeContext::new(HUB_ID, authok.session_id, authok.session_epoch),
            keys: session_keys(&psk(), &fields, &authok),
            alloc: PacketNoAllocator::new(),
            session_id: authok.session_id,
            epoch: authok.session_epoch,
            expires_at: authok.expires_at,
        };

        // After the bootstrap the carrier is Binary and carries sealed records.
        let hello = HelloFields {
            request_id: [0x31; 16],
            services: Vec::new(),
            capabilities: vec!["flow.credit".to_string()],
        };
        socket
            .send_binary(&node.seal(MessageKind::Hello, hello.to_canonical(), Vec::new()))
            .await;
        let (opcode, payload) = socket.read_frame().await.expect("a HelloOk frame");
        assert_eq!(opcode, OPCODE_BINARY);
        assert_eq!(node.open_envelope(&payload).kind, MessageKind::HelloOk);
        assert!(server.hub.is_node_registered(NODE_ID));

        // Section 5.3: losing the carrier releases the lease, and section 5.5's
        // session/epoch guard is what keeps such a teardown from touching a lease
        // that replaced it.
        socket
            .send_frame(OPCODE_CLOSE, &1000u16.to_be_bytes())
            .await;
        drop(socket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while server.hub.is_node_registered(NODE_ID) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a closed carrier must release its node lease"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.hub.session_count(), 0);
    })
    .await;
}

/// A pre-authentication WebSocket failure must be a Close, never HTTP bytes.
#[tokio::test]
async fn a_bad_websocket_auth_is_closed_rather_than_answered_with_http() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let mut socket = WebSocketClient::connect(server.addr, "/w").await;
        let fields = auth_fields("ghost-node", [0x34; 32]);
        let mac = auth_mac(&psk(), &fields);
        let record = Record::new(MessageKind::Auth, fields.to_canonical(&mac));
        socket
            .send_text(&hex::encode(record.encode().unwrap()))
            .await;
        let (opcode, payload) = socket.read_frame().await.expect("a close frame");
        assert_eq!(opcode, OPCODE_CLOSE, "section 9.1 allows only a Close");
        assert!(
            !payload.starts_with(b"HTTP/") && !payload.starts_with(b"<!doc"),
            "no HTTP bytes may follow an upgrade"
        );
        assert!(!server.hub.is_node_registered("ghost-node"));
    })
    .await;
}

/// Section 4.3: the SSE downlink carries well-formed events.
#[tokio::test]
async fn sse_emits_a_well_formed_event_for_a_downlink_record() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let node = authenticate(&server).await;

        let proof = node.proof("GET", "/e", b"", 0x05);
        let mut conn = RawConn::connect(server.addr).await;
        conn.write(
            format!("GET /e HTTP/1.1\r\nHost: 127.0.0.1\r\n{BIND_PROOF_HEADER}: {proof}\r\n\r\n")
                .as_bytes(),
        )
        .await;
        let head = conn
            .read_until(b"\r\n\r\n")
            .await
            .expect("the SSE head must arrive immediately");
        let head = String::from_utf8_lossy(&head).to_string();
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: text/event-stream"),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("cache-control: no-store"),
            "{head}"
        );
        assert!(
            conn.wait_for(b": connected\n\n", Duration::from_secs(5))
                .await,
            "the subscription must flush an opening event"
        );

        // A sealed Ping produces a sealed Pong on the downlink.
        let ping = node.seal(MessageKind::Ping, Canonical::empty_object(), Vec::new());
        let response = node.post_sealed(&server, "/m", vec![ping], 0x06).await;
        assert_eq!(response.status, 200);

        assert!(
            conn.wait_for(b"data: ", Duration::from_secs(5)).await,
            "the downlink must produce an SSE event"
        );
        let raw = std::mem::take(&mut conn.buf);
        let start = find(&raw, b"data: ").expect("an event payload");
        let end = find(&raw[start..], b"\n\n").expect("the event terminator");
        let event = &raw[start..start + end + 2];
        assert!(event.len() <= MAX_SSE_EVENT);

        let envelopes = sse::decode(event).expect("the event must decode as an SSE carrier");
        assert_eq!(envelopes.len(), 1);
        assert_eq!(node.open_envelope(&envelopes[0]).kind, MessageKind::Pong);
    })
    .await;
}

/// Section 9.1: an unbound SSE subscription is refused before any headers.
#[tokio::test]
async fn an_unbound_sse_subscription_is_refused_with_the_site_failure() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;
        let response = http_request(server.addr, "GET", "/e", &[], b"").await;
        assert_eq!(response.status, 404);
        assert_eq!(
            response.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert!(response.header("content-type").is_some());
        assert!(!response
            .header("content-type")
            .unwrap_or_default()
            .contains("event-stream"));
    })
    .await;
}

/// Section 6.5: unknown paths get the site's real 404, and reserved paths are
/// never served by it.
#[tokio::test]
async fn unknown_paths_use_the_site_404_and_reserved_paths_are_not_served_by_it() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;

        let home = http_request(server.addr, "GET", "/", &[], b"").await;
        assert_eq!(home.status, 200);
        assert_eq!(
            home.header("content-type"),
            Some("text/html; charset=utf-8")
        );

        let missing = http_request(server.addr, "GET", "/no/such/page", &[], b"").await;
        assert_eq!(missing.status, 404);
        assert!(missing.body.len() <= MAX_SITE_RESOURCE);
        assert!(String::from_utf8_lossy(&missing.body).contains("404"));

        let robots = http_request(server.addr, "GET", "/robots.txt", &[], b"").await;
        assert_eq!(robots.status, 200);
        assert!(robots.header("cache-control").unwrap().contains("max-age"));

        // Reserved paths are the proxy's, never the site's.
        for path in [
            "/m",
            "/e",
            "/w",
            "/transport/page",
            "/transport/script",
            "/transport/style",
            "/transport/api",
        ] {
            assert!(
                server.hub.site().route(path).is_none(),
                "{path} must be reserved"
            );
        }
        assert_eq!(server.hub.site().route("/nope").unwrap().status, 404);

        // `GET /m` is not a carrier request at all.
        let wrong_method = http_request(server.addr, "GET", "/m", &[], b"").await;
        assert_eq!(wrong_method.status, 405);
    })
    .await;
}

/// Section 9.2 and section 4.3: bodies are bounded before they are decoded, and
/// every response stays inside its budget.
#[tokio::test]
async fn oversized_bodies_and_failures_stay_inside_their_limits() {
    within(async {
        let server = start_with(Vec::new(), Vec::new()).await;

        // Past the POST batch byte cap.
        let oversized_batch = vec![0u8; MAX_POST_BATCH_BYTES + 1];
        let response = http_request(server.addr, "POST", "/m", &[], &oversized_batch).await;
        assert_eq!(response.status, 404);
        assert!(response.body.len() <= FAILURE_MAX_BODY);

        // A single envelope past the per-record cap, inside a legal batch size.
        let mut body = Vec::new();
        let declared = (MAX_CARRIER_RECORD + 1) as u32;
        body.extend_from_slice(&declared.to_be_bytes());
        body.extend_from_slice(&vec![0u8; MAX_CARRIER_RECORD + 1]);
        let response = http_request(server.addr, "POST", "/m", &[], &body).await;
        assert_eq!(response.status, 404);
        assert!(response.body.len() <= FAILURE_MAX_BODY);

        // A body past the HTTP read bound is refused too; the exchange may end at
        // the socket instead of with a response, which is equally a refusal.
        let too_long = vec![0u8; MAX_HTTP_BODY + 4096];
        let attempt = tokio::time::timeout(
            Duration::from_secs(10),
            http_request_or_refused(server.addr, "POST", "/m", &too_long),
        )
        .await;
        match attempt {
            Ok(Some(response)) => {
                assert_ne!(response.status, 200);
                assert!(response.body.len() <= FAILURE_MAX_BODY);
            }
            Ok(None) => {}
            Err(_) => panic!("the hub hung on an oversized body"),
        }

        // An ordinary batch response is inside the batch budget.
        let node = authenticate(&server).await;
        node.register(&server, Vec::new(), 1).await;
        let response = node.hello(&server, Vec::new(), 2).await;
        assert!(response.body.len() <= MAX_POST_BATCH_BYTES);
    })
    .await;
}

// ---------------------------------------------------------------------------
// A minimal RFC 6455 client
// ---------------------------------------------------------------------------

const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;

struct WebSocketClient {
    conn: RawConn,
}

impl WebSocketClient {
    async fn connect(addr: SocketAddr, path: &str) -> Self {
        let mut conn = RawConn::connect(addr).await;
        // The RFC 6455 example nonce decodes to exactly 16 bytes.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        conn.write(
            format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
        let head = conn
            .read_until(b"\r\n\r\n")
            .await
            .expect("an upgrade response");
        let head_text = String::from_utf8_lossy(&head).to_string();
        assert!(
            head_text.starts_with("HTTP/1.1 101"),
            "the upgrade must succeed: {head_text}"
        );
        WebSocketClient { conn }
    }

    async fn send_frame(&mut self, opcode: u8, payload: &[u8]) {
        // A client frame must be masked.
        let mask = [0x37u8, 0x11, 0x5A, 0x9C];
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode);
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.conn.write(&frame).await;
    }

    async fn send_text(&mut self, text: &str) {
        self.send_frame(OPCODE_TEXT, text.as_bytes()).await;
    }

    async fn send_binary(&mut self, payload: &[u8]) {
        self.send_frame(OPCODE_BINARY, payload).await;
    }

    async fn read_frame(&mut self) -> Option<(u8, Vec<u8>)> {
        let head = self.conn.read_exactly(2).await?;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let mut len = u64::from(head[1] & 0x7F);
        if len == 126 {
            let bytes = self.conn.read_exactly(2).await?;
            len = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        } else if len == 127 {
            let bytes = self.conn.read_exactly(8).await?;
            let mut array = [0u8; 8];
            array.copy_from_slice(&bytes);
            len = u64::from_be_bytes(array);
        }
        let mask = if masked {
            Some(self.conn.read_exactly(4).await?)
        } else {
            None
        };
        let mut payload = self.conn.read_exactly(len as usize).await?;
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        Some((opcode, payload))
    }
}

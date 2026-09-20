//! Typed metadata for every wsnet message kind (DESIGN.md section 4.1).
//!
//! Section 4.1 fixes the record layout but leaves the metadata as canonical
//! JSON. This module is the single place that knows each message's schema, so
//! that a field cannot be spelled one way on the sending side and another on the
//! receiving side.
//!
//! Two conventions come straight from section 4.1 and are applied uniformly:
//!
//! * Integers that matter to a signature or an offset are carried as **decimal
//!   strings** ("签名所需整数用十进制字符串"), because a `u64` offset cannot
//!   survive a JSON number round trip through a peer that uses doubles.
//! * Fixed-width identifiers are carried as lowercase hex.

use wsnet_protocol::{Canonical, MessageKind};
use wsnet_routing::{Destination, Proto};

/// Errors while building or reading message metadata.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageError {
    /// A required field was absent.
    #[error("message {kind} is missing field `{field}`")]
    MissingField {
        /// The message kind.
        kind: &'static str,
        /// The missing field.
        field: &'static str,
    },
    /// A field had the wrong canonical type.
    #[error("message {kind} field `{field}` has the wrong type")]
    WrongType {
        /// The message kind.
        kind: &'static str,
        /// The offending field.
        field: &'static str,
    },
    /// A hex field was not valid hex of the expected width.
    #[error("message {kind} field `{field}` is not {expected} bytes of hex")]
    BadHex {
        /// The message kind.
        kind: &'static str,
        /// The offending field.
        field: &'static str,
        /// Expected byte width.
        expected: usize,
    },
    /// A decimal-string integer did not parse.
    #[error("message {kind} field `{field}` is not a decimal integer")]
    BadInteger {
        /// The message kind.
        kind: &'static str,
        /// The offending field.
        field: &'static str,
    },
    /// An enum-valued field carried an unknown spelling.
    #[error("message {kind} field `{field}` has unknown value `{value}`")]
    UnknownValue {
        /// The message kind.
        kind: &'static str,
        /// The offending field.
        field: &'static str,
        /// The unrecognised value.
        value: String,
    },
    /// A nested value was itself malformed.
    #[error("message {kind} field `{field}` is invalid: {reason}")]
    Nested {
        /// The message kind.
        kind: &'static str,
        /// The offending field.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },
    /// A list exceeded a design bound.
    #[error("message {kind} field `{field}` has {actual} entries, limit is {limit}")]
    TooMany {
        /// The message kind.
        kind: &'static str,
        /// The offending field.
        field: &'static str,
        /// Observed count.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// A capability this build does not implement was marked required.
    #[error("peer requires unsupported capability `{0}`")]
    UnsupportedCapability(String),
}

/// Lowercase hex of a byte slice.
pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Reads fixed-width lowercase hex.
fn hex_field<const N: usize>(
    value: &Canonical,
    field: &'static str,
    kind: &'static str,
) -> Result<[u8; N], MessageError> {
    let text = value.get_str(field).map_err(|_| MessageError::MissingField { kind, field })?;
    let bytes = hex::decode(text).map_err(|_| MessageError::BadHex {
        kind,
        field,
        expected: N,
    })?;
    bytes.try_into().map_err(|_| MessageError::BadHex {
        kind,
        field,
        expected: N,
    })
}

fn decimal_field(
    value: &Canonical,
    field: &'static str,
    kind: &'static str,
) -> Result<u64, MessageError> {
    // Distinguish "absent" from "present but not a decimal integer": the two
    // need different fixes, and collapsing them makes a schema typo look like a
    // peer bug.
    value
        .field(field)
        .map_err(|_| MessageError::MissingField { kind, field })?;
    value
        .get_u64(field)
        .map_err(|_| MessageError::BadInteger { kind, field })
}

fn string_field(
    value: &Canonical,
    field: &'static str,
    kind: &'static str,
) -> Result<String, MessageError> {
    value
        .field(field)
        .map_err(|_| MessageError::MissingField { kind, field })?;
    value
        .get_str(field)
        .map(|s| s.to_string())
        .map_err(|_| MessageError::WrongType { kind, field })
}

fn string_list(
    value: &Canonical,
    field: &'static str,
    kind: &'static str,
) -> Result<Vec<String>, MessageError> {
    let items = value.get_array(field).map_err(|_| MessageError::WrongType { kind, field })?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Canonical::Str(s) => out.push(s.clone()),
            _ => return Err(MessageError::WrongType { kind, field }),
        }
    }
    Ok(out)
}

/// The protocol version this build speaks, as metadata spells it.
pub fn version_value() -> Canonical {
    Canonical::int(i64::from(wsnet_protocol::PROTOCOL_VERSION))
}

// ---------------------------------------------------------------------------
// Auth / AuthOk
// ---------------------------------------------------------------------------

/// The `Auth` bootstrap fields (DESIGN.md section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFields {
    /// Protocol version.
    pub version: u8,
    /// Hub the node is authenticating to.
    pub hub_id: String,
    /// Key generation the node used.
    pub key_id: String,
    /// Node identity.
    pub node_id: String,
    /// Candidate identity, so losers can be cancelled (§6.7).
    pub attempt_id: [u8; 16],
    /// UTC Unix seconds.
    pub ts: i64,
    /// 32-byte CSPRNG nonce.
    pub nonce: [u8; 32],
    /// Capabilities the node offers.
    pub capabilities: Vec<String>,
}

impl AuthFields {
    /// Every field except `mac`, in canonical form.
    ///
    /// This is the MAC input, so it must be byte-identical on both ends; the
    /// canonical encoder's sorted keys are what make that true.
    pub fn signing_canonical(&self) -> Canonical {
        Canonical::object([
            ("attempt_id", Canonical::str(hex_encode(&self.attempt_id))),
            ("capabilities", str_array(&self.capabilities)),
            ("hub_id", Canonical::str(self.hub_id.clone())),
            ("key_id", Canonical::str(self.key_id.clone())),
            ("node_id", Canonical::str(self.node_id.clone())),
            ("nonce", Canonical::str(hex_encode(&self.nonce))),
            ("ts", Canonical::u64_decimal(self.ts.max(0) as u64)),
            ("version", Canonical::int(i64::from(self.version))),
        ])
    }

    /// The complete metadata, including the MAC.
    pub fn to_canonical(&self, mac: &[u8]) -> Canonical {
        let Canonical::Object(mut map) = self.signing_canonical() else {
            unreachable!("signing_canonical always builds an object")
        };
        map.insert("mac".to_string(), Canonical::str(hex_encode(mac)));
        Canonical::Object(map)
    }

    /// Parses metadata, returning the fields and the presented MAC.
    pub fn from_canonical(value: &Canonical) -> Result<(AuthFields, [u8; 32]), MessageError> {
        const KIND: &str = "Auth";
        let fields = AuthFields {
            version: value
                .get_i64("version")
                .map_err(|_| MessageError::WrongType { kind: KIND, field: "version" })?
                as u8,
            hub_id: string_field(value, "hub_id", KIND)?,
            key_id: string_field(value, "key_id", KIND)?,
            node_id: string_field(value, "node_id", KIND)?,
            attempt_id: hex_field::<16>(value, "attempt_id", KIND)?,
            // `ts` is signature-relevant, so section 4.1 carries it as a decimal
            // string and it must be read back the same way.
            ts: decimal_field(value, "ts", KIND)? as i64,
            nonce: hex_field::<32>(value, "nonce", KIND)?,
            capabilities: string_list(value, "capabilities", KIND)?,
        };
        let mac = hex_field::<32>(value, "mac", KIND)?;
        Ok((fields, mac))
    }
}

/// The `AuthOk` response fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOkFields {
    /// Assigned session id.
    pub session_id: [u8; 16],
    /// Session key epoch.
    pub session_epoch: [u8; 16],
    /// Echo of the accepted candidate, so losers can be identified.
    pub attempt_id: [u8; 16],
    /// Fresh server nonce, mixed into the transcript.
    pub server_nonce: [u8; 32],
    /// Absolute session expiry, UTC Unix seconds.
    pub expires_at: i64,
    /// Capabilities the Hub selected.
    pub capabilities: Vec<String>,
}

impl AuthOkFields {
    /// Every field except `mac`.
    pub fn signing_canonical(&self) -> Canonical {
        Canonical::object([
            ("attempt_id", Canonical::str(hex_encode(&self.attempt_id))),
            ("capabilities", str_array(&self.capabilities)),
            ("expires_at", Canonical::u64_decimal(self.expires_at.max(0) as u64)),
            ("server_nonce", Canonical::str(hex_encode(&self.server_nonce))),
            ("session_epoch", Canonical::str(hex_encode(&self.session_epoch))),
            ("session_id", Canonical::str(hex_encode(&self.session_id))),
        ])
    }

    /// The complete metadata, including the MAC.
    pub fn to_canonical(&self, mac: &[u8]) -> Canonical {
        let Canonical::Object(mut map) = self.signing_canonical() else {
            unreachable!("signing_canonical always builds an object")
        };
        map.insert("mac".to_string(), Canonical::str(hex_encode(mac)));
        Canonical::Object(map)
    }

    /// Parses metadata, returning the fields and the presented MAC.
    pub fn from_canonical(value: &Canonical) -> Result<(AuthOkFields, [u8; 32]), MessageError> {
        const KIND: &str = "AuthOk";
        let fields = AuthOkFields {
            session_id: hex_field::<16>(value, "session_id", KIND)?,
            session_epoch: hex_field::<16>(value, "session_epoch", KIND)?,
            attempt_id: hex_field::<16>(value, "attempt_id", KIND)?,
            server_nonce: hex_field::<32>(value, "server_nonce", KIND)?,
            // Decimal string for the same reason as `ts` above.
            expires_at: decimal_field(value, "expires_at", KIND)? as i64,
            capabilities: string_list(value, "capabilities", KIND)?,
        };
        let mac = hex_field::<32>(value, "mac", KIND)?;
        Ok((fields, mac))
    }
}

// ---------------------------------------------------------------------------
// Hello / HelloOk
// ---------------------------------------------------------------------------

/// One service a node publishes during `Hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRegistration {
    /// Service name.
    pub name: String,
    /// Protocol.
    pub proto: Proto,
    /// Local target, `host:port`.
    pub target: String,
}

impl ServiceRegistration {
    fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("name", Canonical::str(self.name.clone())),
            ("proto", Canonical::str(self.proto.as_str())),
            ("target", Canonical::str(self.target.clone())),
        ])
    }

    fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Hello";
        let proto = match string_field(value, "proto", KIND)?.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            other => {
                return Err(MessageError::UnknownValue {
                    kind: KIND,
                    field: "proto",
                    value: other.to_string(),
                })
            }
        };
        Ok(ServiceRegistration {
            name: string_field(value, "name", KIND)?,
            proto,
            target: string_field(value, "target", KIND)?,
        })
    }
}

/// The `Hello` registration barrier (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloFields {
    /// Operation id for the registration itself.
    pub request_id: [u8; 16],
    /// Services being published.
    pub services: Vec<ServiceRegistration>,
    /// Capabilities the node wants to use.
    pub capabilities: Vec<String>,
}

impl HelloFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("capabilities", str_array(&self.capabilities)),
            ("request_id", Canonical::str(hex_encode(&self.request_id))),
            (
                "services",
                Canonical::Array(self.services.iter().map(|s| s.to_canonical()).collect()),
            ),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Hello";
        let services = value
            .get_array("services")
            .map_err(|_| MessageError::WrongType { kind: KIND, field: "services" })?
            .iter()
            .map(ServiceRegistration::from_canonical)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(HelloFields {
            request_id: hex_field::<16>(value, "request_id", KIND)?,
            services,
            capabilities: string_list(value, "capabilities", KIND)?,
        })
    }
}

/// The `HelloOk` acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloOkFields {
    /// Echoed operation id.
    pub request_id: [u8; 16],
    /// Capabilities the Hub accepted.
    pub capabilities: Vec<String>,
}

impl HelloOkFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("capabilities", str_array(&self.capabilities)),
            ("request_id", Canonical::str(hex_encode(&self.request_id))),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "HelloOk";
        Ok(HelloOkFields {
            request_id: hex_field::<16>(value, "request_id", KIND)?,
            capabilities: string_list(value, "capabilities", KIND)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Open / OpenResult / QueryResult
// ---------------------------------------------------------------------------

/// The outcome of an `Open`, as section 4.1's `OpenResult{status}` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenStatus {
    /// The stream is established; `Ready` follows.
    Ok,
    /// The exit refused the connection.
    Refused,
    /// Authorisation denied it.
    Denied,
    /// The publisher or service is not online.
    Offline,
    /// The target could not be reached.
    Unreachable,
    /// The operation exceeded its deadline and must be treated as unknown.
    Timeout,
    /// The same `request_id` was reused with different content.
    Conflict,
}

impl OpenStatus {
    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            OpenStatus::Ok => "ok",
            OpenStatus::Refused => "refused",
            OpenStatus::Denied => "denied",
            OpenStatus::Offline => "offline",
            OpenStatus::Unreachable => "unreachable",
            OpenStatus::Timeout => "timeout",
            OpenStatus::Conflict => "conflict",
        }
    }

    /// Parses the wire spelling.
    pub fn parse(value: &str) -> Option<OpenStatus> {
        Some(match value {
            "ok" => OpenStatus::Ok,
            "refused" => OpenStatus::Refused,
            "denied" => OpenStatus::Denied,
            "offline" => OpenStatus::Offline,
            "unreachable" => OpenStatus::Unreachable,
            "timeout" => OpenStatus::Timeout,
            "conflict" => OpenStatus::Conflict,
            _ => return None,
        })
    }
}

/// The `Open` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFields {
    /// Operation id.
    pub request_id: [u8; 16],
    /// Stream being established.
    pub stream_id: u64,
    /// Protocol.
    pub proto: Proto,
    /// The strict destination union.
    pub destination: Destination,
    /// Intermediate hops; for a named service the publisher is the final leg.
    pub via: Vec<String>,
}

impl OpenFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("destination", self.destination.to_canonical()),
            ("proto", Canonical::str(self.proto.as_str())),
            ("request_id", Canonical::str(hex_encode(&self.request_id))),
            ("stream_id", Canonical::u64_decimal(self.stream_id)),
            ("via", str_array(&self.via)),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Open";
        let proto = match string_field(value, "proto", KIND)?.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            other => {
                return Err(MessageError::UnknownValue {
                    kind: KIND,
                    field: "proto",
                    value: other.to_string(),
                })
            }
        };
        let destination = value
            .field("destination")
            .map_err(|_| MessageError::MissingField {
                kind: KIND,
                field: "destination",
            })
            .and_then(|v| {
                Destination::from_canonical(v).map_err(|source| MessageError::Nested {
                    kind: KIND,
                    field: "destination",
                    reason: format!("{source}"),
                })
            })?;
        Ok(OpenFields {
            request_id: hex_field::<16>(value, "request_id", KIND)?,
            stream_id: decimal_field(value, "stream_id", KIND)?,
            proto,
            destination,
            via: string_list(value, "via", KIND)?,
        })
    }

    /// The bytes hashed into the idempotency key (§5.2).
    pub fn operation_bytes(&self) -> Vec<u8> {
        self.to_canonical().to_bytes()
    }
}

/// The `OpenResult` / `QueryResult` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenResultFields {
    /// Echoed operation id.
    pub request_id: [u8; 16],
    /// Stream the operation concerns.
    pub stream_id: u64,
    /// Outcome.
    pub status: OpenStatus,
    /// A locally-diagnosable detail, never sent to an application.
    pub detail: String,
}

impl OpenResultFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("detail", Canonical::str(self.detail.clone())),
            ("request_id", Canonical::str(hex_encode(&self.request_id))),
            ("status", Canonical::str(self.status.as_str())),
            ("stream_id", Canonical::u64_decimal(self.stream_id)),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        let kind: &'static str = "OpenResult";
        let status_text = string_field(value, "status", kind)?;
        let status = OpenStatus::parse(&status_text).ok_or(MessageError::UnknownValue {
            kind,
            field: "status",
            value: status_text,
        })?;
        Ok(OpenResultFields {
            request_id: hex_field::<16>(value, "request_id", kind)?,
            stream_id: decimal_field(value, "stream_id", kind)?,
            status,
            detail: value
                .get_str("detail")
                .map(|s| s.to_string())
                .unwrap_or_default(),
        })
    }
}

// ---------------------------------------------------------------------------
// Stream control
// ---------------------------------------------------------------------------

/// `Data` metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFields {
    /// Stream the bytes belong to.
    pub stream_id: u64,
    /// Absolute offset of the first byte, excluding framing and padding.
    pub offset: u64,
}

impl DataFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("offset", Canonical::u64_decimal(self.offset)),
            ("stream_id", Canonical::u64_decimal(self.stream_id)),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Data";
        Ok(DataFields {
            stream_id: decimal_field(value, "stream_id", KIND)?,
            offset: decimal_field(value, "offset", KIND)?,
        })
    }
}

/// `Fin` metadata: the half-close and the offset it closes at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinFields {
    /// Stream being half-closed.
    pub stream_id: u64,
    /// Exclusive end offset; only `[0, final_offset)` may be delivered.
    pub final_offset: u64,
}

impl FinFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("final_offset", Canonical::u64_decimal(self.final_offset)),
            ("stream_id", Canonical::u64_decimal(self.stream_id)),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Fin";
        Ok(FinFields {
            stream_id: decimal_field(value, "stream_id", KIND)?,
            final_offset: decimal_field(value, "final_offset", KIND)?,
        })
    }
}

/// Why a stream was reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetReason {
    /// The peer violated the protocol.
    ProtocolError,
    /// A deadline expired.
    Timeout,
    /// The local side cancelled.
    Canceled,
    /// A buffer or budget was exhausted.
    Overflow,
    /// The exit could not reach the target.
    Unreachable,
}

impl ResetReason {
    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            ResetReason::ProtocolError => "protocol_error",
            ResetReason::Timeout => "timeout",
            ResetReason::Canceled => "canceled",
            ResetReason::Overflow => "overflow",
            ResetReason::Unreachable => "unreachable",
        }
    }

    /// Parses the wire spelling.
    pub fn parse(value: &str) -> Option<ResetReason> {
        Some(match value {
            "protocol_error" => ResetReason::ProtocolError,
            "timeout" => ResetReason::Timeout,
            "canceled" => ResetReason::Canceled,
            "overflow" => ResetReason::Overflow,
            "unreachable" => ResetReason::Unreachable,
            _ => return None,
        })
    }
}

/// `Reset` metadata. Never a substitute for a half-close (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetFields {
    /// Stream being terminated.
    pub stream_id: u64,
    /// Why.
    pub reason: ResetReason,
}

impl ResetFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("reason", Canonical::str(self.reason.as_str())),
            ("stream_id", Canonical::u64_decimal(self.stream_id)),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Reset";
        let text = string_field(value, "reason", KIND)?;
        let reason = ResetReason::parse(&text).ok_or(MessageError::UnknownValue {
            kind: KIND,
            field: "reason",
            value: text,
        })?;
        Ok(ResetFields {
            stream_id: decimal_field(value, "stream_id", KIND)?,
            reason,
        })
    }
}

/// `Ready` metadata: both receive halves are installed (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyFields {
    /// Stream that became ready.
    pub stream_id: u64,
}

impl ReadyFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([("stream_id", Canonical::u64_decimal(self.stream_id))])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        Ok(ReadyFields {
            stream_id: decimal_field(value, "stream_id", "Ready")?,
        })
    }
}

/// `Progress` metadata: cumulative acknowledgement and credit (§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressFields {
    /// Stream the progress concerns.
    pub stream_id: u64,
    /// Bytes received contiguously into the local bounded buffer.
    pub received_offset: u64,
    /// Bytes successfully written to the next hop.
    pub consumed_offset: u64,
    /// Absolute offset the peer may send up to.
    pub limit_offset: u64,
}

impl ProgressFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("consumed_offset", Canonical::u64_decimal(self.consumed_offset)),
            ("limit_offset", Canonical::u64_decimal(self.limit_offset)),
            ("received_offset", Canonical::u64_decimal(self.received_offset)),
            ("stream_id", Canonical::u64_decimal(self.stream_id)),
        ])
    }

    /// Parses the metadata.
    ///
    /// Section 7.5 requires the fields to be monotonic and to satisfy
    /// `consumed <= received <= sent_end`; the caller enforces that, because
    /// only it knows `sent_end`.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Progress";
        Ok(ProgressFields {
            stream_id: decimal_field(value, "stream_id", KIND)?,
            received_offset: decimal_field(value, "received_offset", KIND)?,
            consumed_offset: decimal_field(value, "consumed_offset", KIND)?,
            limit_offset: decimal_field(value, "limit_offset", KIND)?,
        })
    }
}

/// `Resume` metadata: in-session recovery, never a second target socket (§7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeFields {
    /// Stream being resumed.
    pub stream_id: u64,
    /// How far the sender believes the peer has received.
    pub received_offset: u64,
}

impl ResumeFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([
            ("received_offset", Canonical::u64_decimal(self.received_offset)),
            ("stream_id", Canonical::u64_decimal(self.stream_id)),
        ])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        const KIND: &str = "Resume";
        Ok(ResumeFields {
            stream_id: decimal_field(value, "stream_id", KIND)?,
            received_offset: decimal_field(value, "received_offset", KIND)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Session control
// ---------------------------------------------------------------------------

/// `CancelCandidate` metadata (§6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelCandidateFields {
    /// The losing candidate.
    pub attempt_id: [u8; 16],
}

impl CancelCandidateFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([("attempt_id", Canonical::str(hex_encode(&self.attempt_id)))])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        Ok(CancelCandidateFields {
            attempt_id: hex_field::<16>(value, "attempt_id", "CancelCandidate")?,
        })
    }
}

/// `Bye` metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByeFields {
    /// A human-readable reason, for local logs only.
    pub reason: String,
}

impl ByeFields {
    /// Builds the metadata.
    pub fn to_canonical(&self) -> Canonical {
        Canonical::object([("reason", Canonical::str(self.reason.clone()))])
    }

    /// Parses the metadata.
    pub fn from_canonical(value: &Canonical) -> Result<Self, MessageError> {
        Ok(ByeFields {
            reason: value
                .get_str("reason")
                .map(|s| s.to_string())
                .unwrap_or_default(),
        })
    }
}

/// `Bye` for a session that never had a reason recorded.
pub const BYE_NORMAL: &str = "normal";

/// The empty metadata used by `Ping`, `Pong`, and `QueryResult`-free control
/// messages.
pub fn empty_metadata() -> Canonical {
    Canonical::empty_object()
}

/// Which kinds this build actually implements, for capability negotiation.
///
/// Section 4.1 requires unknown *required* capabilities to be refused rather
/// than silently downgraded, so the set is explicit.
pub const SUPPORTED_CAPABILITIES: [&str; 6] = [
    "carrier.ws",
    "carrier.post",
    "carrier.sse",
    "profile.json",
    "profile.html",
    "flow.credit",
];

/// Capabilities that a peer must not omit.
pub const REQUIRED_CAPABILITIES: [&str; 1] = ["flow.credit"];

/// Checks a peer's capability list against this build.
pub fn negotiate_capabilities(peer: &[String]) -> Result<Vec<String>, MessageError> {
    for required in REQUIRED_CAPABILITIES {
        if !peer.iter().any(|c| c == required) {
            return Err(MessageError::UnsupportedCapability((*required).to_string()));
        }
    }
    Ok(peer
        .iter()
        .filter(|c| SUPPORTED_CAPABILITIES.contains(&c.as_str()))
        .cloned()
        .collect())
}

/// The wire name of a kind, for error messages.
pub fn kind_name(kind: MessageKind) -> &'static str {
    kind.name()
}

fn str_array(items: &[String]) -> Canonical {
    Canonical::Array(items.iter().map(|s| Canonical::str(s.clone())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_signing_canonical_excludes_the_mac() {
        let fields = AuthFields {
            version: 1,
            hub_id: "hub-a".into(),
            key_id: "a-1".into(),
            node_id: "client-a".into(),
            attempt_id: [7u8; 16],
            ts: 1_700_000_000,
            nonce: [9u8; 32],
            capabilities: vec!["carrier.ws".into()],
        };
        let signing = fields.signing_canonical();
        assert!(!String::from_utf8(signing.to_bytes())
            .unwrap()
            .contains("mac"));

        let full = fields.to_canonical(&[1u8; 32]);
        let (parsed, mac) = AuthFields::from_canonical(&full).unwrap();
        assert_eq!(parsed, fields);
        assert_eq!(mac, [1u8; 32]);
        // Rebuilding the signing input from the parsed fields must reproduce it
        // byte for byte, which is what makes the MAC verifiable.
        assert_eq!(parsed.signing_canonical().to_bytes(), signing.to_bytes());
    }

    #[test]
    fn authok_round_trips() {
        let fields = AuthOkFields {
            session_id: [1u8; 16],
            session_epoch: [2u8; 16],
            attempt_id: [3u8; 16],
            server_nonce: [4u8; 32],
            expires_at: 1_700_000_600,
            capabilities: vec!["carrier.ws".into(), "flow.credit".into()],
        };
        let value = fields.to_canonical(&[5u8; 32]);
        let (parsed, mac) = AuthOkFields::from_canonical(&value).unwrap();
        assert_eq!(parsed, fields);
        assert_eq!(mac, [5u8; 32]);
        assert_eq!(parsed.signing_canonical().to_bytes(), fields.signing_canonical().to_bytes());
    }

    #[test]
    fn hello_round_trips_with_services() {
        let fields = HelloFields {
            request_id: [1u8; 16],
            services: vec![
                ServiceRegistration {
                    name: "web".into(),
                    proto: Proto::Tcp,
                    target: "127.0.0.1:8080".into(),
                },
                ServiceRegistration {
                    name: "dns".into(),
                    proto: Proto::Udp,
                    target: "127.0.0.1:53".into(),
                },
            ],
            capabilities: vec!["carrier.ws".into()],
        };
        let value = fields.to_canonical();
        assert_eq!(HelloFields::from_canonical(&value).unwrap(), fields);
    }

    #[test]
    fn hello_rejects_an_unknown_proto() {
        let value = Canonical::object([
            ("capabilities", Canonical::Array(vec![])),
            ("request_id", Canonical::str(hex_encode(&[0u8; 16]))),
            (
                "services",
                Canonical::Array(vec![Canonical::object([
                    ("name", Canonical::str("web")),
                    ("proto", Canonical::str("sctp")),
                    ("target", Canonical::str("127.0.0.1:1")),
                ])]),
            ),
        ]);
        assert!(matches!(
            HelloFields::from_canonical(&value).unwrap_err(),
            MessageError::UnknownValue { .. }
        ));
    }

    #[test]
    fn open_round_trips_every_destination_kind() {
        for destination in [
            Destination::address("example.com", 443),
            Destination::service("client-a", "web"),
            Destination::node_address("client-a", "10.0.0.1", 22),
        ] {
            let fields = OpenFields {
                request_id: [1u8; 16],
                stream_id: 7,
                proto: Proto::Tcp,
                destination,
                via: vec!["client-b".into()],
            };
            let value = fields.to_canonical();
            assert_eq!(OpenFields::from_canonical(&value).unwrap(), fields);
        }
    }

    /// Section 5.2 hashes the Open, so two openings of the same destination must
    /// hash identically and different ones must not.
    #[test]
    fn open_operation_bytes_are_stable_and_distinct() {
        let make = |destination: Destination, stream_id: u64| OpenFields {
            request_id: [1u8; 16],
            stream_id,
            proto: Proto::Tcp,
            destination,
            via: vec![],
        };
        let a = make(Destination::service("client-a", "web"), 1);
        let b = make(Destination::service("client-a", "web"), 2);
        // The stream id is part of the request, so the hashes differ...
        assert_ne!(a.operation_bytes(), b.operation_bytes());
        // ...but re-serialising the same fields is byte-stable.
        assert_eq!(a.operation_bytes(), a.operation_bytes());
        let c = make(Destination::service("client-a", "db"), 1);
        assert_ne!(a.operation_bytes(), c.operation_bytes());
    }

    #[test]
    fn open_result_round_trips_every_status() {
        for status in [
            OpenStatus::Ok,
            OpenStatus::Refused,
            OpenStatus::Denied,
            OpenStatus::Offline,
            OpenStatus::Unreachable,
            OpenStatus::Timeout,
            OpenStatus::Conflict,
        ] {
            let fields = OpenResultFields {
                request_id: [2u8; 16],
                stream_id: 9,
                status,
                detail: "local only".into(),
            };
            let value = fields.to_canonical();
            assert_eq!(OpenResultFields::from_canonical(&value).unwrap(), fields);
        }
    }

    #[test]
    fn open_result_rejects_an_unknown_status() {
        let value = Canonical::object([
            ("request_id", Canonical::str(hex_encode(&[0u8; 16]))),
            ("status", Canonical::str("maybe")),
            ("stream_id", Canonical::u64_decimal(1)),
        ]);
        assert!(matches!(
            OpenResultFields::from_canonical(&value).unwrap_err(),
            MessageError::UnknownValue { .. }
        ));
    }

    #[test]
    fn stream_messages_round_trip() {
        let data = DataFields {
            stream_id: 3,
            offset: 4096,
        };
        assert_eq!(
            DataFields::from_canonical(&data.to_canonical()).unwrap(),
            data
        );

        let fin = FinFields {
            stream_id: 3,
            final_offset: 8192,
        };
        assert_eq!(FinFields::from_canonical(&fin.to_canonical()).unwrap(), fin);

        let ready = ReadyFields { stream_id: 3 };
        assert_eq!(
            ReadyFields::from_canonical(&ready.to_canonical()).unwrap(),
            ready
        );

        for reason in [
            ResetReason::ProtocolError,
            ResetReason::Timeout,
            ResetReason::Canceled,
            ResetReason::Overflow,
            ResetReason::Unreachable,
        ] {
            let reset = ResetFields {
                stream_id: 3,
                reason,
            };
            assert_eq!(
                ResetFields::from_canonical(&reset.to_canonical()).unwrap(),
                reset
            );
        }

        let progress = ProgressFields {
            stream_id: 3,
            received_offset: 100,
            consumed_offset: 50,
            limit_offset: 1000,
        };
        assert_eq!(
            ProgressFields::from_canonical(&progress.to_canonical()).unwrap(),
            progress
        );

        let resume = ResumeFields {
            stream_id: 3,
            received_offset: 100,
        };
        assert_eq!(
            ResumeFields::from_canonical(&resume.to_canonical()).unwrap(),
            resume
        );
    }

    /// Section 4.1: offsets must survive a full u64 range, which only works
    /// because they are decimal strings.
    #[test]
    fn large_offsets_survive_round_trip() {
        let data = DataFields {
            stream_id: u64::MAX,
            offset: u64::MAX - 1,
        };
        let text = String::from_utf8(data.to_canonical().to_bytes()).unwrap();
        assert!(text.contains(&u64::MAX.to_string()));
        assert_eq!(
            DataFields::from_canonical(&data.to_canonical()).unwrap(),
            data
        );
    }

    #[test]
    fn hex_fields_reject_the_wrong_width() {
        let value = Canonical::object([
            ("attempt_id", Canonical::str(hex_encode(&[0u8; 8]))),
        ]);
        assert!(matches!(
            CancelCandidateFields::from_canonical(&value).unwrap_err(),
            MessageError::BadHex { expected: 16, .. }
        ));

        let value = Canonical::object([("attempt_id", Canonical::str("zz"))]);
        assert!(matches!(
            CancelCandidateFields::from_canonical(&value).unwrap_err(),
            MessageError::BadHex { .. }
        ));
    }

    #[test]
    fn missing_fields_are_reported_with_their_name() {
        let value = Canonical::empty_object();
        assert_eq!(
            DataFields::from_canonical(&value).unwrap_err(),
            MessageError::MissingField {
                kind: "Data",
                field: "stream_id"
            }
        );
    }

    #[test]
    fn bye_round_trips_and_tolerates_a_missing_reason() {
        let bye = ByeFields {
            reason: "shutdown".into(),
        };
        assert_eq!(ByeFields::from_canonical(&bye.to_canonical()).unwrap(), bye);
        assert_eq!(
            ByeFields::from_canonical(&Canonical::empty_object()).unwrap().reason,
            ""
        );
    }

    /// Section 4.1: an unknown *required* capability is refused, not ignored.
    #[test]
    fn capability_negotiation_refuses_unknown_required_capabilities() {
        assert!(negotiate_capabilities(&["carrier.ws".to_string()]).is_err());

        let accepted = negotiate_capabilities(&[
            "flow.credit".to_string(),
            "carrier.ws".to_string(),
            "carrier.quantum".to_string(),
        ])
        .unwrap();
        assert_eq!(accepted, vec!["flow.credit", "carrier.ws"]);

        // The required set is a subset of the supported set.
        for required in REQUIRED_CAPABILITIES {
            assert!(SUPPORTED_CAPABILITIES.contains(&required));
        }
    }
}

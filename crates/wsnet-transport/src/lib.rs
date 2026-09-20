//! wsnet carrier encodings (DESIGN.md §4.3, §6.4).
//!
//! A carrier moves *sealed envelopes* — the bytes [`wsnet_crypto::seal`] produced —
//! between the two ends. This crate knows nothing about keys, records, or session
//! state, which is what makes each carrier independently testable and fuzzable.
//!
//! | carrier | framing |
//! | --- | --- |
//! | [`ws`] | one RFC6455 binary message per envelope; the library reassembles fragmentation |
//! | [`post`] | `envelope_len:u32be \| envelope` list, bounded by count *and* bytes |
//! | [`sse`] | `data: <base64>` plus a blank line, parsed as a stream |
//! | [`profile`] | JSON document or a delimited HTML/CSS/JS region |
//!
//! §4.3's rule that a malformed body must never execute a partial business
//! command is enforced uniformly: every decoder returns a typed error and no
//! envelopes at all, rather than the records it managed to read first.

#![forbid(unsafe_code)]

pub mod error;
pub mod post;
pub mod profile;
pub mod sse;
pub mod ws;

pub use error::CarrierError;
pub use profile::{TemplateProfile, PROFILE_VERSION, TEMPLATE_MARKER};
pub use sse::SseDecoder;

/// One of the configured carriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Carrier {
    /// WebSocket binary message.
    Ws,
    /// HTTPS POST body or response.
    Post,
    /// Server-sent events.
    Sse,
    /// JSON API profile.
    JsonProfile,
    /// HTML template profile.
    HtmlProfile,
    /// CSS template profile.
    CssProfile,
    /// JavaScript template profile.
    JsProfile,
}

impl Carrier {
    /// The carrier's name, for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Carrier::Ws => "ws",
            Carrier::Post => "post",
            Carrier::Sse => "sse",
            Carrier::JsonProfile => "json-profile",
            Carrier::HtmlProfile => "html-profile",
            Carrier::CssProfile => "css-profile",
            Carrier::JsProfile => "js-profile",
        }
    }

    /// Whether this carrier may carry client-to-server business data (§6.1).
    ///
    /// §6.1 is explicit that SSE is a downlink-only carrier and never carries
    /// authentication, so this is a property of the carrier rather than a
    /// convention the scheduler is trusted to remember.
    pub const fn is_uplink_capable(self) -> bool {
        matches!(
            self,
            Carrier::Ws
                | Carrier::Post
                | Carrier::JsonProfile
                | Carrier::HtmlProfile
                | Carrier::CssProfile
                | Carrier::JsProfile
        )
    }

    fn template(self) -> Option<TemplateProfile> {
        match self {
            Carrier::HtmlProfile => Some(TemplateProfile::HTML),
            Carrier::CssProfile => Some(TemplateProfile::CSS),
            Carrier::JsProfile => Some(TemplateProfile::JS),
            _ => None,
        }
    }

    /// Encodes envelopes for this carrier.
    ///
    /// The WebSocket carrier holds exactly one envelope per message, so any other
    /// count is a programming error rather than something to split silently.
    pub fn encode(self, envelopes: &[Vec<u8>]) -> Result<Vec<u8>, CarrierError> {
        match self {
            Carrier::Ws => match envelopes {
                [single] => ws::encode(single),
                _ => Err(CarrierError::MalformedProfile {
                    profile: "ws",
                    reason: "a WebSocket message carries exactly one envelope",
                }),
            },
            Carrier::Post => post::encode(envelopes),
            Carrier::Sse => sse::encode(envelopes),
            Carrier::JsonProfile => profile::json::encode(envelopes),
            other => other
                .template()
                .expect("template carriers are matched above")
                .encode(envelopes),
        }
    }

    /// Decodes a complete body for this carrier.
    pub fn decode(self, body: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
        match self {
            Carrier::Ws => Ok(vec![ws::decode(body)?]),
            Carrier::Post => post::decode(body),
            Carrier::Sse => sse::decode(body),
            Carrier::JsonProfile => profile::json::decode(body),
            other => other
                .template()
                .expect("template carriers are matched above")
                .decode(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    /// Every carrier must round-trip the same envelope list.
    #[test]
    fn all_carriers_round_trip() {
        let batch = vec![envelope(1, 16), envelope(2, 300)];
        for carrier in [
            Carrier::Post,
            Carrier::Sse,
            Carrier::JsonProfile,
            Carrier::HtmlProfile,
            Carrier::CssProfile,
            Carrier::JsProfile,
        ] {
            let body = carrier.encode(&batch).unwrap();
            assert_eq!(
                carrier.decode(&body).unwrap(),
                batch,
                "carrier {} did not round-trip",
                carrier.name()
            );
        }
    }

    #[test]
    fn websocket_carrier_holds_exactly_one_envelope() {
        let one = vec![envelope(5, 64)];
        let body = Carrier::Ws.encode(&one).unwrap();
        assert_eq!(Carrier::Ws.decode(&body).unwrap(), one);

        assert!(Carrier::Ws.encode(&[]).is_err());
        assert!(Carrier::Ws
            .encode(&[envelope(1, 1), envelope(2, 1)])
            .is_err());
    }

    /// §6.1: SSE is downlink-only and never carries uplink business data.
    #[test]
    fn sse_is_not_uplink_capable() {
        assert!(!Carrier::Sse.is_uplink_capable());
        assert!(Carrier::Ws.is_uplink_capable());
        assert!(Carrier::Post.is_uplink_capable());
    }

    #[test]
    fn carrier_names_are_unique() {
        let all = [
            Carrier::Ws,
            Carrier::Post,
            Carrier::Sse,
            Carrier::JsonProfile,
            Carrier::HtmlProfile,
            Carrier::CssProfile,
            Carrier::JsProfile,
        ];
        let names: std::collections::BTreeSet<_> = all.iter().map(|c| c.name()).collect();
        assert_eq!(names.len(), all.len());
    }

    /// A malformed body must yield an error, never a partial batch.
    #[test]
    fn malformed_bodies_yield_no_partial_batch() {
        for carrier in [
            Carrier::Post,
            Carrier::Sse,
            Carrier::JsonProfile,
            Carrier::HtmlProfile,
            Carrier::CssProfile,
            Carrier::JsProfile,
        ] {
            assert!(
                carrier
                    .decode(b"definitely not a valid carrier body")
                    .is_err(),
                "carrier {} accepted garbage",
                carrier.name()
            );
        }
    }

    /// T20: arbitrary bodies must not panic any carrier decoder.
    #[test]
    fn hostile_bodies_do_not_panic() {
        let bodies: &[&[u8]] = &[
            b"",
            b"\x00\x00\x00\xff",
            b"data:",
            b"data: \n\n",
            b"<!--",
            b"/*wsnet:v1:",
            b"{\"d\":[",
            b"\xff\xfe\xfd",
            &[0u8; 64],
        ];
        for carrier in [
            Carrier::Ws,
            Carrier::Post,
            Carrier::Sse,
            Carrier::JsonProfile,
            Carrier::HtmlProfile,
            Carrier::CssProfile,
            Carrier::JsProfile,
        ] {
            for body in bodies {
                let _ = carrier.decode(body);
            }
        }
    }
}

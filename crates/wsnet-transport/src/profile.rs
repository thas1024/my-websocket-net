//! Site-shape profiles (DESIGN.md §6.4).
//!
//! > 形态 profile 是应用层编码，不修改 HTTP/TLS/WS 标准。
//!
//! Two shapes are provided:
//!
//! * [`json`] — a real JSON document (`{"d":[...],"v":1}`), parsed with the
//!   workspace's own bounded canonical-JSON parser, so duplicate keys, floats,
//!   and over-long integers are refused.
//! * [`template`] — a negotiated, delimited region inside an HTML, CSS, or JS
//!   document. The document itself is never rendered or executed: the decoder
//!   scans bytes for the configured markers, which is why §6.4's "不执行 JS、不
//!   任意渲染 HTML" holds by construction rather than by discipline.

use crate::error::CarrierError;

/// The profile version this build emits and accepts.
pub const PROFILE_VERSION: i64 = 1;
/// The marker text that identifies a wsnet payload inside a template.
pub const TEMPLATE_MARKER: &[u8] = b"wsnet:v1:";

/// JSON API profile.
pub mod json {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    use super::PROFILE_VERSION;
    use crate::error::CarrierError;
    use wsnet_limits::{MAX_CARRIER_RECORD, MAX_HTTP_BODY};
    use wsnet_protocol::Canonical;

    /// The key carrying the envelope list.
    pub const DATA_KEY: &str = "d";
    /// The key carrying the profile version.
    pub const VERSION_KEY: &str = "v";

    /// Encodes sealed envelopes as a JSON document.
    pub fn encode(envelopes: &[Vec<u8>]) -> Result<Vec<u8>, CarrierError> {
        let mut items = Vec::with_capacity(envelopes.len());
        for envelope in envelopes {
            if envelope.len() > MAX_CARRIER_RECORD {
                return Err(CarrierError::EnvelopeTooLarge {
                    actual: envelope.len(),
                    limit: MAX_CARRIER_RECORD,
                });
            }
            items.push(Canonical::str(STANDARD.encode(envelope)));
        }

        let document = Canonical::object([
            (DATA_KEY, Canonical::Array(items)),
            (VERSION_KEY, Canonical::int(PROFILE_VERSION)),
        ]);
        let body = document.to_bytes();
        if body.len() > MAX_HTTP_BODY {
            return Err(CarrierError::BodyTooLarge {
                actual: body.len(),
                limit: MAX_HTTP_BODY,
            });
        }
        Ok(body)
    }

    /// Decodes a JSON document into sealed envelopes.
    pub fn decode(body: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
        let document = Canonical::from_bytes_bounded(body, MAX_HTTP_BODY).map_err(|_| {
            CarrierError::MalformedProfile {
                profile: "json",
                reason: "body is not canonical JSON within the body bound",
            }
        })?;

        let version =
            document
                .get_i64(VERSION_KEY)
                .map_err(|_| CarrierError::MalformedProfile {
                    profile: "json",
                    reason: "missing or non-integer version field",
                })?;
        if version != PROFILE_VERSION {
            return Err(CarrierError::UnsupportedProfileVersion {
                profile: "json",
                found: version.unsigned_abs(),
            });
        }

        let items = document
            .get_array(DATA_KEY)
            .map_err(|_| CarrierError::MalformedProfile {
                profile: "json",
                reason: "missing data array",
            })?;

        let mut envelopes = Vec::with_capacity(items.len());
        for item in items {
            let encoded = match item {
                Canonical::Str(value) => value,
                _ => {
                    return Err(CarrierError::MalformedProfile {
                        profile: "json",
                        reason: "data array must contain only strings",
                    })
                }
            };
            let envelope =
                STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|_| CarrierError::InvalidBase64 {
                        field: "json data item",
                    })?;
            if envelope.len() > MAX_CARRIER_RECORD {
                return Err(CarrierError::EnvelopeTooLarge {
                    actual: envelope.len(),
                    limit: MAX_CARRIER_RECORD,
                });
            }
            envelopes.push(envelope);
        }
        Ok(envelopes)
    }
}

/// A delimited HTML/CSS/JS template profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateProfile {
    /// Name used in diagnostics, matching §6.4's table.
    pub name: &'static str,
    /// Bytes that open the payload region.
    pub open: &'static [u8],
    /// Bytes that close the payload region.
    pub close: &'static [u8],
}

impl TemplateProfile {
    /// HTML comment form: `<!--wsnet:v1:...-->`.
    pub const HTML: TemplateProfile = TemplateProfile {
        name: "html",
        open: b"<!--",
        close: b"-->",
    };

    /// CSS comment form: `/*wsnet:v1:...*/`.
    pub const CSS: TemplateProfile = TemplateProfile {
        name: "css",
        open: b"/*",
        close: b"*/",
    };

    /// JavaScript comment form. A block comment is used rather than a string or
    /// an identifier so that loading the document cannot execute anything.
    pub const JS: TemplateProfile = TemplateProfile {
        name: "js",
        open: b"/*",
        close: b"*/",
    };

    /// Encodes sealed envelopes into a payload region wrapped by this profile's
    /// delimiters.
    pub fn encode(&self, envelopes: &[Vec<u8>]) -> Result<Vec<u8>, CarrierError> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        let mut out = Vec::new();
        out.extend_from_slice(self.open);
        out.extend_from_slice(TEMPLATE_MARKER);
        for (index, envelope) in envelopes.iter().enumerate() {
            if envelope.len() > MAX_CARRIER_RECORD {
                return Err(CarrierError::EnvelopeTooLarge {
                    actual: envelope.len(),
                    limit: MAX_CARRIER_RECORD,
                });
            }
            if index > 0 {
                out.push(b'\n');
            }
            out.extend_from_slice(STANDARD.encode(envelope).as_bytes());
        }
        out.extend_from_slice(self.close);
        if out.len() > MAX_HTTP_BODY {
            return Err(CarrierError::BodyTooLarge {
                actual: out.len(),
                limit: MAX_HTTP_BODY,
            });
        }
        Ok(out)
    }

    /// Extracts and decodes the payload region from a document.
    ///
    /// The document is only scanned; nothing is executed or rendered.
    pub fn decode(&self, document: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;

        if document.len() > MAX_HTTP_BODY {
            return Err(CarrierError::BodyTooLarge {
                actual: document.len(),
                limit: MAX_HTTP_BODY,
            });
        }

        let open_at = find(document, self.open).ok_or(CarrierError::MalformedProfile {
            profile: self.name,
            reason: "opening delimiter not found",
        })?;
        let after_open = open_at + self.open.len();
        let close_at = find(&document[after_open..], self.close)
            .map(|offset| after_open + offset)
            .ok_or(CarrierError::MalformedProfile {
                profile: self.name,
                reason: "closing delimiter not found",
            })?;

        let region = &document[after_open..close_at];
        let payload =
            region
                .strip_prefix(TEMPLATE_MARKER)
                .ok_or(CarrierError::MalformedProfile {
                    profile: self.name,
                    reason: "payload region is missing the wsnet marker",
                })?;

        let text = std::str::from_utf8(payload).map_err(|_| CarrierError::InvalidUtf8 {
            field: "template payload",
        })?;
        let mut envelopes = Vec::new();
        for line in text.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let envelope =
                STANDARD
                    .decode(line.as_bytes())
                    .map_err(|_| CarrierError::InvalidBase64 {
                        field: "template payload line",
                    })?;
            if envelope.len() > MAX_CARRIER_RECORD {
                return Err(CarrierError::EnvelopeTooLarge {
                    actual: envelope.len(),
                    limit: MAX_CARRIER_RECORD,
                });
            }
            envelopes.push(envelope);
        }
        Ok(envelopes)
    }
}

use wsnet_limits::{MAX_CARRIER_RECORD, MAX_HTTP_BODY};

/// Finds the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    #[test]
    fn json_round_trip() {
        let batch = vec![envelope(1, 10), envelope(2, 0), envelope(3, 300)];
        let body = json::encode(&batch).unwrap();
        assert_eq!(json::decode(&body).unwrap(), batch);
    }

    #[test]
    fn json_document_shape_is_as_documented() {
        let body = json::encode(&[envelope(0xAB, 1)]).unwrap();
        let text = String::from_utf8(body).unwrap();
        // Keys are sorted, so "d" precedes "v".
        assert!(text.starts_with(r#"{"d":["#), "unexpected document: {text}");
        assert!(text.ends_with(r#"],"v":1}"#), "unexpected document: {text}");
    }

    /// T20: the JSON profile inherits the canonical parser's hardening.
    #[test]
    fn json_duplicate_keys_are_rejected() {
        assert!(json::decode(br#"{"d":[],"d":[],"v":1}"#).is_err());
    }

    #[test]
    fn json_version_is_checked() {
        assert_eq!(
            json::decode(br#"{"d":[],"v":2}"#).unwrap_err(),
            CarrierError::UnsupportedProfileVersion {
                profile: "json",
                found: 2
            }
        );
        assert!(json::decode(br#"{"d":[]}"#).is_err());
        assert!(json::decode(br#"{"d":[],"v":"1"}"#).is_err());
    }

    #[test]
    fn json_non_string_items_are_rejected() {
        assert!(json::decode(br#"{"d":[1],"v":1}"#).is_err());
        assert!(json::decode(br#"{"d":[["x"]],"v":1}"#).is_err());
    }

    #[test]
    fn json_invalid_base64_is_rejected() {
        assert_eq!(
            json::decode(br#"{"d":["***"],"v":1}"#).unwrap_err(),
            CarrierError::InvalidBase64 {
                field: "json data item"
            }
        );
    }

    #[test]
    fn json_empty_batch_round_trips() {
        let body = json::encode(&[]).unwrap();
        assert_eq!(json::decode(&body).unwrap(), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn template_round_trips_for_every_profile() {
        let batch = vec![envelope(1, 10), envelope(2, 200)];
        for profile in [
            TemplateProfile::HTML,
            TemplateProfile::CSS,
            TemplateProfile::JS,
        ] {
            let document = profile.encode(&batch).unwrap();
            assert_eq!(
                profile.decode(&document).unwrap(),
                batch,
                "profile {} failed",
                profile.name
            );
        }
    }

    #[test]
    fn template_embeds_inside_a_real_document() {
        let batch = vec![envelope(9, 32)];
        let payload = TemplateProfile::HTML.encode(&batch).unwrap();
        let mut document = b"<!doctype html><html><head><title>site</title></head><body>".to_vec();
        document.extend_from_slice(&payload);
        document.extend_from_slice(b"</body></html>");
        assert_eq!(TemplateProfile::HTML.decode(&document).unwrap(), batch);
    }

    /// §6.4: a profile document must not be executed. The decoder only scans, so
    /// hostile script text next to the payload is inert data.
    #[test]
    fn hostile_script_text_is_never_executed() {
        let batch = vec![envelope(3, 8)];
        let payload = TemplateProfile::JS.encode(&batch).unwrap();
        let mut document = b"<script>process.exit(1)</script>".to_vec();
        document.extend_from_slice(&payload);
        assert_eq!(TemplateProfile::JS.decode(&document).unwrap(), batch);
    }

    #[test]
    fn template_missing_delimiters_are_rejected() {
        assert!(matches!(
            TemplateProfile::HTML
                .decode(b"<html>no payload</html>")
                .unwrap_err(),
            CarrierError::MalformedProfile {
                profile: "html",
                ..
            }
        ));
        assert!(matches!(
            TemplateProfile::HTML.decode(b"<!--unclosed").unwrap_err(),
            CarrierError::MalformedProfile {
                profile: "html",
                ..
            }
        ));
    }

    #[test]
    fn template_missing_marker_is_rejected() {
        assert!(matches!(
            TemplateProfile::HTML.decode(b"<!--AQID-->").unwrap_err(),
            CarrierError::MalformedProfile {
                profile: "html",
                ..
            }
        ));
    }

    #[test]
    fn template_invalid_base64_is_rejected() {
        assert_eq!(
            TemplateProfile::HTML
                .decode(b"<!--wsnet:v1:***-->")
                .unwrap_err(),
            CarrierError::InvalidBase64 {
                field: "template payload line"
            }
        );
    }

    #[test]
    fn template_empty_batch_round_trips() {
        let document = TemplateProfile::CSS.encode(&[]).unwrap();
        assert_eq!(
            TemplateProfile::CSS.decode(&document).unwrap(),
            Vec::<Vec<u8>>::new()
        );
    }

    #[test]
    fn find_helper_handles_edges() {
        assert_eq!(find(b"", b"x"), None);
        assert_eq!(find(b"abc", b""), None);
        assert_eq!(find(b"abc", b"cd"), None);
        assert_eq!(find(b"abc", b"bc"), Some(1));
        assert_eq!(find(b"abc", b"a"), Some(0));
    }
}

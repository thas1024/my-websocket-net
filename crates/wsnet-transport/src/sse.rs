//! SSE carrier (DESIGN.md §4.3).
//!
//! > SSE | `data: <base64(envelope)>` 加空行，每事件一份完整信封；先流式解析 SSE
//! > 行/事件，再 base64 解码；支持任意网络分块
//!
//! The decoder is a streaming line/event parser, not a "split the body on \n\n"
//! shortcut, so a chunk boundary may fall anywhere — mid-line, mid-CRLF, or
//! between two events (T08/T18). Events are only decoded once terminated, and an
//! oversized or malformed event is refused without emitting a partial batch.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::CarrierError;
use wsnet_limits::{MAX_CARRIER_RECORD, MAX_SSE_EVENT};

/// Encodes sealed envelopes as an SSE response body.
pub fn encode(envelopes: &[Vec<u8>]) -> Result<Vec<u8>, CarrierError> {
    let mut out = Vec::new();
    for envelope in envelopes {
        if envelope.len() > MAX_CARRIER_RECORD {
            return Err(CarrierError::EnvelopeTooLarge {
                actual: envelope.len(),
                limit: MAX_CARRIER_RECORD,
            });
        }
        let encoded = STANDARD.encode(envelope);
        // "data: " + payload, then the blank line that terminates the event.
        if encoded.len() + 8 > MAX_SSE_EVENT {
            return Err(CarrierError::SseEventTooLarge {
                actual: encoded.len() + 8,
                limit: MAX_SSE_EVENT,
            });
        }
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(encoded.as_bytes());
        out.extend_from_slice(b"\n\n");
    }
    Ok(out)
}

/// Decodes a complete SSE body.
pub fn decode(body: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
    let mut decoder = SseDecoder::new();
    let mut envelopes = decoder.feed(body)?;
    decoder.finish()?;
    envelopes.shrink_to_fit();
    Ok(envelopes)
}

/// A streaming SSE parser that emits one envelope per terminated event.
#[derive(Debug, Default)]
pub struct SseDecoder {
    /// Bytes received but not yet formed into a complete line.
    pending: Vec<u8>,
    /// Accumulated `data:` payload for the event currently being built.
    data: String,
    /// Whether the current event has seen at least one `data:` field.
    has_data: bool,
}

impl SseDecoder {
    /// A fresh decoder.
    pub fn new() -> Self {
        SseDecoder::default()
    }

    /// Feeds an arbitrary network chunk and returns any events it completed.
    ///
    /// Callers are expected to bound `chunk` by the HTTP body budget; the
    /// decoder additionally refuses any single unterminated line larger than the
    /// SSE event bound, so a hostile peer cannot grow `pending` without limit.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
        self.pending.extend_from_slice(chunk);

        let mut finished = Vec::new();
        let mut line_start = 0usize;
        let mut i = 0usize;
        while i < self.pending.len() {
            match self.pending[i] {
                b'\n' => {
                    let line = self.pending[line_start..i].to_vec();
                    i += 1;
                    line_start = i;
                    self.handle_line(&line, &mut finished)?;
                }
                b'\r' => {
                    let line = self.pending[line_start..i].to_vec();
                    // A CRLF pair counts as one terminator.
                    i += if self.pending.get(i + 1) == Some(&b'\n') {
                        2
                    } else {
                        1
                    };
                    line_start = i;
                    self.handle_line(&line, &mut finished)?;
                }
                _ => i += 1,
            }
        }
        self.pending.drain(..line_start);

        // Whatever is left is one unterminated line; it must fit one event.
        if self.pending.len() > MAX_SSE_EVENT {
            return Err(CarrierError::SseEventTooLarge {
                actual: self.pending.len(),
                limit: MAX_SSE_EVENT,
            });
        }
        Ok(finished)
    }

    /// Declares the stream finished.
    ///
    /// A conforming peer terminates every event with a blank line, so a leftover
    /// line or an undispatched payload is a protocol error rather than a
    /// half-applied event.
    pub fn finish(self) -> Result<(), CarrierError> {
        if !self.pending.is_empty() || self.has_data {
            return Err(CarrierError::IncompleteEvent);
        }
        Ok(())
    }

    fn handle_line(
        &mut self,
        line: &[u8],
        finished: &mut Vec<Vec<u8>>,
    ) -> Result<(), CarrierError> {
        // A blank line dispatches the event.
        if line.is_empty() {
            return self.dispatch(finished);
        }
        // Comments start with ':' and carry no business data.
        if line[0] == b':' {
            return Ok(());
        }
        let (field, value) = match line.iter().position(|b| *b == b':') {
            Some(colon) => (&line[..colon], &line[colon + 1..]),
            // A bare word is a field name with an empty value.
            None => (line, &line[line.len()..]),
        };
        if field != b"data" {
            // `event:`, `id:`, `retry:`, and unknown fields are ignored: none of
            // them may be treated as business payload, and `Last-Event-ID` is
            // explicitly not a credential (§4.4).
            return Ok(());
        }
        // One optional leading space after the colon is part of the framing.
        let value = value.strip_prefix(b" ").unwrap_or(value);
        let value = std::str::from_utf8(value).map_err(|_| CarrierError::InvalidUtf8 {
            field: "sse data field",
        })?;
        if self.has_data {
            self.data.push('\n');
        }
        self.data.push_str(value);
        self.has_data = true;
        if self.data.len() > MAX_SSE_EVENT {
            return Err(CarrierError::SseEventTooLarge {
                actual: self.data.len(),
                limit: MAX_SSE_EVENT,
            });
        }
        Ok(())
    }

    fn dispatch(&mut self, finished: &mut Vec<Vec<u8>>) -> Result<(), CarrierError> {
        if !self.has_data {
            return Ok(());
        }
        let payload = std::mem::take(&mut self.data);
        self.has_data = false;

        // A multi-line `data:` field is joined with '\n' by the SSE spec; our
        // encoder never emits that, so a joined value simply fails base64
        // decoding rather than being silently truncated.
        let envelope = STANDARD
            .decode(payload.as_bytes())
            .map_err(|_| CarrierError::InvalidBase64 { field: "sse event" })?;
        if envelope.len() > MAX_CARRIER_RECORD {
            return Err(CarrierError::EnvelopeTooLarge {
                actual: envelope.len(),
                limit: MAX_CARRIER_RECORD,
            });
        }
        finished.push(envelope);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn envelope(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    #[test]
    fn round_trip() {
        let batch = vec![envelope(1, 10), envelope(2, 0), envelope(3, 500)];
        let body = encode(&batch).unwrap();
        assert_eq!(decode(&body).unwrap(), batch);
    }

    #[test]
    fn layout_is_data_field_plus_blank_line() {
        let body = encode(&[envelope(0xAB, 3)]).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("data: "));
        assert!(text.ends_with("\n\n"));
        assert_eq!(STANDARD.decode(text[6..].trim()).unwrap(), vec![0xAB; 3]);
    }

    /// T18/T08: a chunk boundary may fall anywhere, including inside the CRLF.
    #[test]
    fn every_chunk_split_produces_identical_results() {
        let batch = vec![envelope(1, 64), envelope(2, 200), envelope(3, 7)];
        let body = encode(&batch).unwrap();

        // Feed one byte at a time.
        let mut decoder = SseDecoder::new();
        let mut collected = Vec::new();
        for byte in &body {
            collected.extend(decoder.feed(&[*byte]).unwrap());
        }
        decoder.finish().unwrap();
        assert_eq!(collected, batch);

        // Feed every possible two-way split.
        for split in 0..=body.len() {
            let mut decoder = SseDecoder::new();
            let mut collected = decoder.feed(&body[..split]).unwrap();
            collected.extend(decoder.feed(&body[split..]).unwrap());
            decoder.finish().unwrap();
            assert_eq!(collected, batch, "split at {split} changed the result");
        }
    }

    /// Random chunking must not change the outcome.
    #[test]
    fn randomised_chunking_is_stable() {
        let batch: Vec<Vec<u8>> = (0..20).map(|i| envelope(i as u8, i * 13)).collect();
        let body = encode(&batch).unwrap();

        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..50 {
            let mut decoder = SseDecoder::new();
            let mut collected = Vec::new();
            let mut cursor = 0usize;
            while cursor < body.len() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let take = ((seed % 17) as usize + 1).min(body.len() - cursor);
                collected.extend(decoder.feed(&body[cursor..cursor + take]).unwrap());
                cursor += take;
            }
            decoder.finish().unwrap();
            assert_eq!(collected, batch);
        }
    }

    #[test]
    fn crlf_terminators_are_accepted() {
        let body = b"data: AQID\r\n\r\ndata: BAUG\r\n\r\n";
        let decoded = decode(body).unwrap();
        assert_eq!(decoded, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }

    #[test]
    fn comments_and_other_fields_are_ignored() {
        // `id:` must never be treated as a credential or as payload (§4.4).
        let body = b": keep-alive\nevent: message\nid: 42\nretry: 100\ndata: AQID\n\n";
        assert_eq!(decode(body).unwrap(), vec![vec![1, 2, 3]]);
    }

    #[test]
    fn a_missing_space_after_the_colon_is_accepted() {
        assert_eq!(decode(b"data:AQID\n\n").unwrap(), vec![vec![1, 2, 3]]);
    }

    #[test]
    fn invalid_base64_is_rejected() {
        assert_eq!(
            decode(b"data: not*base64!\n\n").unwrap_err(),
            CarrierError::InvalidBase64 { field: "sse event" }
        );
    }

    /// Non-canonical padding must not be accepted as if it were valid.
    #[test]
    fn non_canonical_padding_is_rejected() {
        // "AQID" is canonical; a stray '=' is not.
        assert!(decode(b"data: AQID=\n\n").is_err());
        assert!(decode(b"data: AQI\n\n").is_err());
    }

    /// T20: a malformed event must not produce a partial batch.
    #[test]
    fn a_bad_event_yields_no_partial_batch() {
        let mut decoder = SseDecoder::new();
        // First event is fine, second is corrupt.
        assert_eq!(decoder.feed(b"data: AQID\n\n").unwrap().len(), 1);
        assert!(decoder.feed(b"data: ***\n\n").is_err());
    }

    #[test]
    fn unterminated_stream_is_an_error() {
        let mut decoder = SseDecoder::new();
        decoder.feed(b"data: AQID").unwrap();
        assert_eq!(decoder.finish().unwrap_err(), CarrierError::IncompleteEvent);

        let mut decoder = SseDecoder::new();
        decoder.feed(b"data: AQID\n").unwrap();
        assert_eq!(decoder.finish().unwrap_err(), CarrierError::IncompleteEvent);

        // A properly terminated stream is clean.
        let mut decoder = SseDecoder::new();
        decoder.feed(b"data: AQID\n\n").unwrap();
        decoder.finish().unwrap();
    }

    /// A single unterminated line larger than the event bound is refused, so a
    /// hostile peer cannot grow the buffer without limit.
    #[test]
    fn oversized_unterminated_line_is_rejected() {
        let mut decoder = SseDecoder::new();
        let huge = vec![b'A'; MAX_SSE_EVENT + 1];
        assert!(matches!(
            decoder.feed(&huge).unwrap_err(),
            CarrierError::SseEventTooLarge { .. }
        ));
    }

    #[test]
    fn oversized_event_payload_is_rejected() {
        let mut decoder = SseDecoder::new();
        let mut body = b"data: ".to_vec();
        body.extend(std::iter::repeat(b'A').take(MAX_SSE_EVENT + 1));
        assert!(matches!(
            decoder.feed(&body).unwrap_err(),
            CarrierError::SseEventTooLarge { .. }
        ));
    }

    #[test]
    fn oversized_envelope_is_rejected_on_encode() {
        assert!(matches!(
            encode(&[envelope(0, MAX_CARRIER_RECORD + 1)]).unwrap_err(),
            CarrierError::EnvelopeTooLarge { .. }
        ));
    }

    /// Events are emitted in order and exactly once.
    #[test]
    fn ordering_is_preserved() {
        let batch: Vec<Vec<u8>> = (0..30u8).map(|i| vec![i; (i as usize) + 1]).collect();
        let body = encode(&batch).unwrap();
        let decoded = decode(&body).unwrap();
        assert_eq!(decoded, batch);
        let seen: BTreeSet<Vec<u8>> = decoded.into_iter().collect();
        assert_eq!(seen.len(), 30);
    }
}

//! WebSocket carrier (DESIGN.md §4.3).
//!
//! > WS | 一条 RFC6455 Binary message 一份完整信封；先由库重组 WS fragmentation，
//! > 再解码；不把 TCP read 边界当消息边界
//!
//! There is deliberately no framing to implement here: a WebSocket library hands
//! the application whole messages, so reassembling `fragmentation` and ignoring
//! TCP read boundaries is the library's contract. This module is the validation
//! boundary that guarantees the property the design actually cares about —
//! exactly one sealed envelope per binary message, within the size bound.

use crate::error::CarrierError;
use wsnet_limits::MAX_CARRIER_RECORD;

/// Encodes one sealed envelope as a WebSocket binary message payload.
///
/// The bytes are passed through unchanged; this exists so that the WS carrier
/// enforces the same bound as every other carrier instead of relying on the
/// caller.
pub fn encode(envelope: &[u8]) -> Result<Vec<u8>, CarrierError> {
    check(envelope)?;
    Ok(envelope.to_vec())
}

/// Validates and returns one WebSocket binary message payload as an envelope.
pub fn decode(message: &[u8]) -> Result<Vec<u8>, CarrierError> {
    check(message)?;
    Ok(message.to_vec())
}

/// Returns the envelope without copying, after validating its bound.
pub fn decode_ref(message: &[u8]) -> Result<&[u8], CarrierError> {
    check(message)?;
    Ok(message)
}

fn check(envelope: &[u8]) -> Result<(), CarrierError> {
    if envelope.len() > MAX_CARRIER_RECORD {
        return Err(CarrierError::EnvelopeTooLarge {
            actual: envelope.len(),
            limit: MAX_CARRIER_RECORD,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_byte_identical() {
        let envelope = vec![7u8; 1000];
        let message = encode(&envelope).unwrap();
        assert_eq!(message, envelope);
        assert_eq!(decode(&message).unwrap(), envelope);
    }

    #[test]
    fn empty_envelope_is_allowed() {
        // An empty message is a legal seal of an empty plaintext; the record
        // layer, not the carrier, decides whether the contents are meaningful.
        assert!(encode(&[]).is_ok());
        assert_eq!(decode(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn oversized_message_is_rejected() {
        let huge = vec![0u8; MAX_CARRIER_RECORD + 1];
        assert_eq!(
            encode(&huge).unwrap_err(),
            CarrierError::EnvelopeTooLarge {
                actual: MAX_CARRIER_RECORD + 1,
                limit: MAX_CARRIER_RECORD
            }
        );
        assert!(decode(&huge).is_err());
        assert!(decode_ref(&huge).is_err());
    }

    #[test]
    fn decode_ref_borrows_without_copying() {
        let envelope = vec![1u8, 2, 3];
        let borrowed = decode_ref(&envelope).unwrap();
        assert_eq!(borrowed, &envelope[..]);
        assert_eq!(borrowed.as_ptr(), envelope.as_ptr());
    }

    #[test]
    fn maximum_size_message_is_accepted() {
        let envelope = vec![0u8; MAX_CARRIER_RECORD];
        assert!(decode(&envelope).is_ok());
    }
}

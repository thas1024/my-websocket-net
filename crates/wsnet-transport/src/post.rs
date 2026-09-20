//! HTTPS POST carrier (DESIGN.md §4.3).
//!
//! > POST body / response | 二进制 `envelope_len:u32be + envelope` 列表；每批解码后
//! > 不超过 256 KiB、至多 64 记录
//!
//! Both caps are applied independently. A 64-record batch of maximum-size
//! records therefore does not fit — the byte cap binds for large records and the
//! count cap binds for small ones — so `decode` checks the count, the running
//! byte total, and each declared length before it copies anything.

use crate::error::CarrierError;
use wsnet_limits::{MAX_CARRIER_RECORD, MAX_POST_BATCH_BYTES, MAX_POST_BATCH_RECORDS};

/// Encodes a list of sealed envelopes as a POST body.
pub fn encode(envelopes: &[Vec<u8>]) -> Result<Vec<u8>, CarrierError> {
    if envelopes.len() > MAX_POST_BATCH_RECORDS {
        return Err(CarrierError::TooManyRecords {
            actual: envelopes.len(),
            limit: MAX_POST_BATCH_RECORDS,
        });
    }
    let mut total = 0usize;
    for envelope in envelopes {
        if envelope.len() > MAX_CARRIER_RECORD {
            return Err(CarrierError::EnvelopeTooLarge {
                actual: envelope.len(),
                limit: MAX_CARRIER_RECORD,
            });
        }
        total += 4 + envelope.len();
    }
    if total > MAX_POST_BATCH_BYTES {
        return Err(CarrierError::BodyTooLarge {
            actual: total,
            limit: MAX_POST_BATCH_BYTES,
        });
    }

    let mut out = Vec::with_capacity(total);
    for envelope in envelopes {
        out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        out.extend_from_slice(envelope);
    }
    Ok(out)
}

/// Decodes a POST body into its sealed envelopes.
pub fn decode(body: &[u8]) -> Result<Vec<Vec<u8>>, CarrierError> {
    if body.len() > MAX_POST_BATCH_BYTES {
        return Err(CarrierError::BodyTooLarge {
            actual: body.len(),
            limit: MAX_POST_BATCH_BYTES,
        });
    }

    let mut envelopes = Vec::new();
    let mut cursor = 0usize;
    while cursor < body.len() {
        if envelopes.len() >= MAX_POST_BATCH_RECORDS {
            return Err(CarrierError::TooManyRecords {
                actual: envelopes.len() + 1,
                limit: MAX_POST_BATCH_RECORDS,
            });
        }
        let header = body
            .get(cursor..cursor + 4)
            .ok_or(CarrierError::Truncated {
                field: "envelope_len",
            })?;
        let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        cursor += 4;

        // Bound the declared length before slicing, per §4.1's "先限长再分配/解码".
        if len > MAX_CARRIER_RECORD {
            return Err(CarrierError::EnvelopeTooLarge {
                actual: len,
                limit: MAX_CARRIER_RECORD,
            });
        }
        let envelope = body
            .get(cursor..cursor + len)
            .ok_or(CarrierError::Truncated { field: "envelope" })?;
        cursor += len;
        envelopes.push(envelope.to_vec());
    }
    Ok(envelopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    #[test]
    fn round_trip() {
        let batch = vec![envelope(1, 10), envelope(2, 0), envelope(3, 1000)];
        let body = encode(&batch).unwrap();
        assert_eq!(decode(&body).unwrap(), batch);
    }

    #[test]
    fn layout_is_length_prefixed_big_endian() {
        let body = encode(&[envelope(0xAB, 3)]).unwrap();
        assert_eq!(&body[0..4], &3u32.to_be_bytes());
        assert_eq!(&body[4..], &[0xAB, 0xAB, 0xAB]);
    }

    #[test]
    fn empty_batch_round_trips() {
        let body = encode(&[]).unwrap();
        assert!(body.is_empty());
        assert!(decode(&body).unwrap().is_empty());
    }

    #[test]
    fn too_many_records_are_rejected_on_encode() {
        let batch = vec![envelope(0, 1); MAX_POST_BATCH_RECORDS + 1];
        assert_eq!(
            encode(&batch).unwrap_err(),
            CarrierError::TooManyRecords {
                actual: MAX_POST_BATCH_RECORDS + 1,
                limit: MAX_POST_BATCH_RECORDS
            }
        );
    }

    #[test]
    fn too_many_records_are_rejected_on_decode() {
        // 65 empty records: within the byte cap, past the count cap.
        let mut body = Vec::new();
        for _ in 0..(MAX_POST_BATCH_RECORDS + 1) {
            body.extend_from_slice(&0u32.to_be_bytes());
        }
        assert!(matches!(
            decode(&body).unwrap_err(),
            CarrierError::TooManyRecords { .. }
        ));
    }

    #[test]
    fn oversized_envelope_is_rejected_on_encode() {
        let batch = vec![envelope(0, MAX_CARRIER_RECORD + 1)];
        assert!(matches!(
            encode(&batch).unwrap_err(),
            CarrierError::EnvelopeTooLarge { .. }
        ));
    }

    /// The byte cap and the count cap are independent: 64 large records exceed
    /// the byte budget even though the count is legal.
    #[test]
    fn byte_cap_binds_before_the_count_cap_for_large_records() {
        let per_record = 8 * 1024;
        let batch = vec![envelope(0, per_record); MAX_POST_BATCH_RECORDS];
        assert!(batch.len() <= MAX_POST_BATCH_RECORDS);
        assert_eq!(
            encode(&batch).unwrap_err(),
            CarrierError::BodyTooLarge {
                actual: MAX_POST_BATCH_RECORDS * (4 + per_record),
                limit: MAX_POST_BATCH_BYTES,
            }
        );
    }

    #[test]
    fn declared_length_beyond_the_body_is_truncation() {
        let mut body = Vec::new();
        body.extend_from_slice(&100u32.to_be_bytes());
        body.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            decode(&body).unwrap_err(),
            CarrierError::Truncated { field: "envelope" }
        );
    }

    #[test]
    fn a_partial_length_prefix_is_truncation() {
        assert_eq!(
            decode(&[0, 0]).unwrap_err(),
            CarrierError::Truncated {
                field: "envelope_len"
            }
        );
    }

    /// A hostile declared length must be rejected before any slice is taken.
    #[test]
    fn oversized_declared_length_is_caught_before_slicing() {
        let mut body = Vec::new();
        body.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert!(matches!(
            decode(&body).unwrap_err(),
            CarrierError::EnvelopeTooLarge { .. }
        ));
    }

    #[test]
    fn oversized_body_is_rejected_up_front() {
        let body = vec![0u8; MAX_POST_BATCH_BYTES + 1];
        assert!(matches!(
            decode(&body).unwrap_err(),
            CarrierError::BodyTooLarge { .. }
        ));
    }

    /// T20: truncation must either be a typed error or yield a strict prefix of
    /// the batch — never a corrupt or reordered record.
    ///
    /// The POST body carries no record count or terminator, so a body cut
    /// exactly on a record boundary is byte-for-byte indistinguishable from a
    /// legitimately shorter batch. §4.3 accepts that, because "批处理每条记录有
    /// 独立身份和结果，不把整个批次当事务": each envelope is independently
    /// authenticated, and a record that never arrived is simply retransmitted
    /// rather than silently lost.
    #[test]
    fn every_truncation_is_an_error_or_a_strict_prefix() {
        let batch = vec![envelope(1, 50), envelope(2, 20)];
        let body = encode(&batch).unwrap();
        let full = decode(&body).unwrap();

        for cut in 0..body.len() {
            match decode(&body[..cut]) {
                Err(_) => {}
                Ok(partial) => {
                    assert!(
                        partial.len() < full.len(),
                        "truncation to {cut} bytes returned the whole batch"
                    );
                    assert_eq!(
                        partial,
                        full[..partial.len()].to_vec(),
                        "truncation to {cut} bytes reordered or altered records"
                    );
                }
            }
        }
        assert_eq!(decode(&body).unwrap(), batch);
    }

    /// T20: arbitrary mutations must not panic the decoder.
    #[test]
    fn mutations_do_not_panic() {
        let body = encode(&[envelope(1, 40)]).unwrap();
        for i in 0..body.len() {
            for delta in [1u8, 0x7f, 0x80, 0xff] {
                let mut mutated = body.clone();
                mutated[i] = mutated[i].wrapping_add(delta);
                let _ = decode(&mutated);
            }
        }
    }
}

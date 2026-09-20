//! Record framing (DESIGN.md §4.1).
//!
//! ```text
//! kind:u8 | metadata_len:u32be | canonical_metadata
//!         | payload_len:u32be  | payload
//!         | padding_len:u16be  | padding
//! ```
//!
//! Every bound is checked against the declared length *before* the corresponding
//! slice is taken or copied, which is what §4.1 asks for with
//! "先限长再分配/解码". A decoder therefore never allocates based on an
//! attacker-supplied length that it has not already validated.

use crate::canon::{CanonError, Canonical};
use crate::kind::MessageKind;
use wsnet_limits::{MAX_METADATA, MAX_PADDING, MAX_RECORD_PLAINTEXT};

/// Fixed framing overhead: `kind` + `metadata_len` + `payload_len` + `padding_len`.
pub const RECORD_OVERHEAD: usize = 1 + 4 + 4 + 2;

/// Errors produced while encoding or decoding a record.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordError {
    /// The encoded record exceeds the record plaintext bound.
    #[error("record is {actual} bytes, limit is {limit}")]
    TooLarge {
        /// Observed or would-be length.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// The declared metadata length exceeds the metadata bound.
    #[error("metadata length {0} exceeds the metadata bound")]
    MetadataTooLarge(usize),
    /// The payload is larger than this kind permits.
    #[error("{kind} payload is {actual} bytes, limit is {limit}")]
    PayloadTooLarge {
        /// Offending kind.
        kind: MessageKind,
        /// Declared length.
        actual: usize,
        /// Permitted length for this kind.
        limit: usize,
    },
    /// The padding length exceeds the padding bound.
    #[error("padding length {0} exceeds the padding bound")]
    PaddingTooLarge(usize),
    /// The frame ended before a declared field.
    #[error("record truncated while reading {field}")]
    Truncated {
        /// Which field ran off the end.
        field: &'static str,
    },
    /// The `kind` byte is not a known message kind.
    #[error("unknown message kind {0}")]
    UnknownKind(u8),
    /// Metadata did not decode as canonical JSON.
    #[error("invalid metadata: {0}")]
    Metadata(#[from] CanonError),
    /// Bytes remained after the record.
    #[error("{0} trailing bytes after the record")]
    TrailingData(usize),
}

/// One decoded record.
///
/// Padding is stored as a length only. Its bytes are not meaningful — padding
/// exists to blur record sizes — so the encoder emits zeros, which keeps
/// canonical test vectors reproducible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Message kind.
    pub kind: MessageKind,
    /// Canonical metadata.
    pub metadata: Canonical,
    /// Opaque payload; empty for metadata-only kinds.
    pub payload: Vec<u8>,
    /// Number of padding bytes appended after the payload.
    pub padding_len: u16,
}

impl Record {
    /// Builds a metadata-only record.
    pub fn new(kind: MessageKind, metadata: Canonical) -> Self {
        Record {
            kind,
            metadata,
            payload: Vec::new(),
            padding_len: 0,
        }
    }

    /// Builds a record carrying a payload.
    pub fn with_payload(kind: MessageKind, metadata: Canonical, payload: Vec<u8>) -> Self {
        Record {
            kind,
            metadata,
            payload,
            padding_len: 0,
        }
    }

    /// Total encoded length this record would occupy.
    pub fn encoded_len(&self) -> Result<usize, RecordError> {
        let metadata = self.metadata.to_bounded_bytes()?;
        self.validate_against(&metadata)?;
        Ok(RECORD_OVERHEAD + metadata.len() + self.payload.len() + self.padding_len as usize)
    }

    fn validate_against(&self, metadata: &[u8]) -> Result<(), RecordError> {
        if metadata.len() > MAX_METADATA {
            return Err(RecordError::MetadataTooLarge(metadata.len()));
        }
        let limit = self.kind.max_payload();
        if self.payload.len() > limit {
            return Err(RecordError::PayloadTooLarge {
                kind: self.kind,
                actual: self.payload.len(),
                limit,
            });
        }
        if self.padding_len as usize > MAX_PADDING {
            return Err(RecordError::PaddingTooLarge(self.padding_len as usize));
        }
        let total =
            RECORD_OVERHEAD + metadata.len() + self.payload.len() + self.padding_len as usize;
        if total > MAX_RECORD_PLAINTEXT {
            return Err(RecordError::TooLarge {
                actual: total,
                limit: MAX_RECORD_PLAINTEXT,
            });
        }
        Ok(())
    }

    /// Encodes the record, checking every bound first.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let metadata = self.metadata.to_bounded_bytes()?;
        self.validate_against(&metadata)?;
        let mut out =
            Vec::with_capacity(RECORD_OVERHEAD + metadata.len() + self.payload.len() + self.padding_len as usize);
        self.encode_into(&metadata, &mut out);
        Ok(out)
    }

    /// Encodes into an existing buffer, avoiding a per-record allocation.
    pub fn encode_to(&self, out: &mut Vec<u8>) -> Result<(), RecordError> {
        let metadata = self.metadata.to_bounded_bytes()?;
        self.validate_against(&metadata)?;
        self.encode_into(&metadata, out);
        Ok(())
    }

    fn encode_into(&self, metadata: &[u8], out: &mut Vec<u8>) {
        out.push(self.kind.as_u8());
        out.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
        out.extend_from_slice(metadata);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.padding_len.to_be_bytes());
        out.extend(std::iter::repeat(0u8).take(self.padding_len as usize));
    }

    /// Decodes exactly one record from `input`, rejecting trailing bytes.
    pub fn decode(input: &[u8]) -> Result<Record, RecordError> {
        let (record, consumed) = Record::decode_prefix(input)?;
        if consumed != input.len() {
            return Err(RecordError::TrailingData(input.len() - consumed));
        }
        Ok(record)
    }

    /// Decodes one record from the front of `input`, returning bytes consumed.
    ///
    /// This is the form carriers use: a POST batch is a list of records, so the
    /// caller needs the consumed length to find the next one.
    pub fn decode_prefix(input: &[u8]) -> Result<(Record, usize), RecordError> {
        if input.len() > MAX_RECORD_PLAINTEXT {
            return Err(RecordError::TooLarge {
                actual: input.len(),
                limit: MAX_RECORD_PLAINTEXT,
            });
        }

        let mut cursor = 0usize;
        let kind_byte = *input.get(cursor).ok_or(RecordError::Truncated { field: "kind" })?;
        cursor += 1;
        let kind = MessageKind::from_u8(kind_byte).ok_or(RecordError::UnknownKind(kind_byte))?;

        let metadata_len = read_u32(input, &mut cursor, "metadata_len")? as usize;
        if metadata_len > MAX_METADATA {
            return Err(RecordError::MetadataTooLarge(metadata_len));
        }
        let metadata_bytes = take(input, &mut cursor, metadata_len, "metadata")?;
        let metadata = Canonical::from_bytes_bounded(metadata_bytes, MAX_METADATA)?;

        let payload_limit = kind.max_payload();
        let payload_len = read_u32(input, &mut cursor, "payload_len")? as usize;
        if payload_len > payload_limit {
            return Err(RecordError::PayloadTooLarge {
                kind,
                actual: payload_len,
                limit: payload_limit,
            });
        }
        let payload = take(input, &mut cursor, payload_len, "payload")?.to_vec();

        let padding_len = read_u16(input, &mut cursor, "padding_len")? as usize;
        if padding_len > MAX_PADDING {
            return Err(RecordError::PaddingTooLarge(padding_len));
        }
        take(input, &mut cursor, padding_len, "padding")?;

        Ok((
            Record {
                kind,
                metadata,
                payload,
                padding_len: padding_len as u16,
            },
            cursor,
        ))
    }
}

fn read_u32(input: &[u8], cursor: &mut usize, field: &'static str) -> Result<u32, RecordError> {
    let bytes = take(input, cursor, 4, field)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u16(input: &[u8], cursor: &mut usize, field: &'static str) -> Result<u16, RecordError> {
    let bytes = take(input, cursor, 2, field)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    len: usize,
    field: &'static str,
) -> Result<&'a [u8], RecordError> {
    let end = cursor
        .checked_add(len)
        .ok_or(RecordError::Truncated { field })?;
    let slice = input.get(*cursor..end).ok_or(RecordError::Truncated { field })?;
    *cursor = end;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::Canonical;

    fn data_record(stream_id: u64, offset: u64, payload: &[u8]) -> Record {
        Record::with_payload(
            MessageKind::Data,
            Canonical::object([
                ("stream_id", Canonical::u64_decimal(stream_id)),
                ("offset", Canonical::u64_decimal(offset)),
            ]),
            payload.to_vec(),
        )
    }

    #[test]
    fn round_trip_metadata_only() {
        let record = Record::new(
            MessageKind::Ping,
            Canonical::object([("ts", Canonical::u64_decimal(1_700_000_000))]),
        );
        let encoded = record.encode().unwrap();
        assert_eq!(Record::decode(&encoded).unwrap(), record);
    }

    #[test]
    fn round_trip_with_payload_and_padding() {
        let mut record = data_record(1, 4096, b"hello wsnet");
        record.padding_len = 32;
        let encoded = record.encode().unwrap();
        assert_eq!(encoded.len(), record.encoded_len().unwrap());
        let decoded = Record::decode(&encoded).unwrap();
        assert_eq!(decoded, record);
        // Padding bytes are not retained, only the length.
        assert_eq!(decoded.padding_len, 32);
    }

    #[test]
    fn layout_matches_the_documented_wire_order() {
        let record = Record::new(
            MessageKind::Ping,
            Canonical::object([("a", Canonical::int(1))]),
        );
        let encoded = record.encode().unwrap();
        assert_eq!(encoded[0], MessageKind::Ping.as_u8());
        let md_len = u32::from_be_bytes([encoded[1], encoded[2], encoded[3], encoded[4]]) as usize;
        assert_eq!(md_len, br#"{"a":1}"#.len());
        assert_eq!(&encoded[5..5 + md_len], br#"{"a":1}"#);
        let tail = &encoded[5 + md_len..];
        assert_eq!(&tail[0..4], &0u32.to_be_bytes()); // payload_len
        assert_eq!(&tail[4..6], &0u16.to_be_bytes()); // padding_len
        assert_eq!(tail.len(), 6);
    }

    #[test]
    fn payload_is_rejected_for_metadata_only_kinds() {
        let record = Record::with_payload(MessageKind::Ping, Canonical::empty_object(), vec![1, 2, 3]);
        assert_eq!(
            record.encode().unwrap_err(),
            RecordError::PayloadTooLarge {
                kind: MessageKind::Ping,
                actual: 3,
                limit: 0,
            }
        );
    }

    #[test]
    fn oversized_tcp_payload_is_rejected() {
        let record = data_record(1, 0, &vec![0u8; wsnet_limits::MAX_TCP_PAYLOAD + 1]);
        assert!(matches!(
            record.encode().unwrap_err(),
            RecordError::PayloadTooLarge { .. }
        ));
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let mut encoded = data_record(1, 0, b"x").encode().unwrap();
        encoded[0] = 200;
        assert_eq!(
            Record::decode(&encoded).unwrap_err(),
            RecordError::UnknownKind(200)
        );
    }

    #[test]
    fn declared_length_beyond_input_is_truncation_not_allocation() {
        // metadata_len claims 900 bytes but only 2 are present.
        let mut encoded = Vec::new();
        encoded.push(MessageKind::Ping.as_u8());
        encoded.extend_from_slice(&900u32.to_be_bytes());
        encoded.extend_from_slice(b"{}");
        assert!(matches!(
            Record::decode(&encoded).unwrap_err(),
            RecordError::Truncated { field: "metadata" }
        ));
    }

    #[test]
    fn oversized_declared_lengths_are_caught_before_slicing() {
        // payload_len far beyond MAX_TCP_PAYLOAD, and no bytes behind it. The
        // check must fire from the declared length alone, before any slice is
        // taken, so a hostile length can never drive an allocation.
        let mut encoded = Vec::new();
        encoded.push(MessageKind::Data.as_u8());
        encoded.extend_from_slice(&2u32.to_be_bytes());
        encoded.extend_from_slice(b"{}");
        encoded.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert!(matches!(
            Record::decode(&encoded).unwrap_err(),
            RecordError::PayloadTooLarge { .. }
        ));

        // metadata_len alone exceeds the metadata bound.
        let mut encoded = Vec::new();
        encoded.push(MessageKind::Ping.as_u8());
        encoded.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert_eq!(
            Record::decode(&encoded).unwrap_err(),
            RecordError::MetadataTooLarge(u32::MAX as usize)
        );
    }

    /// An empty metadata blob is not `{}` and must not be accepted: metadata is
    /// parsed as canonical JSON, and zero bytes is not a JSON value.
    #[test]
    fn empty_metadata_is_rejected() {
        let mut encoded = Vec::new();
        encoded.push(MessageKind::Ping.as_u8());
        encoded.extend_from_slice(&0u32.to_be_bytes());
        encoded.extend_from_slice(&0u32.to_be_bytes());
        encoded.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            Record::decode(&encoded).unwrap_err(),
            RecordError::Metadata(CanonError::UnexpectedEnd(0))
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = data_record(1, 0, b"x").encode().unwrap();
        encoded.push(0);
        assert_eq!(
            Record::decode(&encoded).unwrap_err(),
            RecordError::TrailingData(1)
        );
    }

    #[test]
    fn decode_prefix_reports_consumed_length() {
        let a = data_record(1, 0, b"aaaa").encode().unwrap();
        let b = data_record(2, 0, b"bb").encode().unwrap();
        let mut batch = a.clone();
        batch.extend_from_slice(&b);

        let (first, consumed) = Record::decode_prefix(&batch).unwrap();
        assert_eq!(consumed, a.len());
        let (second, consumed2) = Record::decode_prefix(&batch[consumed..]).unwrap();
        assert_eq!(consumed2, b.len());
        assert_eq!(first.payload, b"aaaa");
        assert_eq!(second.payload, b"bb");
    }

    /// T20: every truncation of a valid record must produce a typed error and
    /// must never panic or read out of bounds.
    #[test]
    fn every_truncation_is_a_typed_error() {
        let mut record = data_record(7, 123, b"payload-bytes");
        record.padding_len = 8;
        let encoded = record.encode().unwrap();

        for cut in 0..encoded.len() {
            let result = Record::decode(&encoded[..cut]);
            assert!(
                result.is_err(),
                "truncation to {cut} bytes unexpectedly decoded"
            );
        }
        assert_eq!(Record::decode(&encoded).unwrap(), record);
    }

    /// T20: arbitrary byte mutations must not panic the decoder.
    #[test]
    fn byte_mutations_do_not_panic() {
        let encoded = data_record(9, 512, b"abcdefghij").encode().unwrap();
        for i in 0..encoded.len() {
            for delta in [1u8, 0x7f, 0x80, 0xff] {
                let mut mutated = encoded.clone();
                mutated[i] = mutated[i].wrapping_add(delta);
                let _ = Record::decode(&mutated);
            }
        }
    }

    #[test]
    fn empty_input_is_truncated() {
        assert_eq!(
            Record::decode(&[]).unwrap_err(),
            RecordError::Truncated { field: "kind" }
        );
    }

    #[test]
    fn metadata_errors_surface_as_record_errors() {
        let mut encoded = Vec::new();
        encoded.push(MessageKind::Ping.as_u8());
        let bad = br#"{"a":1,"a":2}"#;
        encoded.extend_from_slice(&(bad.len() as u32).to_be_bytes());
        encoded.extend_from_slice(bad);
        encoded.extend_from_slice(&0u32.to_be_bytes());
        encoded.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            Record::decode(&encoded).unwrap_err(),
            RecordError::Metadata(CanonError::DuplicateKey("a".into()))
        );
    }

    #[test]
    fn oversized_record_is_rejected_up_front() {
        let input = vec![0u8; MAX_RECORD_PLAINTEXT + 1];
        assert!(matches!(
            Record::decode(&input).unwrap_err(),
            RecordError::TooLarge { .. }
        ));
    }
}

//! Length-prefixed JSON framing for the management socket (USAGE.md section 2).
//!
//! ```text
//! body_len:u32be | UTF-8 JSON body
//! ```
//!
//! Any process running as the same OS user can reach the control endpoint, so
//! this decoder treats its input as hostile. Three rules are enforced, all of
//! them design rules rather than conveniences:
//!
//! * The declared length is bounded **before** a body buffer is allocated, which
//!   is DESIGN.md section 4.1's "bound the length before you allocate or decode".
//!   A `u32` prefix claiming 4 GiB must cost nothing but an error.
//! * The body must be strict UTF-8. JSON is defined over Unicode text, so this is
//!   a boundary check the JSON parser must not be asked to guess at.
//! * A frame carrying trailing bytes is refused. Accepting it would let the
//!   stream carry data the protocol never described, and the length prefix exists
//!   precisely so that the end of a frame is unambiguous.

use std::io;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wsnet_limits::MAX_RECORD_PLAINTEXT;

use crate::error::ControlError;

/// Hard maximum size of one control frame body, in bytes.
///
/// Taken from the largest single record the data plane can carry
/// ([`MAX_RECORD_PLAINTEXT`](wsnet_limits::MAX_RECORD_PLAINTEXT)). Everything a
/// management answer can describe is something the protocol itself must be able
/// to express in one record, so a larger frame is a bug or an attack and never a
/// legitimate readout. A frame that declares more than this is refused before the
/// body is allocated.
pub const MAX_CONTROL_FRAME: usize = MAX_RECORD_PLAINTEXT;

/// The 32-bit length prefix must be able to hold the bound above.
const _: () = assert!(MAX_CONTROL_FRAME <= u32::MAX as usize);

/// Why a control frame could not be encoded or decoded.
///
/// Every variant is a clean refusal: no partial message is ever returned, because
/// a management command must not be executed from a body that was only partly
/// understood.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    /// The frame ended before a declared field.
    #[error("control frame truncated while reading {field}")]
    Truncated {
        /// Which field ran off the end.
        field: &'static str,
    },
    /// The declared body length exceeds [`MAX_CONTROL_FRAME`].
    #[error("control frame declares {actual} bytes, limit is {limit}")]
    TooLarge {
        /// Declared or observed length.
        actual: usize,
        /// Enforced bound.
        limit: usize,
    },
    /// The frame declared an empty body, which can never be a valid message.
    #[error("control frame declares an empty body")]
    Empty,
    /// The body was not valid UTF-8.
    #[error("control frame body is not valid UTF-8")]
    InvalidUtf8,
    /// Bytes remained after the frame.
    #[error("{0} trailing bytes after the control frame")]
    TrailingData(usize),
    /// The body was not valid JSON for the expected message.
    #[error("control frame is not a valid message: {reason}")]
    InvalidJson {
        /// What the JSON decoder objected to.
        reason: String,
    },
    /// A message could not be turned into JSON at all.
    #[error("control message could not be encoded: {reason}")]
    Encoding {
        /// What the JSON encoder objected to.
        reason: String,
    },
}

/// Validates one 4-byte length prefix and returns the body length it declares.
///
/// Separate from the body read so the bound can be shown to hold before any
/// allocation happens.
pub fn frame_length(header: [u8; 4]) -> Result<usize, FrameError> {
    let declared = u32::from_be_bytes(header) as usize;
    if declared == 0 {
        return Err(FrameError::Empty);
    }
    if declared > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge {
            actual: declared,
            limit: MAX_CONTROL_FRAME,
        });
    }
    Ok(declared)
}

/// Encodes one message as a complete frame (prefix and body).
///
/// Used where a whole frame is handled at once: tests, and any future transport
/// that already delimits messages. Stream transports should pair [`encode_body`]
/// with [`write_frame`] instead.
pub fn encode_message<T>(message: &T) -> Result<Vec<u8>, FrameError>
where
    T: Serialize + ?Sized,
{
    let body = encode_body(message)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes one complete frame into a message.
///
/// The buffer must hold exactly one frame: a short one is truncation and a long
/// one is trailing data, and neither is accepted.
pub fn decode_message<T>(frame: &[u8]) -> Result<T, FrameError>
where
    T: DeserializeOwned,
{
    decode_body(split_frame(frame)?)
}

/// Encodes one message as a UTF-8 JSON body, without the length prefix.
pub fn encode_body<T>(message: &T) -> Result<Vec<u8>, FrameError>
where
    T: Serialize + ?Sized,
{
    let body = serde_json::to_vec(message).map_err(|error| FrameError::Encoding {
        reason: error.to_string(),
    })?;
    if body.is_empty() {
        return Err(FrameError::Empty);
    }
    if body.len() > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge {
            actual: body.len(),
            limit: MAX_CONTROL_FRAME,
        });
    }
    Ok(body)
}

/// Decodes one UTF-8 JSON body, without the length prefix.
///
/// Bodies reaching this function from a stream have already been length-checked
/// by [`read_frame`]; the checks are repeated so that a body from any other
/// source still cannot bypass the bound.
pub fn decode_body<T>(body: &[u8]) -> Result<T, FrameError>
where
    T: DeserializeOwned,
{
    if body.is_empty() {
        return Err(FrameError::Empty);
    }
    if body.len() > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge {
            actual: body.len(),
            limit: MAX_CONTROL_FRAME,
        });
    }
    let text = std::str::from_utf8(body).map_err(|_| FrameError::InvalidUtf8)?;
    serde_json::from_str(text).map_err(|error| FrameError::InvalidJson {
        reason: error.to_string(),
    })
}

/// Reads one frame body from a stream.
///
/// Returns `Ok(None)` when the peer closed the connection cleanly between frames,
/// which is a normal CLI exit; any truncation *inside* a frame is an error. The
/// two cases are kept apart so the server can close quietly on the first and log
/// the second.
///
/// This is the only function in the crate that returns [`ControlError`] rather
/// than [`FrameError`], because reading a socket can also fail for reasons that
/// have nothing to do with framing.
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>, ControlError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    let mut filled = 0usize;
    while filled < header.len() {
        let read = reader.read(&mut header[filled..]).await?;
        if read == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated { field: "length" }.into())
            };
        }
        filled += read;
    }
    let length = frame_length(header)?;
    // The buffer is created only now, once the declared length has been checked
    // against the bound, so a hostile prefix cannot make us allocate.
    let mut body = vec![0u8; length];
    if let Err(error) = reader.read_exact(&mut body).await {
        return Err(if error.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated { field: "body" }.into()
        } else {
            ControlError::Io(error)
        });
    }
    Ok(Some(body))
}

/// Writes one frame body to a stream, prefixing its length.
pub async fn write_frame<W>(writer: &mut W, body: &[u8]) -> Result<(), ControlError>
where
    W: AsyncWrite + Unpin,
{
    if body.is_empty() {
        return Err(FrameError::Empty.into());
    }
    if body.len() > MAX_CONTROL_FRAME {
        return Err(FrameError::TooLarge {
            actual: body.len(),
            limit: MAX_CONTROL_FRAME,
        }
        .into());
    }
    let prefix = (body.len() as u32).to_be_bytes();
    writer.write_all(&prefix).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

/// Splits a complete frame and enforces the length rules.
fn split_frame(frame: &[u8]) -> Result<&[u8], FrameError> {
    let header = match frame.get(..4) {
        Some(bytes) => [bytes[0], bytes[1], bytes[2], bytes[3]],
        None => return Err(FrameError::Truncated { field: "length" }),
    };
    let length = frame_length(header)?;
    // Cannot overflow: `length` is bounded by MAX_CONTROL_FRAME.
    let end = 4 + length;
    let body = frame
        .get(4..end)
        .ok_or(FrameError::Truncated { field: "body" })?;
    if frame.len() > end {
        return Err(FrameError::TrailingData(frame.len() - end));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ErrorCode, ForwardSpec, Request, Response};
    use std::net::SocketAddr;
    use wsnet_routing::{Destination, Proto};

    /// The bound must be the data plane's largest record; a drift here would mean
    /// the control channel accepts messages the protocol cannot carry.
    #[test]
    fn the_frame_bound_comes_from_the_record_bound() {
        assert_eq!(MAX_CONTROL_FRAME, MAX_RECORD_PLAINTEXT);
    }

    #[test]
    fn a_length_prefix_is_big_endian() {
        let frame = encode_message(&Request::Status).unwrap();
        let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(declared, frame.len() - 4);
    }

    /// A pending `listen` address keeps this test independent of the platform.
    fn spec() -> ForwardSpec {
        ForwardSpec {
            name: "a-web".into(),
            listen: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            proto: Proto::Tcp,
            hub: "auto".into(),
            via: Vec::new(),
            destination: Destination::service("client-a", "web"),
        }
    }

    #[test]
    fn oversized_declared_length_is_refused() {
        assert_eq!(
            frame_length(u32::MAX.to_be_bytes()).unwrap_err(),
            FrameError::TooLarge {
                actual: u32::MAX as usize,
                limit: MAX_CONTROL_FRAME
            }
        );
        // One byte past the bound is already too much.
        assert!(frame_length(((MAX_CONTROL_FRAME + 1) as u32).to_be_bytes()).is_err());
        assert!(frame_length((MAX_CONTROL_FRAME as u32).to_be_bytes()).is_ok());
    }

    #[test]
    fn an_empty_declared_body_is_refused() {
        assert_eq!(frame_length(0u32.to_be_bytes()).unwrap_err(), FrameError::Empty);
        assert_eq!(decode_message::<Request>(&0u32.to_be_bytes()).unwrap_err(), FrameError::Empty);
    }

    #[test]
    fn truncated_frames_are_refused() {
        let frame = encode_message(&Request::Status).unwrap();
        for cut in 0..frame.len() {
            assert!(
                decode_message::<Request>(&frame[..cut]).is_err(),
                "a frame cut to {cut} bytes was accepted"
            );
        }
        assert_eq!(
            decode_message::<Request>(&[]).unwrap_err(),
            FrameError::Truncated { field: "length" }
        );
        assert_eq!(
            decode_message::<Request>(&frame[..2]).unwrap_err(),
            FrameError::Truncated { field: "length" }
        );
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut frame = encode_message(&Request::Status).unwrap();
        frame.extend_from_slice(b"{}");
        assert_eq!(
            decode_message::<Request>(&frame).unwrap_err(),
            FrameError::TrailingData(2)
        );
    }

    #[test]
    fn invalid_utf8_is_refused() {
        let body = [0xffu8, 0xfe, 0xfd, 0x00];
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        assert_eq!(
            decode_message::<Request>(&frame).unwrap_err(),
            FrameError::InvalidUtf8
        );
        assert_eq!(decode_body::<Request>(&body).unwrap_err(), FrameError::InvalidUtf8);
    }

    #[test]
    fn garbage_bodies_are_refused_without_panicking() {
        for body in [
            &b"not json"[..],
            &b"{"[..],
            &b"[]"[..],
            &b"null"[..],
            &b"{\"request\":\"no_such_command\"}"[..],
            &[0u8; 32][..],
            &b"{\"response\":\"status\"}"[..],
        ] {
            assert!(decode_body::<Request>(body).is_err(), "{body:?} was accepted");
        }
    }

    /// The frame codec must survive arbitrary mutations of a valid frame.
    #[test]
    fn mutations_do_not_panic() {
        let frame = encode_message(&spec_request()).unwrap();
        for index in 0..frame.len() {
            for delta in [1u8, 0x7f, 0x80, 0xff] {
                let mut mutated = frame.clone();
                mutated[index] = mutated[index].wrapping_add(delta);
                let _ = decode_message::<Request>(&mutated);
            }
        }
    }

    fn spec_request() -> Request {
        Request::ForwardAdd { spec: spec() }
    }

    #[test]
    fn responses_round_trip_through_the_codec() {
        let responses = [
            Response::ForwardRemoved {
                name: "a-web".into(),
            },
            Response::error(ErrorCode::Conflict, "listen address already in use"),
        ];
        for response in responses {
            let frame = encode_message(&response).unwrap();
            assert_eq!(decode_message::<Response>(&frame).unwrap(), response);
        }
    }

    /// Reading a stream must distinguish a clean close from a truncated frame.
    #[tokio::test]
    async fn reading_a_stream_separates_eof_from_truncation() {
        let frame = encode_message(&Request::ForwardList).unwrap();

        let mut empty: &[u8] = &[];
        assert!(read_frame(&mut empty).await.unwrap().is_none());

        let mut whole: &[u8] = &frame;
        let body = read_frame(&mut whole).await.unwrap().unwrap();
        assert_eq!(decode_body::<Request>(&body).unwrap(), Request::ForwardList);

        // A prefix that promises more than the stream holds is truncation.
        let mut short: &[u8] = &frame[..frame.len() - 1];
        assert!(matches!(
            read_frame(&mut short).await.unwrap_err(),
            ControlError::Frame(FrameError::Truncated { field: "body" })
        ));

        let mut half_header: &[u8] = &frame[..2];
        assert!(matches!(
            read_frame(&mut half_header).await.unwrap_err(),
            ControlError::Frame(FrameError::Truncated { field: "length" })
        ));
    }

    /// A hostile prefix must be refused before the body is read or allocated.
    #[tokio::test]
    async fn a_hostile_prefix_costs_nothing() {
        let mut hostile: &[u8] = &u32::MAX.to_be_bytes();
        assert!(matches!(
            read_frame(&mut hostile).await.unwrap_err(),
            ControlError::Frame(FrameError::TooLarge { .. })
        ));
    }

    /// Writing must refuse an empty body rather than emit a zero-length frame.
    #[tokio::test]
    async fn writing_an_empty_body_is_refused() {
        let mut out: Vec<u8> = Vec::new();
        assert!(matches!(
            write_frame(&mut out, &[]).await.unwrap_err(),
            ControlError::Frame(FrameError::Empty)
        ));
        assert!(out.is_empty());
    }

    /// A round trip through the streaming pair must match the buffered codec.
    #[tokio::test]
    async fn stream_write_and_read_agree_with_the_buffered_codec() {
        let request = spec_request();
        let body = encode_body(&request).unwrap();
        let mut wire: Vec<u8> = Vec::new();
        write_frame(&mut wire, &body).await.unwrap();
        assert_eq!(wire, encode_message(&request).unwrap());

        let mut reader: &[u8] = &wire;
        let read = read_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(decode_body::<Request>(&read).unwrap(), request);
    }
}

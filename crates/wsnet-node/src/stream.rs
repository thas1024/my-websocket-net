//! One session stream, exposed as an async byte stream.
//!
//! DESIGN.md section 7.2 fixes the half-close rule this type implements:
//!
//! > Fin 携带 final_offset；只有 `[0,final_offset)` 字节全部连续写给本地 TCP 后才
//! > shutdown(Write)，不能因跨载体 Fin 先到而截断数据。
//!
//! and section 7.5 fixes the other direction: sending is bounded by the peer's
//! granted `limit_offset` (`offset + payload_len <= limit_offset`), and credit is
//! replenished from bytes the *application consumed*, never from bytes that
//! merely arrived. Both rules are properties of this type rather than something
//! its callers have to remember.
//!
//! The driver that owns the session pushes [`StreamMsg`] values here, so this is
//! the only place that translates between "session stream" and `AsyncRead`
//! plus `AsyncWrite`. No read on the local socket ever starts before the remote
//! `Open` and `Ready` completed, because the SOCKS5 and Local Forward layers only
//! obtain this value from a successful open.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use wsnet_limits::STREAM_MAX_CREDIT;
use wsnet_session::{ResetReason, SessionError, SessionHandle};
use wsnet_stream::StreamError;

/// One update the session driver hands to a single stream.
#[derive(Debug)]
pub(crate) enum StreamMsg {
    /// Ordered business bytes.
    Data(Vec<u8>),
    /// The peer raised the granted credit.
    Credit,
    /// The peer half-closed at this exclusive offset.
    Fin(u64),
    /// The peer terminated the stream.
    Reset(ResetReason),
}

/// One TCP-like stream carried by a hub session.
pub struct SessionStream {
    handle: SessionHandle,
    stream_id: u64,
    rx: mpsc::UnboundedReceiver<StreamMsg>,
    /// Bytes received in order but not yet handed to the application.
    read_buf: VecDeque<u8>,
    /// Bytes already handed to the application.
    delivered: u64,
    /// The peer's half-close offset, once `Fin` arrived.
    fin_at: Option<u64>,
    /// Set once the peer terminated the stream.
    reset: Option<ResetReason>,
    /// Bytes accepted from the application but not yet inside a `Data` record,
    /// because the granted credit did not cover them.
    write_buf: Vec<u8>,
    fin_sent: bool,
    write_closed: bool,
}

impl SessionStream {
    /// Builds the application-facing half of one stream.
    pub(crate) fn new(
        handle: SessionHandle,
        stream_id: u64,
        rx: mpsc::UnboundedReceiver<StreamMsg>,
    ) -> Self {
        SessionStream {
            handle,
            stream_id,
            rx,
            read_buf: VecDeque::new(),
            delivered: 0,
            fin_at: None,
            reset: None,
            write_buf: Vec::new(),
            fin_sent: false,
            write_closed: false,
        }
    }

    /// The session stream id, for diagnostics and tests.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Folds one driver message into the local state.
    fn absorb(&mut self, message: StreamMsg) {
        match message {
            StreamMsg::Data(payload) => self.read_buf.extend(payload),
            StreamMsg::Credit => {}
            StreamMsg::Fin(final_offset) => {
                // Section 7.2: the offset, not the arrival order, decides when the
                // write half may be shut down.
                self.fin_at = Some(match self.fin_at {
                    Some(previous) => previous.max(final_offset),
                    None => final_offset,
                });
            }
            StreamMsg::Reset(reason) => self.reset = Some(reason),
        }
    }

    /// Drains every queued driver message, registering a waker when the channel
    /// runs dry, and flushes whatever the current credit allows.
    fn pump(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        loop {
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(message)) => self.absorb(message),
                Poll::Ready(None) => {
                    self.write_closed = true;
                    break;
                }
                Poll::Pending => break,
            }
        }
        self.flush_writes()
    }

    /// Sends as much buffered output as the granted credit covers.
    fn flush_writes(&mut self) -> io::Result<()> {
        while !self.write_buf.is_empty() {
            match self.handle.send_data(self.stream_id, &self.write_buf) {
                // An empty payload is a no-op, so zero progress means the peer's
                // window is zero; waiting for `Progress` is the correct answer.
                Ok(0) => break,
                Ok(sent) => {
                    self.write_buf.drain(..sent);
                }
                Err(SessionError::Stream(StreamError::CreditExceeded { .. })) => break,
                Err(SessionError::UnknownStream(_)) => {
                    self.write_buf.clear();
                    return Err(broken_pipe("the session stream is gone"));
                }
                Err(error) => return Err(broken_pipe(&error.to_string())),
            }
        }
        Ok(())
    }
}

impl Drop for SessionStream {
    fn drop(&mut self) {
        // Dropping the application half ends the stream's engine state; the
        // driver notices through its channel and stops tracking it.
        self.handle.close_stream(self.stream_id);
    }
}

fn broken_pipe(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, reason.to_string())
}

impl AsyncRead for SessionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let contiguous = this.read_buf.make_contiguous();
                let take = buf.remaining().min(contiguous.len());
                buf.put_slice(&contiguous[..take]);
                this.read_buf.drain(..take);
                this.delivered += take as u64;
                // Section 7.5: credit is earned by consumption, which is exactly
                // this point — the bytes left the session buffer for the local
                // socket.
                let _ = this.handle.consume(this.stream_id, take as u64);
                return Poll::Ready(Ok(()));
            }
            if let Some(reason) = this.reset {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!("the peer reset the stream: {reason:?}"),
                )));
            }
            if this
                .fin_at
                .is_some_and(|final_offset| this.delivered >= final_offset)
            {
                // Everything below `final_offset` was delivered, so the peer's
                // half-close is now visible as end-of-file (section 7.2).
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(message)) => this.absorb(message),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SessionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.write_closed {
            return Poll::Ready(Err(broken_pipe("the write half is already closed")));
        }
        if let Err(error) = this.pump(cx) {
            return Poll::Ready(Err(error));
        }
        if !this.write_buf.is_empty() {
            if this.write_closed {
                // The session ended with bytes still unsent, and no `Progress`
                // can ever arrive to release them, so reporting backpressure
                // would hang the writer forever.
                return Poll::Ready(Err(broken_pipe("the session ended with unsent data")));
            }
            // The peer's window is full. `pump` registered the waker, so a
            // `Progress` message will wake this task (section 7.5).
            return Poll::Pending;
        }
        if this.write_buf.len() + buf.len() > STREAM_MAX_CREDIT as usize {
            // Never buffer more than the maximum window: beyond it the honest
            // answer is backpressure, not unbounded memory.
            return Poll::Pending;
        }
        match this.handle.send_data(this.stream_id, buf) {
            Ok(sent) => Poll::Ready(Ok(sent)),
            Err(SessionError::Stream(StreamError::CreditExceeded { .. })) => {
                this.write_buf.extend_from_slice(buf);
                if let Err(error) = this.pump(cx) {
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Err(SessionError::UnknownStream(_)) => {
                Poll::Ready(Err(broken_pipe("the session stream is gone")))
            }
            Err(error) => Poll::Ready(Err(broken_pipe(&error.to_string()))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if let Err(error) = this.pump(cx) {
            return Poll::Ready(Err(error));
        }
        if this.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if this.write_closed {
            // No `Progress` can arrive any more, so a pending flush would hang.
            return Poll::Ready(Err(broken_pipe("the session ended with unsent data")));
        }
        Poll::Pending
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.fin_sent {
            return Poll::Ready(Ok(()));
        }
        match this.handle.send_fin(this.stream_id) {
            Ok(_) => {
                this.fin_sent = true;
                Poll::Ready(Ok(()))
            }
            Err(SessionError::UnknownStream(_)) => Poll::Ready(Ok(())),
            Err(error) => Poll::Ready(Err(broken_pipe(&error.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wsnet_crypto::{Psk, SessionKeys};
    use wsnet_session::{Session, SessionConfig, SessionState, Side};

    fn keys() -> SessionKeys {
        SessionKeys::derive(&Psk::from_bytes([0x5a; 32]), br#"{"a":1}"#, br#"{"b":2}"#)
    }

    /// Builds a paired node/hub session plus a stream on the node side, with the
    /// envelope pump running between them.
    fn pair() -> (SessionHandle, SessionStream) {
        let node: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let hub: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Hub),
            keys(),
        );
        let node_handle = node.handle.clone();
        let hub_handle = hub.handle.clone();
        let node_for_task = hub_handle.clone();
        let hub_for_task = node_handle.clone();
        let mut node_session = node;
        let mut hub_session = hub;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(envelope) = node_session.outbound.recv() => {
                        let _ = node_for_task.feed_lossy(&envelope);
                    }
                    Some(envelope) = hub_session.outbound.recv() => {
                        let _ = hub_for_task.feed_lossy(&envelope);
                    }
                    else => break,
                }
            }
        });
        node_handle.set_state(SessionState::Ready);
        hub_handle.set_state(SessionState::Ready);
        let (stream_id, _) = node_handle
            .open(
                wsnet_routing::Destination::address("example.com", 80),
                Vec::new(),
                wsnet_routing::Proto::Tcp,
                [9u8; 16],
            )
            .unwrap();
        let (_tx, rx) = mpsc::unbounded_channel();
        let stream = SessionStream::new(node_handle, stream_id, rx);
        (hub_handle, stream)
    }

    /// Section 7.2: a `Fin` that arrives before the buffered bytes are handed to
    /// the application must not look like end-of-file yet.
    #[tokio::test]
    async fn fin_waits_for_the_declared_offsets() {
        let session: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let handle = session.handle.clone();
        let stream_id = 1;
        let (tx, rx) = mpsc::unbounded_channel();
        let mut stream = SessionStream::new(handle, stream_id, rx);

        tx.send(StreamMsg::Data(b"hello".to_vec())).unwrap();
        tx.send(StreamMsg::Fin(5)).unwrap();
        drop(tx);

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
    }

    /// A `Fin` beyond the received bytes keeps the reader waiting rather than
    /// truncating the stream.
    #[tokio::test]
    async fn a_fin_beyond_the_received_bytes_does_not_end_the_stream() {
        let session: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let handle = session.handle.clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let mut stream = SessionStream::new(handle, 1, rx);

        tx.send(StreamMsg::Data(b"abc".to_vec())).unwrap();
        tx.send(StreamMsg::Fin(10)).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 3);
        // The remaining seven bytes never arrive, so the read is still pending:
        // the local half must not be shut down on a premature `Fin`.
        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.read(&mut buf)).await;
        assert!(pending.is_err(), "the stream ended before final_offset");
    }

    /// A reset surfaces as a connection reset instead of a clean end-of-file.
    #[tokio::test]
    async fn a_reset_is_reported_as_an_error() {
        let session: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let handle = session.handle.clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let mut stream = SessionStream::new(handle, 1, rx);
        tx.send(StreamMsg::Reset(ResetReason::Unreachable)).unwrap();
        let mut buf = [0u8; 8];
        let error = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    /// Writes smaller than the initial credit go straight out; consuming them on
    /// the hub side grants more (section 7.5).
    #[tokio::test]
    async fn consumption_grants_more_credit() {
        let (hub, mut stream) = pair();
        stream.write_all(b"0123456789").await.unwrap();
        stream.flush().await.unwrap();

        wait_for(|| hub.offsets(stream.stream_id()).map(|o| o.2) == Some(10)).await;
        let progress = hub.consume(stream.stream_id(), 10).unwrap().unwrap();
        assert_eq!(progress.consumed_offset, 10);
        // The granted window grew by exactly what was consumed.
        assert!(progress.limit_offset > wsnet_limits::STREAM_INITIAL_CREDIT);
    }

    async fn wait_for(mut condition: impl FnMut() -> bool) {
        for _ in 0..200 {
            if condition() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("condition never became true");
    }

    #[tokio::test]
    async fn shutdown_sends_a_fin_with_the_final_offset() {
        let (hub, mut stream) = pair();
        stream.write_all(b"abc").await.unwrap();
        // The hub sees the bytes arrive before the half-close is sent, which is
        // the ordering section 7.2 requires.
        wait_for(|| hub.offsets(stream.stream_id()).map(|o| o.2) == Some(3)).await;
        stream.shutdown().await.unwrap();
        // `send_fin` reports the offset of everything already sent, and is
        // idempotent.
        assert_eq!(stream.handle.offsets(stream.stream_id()).unwrap().0, 3);
        assert_eq!(stream.handle.send_fin(stream.stream_id()).unwrap(), 3);
    }

    /// The driver channel closing is a clean end-of-file for the reader.
    #[tokio::test]
    async fn a_closed_driver_ends_the_read_half() {
        let session: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        drop(tx);
        let mut stream = SessionStream::new(session.handle, 1, rx);
        let mut buf = [0u8; 4];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }
}

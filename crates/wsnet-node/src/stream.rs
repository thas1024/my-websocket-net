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

use wsnet_limits::{
    MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION, MAX_QUEUED_DATAGRAM_BYTES, STREAM_MAX_CREDIT,
};
use wsnet_session::{DatagramFields, ResetReason, SessionError, SessionHandle};
use wsnet_stream::StreamError;

/// One update the session driver hands to a single stream.
#[derive(Debug)]
pub(crate) enum StreamMsg {
    /// Ordered business bytes.
    Data(Vec<u8>),
    /// One complete datagram on this stream's UDP route (section 7.4).
    Datagram(Box<DatagramFields>, Vec<u8>),
    /// The peer raised the granted credit.
    Credit,
    /// The peer half-closed at this exclusive offset.
    Fin(u64),
    /// The peer terminated the stream.
    Reset(ResetReason),
}

/// The sending half of one UDP route (section 7.4).
///
/// It holds the session handle and the route's id, so it can be moved into the task
/// that owns a route while the receiving half stays borrowed in the same `select!`.
#[derive(Clone)]
pub struct DatagramSender {
    handle: SessionHandle,
    stream_id: u64,
}

impl DatagramSender {
    /// The route this sender writes to.
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Sends one datagram, with the same contract as
    /// [`SessionStream::send_datagram`].
    pub fn send(&self, fields: DatagramFields, payload: &[u8]) -> Result<(), SessionError> {
        self.handle
            .send_datagram(fields.to_canonical(), payload.to_vec())
    }
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
    /// Datagrams that arrived for this stream's UDP route but have not been taken.
    ///
    /// Section 7.4 keeps datagrams out of the byte path on purpose ("不与 TCP
    /// offset 混用"), so they queue here rather than in `read_buf`; the same section
    /// bounds the queue by count and by bytes.
    datagrams: VecDeque<(DatagramFields, Vec<u8>)>,
    /// Bytes held in `datagrams`, so the section 7.4 byte budget is enforced without
    /// summing the queue on every arrival.
    datagram_bytes: usize,
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
            datagrams: VecDeque::new(),
            datagram_bytes: 0,
        }
    }

    /// Datagrams waiting to be taken.
    pub fn queued_datagrams(&self) -> usize {
        self.datagrams.len()
    }

    /// Bytes held in the datagram queue (section 7.4's 256 KiB budget).
    pub fn queued_datagram_bytes(&self) -> usize {
        self.datagram_bytes
    }

    /// Sends one complete datagram on this stream's UDP route (section 7.4).
    ///
    /// The caller supplies `association_id` and `datagram_id`; this type only
    /// carries them, because the association those numbers describe lives above the
    /// stream (one association, many routes). An oversized payload is refused by the
    /// record layer, which is the layer section 7.4 gives the "one datagram, one
    /// record, never split" rule to.
    pub fn send_datagram(
        &self,
        fields: DatagramFields,
        payload: &[u8],
    ) -> Result<(), SessionError> {
        self.handle
            .send_datagram(fields.to_canonical(), payload.to_vec())
    }

    /// The sending half of this route, as a value that borrows nothing.
    ///
    /// A route handler has to send outgoing datagrams and wait for incoming ones at
    /// the same time, and one `&mut SessionStream` cannot appear in both halves of a
    /// `select!`. Splitting the sender out is what makes that legal rather than
    /// clever.
    pub fn datagram_sender(&self) -> DatagramSender {
        DatagramSender {
            handle: self.handle.clone(),
            stream_id: self.stream_id,
        }
    }

    /// Takes the next datagram, waiting for one to arrive.
    ///
    /// Returns `None` once the stream is over and no datagram is left. Byte data
    /// that arrives meanwhile is kept for the byte path rather than discarded, and
    /// counts as delivered only when a read takes it, exactly as section 7.5
    /// requires of credit.
    pub async fn recv_datagram(&mut self) -> Option<(DatagramFields, Vec<u8>)> {
        loop {
            // Absorb everything already queued before taking one, so section 7.4's
            // count and byte budgets apply to a *burst*: absorbing a single message
            // per call would leave the queue one entry deep and make the budgets
            // unreachable, which is the opposite of what they are for.
            while let Ok(message) = self.rx.try_recv() {
                self.absorb(message);
            }
            if let Some(datagram) = self.take_datagram() {
                return Some(datagram);
            }
            match self.rx.recv().await {
                Some(message) => self.absorb(message),
                None => return None,
            }
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
            StreamMsg::Datagram(fields, payload) => self.queue_datagram(*fields, payload),
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

    /// Queues one datagram inside section 7.4's count and byte budgets.
    ///
    /// When the queue is full the *oldest* datagram is dropped, not the new one:
    /// UDP has no delivery promise here (section 7.4 says so explicitly), and for a
    /// real-time-ish flow the datagram that has been waiting longest is the one
    /// least worth keeping. A refusal would instead hand the sender backpressure it
    /// cannot use, since a datagram cannot be retried without changing the
    /// protocol's meaning.
    fn queue_datagram(&mut self, fields: DatagramFields, payload: Vec<u8>) {
        while self.datagrams.len() >= MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION
            || self.datagram_bytes + payload.len() > MAX_QUEUED_DATAGRAM_BYTES
        {
            let Some((_, dropped)) = self.datagrams.pop_front() else {
                break;
            };
            self.datagram_bytes -= dropped.len();
        }
        // A single payload larger than the whole budget was already refused by the
        // record layer, so this can only be reached with a legal payload.
        self.datagram_bytes += payload.len();
        self.datagrams.push_back((fields, payload));
    }

    /// Removes the next queued datagram, if any.
    fn take_datagram(&mut self) -> Option<(DatagramFields, Vec<u8>)> {
        let (fields, payload) = self.datagrams.pop_front()?;
        self.datagram_bytes -= payload.len();
        Some((fields, payload))
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

    // ------------------------------------------------------------- section 7.4

    fn datagram(id: u64, payload: &[u8]) -> (DatagramFields, Vec<u8>) {
        (
            DatagramFields {
                stream_id: 1,
                association_id: 2,
                datagram_id: id,
                host: "example.com".to_string(),
                port: 53,
                remaining_ttl_ms: 1_000,
            },
            payload.to_vec(),
        )
    }

    /// Section 7.4 bounds a queue by count *and* by bytes, and drops rather than
    /// blocking: a datagram has no delivery promise to break.
    #[tokio::test]
    async fn the_datagram_queue_honours_the_section_7_4_budgets() {
        let session: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        let mut stream = SessionStream::new(session.handle, 1, rx);

        // One past the count budget. Nothing is absorbed until the first take, and
        // that take drains the whole burst first: the budgets exist for a burst, so
        // applying them one message at a time would make them unreachable.
        let overflow = MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION + 8;
        for id in 0..overflow as u64 {
            let (fields, payload) = datagram(id, b"x");
            tx.send(StreamMsg::Datagram(Box::new(fields), payload))
                .unwrap();
        }
        let first = stream.recv_datagram().await.expect("a queued datagram");
        assert_eq!(
            first.0.datagram_id, 8,
            "the oldest datagrams must be the ones dropped"
        );
        assert_eq!(
            stream.queued_datagrams(),
            MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION - 1,
            "the count budget must bind at {MAX_QUEUED_DATAGRAMS_PER_ASSOCIATION}"
        );

        // Then the byte budget, with a small count so only bytes can bind.
        let session: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        let mut stream = SessionStream::new(session.handle, 1, rx);
        let chunk = vec![0u8; MAX_QUEUED_DATAGRAM_BYTES / 4];
        for id in 0..8u64 {
            let (fields, payload) = datagram(id, &chunk);
            tx.send(StreamMsg::Datagram(Box::new(fields), payload))
                .unwrap();
        }
        let first = stream.recv_datagram().await.expect("a queued datagram");
        assert_eq!(
            first.0.datagram_id, 4,
            "only four chunks fit the byte budget"
        );
        assert!(
            stream.queued_datagram_bytes() <= MAX_QUEUED_DATAGRAM_BYTES,
            "held {} bytes, budget is {MAX_QUEUED_DATAGRAM_BYTES}",
            stream.queued_datagram_bytes()
        );
        assert_eq!(stream.queued_datagrams(), 3, "three chunks are left");

        // Draining restores the byte accounting, so the budget is not a one-way
        // leak of the structure's capacity. The sender has to go first: an empty
        // queue with a live channel is simply "nothing yet", which is a wait, not an
        // end.
        drop(tx);
        while stream.recv_datagram().await.is_some() {}
        assert_eq!(stream.queued_datagram_bytes(), 0);
        assert_eq!(stream.queued_datagrams(), 0);
    }

    /// A datagram and byte data share one channel without either being lost.
    #[tokio::test]
    async fn datagrams_and_bytes_do_not_consume_each_other() {
        let session: Session = Session::new(
            SessionConfig::new("hub-a", "client-a", [1u8; 16], [2u8; 16], Side::Node),
            keys(),
        );
        let (tx, rx) = mpsc::unbounded_channel();
        let mut stream = SessionStream::new(session.handle, 1, rx);

        let (fields, payload) = datagram(7, b"dgram");
        tx.send(StreamMsg::Data(b"bytes".to_vec())).unwrap();
        tx.send(StreamMsg::Datagram(Box::new(fields.clone()), payload))
            .unwrap();
        tx.send(StreamMsg::Fin(5)).unwrap();
        drop(tx);

        // Reading the byte path must not swallow the datagram that arrived in
        // between, which is what "不与 TCP offset 混用" means in practice.
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bytes");
        let taken = stream.recv_datagram().await.expect("the datagram survived");
        assert_eq!(taken.0, fields);
        assert_eq!(taken.1, b"dgram");
        assert!(stream.recv_datagram().await.is_none());
    }
}

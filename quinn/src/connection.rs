use std::{
    collections::HashMap,
    fmt,
    future::Future,
    mem,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Instant,
};

use bytes::Bytes;
use err_derive::Error;
use futures::{
    channel::{mpsc, oneshot},
    FutureExt, StreamExt,
};
use proto::{ConnectionError, ConnectionHandle, Dir, StreamEvent, StreamId};
use tokio::time::{delay_until, Delay, Instant as TokioInstant};
use tracing::info_span;

use crate::{
    broadcast::{self, Broadcast},
    streams::{RecvStream, SendStream, WriteError},
    ConnectionEvent, EndpointEvent, VarInt,
};

/// In-progress connection attempt future
#[derive(Debug)]
pub struct Connecting<S>
where
    S: proto::crypto::Session,
{
    conn: Option<ConnectionRef<S>>,
    connected: oneshot::Receiver<bool>,
    auth_data_ready: Option<oneshot::Receiver<()>>,
}

impl<S> Connecting<S>
where
    S: proto::crypto::Session + 'static,
{
    pub(crate) fn new(
        handle: ConnectionHandle,
        conn: proto::generic::Connection<S>,
        endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    ) -> Connecting<S> {
        let (on_auth_data_send, on_auth_data_recv) = oneshot::channel();
        let (on_connected_send, on_connected_recv) = oneshot::channel();
        let conn = ConnectionRef::new(
            handle,
            conn,
            endpoint_events,
            conn_events,
            on_auth_data_send,
            on_connected_send,
        );

        tokio::spawn(ConnectionDriver(conn.clone()));

        Connecting {
            conn: Some(conn),
            connected: on_connected_recv,
            auth_data_ready: Some(on_auth_data_recv),
        }
    }

    /// Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened security
    ///
    /// Opens up the connection for use before the handshake finishes, allowing the API user to
    /// send data with 0-RTT encryption if the necessary key material is available. This is useful
    /// for reducing start-up latency by beginning transmission of application data without waiting
    /// for the handshake's cryptographic security guarantees to be established.
    ///
    /// When the `ZeroRttAccepted` future completes, the connection has been fully established.
    ///
    /// # Security
    ///
    /// On outgoing connections, this enables transmission of 0-RTT data, which might be vulnerable
    /// to replay attacks, and should therefore never invoke non-idempotent operations.
    ///
    /// On incoming connections, this enables transmission of 0.5-RTT data, which might be
    /// intercepted by a man-in-the-middle. If this occurs, the handshake will not complete
    /// successfully.
    ///
    /// # Errors
    ///
    /// Outgoing connections are only 0-RTT-capable when a cryptographic session ticket cached from
    /// a previous connection to the same server is available, and includes a 0-RTT key. If no such
    /// ticket is found, `self` is returned unmodified.
    ///
    /// For incoming connections, a 0.5-RTT connection will always be successfully constructed.
    pub fn into_0rtt(mut self) -> Result<(NewConnection<S>, ZeroRttAccepted), Self> {
        // This lock borrows `self` and would normally be dropped at the end of this scope, so we'll
        // have to release it explicitly before returning `self` by value.
        let conn = (self.conn.as_mut().unwrap().0).lock().unwrap();
        if conn.inner.has_0rtt() || conn.inner.side().is_server() {
            drop(conn);
            let conn = self.conn.take().unwrap();
            Ok((NewConnection::new(conn), ZeroRttAccepted(self.connected)))
        } else {
            drop(conn);
            Err(self)
        }
    }

    /// Data conveyed by the peer during the handshake
    ///
    /// Since the handshake is incomplete at this point, the returned data is likely to be
    /// incomplete as well.
    pub async fn authentication_data(&mut self) -> S::AuthenticationData {
        // Taking &mut self allows us to use a single oneshot channel rather than dealing with
        // potentially many tasks waiting on the same event. It's a bit of a hack, but keeps things
        // simple.
        if let Some(x) = self.auth_data_ready.take() {
            let _ = x.await;
        }
        self.conn
            .as_ref()
            .unwrap()
            .0
            .lock()
            .unwrap()
            .inner
            .crypto_session()
            .authentication_data()
    }
}

impl<S> Future for Connecting<S>
where
    S: proto::crypto::Session,
{
    type Output = Result<NewConnection<S>, ConnectionError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.connected.poll_unpin(cx).map(|_| {
            let conn = self.conn.take().unwrap();
            let inner = conn.lock().unwrap();
            if inner.connected {
                drop(inner);
                Ok(NewConnection::new(conn))
            } else {
                Err(inner
                    .error
                    .clone()
                    .expect("connected signaled without connection success or error"))
            }
        })
    }
}

impl<S> Connecting<S>
where
    S: proto::crypto::Session,
{
    /// The peer's UDP address.
    ///
    /// Will panic if called after `poll` has returned `Ready`.
    pub fn remote_address(&self) -> SocketAddr {
        let conn_ref: &ConnectionRef<S> = &self.conn.as_ref().expect("used after yielding Ready");
        conn_ref.lock().unwrap().inner.remote_address()
    }
}

/// Future that completes when a connection is fully established
///
/// For clients, the resulting value indicates if 0-RTT was accepted. For servers, the resulting
/// value is meaningless.
pub struct ZeroRttAccepted(oneshot::Receiver<bool>);

impl Future for ZeroRttAccepted {
    type Output = bool;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.0.poll_unpin(cx).map(|x| x.unwrap_or(false))
    }
}

/// Components of a newly established connection
///
/// All fields of this struct, in addition to any other handles constructed later, must be dropped
/// for a connection to be implicitly closed. If the `NewConnection` is stored in a long-lived
/// variable, moving individual fields won't cause remaining unused fields to be dropped, even with
/// pattern-matching. The easiest way to ensure unused fields are dropped is to pattern-match on the
/// variable wrapped in brackets, which forces the entire `NewConnection` to be moved out of the
/// variable and into a temporary, ensuring all unused fields are dropped at the end of the
/// statement:
///
#[cfg_attr(
    feature = "rustls",
    doc = "```rust
# use quinn::NewConnection;
# fn dummy(new_connection: NewConnection) {
let NewConnection { connection, .. } = { new_connection };
# }
```"
)]
///
/// You can also explicitly invoke `Connection::close` at any time.
#[derive(Debug)]
#[non_exhaustive]
pub struct NewConnection<S>
where
    S: proto::crypto::Session,
{
    /// Handle for interacting with the connection
    pub connection: Connection<S>,
    /// Unidirectional streams initiated by the peer, in the order they were opened
    ///
    /// Note that data for separate streams may be delivered in any order. In other words, reading
    /// from streams in the order they're opened is not optimal. See `IncomingUniStreams` for
    /// details.
    pub uni_streams: IncomingUniStreams<S>,
    /// Bidirectional streams initiated by the peer, in the order they were opened
    pub bi_streams: IncomingBiStreams<S>,
    /// Unordered, unreliable datagrams sent by the peer
    pub datagrams: Datagrams<S>,
}

impl<S> NewConnection<S>
where
    S: proto::crypto::Session,
{
    fn new(conn: ConnectionRef<S>) -> Self {
        Self {
            connection: Connection(conn.clone()),
            uni_streams: IncomingUniStreams(conn.clone()),
            bi_streams: IncomingBiStreams(conn.clone()),
            datagrams: Datagrams(conn),
        }
    }
}

/// A future that drives protocol logic for a connection
///
/// This future handles the protocol logic for a single connection, routing events from the
/// `Connection` API object to the `Endpoint` task and the related stream-related interfaces.
/// It also keeps track of outstanding timeouts for the `Connection`.
///
/// If the connection encounters an error condition, this future will yield an error. It will
/// terminate (yielding `Ok(())`) if the connection was closed without error. Unlike other
/// connection-related futures, this waits for the draining period to complete to ensure that
/// packets still in flight from the peer are handled gracefully.
#[must_use = "connection drivers must be spawned for their connections to function"]
#[derive(Debug)]
struct ConnectionDriver<S: proto::crypto::Session>(ConnectionRef<S>);

impl<S> Future for ConnectionDriver<S>
where
    S: proto::crypto::Session,
{
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let conn = &mut *self.0.lock().unwrap();

        let span = info_span!("drive", id = conn.handle.0);
        let _guard = span.enter();

        loop {
            let mut keep_going = false;
            if let Err(e) = conn.process_conn_events(cx) {
                conn.terminate(e);
                return Poll::Ready(());
            }
            conn.drive_transmit();
            // If a timer expires, there might be more to transmit. When we transmit something, we
            // might need to reset a timer. Hence, we must loop until neither happens.
            keep_going |= conn.drive_timer(cx);
            conn.forward_endpoint_events();
            conn.forward_app_events();
            if !keep_going || conn.inner.is_drained() {
                break;
            }
        }

        if !conn.inner.is_drained() {
            conn.driver = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match conn.error {
            Some(ConnectionError::LocallyClosed) => Poll::Ready(()),
            Some(_) => Poll::Ready(()),
            None => unreachable!("drained connections always have an error"),
        }
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the `Connection` handle, streams of
/// incoming streams, and the various stream types) other than the `ConnectionDriver` have been
/// dropped, the the connection will be automatically closed with an `error_code` of 0 and an empty
/// `reason`. You can also close the connection explicitly by calling `Connection::close()`.
///
/// May be cloned to obtain another handle to the same connection.
#[derive(Debug)]
pub struct Connection<S: proto::crypto::Session>(ConnectionRef<S>);

impl<S> Connection<S>
where
    S: proto::crypto::Session,
{
    /// Initiate a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub fn open_uni(&self) -> OpenUni<S> {
        OpenUni {
            conn: self.0.clone(),
            state: broadcast::State::default(),
        }
    }

    /// Initiate a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the stream is
    /// actually used.
    pub fn open_bi(&self) -> OpenBi<S> {
        OpenBi {
            conn: self.0.clone(),
            state: broadcast::State::default(),
        }
    }

    /// Close the connection immediately.
    ///
    /// Pending operations will fail immediately with `ConnectionError::LocallyClosed`. Delivery of
    /// data on unfinished streams is not guaranteed, so the application must call this only when
    /// all important communications have been completed, e.g. by calling `finish` on outstanding
    /// `SendStream`s and waiting for the resulting futures to complete.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds that it
    /// is preserved in full, it should be kept under 1KiB.
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        let conn = &mut *self.0.lock().unwrap();
        conn.close(error_code, Bytes::copy_from_slice(reason));
    }

    /// Transmit `data` as an unreliable, unordered application datagram
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out of order,
    /// and `data` must both fit inside a single QUIC packet and be smaller than the maximum
    /// dictated by the peer.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), SendDatagramError> {
        let conn = &mut *self.0.lock().unwrap();
        if let Some(ref x) = conn.error {
            return Err(SendDatagramError::ConnectionClosed(x.clone()));
        }
        use proto::SendDatagramError::*;
        match conn.inner.send_datagram(data) {
            Ok(()) => {
                conn.wake();
                Ok(())
            }
            Err(e) => Err(match e {
                UnsupportedByPeer => SendDatagramError::UnsupportedByPeer,
                Disabled => SendDatagramError::Disabled,
                TooLarge => SendDatagramError::TooLarge,
            }),
        }
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.0.lock().unwrap().inner.max_datagram_size()
    }

    /// The peer's UDP address
    ///
    /// If `ServerConfig::migration` is `true`, clients may change addresses at will, e.g. when
    /// switching to a cellular internet connection.
    pub fn remote_address(&self) -> SocketAddr {
        self.0.lock().unwrap().inner.remote_address()
    }

    /// Data conveyed by the peer during the handshake, including cryptographic identity
    pub fn authentication_data(&self) -> S::AuthenticationData {
        self.0
            .lock()
            .unwrap()
            .inner
            .crypto_session()
            .authentication_data()
    }

    // Update traffic keys spontaneously for testing purposes.
    #[doc(hidden)]
    pub fn force_key_update(&self) {
        self.0.lock().unwrap().inner.initiate_key_update()
    }
}

impl<S> Clone for Connection<S>
where
    S: proto::crypto::Session,
{
    fn clone(&self) -> Self {
        Connection(self.0.clone())
    }
}

/// A stream of unidirectional QUIC streams initiated by a remote peer.
///
/// Incoming streams are *always* opened in the same order that the peer created them, but data can
/// be delivered to open streams in any order. This allows meaning to be assigned to the sequence in
/// which streams are opened. For example, a file transfer protocol might designate the first stream
/// the client opens as a "control" stream, using all others for exchanging file data.
///
/// Processing streams in the order they're opened will produce head-of-line blocking. For best
/// performance, an application should be prepared to fully process later streams before any data is
/// received on earlier streams.
#[derive(Debug)]
pub struct IncomingUniStreams<S: proto::crypto::Session>(ConnectionRef<S>);

impl<S> futures::Stream for IncomingUniStreams<S>
where
    S: proto::crypto::Session,
{
    type Item = Result<RecvStream<S>, ConnectionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut conn = self.0.lock().unwrap();
        if let Some(x) = conn.inner.accept(Dir::Uni) {
            conn.wake(); // To send additional stream ID credit
            mem::drop(conn); // Release the lock so clone can take it
            Poll::Ready(Some(Ok(RecvStream::new(self.0.clone(), x, false))))
        } else if let Some(ConnectionError::LocallyClosed) = conn.error {
            Poll::Ready(None)
        } else if let Some(ref e) = conn.error {
            Poll::Ready(Some(Err(e.clone())))
        } else {
            conn.incoming_uni_streams_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A stream of bidirectional QUIC streams initiated by a remote peer.
///
/// See `IncomingUniStreams` for information about incoming streams in general.
#[derive(Debug)]
pub struct IncomingBiStreams<S: proto::crypto::Session>(ConnectionRef<S>);

impl<S> futures::Stream for IncomingBiStreams<S>
where
    S: proto::crypto::Session,
{
    type Item = Result<(SendStream<S>, RecvStream<S>), ConnectionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut conn = self.0.lock().unwrap();
        if let Some(x) = conn.inner.accept(Dir::Bi) {
            let is_0rtt = conn.inner.is_handshaking();
            conn.wake(); // To send additional stream ID credit
            mem::drop(conn); // Release the lock so clone can take it
            Poll::Ready(Some(Ok((
                SendStream::new(self.0.clone(), x, is_0rtt),
                RecvStream::new(self.0.clone(), x, is_0rtt),
            ))))
        } else if let Some(ConnectionError::LocallyClosed) = conn.error {
            Poll::Ready(None)
        } else if let Some(ref e) = conn.error {
            Poll::Ready(Some(Err(e.clone())))
        } else {
            conn.incoming_bi_streams_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// Stream of unordered, unreliable datagrams sent by the peer
#[derive(Debug)]
pub struct Datagrams<S: proto::crypto::Session>(ConnectionRef<S>);

impl<S> futures::Stream for Datagrams<S>
where
    S: proto::crypto::Session,
{
    type Item = Result<Bytes, ConnectionError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut conn = self.0.lock().unwrap();
        if let Some(x) = conn.inner.recv_datagram() {
            Poll::Ready(Some(Ok(x)))
        } else if let Some(ConnectionError::LocallyClosed) = conn.error {
            Poll::Ready(None)
        } else if let Some(ref e) = conn.error {
            Poll::Ready(Some(Err(e.clone())))
        } else {
            conn.datagram_reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

/// A future that will resolve into an opened outgoing unidirectional stream
pub struct OpenUni<S>
where
    S: proto::crypto::Session,
{
    conn: ConnectionRef<S>,
    state: broadcast::State,
}

impl<S> Future for OpenUni<S>
where
    S: proto::crypto::Session,
{
    type Output = Result<SendStream<S>, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut conn = this.conn.lock().unwrap();
        if let Some(ref e) = conn.error {
            return Poll::Ready(Err(e.clone()));
        }
        if let Some(id) = conn.inner.open(Dir::Uni) {
            let is_0rtt = conn.inner.side().is_client() && conn.inner.is_handshaking();
            drop(conn); // Release lock for clone
            return Poll::Ready(Ok(SendStream::new(this.conn.clone(), id, is_0rtt)));
        }
        conn.uni_opening.register(cx, &mut this.state);
        Poll::Pending
    }
}

/// A future that will resolve into an opened outgoing bidirectional stream
pub struct OpenBi<S>
where
    S: proto::crypto::Session,
{
    conn: ConnectionRef<S>,
    state: broadcast::State,
}

impl<S> Future for OpenBi<S>
where
    S: proto::crypto::Session,
{
    type Output = Result<(SendStream<S>, RecvStream<S>), ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut conn = this.conn.lock().unwrap();
        if let Some(ref e) = conn.error {
            return Poll::Ready(Err(e.clone()));
        }
        if let Some(id) = conn.inner.open(Dir::Bi) {
            let is_0rtt = conn.inner.side().is_client() && conn.inner.is_handshaking();
            drop(conn); // Release lock for clone
            return Poll::Ready(Ok((
                SendStream::new(this.conn.clone(), id, is_0rtt),
                RecvStream::new(this.conn.clone(), id, is_0rtt),
            )));
        }
        conn.bi_opening.register(cx, &mut this.state);
        Poll::Pending
    }
}

#[derive(Debug)]
pub struct ConnectionRef<S: proto::crypto::Session>(Arc<Mutex<ConnectionInner<S>>>);

impl<S> ConnectionRef<S>
where
    S: proto::crypto::Session,
{
    fn new(
        handle: ConnectionHandle,
        conn: proto::generic::Connection<S>,
        endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
        conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
        on_auth_data: oneshot::Sender<()>,
        on_connected: oneshot::Sender<bool>,
    ) -> Self {
        Self(Arc::new(Mutex::new(ConnectionInner {
            inner: conn,
            driver: None,
            handle,
            on_auth_data: Some(on_auth_data),
            on_connected: Some(on_connected),
            connected: false,
            timer: None,
            conn_events,
            endpoint_events,
            blocked_writers: HashMap::new(),
            blocked_readers: HashMap::new(),
            uni_opening: Broadcast::new(),
            bi_opening: Broadcast::new(),
            incoming_uni_streams_reader: None,
            incoming_bi_streams_reader: None,
            datagram_reader: None,
            finishing: HashMap::new(),
            error: None,
            ref_count: 0,
        })))
    }
}

impl<S> Clone for ConnectionRef<S>
where
    S: proto::crypto::Session,
{
    fn clone(&self) -> Self {
        self.0.lock().unwrap().ref_count += 1;
        Self(self.0.clone())
    }
}

impl<S> Drop for ConnectionRef<S>
where
    S: proto::crypto::Session,
{
    fn drop(&mut self) {
        let conn = &mut *self.0.lock().unwrap();
        if let Some(x) = conn.ref_count.checked_sub(1) {
            conn.ref_count = x;
            if x == 0 && !conn.inner.is_closed() {
                // If the driver is alive, it's just it and us, so we'd better shut it down. If it's
                // not, we can't do any harm. If there were any streams being opened, then either
                // the connection will be closed for an unrelated reason or a fresh reference will
                // be constructed for the newly opened stream.
                conn.implicit_close();
            }
        }
    }
}

impl<S> std::ops::Deref for ConnectionRef<S>
where
    S: proto::crypto::Session,
{
    type Target = Mutex<ConnectionInner<S>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct ConnectionInner<S>
where
    S: proto::crypto::Session,
{
    pub(crate) inner: proto::generic::Connection<S>,
    driver: Option<Waker>,
    handle: ConnectionHandle,
    on_auth_data: Option<oneshot::Sender<()>>,
    on_connected: Option<oneshot::Sender<bool>>,
    connected: bool,
    timer: Option<Delay>,
    conn_events: mpsc::UnboundedReceiver<ConnectionEvent>,
    endpoint_events: mpsc::UnboundedSender<(ConnectionHandle, EndpointEvent)>,
    pub(crate) blocked_writers: HashMap<StreamId, Waker>,
    pub(crate) blocked_readers: HashMap<StreamId, Waker>,
    uni_opening: Broadcast,
    bi_opening: Broadcast,
    incoming_uni_streams_reader: Option<Waker>,
    incoming_bi_streams_reader: Option<Waker>,
    datagram_reader: Option<Waker>,
    pub(crate) finishing: HashMap<StreamId, oneshot::Sender<Option<WriteError>>>,
    /// Always set to Some before the connection becomes drained
    pub(crate) error: Option<ConnectionError>,
    /// Number of live handles that can be used to initiate or handle I/O; excludes the driver
    ref_count: usize,
}

impl<S> ConnectionInner<S>
where
    S: proto::crypto::Session,
{
    fn drive_transmit(&mut self) {
        let now = Instant::now();
        while let Some(t) = self.inner.poll_transmit(now) {
            // If the endpoint driver is gone, noop.
            let _ = self
                .endpoint_events
                .unbounded_send((self.handle, EndpointEvent::Transmit(t)));
        }
    }

    fn forward_endpoint_events(&mut self) {
        while let Some(event) = self.inner.poll_endpoint_events() {
            // If the endpoint driver is gone, noop.
            let _ = self
                .endpoint_events
                .unbounded_send((self.handle, EndpointEvent::Proto(event)));
        }
    }

    /// If this returns `Err`, the endpoint is dead, so the driver should exit immediately.
    fn process_conn_events(&mut self, cx: &mut Context) -> Result<(), ConnectionError> {
        loop {
            match self.conn_events.poll_next_unpin(cx) {
                Poll::Ready(Some(ConnectionEvent::Proto(event))) => {
                    self.inner.handle_event(event);
                }
                Poll::Ready(Some(ConnectionEvent::Close { reason, error_code })) => {
                    self.close(error_code, reason);
                }
                Poll::Ready(None) => {
                    return Err(ConnectionError::TransportError(proto::TransportError {
                        code: proto::TransportErrorCode::INTERNAL_ERROR,
                        frame: None,
                        reason: "endpoint driver future was dropped".to_string(),
                    }));
                }
                Poll::Pending => {
                    return Ok(());
                }
            }
        }
    }

    fn forward_app_events(&mut self) {
        while let Some(event) = self.inner.poll() {
            use proto::Event::*;
            match event {
                AuthenticationDataReady => {
                    if let Some(x) = self.on_auth_data.take() {
                        let _ = x.send(());
                    }
                }
                Connected => {
                    self.connected = true;
                    if let Some(x) = self.on_connected.take() {
                        // We don't care if the on-connected future was dropped
                        let _ = x.send(self.inner.accepted_0rtt());
                    }
                }
                ConnectionLost { reason } => {
                    self.terminate(reason);
                }
                Stream(StreamEvent::Writable { id }) => {
                    if let Some(writer) = self.blocked_writers.remove(&id) {
                        writer.wake();
                    }
                }
                Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    if let Some(x) = self.incoming_uni_streams_reader.take() {
                        x.wake();
                    }
                }
                Stream(StreamEvent::Opened { dir: Dir::Bi }) => {
                    if let Some(x) = self.incoming_bi_streams_reader.take() {
                        x.wake();
                    }
                }
                DatagramReceived => {
                    if let Some(x) = self.datagram_reader.take() {
                        x.wake();
                    }
                }
                Stream(StreamEvent::Readable { id }) => {
                    if let Some(reader) = self.blocked_readers.remove(&id) {
                        reader.wake();
                    }
                }
                Stream(StreamEvent::Available { dir }) => {
                    let tasks = match dir {
                        Dir::Uni => &mut self.uni_opening,
                        Dir::Bi => &mut self.bi_opening,
                    };
                    tasks.wake();
                }
                Stream(StreamEvent::Finished { id, stop_reason }) => {
                    if let Some(finishing) = self.finishing.remove(&id) {
                        // If the finishing stream was already dropped, there's nothing more to do.
                        let _ = finishing.send(stop_reason.map(WriteError::Stopped));
                    }
                }
            }
        }
    }

    fn drive_timer(&mut self, cx: &mut Context) -> bool {
        let mut keep_going = false;
        loop {
            if let Some(ref mut delay) = self.timer {
                if delay.poll_unpin(cx) == Poll::Ready(()) {
                    // We must get a fresh `now` each iteration. If the value were cached and tokio
                    // deems a timer for a later time than the cached value to be expired, we'd get
                    // stuck in an infinite loop resetting it.
                    self.inner.handle_timeout(Instant::now());
                    self.timer = None;
                    // A timer expired, so the caller needs to check for new transmits, which might
                    // cause new timers to be set.
                    keep_going = true;
                }
            }
            // Check whether we need to (re)set the timer. If so, we must poll again to ensure the
            // timer is registered with the runtime (and check whether it's already
            // expired). Otherwise, exit the loop.
            match (
                self.inner.poll_timeout().map(TokioInstant::from_std),
                &mut self.timer,
            ) {
                (Some(timeout), &mut None) => self.timer = Some(delay_until(timeout)),
                (Some(timeout), &mut Some(ref mut delay)) if delay.deadline() != timeout => {
                    delay.reset(timeout);
                }
                (None, _) => {
                    self.timer = None;
                    break;
                }
                _ => break,
            }
        }
        keep_going
    }

    /// Wake up a blocked `Driver` task to process I/O
    pub(crate) fn wake(&mut self) {
        if let Some(x) = self.driver.take() {
            x.wake();
        }
    }

    /// Used to wake up all blocked futures when the connection becomes closed for any reason
    fn terminate(&mut self, reason: ConnectionError) {
        self.error = Some(reason.clone());
        for (_, writer) in self.blocked_writers.drain() {
            writer.wake()
        }
        for (_, reader) in self.blocked_readers.drain() {
            reader.wake()
        }
        self.uni_opening.wake();
        self.bi_opening.wake();
        if let Some(x) = self.incoming_uni_streams_reader.take() {
            x.wake();
        }
        if let Some(x) = self.incoming_bi_streams_reader.take() {
            x.wake();
        }
        if let Some(x) = self.datagram_reader.take() {
            x.wake();
        }
        for (_, x) in self.finishing.drain() {
            let _ = x.send(Some(WriteError::ConnectionClosed(reason.clone())));
        }
        if let Some(x) = self.on_connected.take() {
            let _ = x.send(false);
        }
    }

    fn close(&mut self, error_code: VarInt, reason: Bytes) {
        self.inner.close(Instant::now(), error_code, reason);
        self.terminate(ConnectionError::LocallyClosed);
        self.wake();
    }

    /// Close for a reason other than the application's explicit request
    pub fn implicit_close(&mut self) {
        self.close(0u32.into(), Bytes::new());
    }

    pub(crate) fn check_0rtt(&self) -> Result<(), ()> {
        if self.inner.is_handshaking()
            || self.inner.accepted_0rtt()
            || self.inner.side().is_server()
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl<S> Drop for ConnectionInner<S>
where
    S: proto::crypto::Session,
{
    fn drop(&mut self) {
        if !self.inner.is_drained() {
            // Ensure the endpoint can tidy up
            let _ = self.endpoint_events.unbounded_send((
                self.handle,
                EndpointEvent::Proto(proto::EndpointEvent::drained()),
            ));
        }
    }
}

impl<S> fmt::Debug for ConnectionInner<S>
where
    S: proto::crypto::Session,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ConnectionInner")
            .field("inner", &self.inner)
            .finish()
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error(display = "datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error(display = "datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error(display = "datagram too large")]
    TooLarge,
    /// The connection was closed
    #[error(display = "connection closed: {}", _0)]
    ConnectionClosed(ConnectionError),
}

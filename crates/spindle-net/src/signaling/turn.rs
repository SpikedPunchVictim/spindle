//! TURN relay fallback for the native↔native QUIC path (DESIGN.md §A8/A10.8/A10.32, td-c3badf),
//! graduated from `spikes/s19-quic-transport/src/bin/quic-peer.rs`'s leg 3
//! (`turn_relay_setup`/`drive_turn_until`/`TurnRelaySocket`). Read that file's module doc comment
//! for the empirical groundwork; this module does not re-derive it.
//!
//! # Why this path needs an adapter at all
//!
//! `rtc_turn::client::Client` is sans-I/O exactly like `rtc-ice`'s agent: it owns no socket. But
//! unlike the ICE path — where the caller hands the punched `std::net::UdpSocket` straight to
//! quinn (see [`super::ice`]'s module doc comment) — relayed traffic is *encapsulated*: every QUIC
//! datagram must be wrapped in a TURN Send-indication/ChannelData frame before it goes to the TURN
//! server, and every inbound frame must be unwrapped. [`TurnRelaySocket`] is that encoder/decoder,
//! a hand-written [`quinn::AsyncUdpSocket`] around the sans-I/O client plus the real socket talking
//! to the TURN server. Same shape as the spike's adapter, plus the pieces the spike left out:
//! [`spawn_driver`] keeps rtc-turn's allocation/permission refresh timers running once quinn owns
//! the socket (without it the permission expires at 300 s and the allocation at 600 s), and
//! [`TurnRelaySocket`]'s `Drop` releases the allocation with a zero-lifetime Refresh instead of
//! leaving coturn to hold a relay port for its full lifetime. Remaining limits: single remote, no
//! GSO/GRO/ECN, and a send backlog cap ([`MAX_RETRY_WIRE`]) rather than unbounded buffering.
//!
//! # How a relay is selected in this slice (td-c3badf)
//!
//! When `IceConfig::turn` is set, the session **uses the relay unconditionally** and does not run
//! ICE connectivity checks. That is a deliberate slice boundary, not an oversight:
//!
//! - `rtc_ice::agent::Agent` cannot route its checks through TURN. A relayed candidate in the
//!   agent would make it send checks from the local base socket straight to the peer's relayed
//!   address, bypassing the TURN server, so a relay pair can never be selected through ICE here.
//! - Punch-first-with-relay-fallback needs both peers to agree on the outcome. A one-sided ICE
//!   failure (the Linux-conntrack mapping race `td-3c1762` root-caused is exactly one-sided) could
//!   leave one peer on the punched socket and the other on the relay, and the existing wire
//!   payload has no field to coordinate the decision.
//!
//! So the operator chooses: TURN configured ⇒ relay; TURN absent ⇒ punch (the pre-td-c3badf
//! behaviour). The follow-up for punch-then-fallback-with-agreement is scoped on td-c3badf.
//!
//! # Credential source
//!
//! This slice deliberately does **not** call the helper. [`super::ice::TurnCredentials`] accepts
//! either a static `{username, credential}` pair (a TURN deployment configured with static users)
//! or the A8 REST scheme used by `deploy/docker-compose.yml`/`deploy/lab`:
//! `username = "<expiry>:<label>"`, `password = base64(HMAC-SHA1(secret, username))`. In
//! production the credential source is the helper's `helper.turn.get.<nfp>` request, which mints
//! and quota-checks per `root_fp` (§A8); wiring a client for that request is future work. The
//! REST-config path here is the deployment/dev stand-in and is explicitly what the lab uses.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::BytesMut;
use hmac::{Hmac, Mac};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc_turn::client::{
    Client as TurnClient, ClientConfig as TurnClientConfig, Event as TurnEvent,
};
use sansio::Protocol as _;
use sha1::Sha1;

use super::error::SignalingError;
use super::ice::{TurnConfig, TurnCredentials};

/// `SOFTWARE` attribute this crate puts on its TURN requests — diagnostics only.
const SOFTWARE: &str = "spindle-net";

/// One Allocate + CreatePermission exchange is two request/response round trips; the spike used
/// 15 s for the whole setup (allocate and permission each driven by its own timeout). 10 s here
/// matches the ICE timeout defaults and leaves room for a shaped lab path.
pub(crate) const TURN_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Accepted range for a REST credential's embedded expiry (review fix 6): a zero/negative TTL is
/// already expired, and an unreasonably long one defeats the quota/rotation model. coturn's own
/// default allocation lifetime is 10 minutes; 24 h is a deliberately generous ceiling.
const MIN_TURN_TTL: Duration = Duration::from_secs(1);
const MAX_TURN_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cap on the adapter's internal "wire packet could not be sent yet" backlog. Beyond this the
/// relay is not keeping up and quinn must see an error rather than growing memory without bound
/// (review fix 5).
const MAX_RETRY_WIRE: usize = 1024;

/// Driver tick bounds. rtc-turn reports the next allocation/permission refresh deadline via
/// `poll_timeout`; the ticks are clamped so a clock jump or a broken deadline cannot spin the
/// driver or park it past a refresh.
const DRIVER_MIN_TICK: Duration = Duration::from_millis(100);
const DRIVER_MAX_TICK: Duration = Duration::from_secs(5);
const DRIVER_FALLBACK_TICK: Duration = Duration::from_secs(1);

/// A live TURN allocation: the socket talking to the TURN server, the sans-I/O client that owns
/// the allocation state, and the relayed address the server assigned.
///
/// Kept together so the caller can allocate after the offer/answer is on the wire (td-c3badf
/// review fix 1), advertise the relay candidate, and hand the whole thing to the relay transport
/// without any of the three being usable on its own.
pub(crate) struct TurnAllocation {
    socket: tokio::net::UdpSocket,
    client: TurnClient,
    relayed_addr: SocketAddr,
    local_addr: SocketAddr,
}

/// What an [`AllocationGuard`] releases if setup does not reach the relay socket.
pub(crate) trait AllocationRelease {
    fn release(&mut self);
    fn relayed_addr(&self) -> SocketAddr;
    fn local_addr(&self) -> SocketAddr;
}

impl AllocationRelease for TurnAllocation {
    fn release(&mut self) {
        // Same synchronous best-effort body the relay socket's `Drop` uses: enqueue a
        // zero-lifetime Refresh and push it once. There is no await point here — setup failure can
        // land in an async function's error arm, but the release itself is a synchronous enqueue
        // plus one non-blocking send.
        release_allocation(&mut self.client, &self.socket, self.relayed_addr);
    }

    fn relayed_addr(&self) -> SocketAddr {
        self.relayed_addr
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Owns a live allocation between `allocate()` and the moment a relay socket takes it over.
///
/// Every `?` in setup after a successful Allocate (NATS publishes, relay-candidate construction,
/// waiting for the peer's relay candidate, CreatePermission) drops this guard, which releases the
/// allocation. Without it, an authenticated member that allocates and then fails anywhere before
/// `TurnRelaySocket::new` pins a coturn relay port for the allocation lifetime (~600 s) against a
/// 41-port pool. On success, [`Self::into_relay_socket`] takes the allocation out, disarming the
/// guard; the socket's `Drop` then owns release.
pub(crate) struct AllocationGuard<T: AllocationRelease = TurnAllocation> {
    allocation: Option<T>,
}

impl<T: AllocationRelease> AllocationGuard<T> {
    fn from_value(value: T) -> Self {
        Self {
            allocation: Some(value),
        }
    }

    /// Takes the allocation out of the guard. The guard no longer releases it.
    fn take(&mut self) -> Option<T> {
        self.allocation.take()
    }
}

impl<T: AllocationRelease> Drop for AllocationGuard<T> {
    fn drop(&mut self) {
        if let Some(mut allocation) = self.allocation.take() {
            allocation.release();
        }
    }
}

impl AllocationGuard<TurnAllocation> {
    pub(crate) fn relayed_addr(&self) -> Result<SocketAddr, SignalingError> {
        self.allocation
            .as_ref()
            .map(AllocationRelease::relayed_addr)
            .ok_or_else(|| SignalingError::Turn("TURN allocation was already released".into()))
    }

    pub(crate) fn local_addr(&self) -> Result<SocketAddr, SignalingError> {
        self.allocation
            .as_ref()
            .map(AllocationRelease::local_addr)
            .ok_or_else(|| SignalingError::Turn("TURN allocation was already released".into()))
    }

    pub(crate) fn allocation_mut(&mut self) -> Result<&mut TurnAllocation, SignalingError> {
        self.allocation
            .as_mut()
            .ok_or_else(|| SignalingError::Turn("TURN allocation was already released".into()))
    }

    /// Hands the allocation to the relay socket. The guard is consumed; its `Drop` then has
    /// nothing to release.
    pub(crate) fn into_relay_socket(
        mut self,
        turn_server: SocketAddr,
        expected_peer: SocketAddr,
    ) -> Result<Arc<TurnRelaySocket>, SignalingError> {
        let allocation = self
            .take()
            .ok_or_else(|| SignalingError::Turn("TURN allocation was already released".into()))?;
        Ok(Arc::new(TurnRelaySocket::new(
            allocation,
            turn_server,
            expected_peer,
        )))
    }
}

/// Enqueues a zero-lifetime Refresh for the allocation and sends what the client emitted once.
/// Used by both [`AllocationRelease::release`] (setup failure) and [`TurnRelaySocket`]'s `Drop`.
///
/// Best effort: a `WouldBlock` or socket error is logged and the remainder is abandoned. coturn's
/// acceptance of the release is not verified; the alternative is holding the relay port for the
/// full allocation lifetime.
fn release_allocation(
    client: &mut TurnClient,
    socket: &tokio::net::UdpSocket,
    own_relayed_addr: SocketAddr,
) {
    if let Ok(mut relay) = client.relay(own_relayed_addr) {
        if relay.close().is_err() {
            // rtc-shared's error text is not logged here (see the driver's timer arm).
            tracing::warn!("failed to enqueue TURN allocation release");
        }
    }
    while let Some(transmit) = client.poll_write() {
        if let Err(error) = socket.try_send_to(&transmit.message, transmit.transport.peer_addr) {
            tracing::warn!(error = %error, // redaction-ok: std::io::Error Display carries an OS error string, no peer bytes/paths/full ids
                "failed to flush TURN allocation release");
            break;
        }
    }
}

/// Resolves [`TurnConfig::credentials`] into a concrete `(username, password)` pair.
///
/// The REST arm mints locally from the shared secret, exactly as coturn's `use-auth-secret`
/// expects; both peers minting independently from the same secret is equivalent to one side
/// minting and handing the result over (coturn accepts any credential the HMAC validates).
fn resolve_credentials(cfg: &TurnConfig) -> Result<(String, String), SignalingError> {
    match &cfg.credentials {
        TurnCredentials::Static {
            username,
            credential,
        } => Ok((username.clone(), credential.clone())),
        TurnCredentials::RestSecret { secret, label, ttl } => {
            if *ttl < MIN_TURN_TTL || *ttl > MAX_TURN_TTL {
                return Err(SignalingError::Turn(format!(
                    "TURN credential TTL {ttl:?} is outside the supported range \
                     {MIN_TURN_TTL:?}..={MAX_TURN_TTL:?}"
                )));
            }
            let expiry = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| {
                    SignalingError::Turn(format!(
                        "reading the system clock for credential expiry: {e}"
                    ))
                })?
                .as_secs()
                .saturating_add(ttl.as_secs());
            let username = format!("{expiry}:{label}");
            let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).map_err(|e| {
                // HMAC accepts any key length, so this is unreachable for a non-empty secret;
                // report it rather than panicking a connect attempt.
                SignalingError::Turn(format!("constructing TURN credential HMAC: {e}"))
            })?;
            mac.update(username.as_bytes());
            let password =
                base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
            Ok((username, password))
        }
    }
}

/// Sends `client.allocate()` and drives the sans-I/O client to its relayed address.
pub(crate) async fn allocate(
    cfg: &TurnConfig,
    bind_ip: IpAddr,
    timeout: Duration,
) -> Result<AllocationGuard, SignalingError> {
    // Bind a concrete interface, not the wildcard: the TURN server must be able to reply to this
    // socket, and the lab peers have exactly one routable private address. Same reasoning as the
    // spike's `turn_relay_setup` and this crate's ICE socket bind.
    let socket = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let local_addr = socket.local_addr()?;
    let (username, password) = resolve_credentials(cfg)?;

    let mut client = TurnClient::new(TurnClientConfig {
        // No separate STUN binding: this allocation exists only for the relay path.
        stun_serv_addr: String::new(),
        turn_serv_addr: cfg.server.to_string(),
        local_addr,
        transport_protocol: TransportProtocol::UDP,
        username,
        password,
        // Left empty: `rtc-turn` learns the server's realm from the first anonymous Allocate's
        // 401 challenge and retries with long-term integrity (see quic-peer.rs's leg-3 notes).
        realm: String::new(),
        software: SOFTWARE.to_string(),
        rto_in_ms: 0,
    })
    .map_err(|e| SignalingError::Turn(format!("constructing TURN client: {e}")))?;

    let allocate_tid = client
        .allocate()
        .map_err(|e| SignalingError::Turn(format!("sending TURN Allocate: {e}")))?;
    let relayed_addr = drive_until(
        &mut client,
        &socket,
        local_addr,
        timeout,
        |event| match event {
            TurnEvent::AllocateResponse(tid, addr) if *tid == allocate_tid => Some(Ok(*addr)),
            TurnEvent::AllocateError(tid, error) if *tid == allocate_tid => Some(Err(
                SignalingError::Turn(format!("TURN Allocate failed: {error}")),
            )),
            TurnEvent::TransactionTimeout(tid) if *tid == allocate_tid => Some(Err(
                SignalingError::Turn("TURN Allocate timed out".to_string()),
            )),
            _ => None,
        },
    )
    .await?;

    tracing::debug!(server = %cfg.server, relayed = %relayed_addr, "allocated TURN relay");
    Ok(AllocationGuard::from_value(TurnAllocation {
        socket,
        client,
        relayed_addr,
        local_addr,
    }))
}

/// Creates the TURN permission that lets `peer_relayed_addr` send to this allocation. Required
/// before the peer's first QUIC datagram can be delivered (RFC 5766 §9). The caller keeps the
/// [`AllocationGuard`] alive, so any failure here still releases the allocation.
pub(crate) async fn create_permission(
    allocation: &mut TurnAllocation,
    peer_relayed_addr: SocketAddr,
    timeout: Duration,
) -> Result<(), SignalingError> {
    let permission_tid = allocation
        .client
        .relay(allocation.relayed_addr)
        .map_err(|e| SignalingError::Turn(format!("borrowing TURN allocation: {e}")))?
        .create_permission(peer_relayed_addr)
        .map_err(|e| SignalingError::Turn(format!("sending TURN CreatePermission: {e}")))?;

    if let Some(permission_tid) = permission_tid {
        drive_until(
            &mut allocation.client,
            &allocation.socket,
            allocation.local_addr,
            timeout,
            |event| match event {
                TurnEvent::CreatePermissionResponse(tid, _addr) if *tid == permission_tid => {
                    // rtc-turn synthesizes this event from the request *this side* sent; the STUN
                    // success response carries no peer-address attribute, so `_addr` is not a
                    // server echo and there is nothing to cross-check here.
                    Some(Ok(()))
                }
                TurnEvent::CreatePermissionError(tid, error) if *tid == permission_tid => {
                    Some(Err(SignalingError::Turn(format!(
                        "TURN CreatePermission failed: {error}"
                    ))))
                }
                TurnEvent::TransactionTimeout(tid) if *tid == permission_tid => Some(Err(
                    SignalingError::Turn("TURN CreatePermission timed out".to_string()),
                )),
                _ => None,
            },
        )
        .await?;
    }

    tracing::debug!(peer = %peer_relayed_addr, "TURN permission granted");
    Ok(())
}

/// Drives `client` until `extract` returns `Some(_)` for one of its events, or `timeout` elapses.
/// Mirrors the ICE driving loop's idiom (`drive_ice_agent_trickle`): drain writes, drain events,
/// then select on the agent's own timeout and the socket.
async fn drive_until<T>(
    client: &mut TurnClient,
    socket: &tokio::net::UdpSocket,
    local_addr: SocketAddr,
    timeout: Duration,
    mut extract: impl FnMut(&TurnEvent) -> Option<Result<T, SignalingError>>,
) -> Result<T, SignalingError> {
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + timeout;

    loop {
        while let Some(transmit) = client.poll_write() {
            socket
                .send_to(&transmit.message[..], transmit.transport.peer_addr)
                .await?;
        }
        while let Some(event) = client.poll_event() {
            if let Some(result) = extract(&event) {
                return result;
            }
        }
        if Instant::now() >= deadline {
            return Err(SignalingError::Timeout("TURN operation"));
        }

        let wake_at = client
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + Duration::from_millis(100));
        let sleep_for = wake_at
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));

        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {
                client
                    .handle_timeout(Instant::now())
                    .map_err(|e| SignalingError::Turn(format!("TURN client timeout: {e}")))?;
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer_addr) = res?;
                client
                    .handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr,
                            transport_protocol: TransportProtocol::UDP,
                            ecn: None,
                        },
                        message: BytesMut::from(&buf[..n]),
                    })
                    .map_err(|e| SignalingError::Turn(format!("TURN client read: {e}")))?;
            }
        }
    }
}

/// State shared between [`TurnRelaySocket`]'s trait methods. `quinn::AsyncUdpSocket` exposes only
/// `&self` methods but the sans-I/O client needs `&mut`, hence the mutex. `own_relayed_addr` is
/// the address the client's `Relay` view is keyed by.
struct TurnInner {
    client: TurnClient,
    own_relayed_addr: SocketAddr,
    /// The configured TURN server. Datagrams from anywhere else are dropped: only the server may
    /// speak TURN on this socket (review fix 4).
    turn_server: SocketAddr,
    /// The peer's relayed address, learned from its trickled `relay` candidate. Only data the
    /// TURN server attributes to this peer is delivered to quinn (review fix 4).
    expected_peer: SocketAddr,
    /// Wire-facing packets (TURN Send-indication/ChannelData, addressed to the real TURN server)
    /// that hit `WouldBlock` on the real socket, in production order, awaiting `poll_writable`.
    retry_wire: VecDeque<TaggedBytesMut>,
    /// Decoded application datagrams already drained from the client's event queue, awaiting
    /// quinn's next `poll_recv`.
    recv_queue: VecDeque<(SocketAddr, BytesMut)>,
}

/// [`quinn::AsyncUdpSocket`] bridging the sans-I/O TURN client to quinn — see this module's doc
/// comment for why the ICE path's raw-socket handoff cannot work here.
pub(crate) struct TurnRelaySocket {
    /// The real UDP socket talking to the TURN server — never the peer.
    socket: tokio::net::UdpSocket,
    local_addr: SocketAddr,
    inner: Mutex<TurnInner>,
    /// Wakes [`spawn_driver`] when `try_send` had to buffer a wire packet, so a backlog is
    /// flushed promptly instead of waiting for the next refresh tick (review fix 5).
    flush: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for TurnRelaySocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnRelaySocket")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl TurnRelaySocket {
    /// `turn_server` is the only address allowed to send TURN wire traffic; `expected_peer` is the
    /// only relayed peer whose data is delivered to quinn.
    pub(crate) fn new(
        allocation: TurnAllocation,
        turn_server: SocketAddr,
        expected_peer: SocketAddr,
    ) -> Self {
        Self {
            socket: allocation.socket,
            local_addr: allocation.local_addr,
            inner: Mutex::new(TurnInner {
                client: allocation.client,
                own_relayed_addr: allocation.relayed_addr,
                turn_server,
                expected_peer,
                retry_wire: VecDeque::new(),
                recv_queue: VecDeque::new(),
            }),
            flush: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Locks the shared state, recovering from poisoning instead of panicking.
    ///
    /// No code path in this module panics while holding the lock by design; if one ever does, a
    /// live QUIC connection must not be taken down with it. The poisoned state is still usable
    /// (`TurnClient`'s state is not left half-updated by any panic site here), and a panic already
    /// surfaced through the task that caused it — there is nothing to unwind here.
    fn lock_inner(&self) -> MutexGuard<'_, TurnInner> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("TURN relay state lock was poisoned; continuing with recovered state");
            poisoned.into_inner()
        })
    }

    /// Drains `retry_wire` (oldest first) then `client.poll_write()` onto the real socket using
    /// non-blocking sends. On `WouldBlock`, buffers what is left in order and returns that error;
    /// the caller decides whether it is fatal (`UdpPoller` retries) or transient (`try_send`).
    ///
    /// Sends are always attempted before the backlog cap is considered, so an over-cap backlog can
    /// drain. The cap is enforced only when *enqueuing* new wire packets (below); reaching it
    /// returns an error to quinn (which will drop the connection) while leaving the existing
    /// backlog drainable and memory bounded.
    fn drain_wire(&self, inner: &mut TurnInner) -> io::Result<()> {
        while let Some(transmit) = inner.retry_wire.pop_front() {
            match self
                .socket
                .try_send_to(&transmit.message, transmit.transport.peer_addr)
            {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    inner.retry_wire.push_front(transmit);
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
        while let Some(transmit) = inner.client.poll_write() {
            match self
                .socket
                .try_send_to(&transmit.message, transmit.transport.peer_addr)
            {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    inner.retry_wire.push_back(transmit);
                    while inner.retry_wire.len() <= MAX_RETRY_WIRE {
                        match inner.client.poll_write() {
                            Some(transmit) => inner.retry_wire.push_back(transmit),
                            None => break,
                        }
                    }
                    if inner.retry_wire.len() > MAX_RETRY_WIRE {
                        return Err(io::Error::other(format!(
                            "TURN relay send backlog exceeded {MAX_RETRY_WIRE} packets"
                        )));
                    }
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Only the configured TURN server may send on the relay's wire socket.
fn is_from_turn_server(from: SocketAddr, turn_server: SocketAddr) -> bool {
    from == turn_server
}

/// Only data attributed to the peer whose relayed candidate we actually exchanged is delivered.
fn is_expected_peer(peer: SocketAddr, expected_peer: SocketAddr) -> bool {
    peer == expected_peer
}

/// Sleep length for [`spawn_driver`] given rtc-turn's next deadline. When a send backlog exists,
/// retry at the minimum tick so a `WouldBlock`-buffered packet is not stuck behind a long refresh
/// deadline. Otherwise clamp, so a clock jump or a broken/zero deadline cannot hot-spin and a
/// far-future one cannot skip a refresh.
fn next_driver_sleep(now: Instant, next_deadline: Option<Instant>, has_backlog: bool) -> Duration {
    if has_backlog {
        return DRIVER_MIN_TICK;
    }
    next_deadline
        .map(|deadline| deadline.saturating_duration_since(now))
        .unwrap_or(DRIVER_FALLBACK_TICK)
        .clamp(DRIVER_MIN_TICK, DRIVER_MAX_TICK)
}

/// Spawns the task that keeps the TURN allocation alive once quinn owns the socket.
///
/// Without this, rtc-turn's own timers never run after setup: the allocation is not refreshed
/// (coturn's default lifetime is 10 minutes), the 300 s permission expires, and the allocation is
/// never released (td-c3badf review fix 2). The task holds only a `Weak` handle, so it exits when
/// quinn drops the relay socket; [`TurnRelaySocket`]'s `Drop` then releases the allocation
/// best-effort.
pub(crate) fn spawn_driver(socket: Arc<TurnRelaySocket>) {
    let weak = Arc::downgrade(&socket);
    tokio::spawn(async move {
        loop {
            let Some(socket) = weak.upgrade() else {
                // The endpoint dropped the relay socket; its `Drop` has run (or is running).
                break;
            };
            let now = Instant::now();
            let sleep_for = {
                let mut inner = socket.lock_inner();
                if inner.client.handle_timeout(now).is_err() {
                    // The error type is rtc-shared's open-text enum; log only the fact (this is a
                    // local timer path, not a decode path this crate has audited).
                    tracing::warn!("TURN client timeout handling failed");
                }
                if let Err(error) = socket.drain_wire(&mut inner) {
                    if error.kind() != io::ErrorKind::WouldBlock {
                        tracing::warn!(error = %error, // redaction-ok: std::io::Error Display carries an OS error string, no peer bytes/paths/full ids
                            "TURN relay refresh write failed");
                    }
                }
                next_driver_sleep(
                    now,
                    inner.client.poll_timeout(),
                    !inner.retry_wire.is_empty(),
                )
            };
            // Do not hold a strong reference across the wait: that would keep the adapter alive
            // forever and prevent `Drop` from ever running. The `Notify` is an independent Arc, so
            // it can still wake this task after the socket is gone.
            let flush = socket.flush.clone();
            drop(socket);
            tokio::select! {
                _ = tokio::time::sleep(sleep_for) => {}
                _ = flush.notified() => {
                    // A buffered send needs another drain; loop immediately (the minimum tick is
                    // still enforced by `next_driver_sleep` on the next pass).
                }
            }
        }
    });
}

impl Drop for TurnRelaySocket {
    fn drop(&mut self) {
        // Best-effort, synchronous release: quinn has already dropped the endpoint and this crate
        // has no async context here. A Refresh with lifetime 0 makes coturn free the relay port
        // immediately instead of waiting out its ten-minute allocation lifetime.
        let inner = self
            .inner
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        release_allocation(&mut inner.client, &self.socket, inner.own_relayed_addr);
    }
}

impl AsyncUdpSocket for TurnRelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(TurnUdpPoller { socket: self })
    }

    /// Encodes `transmit.contents` into TURN framing and flushes what it can. A wire-level
    /// `WouldBlock` is buffered rather than bubbled up: the QUIC transmit was already accepted
    /// into the client's queue, so returning an error would tell quinn to retry a datagram that
    /// has not been lost.
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut inner = self.lock_inner();
        let own_relayed_addr = inner.own_relayed_addr;
        inner
            .client
            .relay(own_relayed_addr)
            .and_then(|mut relay| relay.send_to(transmit.contents, transmit.destination))
            .map_err(|e| io::Error::other(e.to_string()))?;
        let result = self.drain_wire(&mut inner);
        if !inner.retry_wire.is_empty() {
            // The datagram is safely in `retry_wire`, but quinn was told the send succeeded. Wake
            // the driver so it is flushed as soon as the socket is writable rather than waiting
            // for the next (up to 5 s) refresh tick.
            self.flush.notify_one();
        }
        match result {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.lock_inner();
        loop {
            if let Some((from, data)) = inner.recv_queue.pop_front() {
                let n = data.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&data[..n]);
                meta[0] = RecvMeta {
                    addr: from,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                return Poll::Ready(Ok(1));
            }
            match self.socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            let mut raw = [0u8; 2048];
            match self.socket.try_recv_from(&mut raw) {
                Ok((n, from)) => {
                    // Only the configured TURN server may speak on this socket. Anything else is
                    // dropped before it can reach the sans-I/O client (review fix 4).
                    if !is_from_turn_server(from, inner.turn_server) {
                        tracing::warn!(
                            %from,
                            expected = %inner.turn_server,
                            "dropping relay datagram from an unexpected source"
                        );
                        continue;
                    }
                    // A malformed wire packet from the TURN server is dropped, not fatal: the
                    // relay stays usable for well-formed traffic (mirrors the spike's adapter,
                    // and this crate's soft-failure policy for peer-controlled ICE candidates).
                    if inner
                        .client
                        .handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: self.local_addr,
                                peer_addr: from,
                                transport_protocol: TransportProtocol::UDP,
                                ecn: None,
                            },
                            message: BytesMut::from(&raw[..n]),
                        })
                        .is_err()
                    {
                        // The client's error text is not logged: it comes from an unaudited TURN
                        // decode path over a semi-trusted server's wire bytes, and this crate's
                        // redaction guard cannot vouch for its content. Source and size are
                        // enough to diagnose a bad server.
                        tracing::warn!(%from, wire_len = n, "dropping malformed TURN packet");
                        continue;
                    }
                    let expected_peer = inner.expected_peer;
                    while let Some(event) = inner.client.poll_event() {
                        // Allocation/permission refresh responses and background transaction
                        // timeouts are ignored here; setup consumed the ones it cared about.
                        if let TurnEvent::DataIndicationOrChannelData(_channel, peer_addr, data) =
                            event
                        {
                            if is_expected_peer(peer_addr, expected_peer) {
                                inner.recv_queue.push_back((peer_addr, data));
                            } else {
                                // The relayed candidate is peer-supplied; a server (or a
                                // confused allocation) attributing data to a different peer must
                                // not be able to inject it into this QUIC connection.
                                tracing::warn!(
                                    %peer_addr,
                                    expected = %expected_peer,
                                    "dropping relayed data from an unexpected peer"
                                );
                            }
                        }
                    }
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// The [`UdpPoller`] for [`TurnRelaySocket`]: re-drains `retry_wire` once the real socket is
/// writable again.
struct TurnUdpPoller {
    socket: Arc<TurnRelaySocket>,
}

impl std::fmt::Debug for TurnUdpPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnUdpPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for TurnUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.socket.lock_inner();
        if inner.retry_wire.is_empty() {
            return Poll::Ready(Ok(()));
        }
        match self.socket.socket.poll_send_ready(cx) {
            Poll::Ready(Ok(())) => match self.socket.drain_wire(&mut inner) {
                Ok(()) => Poll::Ready(Ok(())),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // The readiness we just consumed was spent on the failed send. Re-poll so the
                    // waker is registered again before returning `Pending`; otherwise quinn can
                    // wait forever on a socket that has already fired its edge (review fix 5).
                    match self.socket.socket.poll_send_ready(cx) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                    }
                }
                Err(e) => Poll::Ready(Err(e)),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The REST credential scheme is coturn's `use-auth-secret` contract: the password must be
    /// `base64(HMAC-SHA1(secret, "<expiry>:<label>"))`, and the embedded expiry must be in the
    /// future by roughly the requested TTL. Recomputes the HMAC independently of the production
    /// function so this is a check of the contract, not a mirror of the implementation.
    #[test]
    fn rest_credentials_match_coturns_use_auth_secret_scheme() {
        let secret = "spindle-turn-dev-only";
        let label = "s2-lab";
        let ttl = Duration::from_secs(3600);
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();

        let cfg = TurnConfig {
            server: "127.0.0.1:3478".parse().expect("addr"),
            credentials: TurnCredentials::RestSecret {
                secret: secret.to_string(),
                label: label.to_string(),
                ttl,
            },
        };
        let (username, password) = resolve_credentials(&cfg).expect("credentials resolve");

        let (expiry, username_label) = username.split_once(':').expect("expiry:label shape");
        assert_eq!(username_label, label);
        let expiry: u64 = expiry.parse().expect("numeric expiry");
        assert!(
            expiry >= before + ttl.as_secs(),
            "expiry {expiry} must be at least {ttl:?} in the future (clock was {before})"
        );

        let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC key");
        mac.update(username.as_bytes());
        let expected =
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(password, expected);
    }

    /// Static credentials pass through unchanged — the other supported deployment shape.
    #[test]
    fn static_credentials_pass_through() {
        let cfg = TurnConfig {
            server: "127.0.0.1:3478".parse().expect("addr"),
            credentials: TurnCredentials::Static {
                username: "user".to_string(),
                credential: "pass".to_string(),
            },
        };
        let (username, password) = resolve_credentials(&cfg).expect("credentials resolve");
        assert_eq!(username, "user");
        assert_eq!(password, "pass");
    }

    /// Credentials are secrets: `Debug` must never render them, and neither must the enclosing
    /// `TurnConfig`/`IceConfig` debug output.
    #[test]
    fn debug_output_redacts_credentials() {
        let cfg = TurnConfig {
            server: "127.0.0.1:3478".parse().expect("addr"),
            credentials: TurnCredentials::RestSecret {
                secret: "super-secret-value".to_string(),
                label: "device".to_string(),
                ttl: Duration::from_secs(60),
            },
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(!rendered.contains("device"), "{rendered}");

        let static_cfg = TurnConfig {
            server: "127.0.0.1:3478".parse().expect("addr"),
            credentials: TurnCredentials::Static {
                username: "alice".to_string(),
                credential: "hunter2".to_string(),
            },
        };
        let rendered = format!("{static_cfg:?}");
        assert!(!rendered.contains("alice"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    /// td-c3badf review fix 6: a TTL outside 1 s..=24 h is a configuration error, not something to
    /// hand to coturn (a zero TTL is already expired; an unbounded one defeats rotation/quota).
    #[test]
    fn rest_credential_ttl_is_bounded() {
        let config_for = |ttl: Duration| TurnConfig {
            server: "127.0.0.1:3478".parse().expect("addr"),
            credentials: TurnCredentials::RestSecret {
                secret: "secret".to_string(),
                label: "label".to_string(),
                ttl,
            },
        };
        for rejected in [Duration::ZERO, MAX_TURN_TTL + Duration::from_secs(1)] {
            let error = resolve_credentials(&config_for(rejected)).unwrap_err();
            assert!(
                matches!(&error, SignalingError::Turn(message) if message.contains("TTL")),
                "expected a TTL config error for {rejected:?}, got {error:?}"
            );
        }
        for accepted in [MIN_TURN_TTL, MAX_TURN_TTL] {
            resolve_credentials(&config_for(accepted))
                .unwrap_or_else(|e| panic!("{accepted:?} must be accepted, got {e:?}"));
        }
    }

    /// A fake allocation for exercising the guard's release path without a live coturn.
    struct FakeAllocation {
        released: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AllocationRelease for FakeAllocation {
        fn release(&mut self) {
            self.released
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn relayed_addr(&self) -> SocketAddr {
            "203.0.113.7:49160".parse().expect("relayed")
        }

        fn local_addr(&self) -> SocketAddr {
            "192.0.2.10:5000".parse().expect("local")
        }
    }

    fn fake_guard() -> (
        AllocationGuard<FakeAllocation>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let released = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            AllocationGuard::from_value(FakeAllocation {
                released: released.clone(),
            }),
            released,
        )
    }

    /// Every `?` after a successful Allocate drops the guard; the guard must release exactly once.
    #[test]
    fn allocation_guard_releases_on_setup_failure() {
        let (guard, released) = fake_guard();
        // Simulate an error return after `allocate()`.
        drop(guard);
        assert_eq!(
            released.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an allocation that never reaches the relay socket must be released"
        );
    }

    /// When the relay socket takes ownership, the guard must not also release it.
    #[test]
    fn disarmed_allocation_guard_does_not_release() {
        let (mut guard, released) = fake_guard();
        assert!(guard.take().is_some(), "the allocation must be present");
        drop(guard);
        assert_eq!(
            released.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a disarmed guard must not release an allocation the socket now owns"
        );
    }

    /// The driver's sleep is clamped: no hot spin on an expired/broken deadline, and no skipped
    /// refresh on a far-future one.
    #[test]
    fn driver_sleep_is_clamped() {
        let now = Instant::now();
        assert_eq!(next_driver_sleep(now, None, false), DRIVER_FALLBACK_TICK);
        assert_eq!(
            next_driver_sleep(now, Some(now - Duration::from_secs(1)), false),
            DRIVER_MIN_TICK
        );
        assert_eq!(
            next_driver_sleep(now, Some(now + Duration::from_secs(3600)), false),
            DRIVER_MAX_TICK
        );
        assert_eq!(
            next_driver_sleep(now, Some(now + Duration::from_secs(2)), false),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_driver_sleep(now, Some(now + Duration::from_secs(3600)), true),
            DRIVER_MIN_TICK,
            "a pending backlog must retry promptly, not wait out the refresh deadline"
        );
    }

    /// Review fix 4: the adapter's two source checks reject anything but the configured TURN
    /// server and the negotiated peer.
    #[test]
    fn relay_sources_are_restricted_to_the_server_and_expected_peer() {
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("server");
        let other: SocketAddr = "192.0.2.2:3478".parse().expect("other");
        assert!(is_from_turn_server(server, server));
        assert!(!is_from_turn_server(other, server));

        let peer: SocketAddr = "203.0.113.7:49160".parse().expect("peer");
        let stranger: SocketAddr = "203.0.113.8:49160".parse().expect("stranger");
        assert!(is_expected_peer(peer, peer));
        assert!(!is_expected_peer(stranger, peer));
    }
}

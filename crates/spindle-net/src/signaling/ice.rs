//! Standalone ICE punching (DESIGN.md §A8/A10.32), graduated from `spikes/s2-signaling`'s
//! `s2-connect.rs` (`start_local_ice`/`drive_ice_agent_trickle`), itself built on
//! `spikes/s19-quic-transport`'s leg 2. Not redesigned here — see that spike's module doc comment
//! for the empirical groundwork (`rtc_ice::agent::Agent` is sans-I/O: it "owns no sockets and no
//! clock"; the caller feeds it datagrams and sends whatever it emits; once a pair is selected, the
//! caller already holds the exact `std::net::UdpSocket` [`crate::quic::QuicServer::from_socket`]/
//! [`crate::quic::QuicClient::from_socket`] need). Only adapted to this crate's error type and
//! library conventions (no `println!`/`eprintln!` — callers decide what, if anything, to log).
//!
//! # Gathering is off the offer/answer path (td-c3badf; td-c3badf review fix 1)
//!
//! [`start_local_ice`] only binds the socket, adds the host candidate, and returns — so the offer
//! or answer can be published immediately. Everything slow happens afterwards:
//!
//! - STUN server-reflexive gathering runs **inside the ICE drive loop** ([`drive_ice_agent_trickle`]):
//!   Binding Requests are sent on the same socket once checks start, responses are matched by
//!   transaction id and validated ([`parse_binding_response`]), and each mapped address is added to
//!   the agent and emitted on a local-trickle channel for the caller to sign and publish. ICE
//!   connectivity checks run concurrently, so a blackholed STUN server cannot delay a host-only
//!   session; the gather window is bounded ([`STUN_GATHER_WINDOW`]) and then abandoned with a log.
//! - TURN allocation runs in the caller, after the answer/offer is published (a separate socket,
//!   see [`super::turn`]). On the punch-first path (td-870b25) it runs concurrently with an ICE
//!   attempt bounded by [`IceConfig::punch_window`]: a selected pair wins and releases the
//!   allocation; a window expiry falls back to the relay. The relay candidate is trickled as soon
//!   as the allocation completes, so the peer can use it even while this side is still punching.
//!
//! With the default (empty) [`IceConfig`] this is exactly the pre-td-c3badf host-only behaviour
//! (host candidate, end-of-candidates, no extra queries).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc_ice::agent::agent_config::AgentConfig as IceAgentConfig;
use rtc_ice::agent::Agent as IceAgent;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::candidate_relay::CandidateRelayConfig;
use rtc_ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use rtc_ice::candidate::{unmarshal_candidate, CandidateConfig, CandidateType};
use rtc_ice::state::ConnectionState as IceConnectionState;
use rtc_ice::Event as IceEvent;
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtc_stun::message::{Getter as _, Message as StunMessage, TransactionId, BINDING_REQUEST};
use rtc_stun::xoraddr::XorMappedAddress;
use sansio::Protocol as _;
use tokio::sync::mpsc;

use super::error::SignalingError;

/// How long one STUN Binding exchange may take before that server is written off (the spike's
/// value). A STUN failure is soft: the ICE drive keeps running on the candidates it already has,
/// so this only bounds how long after checks start a late srflx candidate is still accepted.
const STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on the whole post-answer STUN gather window, regardless of how many servers are
/// configured or how the per-server timeouts interleave. After this the drive stops waiting,
/// logs what never answered, and sends end-of-candidates.
const STUN_GATHER_WINDOW: Duration = Duration::from_secs(10);

/// Default for [`IceConfig::punch_window`]: long enough to cover a shaped WAN round trip plus the
/// ICE check exchange, short enough that a failed punch does not visibly delay the relay fallback.
pub const DEFAULT_PUNCH_WINDOW: Duration = Duration::from_secs(3);

/// Smallest accepted [`IceConfig::punch_window`]. Below this the window cannot cover even one
/// shaped check exchange, so it would be indistinguishable from relay-first while still paying
/// the allocation cost.
pub const MIN_PUNCH_WINDOW: Duration = Duration::from_millis(100);

/// Largest accepted [`IceConfig::punch_window`]. The window is the **only** bound on how long a
/// TURN-configured session holds its sockets and the peer's expectation before falling back, so an
/// unbounded value would turn a configuration typo into a multi-hour stall; it also keeps
/// `now + window` far from `Instant`'s range.
pub const MAX_PUNCH_WINDOW: Duration = Duration::from_secs(60);

/// The shared punch window's deadline, validated and overflow-checked (td-870b25 review).
///
/// [`Duration::ZERO`] is the explicit **relay-only** mode and is not an error: the caller skips
/// the ICE attempt and uses the relay as soon as the allocation is ready (the lab's long-relay
/// proof sets `PUNCH_WINDOW_MS=0`). Positive values must be in
/// [`MIN_PUNCH_WINDOW`]..=[`MAX_PUNCH_WINDOW`]; `Instant + Duration` panics on overflow, so a
/// caller-supplied value must never reach raw arithmetic (a `Duration::MAX` from a library caller
/// would take a host's per-session task down with it). Out-of-range positive values are a
/// configuration error ([`SignalingError::PunchWindow`]) reported before any network work.
pub(crate) fn punch_deadline(window: Duration, now: Instant) -> Result<Instant, SignalingError> {
    if window.is_zero() {
        return Ok(now);
    }
    if window < MIN_PUNCH_WINDOW || window > MAX_PUNCH_WINDOW {
        return Err(SignalingError::PunchWindow {
            window,
            min: MIN_PUNCH_WINDOW,
            max: MAX_PUNCH_WINDOW,
        });
    }
    now.checked_add(window).ok_or(SignalingError::PunchWindow {
        window,
        min: MIN_PUNCH_WINDOW,
        max: MAX_PUNCH_WINDOW,
    })
}

/// How long the deadline branch lets the ICE drive run before committing to the relay (td-870b25
/// review fix 1). A publish body in flight when the deadline fires suspends the `select!` loop, so
/// the drive may already hold a selected pair that the loop never observed; this grace gives it a
/// final chance to reach its own selection check. A pair found within it is recorded at the
/// deadline and wins. Ten milliseconds is far longer than a loop iteration over ready work and
/// negligible against the 3 s window.
pub(crate) const DEADLINE_SETTLE: Duration = Duration::from_millis(10);

/// ICE gathering configuration (td-c3badf, punch-first since td-870b25). [`Default`] — an empty
/// server list and no TURN — is the pre-td-c3badf **host-only** behaviour, so a caller that does
/// not opt in is byte-for-byte unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceConfig {
    /// STUN servers to gather server-reflexive candidates from, in order. Empty means host-only.
    ///
    /// Queried once each, on the same UDP socket that carries ICE checks (so the mapped address is
    /// the mapping that socket's traffic actually gets), **during** the ICE drive — never before
    /// the offer/answer is published. A server that fails or times out is logged and skipped; the
    /// session keeps running on the candidates it already has. Used on the punch-first path even
    /// when [`Self::turn`] is set: without an srflx candidate the punch cannot cross a NAT.
    pub stun_servers: Vec<SocketAddr>,

    /// Optional TURN relay (DESIGN.md §A8/A10.8), used as the **fallback** on the punch-first path
    /// (td-870b25). `None` = punch only, exactly the old behaviour.
    ///
    /// When set, the allocation runs in parallel with an ICE attempt bounded by
    /// [`Self::punch_window`] (after the answer/offer is published). A pair selected inside the
    /// window wins and the allocation is released; if the window expires, the ICE agent is torn
    /// down and the session switches to the relay. Both peers must configure TURN, or a side that
    /// falls back waits in vain for the peer's `relay` candidate.
    pub turn: Option<TurnConfig>,

    /// How long the punch attempt runs before both sides are expected to switch to the relay
    /// (td-870b25's shared local window; default [`DEFAULT_PUNCH_WINDOW`], accepted range for
    /// positive values [`MIN_PUNCH_WINDOW`]..=[`MAX_PUNCH_WINDOW`]).
    ///
    /// [`Duration::ZERO`] is an explicit **relay-only** mode: when TURN is configured the ICE
    /// attempt is skipped entirely and the session uses the relay as soon as the allocation is
    /// ready (both peers must choose it). This is what the lab's long-relay refresh proof uses; it
    /// is a documented value, not an error.
    ///
    /// There is no wire field coordinating the choice (the user decision rejected a signed wire
    /// decision for now). Instead each side runs the same local window. The host computes its
    /// deadline after publishing the answer **and** its host candidate; the client computes its own
    /// after verifying that answer and publishing its host candidate. The deadlines therefore
    /// differ by the answer's one-way NATS leg plus the client's verification/decryption — less than
    /// one RTT, not a full round trip. Both peers must be configured with the same value; a shorter
    /// window on one side makes it switch while the other is still punching, which shows up as a
    /// failed QUIC handshake (the attempt fails and the caller retries) rather than a hang.
    ///
    /// A pair *present at the deadline check* wins: the window bounds how long to wait, not the
    /// outcome. The value is validated by [`punch_deadline`] before any network work, so an
    /// out-of-range or overflowing positive value is a [`SignalingError::PunchWindow`], never a
    /// panic.
    pub punch_window: Duration,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            turn: None,
            punch_window: DEFAULT_PUNCH_WINDOW,
        }
    }
}

/// A TURN server plus the credentials to allocate on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnConfig {
    pub server: SocketAddr,
    pub credentials: TurnCredentials,
}

/// Where a TURN long-term credential comes from.
#[derive(Clone, PartialEq, Eq)]
pub enum TurnCredentials {
    /// A deployment configured with static TURN users: pass the pair through unchanged.
    Static {
        username: String,
        credential: String,
    },

    /// coturn `use-auth-secret` (DESIGN.md §A8): mint `"<expiry>:<label>"` /
    /// `base64(HMAC-SHA1(secret, username))` locally. `ttl` must be in `1s..=24h` (a zero TTL is
    /// already expired; an unbounded one defeats rotation/quota) — out-of-range values are a
    /// configuration error.
    ///
    /// Production's credential source is the helper's `helper.turn.get.<nfp>` request (per
    /// `root_fp` quota, §A8); this slice does not call the helper. `label` is the deployment/dev
    /// stand-in for the session's caller identity in that username.
    RestSecret {
        secret: String,
        label: String,
        ttl: Duration,
    },
}

impl std::fmt::Debug for TurnCredentials {
    /// Credentials are secrets: never render them, including through [`IceConfig`]'s derived
    /// `Debug` (which calls this implementation).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TurnCredentials::Static { .. } => {
                f.write_str("Static { username: <redacted>, credential: <redacted> }")
            }
            TurnCredentials::RestSecret { ttl, .. } => {
                write!(
                    f,
                    "RestSecret {{ secret: <redacted>, label: <redacted>, ttl: {ttl:?} }}"
                )
            }
        }
    }
}

/// Which data path a completed session used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedTransport {
    /// The ICE connectivity checks selected a punched pair; quinn owns the punched socket.
    Punch,
    /// The shared punch window expired without a selected pair (or TURN was used with a zero
    /// window): quinn runs over the `turn` module's relay socket adapter.
    Relay,
}

impl SelectedTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            SelectedTransport::Punch => "punch",
            SelectedTransport::Relay => "relay",
        }
    }
}

/// The punch-first selection policy at the moment the shared window closes (td-870b25), factored
/// out as a pure function so the decision is unit-tested with an injected clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowDecision {
    /// Use the punched socket. With no TURN (or a failed allocation) there is no alternative; if
    /// ICE never selects, the attempt fails at its own `ice_timeout` — this variant does not by
    /// itself assert a pair was selected.
    Punch,
    /// A relay allocation is ready and no pair was present at the deadline check: switch to it.
    Relay,
}

/// Decides what the punch-first path does when its window closes.
///
/// - No TURN configured (or the allocation failed): punch only, the pre-td-c3badf path. A failed
///   punch then fails the attempt, because there is nothing to fall back to.
/// - A pair present **at or before** `deadline`: punch. The window bounds how long to wait for a
///   pair, not whether a pair that is already there counts; the deadline check is the last
///   observation point. Both roles pass the deadline itself when the final poll observes a pair,
///   so production never hands this function an instant after `deadline`.
/// - No pair at the deadline: relay.
///
/// `pair_selected_at` is this side's observed selection instant — the injected clock. Both roles
/// call this with deadlines computed from their own start of ICE checks after the offer/answer
/// exchange, so the two deadlines differ by the answer's one-way leg plus verification (less than
/// one RTT). With a zero window the runtime never polls the drive, so `pair_selected_at` is always
/// `None` and the decision is [`WindowDecision::Relay`] whenever an allocation exists — the
/// explicit relay-only mode.
pub(crate) fn decide_after_window(
    turn_configured: bool,
    allocation_ready: bool,
    pair_selected_at: Option<Instant>,
    deadline: Instant,
) -> WindowDecision {
    if !turn_configured || !allocation_ready {
        return WindowDecision::Punch;
    }
    match pair_selected_at {
        // `<=`: a pair present at the deadline check wins (see this function's doc comment).
        Some(selected) if selected <= deadline => WindowDecision::Punch,
        _ => WindowDecision::Relay,
    }
}

/// A locally-gathered ICE agent plus the UDP socket it will punch through, not yet driven to a
/// selected pair (the remote ufrag/pwd aren't known until the offer/answer round trip completes —
/// see [`crate::signaling::client`]/[`crate::signaling::host`]).
pub struct LocalIce {
    pub agent: IceAgent,
    pub socket: tokio::net::UdpSocket,
    pub ufrag: String,
    pub pwd: String,
    /// This side's host candidate, already marshaled (SDP `a=candidate` line body). Published
    /// immediately; server-reflexive candidates follow asynchronously while ICE runs.
    pub host_candidate_line: String,
}

/// One local candidate discovered *after* the offer/answer was published, sent from
/// [`drive_ice_agent_trickle`] to the caller's trickle publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalTrickleEvent {
    Candidate(String),
    EndOfCandidates,
}

/// Binds a UDP socket on `bind_ip`, constructs an [`IceAgent`] with its host candidate, and
/// returns immediately — no STUN/TURN exchange happens here (td-c3badf review fix 1).
///
/// Slow gathering must not sit between receiving an offer and publishing the answer (or between
/// publishing the offer and receiving it): the peer's answer timeout is typically 5 s, while one
/// blackholed STUN server costs a 5 s timeout and TURN allocation costs two round trips. STUN
/// gathering therefore runs inside the ICE drive ([`drive_ice_agent_trickle`], concurrent with
/// connectivity checks) and TURN allocation runs in the caller after the answer/offer is on the
/// wire (see [`super::turn`]). Connectivity checks are NOT started here.
pub async fn start_local_ice(
    is_controlling: bool,
    bind_ip: IpAddr,
) -> Result<LocalIce, SignalingError> {
    let udp = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let local_addr = udp.local_addr()?;

    let mut agent = IceAgent::new(std::sync::Arc::new(IceAgentConfig {
        is_controlling,
        disconnected_timeout: Some(Duration::from_secs(5)),
        failed_timeout: Some(Duration::from_secs(15)),
        ..Default::default()
    }))?;

    let host_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_string(),
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    agent.add_local_candidate(host_candidate.clone())?;
    let host_candidate_line = host_candidate.marshal();

    let credentials = agent.get_local_credentials();
    let ufrag = credentials.ufrag.clone();
    let pwd = credentials.pwd.clone();

    Ok(LocalIce {
        agent,
        socket: udp,
        ufrag,
        pwd,
        host_candidate_line,
    })
}

/// Builds the relayed candidate line for an allocation (td-c3badf). Used by the callers after the
/// answer/offer is published; the allocation itself lives in [`super::turn`].
pub(crate) fn relay_candidate_line(
    relayed: SocketAddr,
    local_addr: SocketAddr,
    turn_server: SocketAddr,
) -> Result<String, SignalingError> {
    let relay_candidate = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_string(),
            address: relayed.ip().to_string(),
            port: relayed.port(),
            component: 1,
            ..Default::default()
        },
        rel_addr: local_addr.ip().to_string(),
        rel_port: local_addr.port(),
        url: Some(format!("turn:{turn_server}")),
    }
    .new_candidate_relay()?;
    Ok(relay_candidate.marshal())
}

/// In-flight STUN Binding exchanges, driven from inside [`drive_ice_agent_trickle`] using the same
/// socket (and therefore the same mapping) as the ICE checks.
///
/// A datagram from a configured STUN server is gather traffic and is never handed to the ICE
/// agent — that includes spoofed or unexpected responses, which are logged and dropped rather than
/// risking an agent error (td-c3badf review fix 3). A datagram from anywhere else is ICE traffic.
pub(crate) struct StunGather {
    servers: Vec<SocketAddr>,
    pending: Vec<PendingBinding>,
    deadline: Instant,
    finished: bool,
    end_of_candidates_sent: bool,
}

struct PendingBinding {
    server: SocketAddr,
    transaction_id: TransactionId,
    deadline: Instant,
}

impl StunGather {
    /// `servers` empty means there is nothing to gather: the drive sends end-of-candidates
    /// immediately, preserving the old host-only behaviour.
    pub(crate) fn new(servers: &[SocketAddr], now: Instant) -> Self {
        Self {
            servers: servers.to_vec(),
            pending: Vec::new(),
            deadline: now + STUN_GATHER_WINDOW,
            finished: servers.is_empty(),
            end_of_candidates_sent: false,
        }
    }

    /// Sends one Binding Request per server. A server that cannot even be sent to is logged and
    /// skipped (soft failure); its absence never fails the session.
    pub(crate) async fn send_requests(&mut self, socket: &tokio::net::UdpSocket) {
        let now = Instant::now();
        for server in self.servers.clone() {
            let mut request = StunMessage::new();
            match request.build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)]) {
                Ok(()) => {}
                Err(_error) => {
                    // rtc-shared's error text is open-ended; log only the fact (a build failure
                    // here means this crate's own request is malformed, not peer input).
                    tracing::warn!(
                        %server,
                        "failed to build STUN Binding Request; skipping server"
                    );
                    continue;
                }
            }
            let transaction_id = request.transaction_id;
            if let Err(error) = socket.send_to(&request.raw, server).await {
                tracing::warn!(
                    %server,
                    error = %error, // redaction-ok: std::io::Error Display carries an OS error string and the configured UDP address, no peer bytes/paths/full ids
                    "failed to send STUN Binding Request; skipping server"
                );
                continue;
            }
            self.pending.push(PendingBinding {
                server,
                transaction_id,
                deadline: now + STUN_TIMEOUT,
            });
        }
        if self.pending.is_empty() {
            self.finished = true;
        }
    }

    /// Classifies one inbound datagram.
    ///
    /// Returns `None` when the datagram is not from a configured STUN server (the caller feeds it
    /// to the ICE agent), and `Some(outcome)` when it is gather traffic the caller must NOT hand to
    /// the agent. A `Some(Ok(Some(mapped)))` is a validated new srflx address; `Some(Ok(None))` is
    /// gather traffic that produces no candidate (e.g. a late response for a completed server);
    /// `Some(Err(_))` is a rejected response worth logging.
    pub(crate) fn handle_datagram(
        &mut self,
        datagram: &[u8],
        from: SocketAddr,
        _now: Instant,
    ) -> Option<Result<Option<SocketAddr>, SignalingError>> {
        if !self.servers.contains(&from) {
            return None;
        }

        let Some(index) = self.pending.iter().position(|p| p.server == from) else {
            // From a configured server but no exchange is outstanding (already answered, already
            // timed out, or a repeated response). Gather traffic; never an ICE peer.
            return Some(Ok(None));
        };

        let result =
            parse_binding_response(datagram, self.pending[index].transaction_id, from).map(Some);
        // Whether the response was valid or rejected, this server's exchange is over. The drive
        // calls `poll_expiry` next, which notices an empty pending list and emits
        // end-of-candidates.
        self.pending.remove(index);
        Some(result)
    }

    /// Expires per-server timeouts and the whole window. Returns `true` exactly once, when the
    /// caller should publish end-of-candidates.
    pub(crate) fn poll_expiry(&mut self, now: Instant) -> bool {
        if !self.finished {
            self.expire(now);
        }
        if self.finished && !self.end_of_candidates_sent {
            self.end_of_candidates_sent = true;
            return true;
        }
        false
    }

    fn expire(&mut self, now: Instant) {
        self.pending.retain(|pending| {
            if now >= pending.deadline {
                tracing::warn!(
                    server = %pending.server,
                    "STUN server did not answer; continuing without its server-reflexive candidate"
                );
                false
            } else {
                true
            }
        });
        if now >= self.deadline {
            for pending in self.pending.drain(..) {
                tracing::warn!(
                    server = %pending.server,
                    "STUN gather window elapsed; abandoning this server-reflexive candidate"
                );
            }
            self.finished = true;
        } else if self.pending.is_empty() {
            self.finished = true;
        }
    }

    /// Earliest instant at which [`Self::poll_expiry`] has work to do, for the drive loop's wake
    /// computation. `None` once finished.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if self.finished {
            return None;
        }
        self.pending
            .iter()
            .map(|pending| pending.deadline)
            .min()
            .map(|deadline| deadline.min(self.deadline))
            .or(Some(self.deadline))
    }
}

/// Decodes and validates one STUN Binding Success response.
///
/// td-c3badf review fix 3: the spike accepted whatever came back from the server address. Here the
/// response's transaction id must be the one this side sent, the message class must be Binding
/// Success, and the mapped address must be usable — same address family as the server, not
/// unspecified (`0.0.0.0`/`::`), not multicast, and a non-zero port. Otherwise a spoofed or broken
/// response could inject an arbitrary candidate (or make the ICE agent treat a response as peer
/// traffic).
fn parse_binding_response(
    datagram: &[u8],
    expected_transaction_id: TransactionId,
    server: SocketAddr,
) -> Result<SocketAddr, SignalingError> {
    let mut response = StunMessage::new();
    response.raw = datagram.to_vec();
    response
        .decode()
        .map_err(|e| SignalingError::Stun(format!("decoding STUN Binding Response: {e}")))?;
    if response.typ != rtc_stun::message::BINDING_SUCCESS {
        return Err(SignalingError::Stun(format!(
            "unexpected STUN message type {:?} from {server} (expected Binding Success)",
            response.typ
        )));
    }
    if response.transaction_id != expected_transaction_id {
        return Err(SignalingError::Stun(format!(
            "STUN response from {server} has the wrong transaction id"
        )));
    }

    let mut mapped = XorMappedAddress::default();
    mapped.get_from(&response).map_err(|e| {
        SignalingError::Stun(format!(
            "reading XOR-MAPPED-ADDRESS from STUN response: {e}"
        ))
    })?;
    let mapped = SocketAddr::new(mapped.ip, mapped.port);
    if mapped.port() == 0 {
        return Err(SignalingError::Stun(format!(
            "STUN server {server} returned a mapped address with port 0"
        )));
    }
    if mapped.ip().is_unspecified() || mapped.ip().is_multicast() {
        return Err(SignalingError::Stun(format!(
            "STUN server {server} returned an unusable mapped address {mapped}"
        )));
    }
    if mapped.is_ipv4() != server.is_ipv4() {
        return Err(SignalingError::Stun(format!(
            "STUN server {server} returned a mapped address of the wrong address family: {mapped}"
        )));
    }
    Ok(mapped)
}

/// Waits for the peer's `relay` candidate on the trickle channel and returns its address. Used by
/// the relay path, which has no ICE selection to wait for; the relayed address travels as an
/// ordinary trickled `a=candidate` line, so no wire change is needed.
///
/// Non-relay candidates are ignored (the peer trickles its host/srflx candidates first), and an
/// end-of-candidates marker does not end the wait — the relay line may arrive before or after it.
/// The channel is the **bounded** one [`split_relay_candidates`] feeds (capacity 1), not the raw
/// peer-driven stream: the fallback needs only the first valid relay candidate, and bounding it
/// stops an authenticated peer from growing a buffer by streaming `typ relay` lines while this side
/// is still inside its punch window.
pub(crate) async fn await_peer_relay_candidate(
    mut candidate_rx: mpsc::Receiver<TrickleEvent>,
    timeout: Duration,
) -> Result<SocketAddr, SignalingError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SignalingError::Timeout("TURN relay candidate"));
        }
        let event = match tokio::time::timeout(remaining, candidate_rx.recv()).await {
            Err(_) => return Err(SignalingError::Timeout("TURN relay candidate")),
            Ok(None) => {
                return Err(SignalingError::Nats(
                    "ICE trickle subscription closed before the peer's relay candidate arrived"
                        .to_string(),
                ))
            }
            Ok(Some(event)) => event,
        };
        match event {
            TrickleEvent::Candidate(line) => match unmarshal_candidate(&line) {
                Ok(candidate) if candidate.candidate_type() == CandidateType::Relay => {
                    return Ok(candidate.addr())
                }
                Ok(_) => {}
                Err(_) => {
                    // Same soft failure as the ICE drive loop: a malformed peer candidate is
                    // dropped rather than aborting a session another line may still complete.
                    tracing::warn!(
                        candidate_len = line.len(),
                        "failed to unmarshal a trickled candidate while waiting for the relay \
                         candidate; ignoring"
                    );
                }
            },
            TrickleEvent::EndOfCandidates => {}
        }
    }
}

/// One decoded, already-verified trickled ICE message, handed from the envelope layer
/// ([`crate::signaling::wire`]) to [`drive_ice_agent_trickle`].
#[derive(Debug)]
pub enum TrickleEvent {
    Candidate(String),
    EndOfCandidates,
}

/// Aborts a spawned task when dropped (td-870b25).
///
/// The connect paths spawn a trickle-bridge task (and, on the punch-first path, a candidate-split
/// task) and then run dozens of fallible steps before they are done with them. Explicitly aborting
/// on every `?` is easy to miss: the pre-td-870b25 relay path did exactly that, so an allocation or
/// publish failure leaked the bridge task (and its NATS subscription) for the process's lifetime.
/// The guard makes teardown a property of scope rather than of remembering every error path.
pub(crate) struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    pub(crate) fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(handle)
    }

    /// Aborts now instead of at end of scope. Idempotent.
    pub(crate) fn abort(&self) {
        self.0.abort();
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Fans one peer trickle stream out to two consumers (td-870b25): ordinary candidates (and the
/// end-of-candidates marker) go to the ICE agent, while `relay` candidate lines go to a separate
/// channel that the relay fallback waits on.
///
/// The split is why the ICE drive no longer owns the only receiver: a peer's `relay` candidate can
/// arrive after the punch window has expired and the ICE drive has been torn down, and the
/// fallback must still see it. `rtc_ice` also cannot route checks through TURN, so feeding it a
/// relay candidate would only produce checks from the local base socket straight to the relayed
/// address — traffic that bypasses the TURN server and can never succeed. Relay-typed lines are
/// therefore withheld from the agent.
///
/// A line that cannot be unmarshaled is forwarded to the ICE agent unchanged, so the drive's
/// existing "bad candidate" accounting still sees (and warns about) it.
///
/// `relay_tx` is **bounded** (the caller creates it with capacity 1) and fed with `try_send`: the
/// fallback needs exactly the first valid relay candidate, and a peer able to trickle at will must
/// not be able to grow this buffer with `typ relay` lines while the ICE drive is still consuming
/// only the ICE side of the split. A second relay candidate (or the same one after the fallback has
/// read it) is dropped; the fallback stops waiting on the first anyway.
pub(crate) async fn split_relay_candidates(
    mut source: mpsc::UnboundedReceiver<TrickleEvent>,
    ice_tx: mpsc::UnboundedSender<TrickleEvent>,
    relay_tx: mpsc::Sender<TrickleEvent>,
) {
    while let Some(event) = source.recv().await {
        if let TrickleEvent::Candidate(line) = &event {
            if let Ok(candidate) = unmarshal_candidate(line) {
                if candidate.candidate_type() == CandidateType::Relay {
                    // Never await the fallback: a full buffer means the first candidate is already
                    // waiting there, which is all it needs.
                    let _ = relay_tx.try_send(event);
                    continue;
                }
            }
        }
        // A closed ICE channel means the punch path already finished; keep forwarding relay
        // candidates until the fallback (or the caller) tears this task down.
        let _ = ice_tx.send(event);
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct TrickleStats {
    /// How many trickled candidates this side actually fed into `add_remote_candidate` before (or
    /// after) selection.
    pub candidates_applied: u32,
    /// How many server-reflexive candidates this side gathered *during* the drive and emitted on
    /// the local-trickle channel (td-c3badf).
    pub local_candidates_gathered: u32,
    pub end_of_candidates_seen: bool,
    /// How many trickled `candidate` lines failed to unmarshal and were dropped (soft failure —
    /// matches `spikes/s2-signaling`'s `s2-connect.rs` precedent of warning and continuing rather
    /// than aborting the whole punch over one malformed line, e.g. from a future peer using a
    /// candidate-line extension this agent doesn't recognize yet).
    pub bad_candidates_seen: u32,
}

/// Starts connectivity checks against the peer's `(remote_ufrag, remote_pwd)` — learned from the
/// offer/answer round trip, the only place they can come from — and then drives `agent` to a
/// selected candidate pair.
///
/// **Starting the checks is this function's job, not the caller's.** `spikes/s2-signaling` did it
/// at both call sites instead (`s2-connect.rs`'s host and client legs each call
/// `agent.start_connectivity_checks(..)` just before their drive loop), and that split is exactly
/// what got lost in graduation: [`start_local_ice`] gathers but deliberately does *not* start
/// checks (it cannot — the remote credentials do not exist yet), so an agent that is only ever
/// gathered and driven sends no binding requests at all and can never select a pair. Every ICE
/// attempt then fails with [`SignalingError::Timeout`], on both sides, every time; no unit test in
/// this crate drives a real agent, so nothing caught it until `tests/live_signaling.rs` ran against
/// the live stack. Folding the call in here makes the two steps impossible to separate again.
///
/// `candidate_rx` is a third `tokio::select!` branch alongside the UDP socket and the agent's own
/// timers: candidates arrive asynchronously, one envelope at a time, and are fed into
/// `agent.add_remote_candidate` the moment they're decoded — this is the trickle mechanic itself.
/// Once a pair is selected, this returns immediately; any not-yet-arrived candidate is simply never
/// applied (harmless — a pair is already selected).
///
/// `gather` is this side's own STUN exchange (td-c3badf). It runs concurrently with connectivity
/// checks on the same socket, and every discovered address is added to the local agent and emitted
/// on `local_candidate_tx` for the caller to sign and trickle. The caller must drain that channel
/// while awaiting this future (see `signaling::client`/`host`), otherwise discovered candidates are
/// added locally but never reach the peer.
#[allow(clippy::too_many_arguments)] // the same explicit-parameter style as `bridge_incoming_ice`
pub(crate) async fn drive_ice_agent_trickle(
    agent: &mut IceAgent,
    socket: &tokio::net::UdpSocket,
    is_controlling: bool,
    remote_ufrag: &str,
    remote_pwd: &str,
    mut candidate_rx: mpsc::UnboundedReceiver<TrickleEvent>,
    mut gather: StunGather,
    local_candidate_tx: mpsc::UnboundedSender<LocalTrickleEvent>,
    timeout: Duration,
) -> Result<(SocketAddr, TrickleStats), SignalingError> {
    agent.start_connectivity_checks(
        is_controlling,
        remote_ufrag.to_string(),
        remote_pwd.to_string(),
    )?;

    let local_addr = socket.local_addr()?;
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + timeout;
    let mut stats = TrickleStats::default();

    // Fire the Binding Requests now; ICE checks below may select a pair before any answer arrives
    // (host-only/LAN), and that must not wait on STUN.
    gather.send_requests(socket).await;
    emit_end_of_candidates_if_due(&mut gather, &local_candidate_tx);

    loop {
        while let Some(transmit) = agent.poll_write() {
            socket
                .send_to(&transmit.message[..], transmit.transport.peer_addr)
                .await?;
        }

        while let Some(event) = agent.poll_event() {
            if let IceEvent::ConnectionStateChange(state) = event {
                if state == IceConnectionState::Failed {
                    return Err(SignalingError::IceFailed);
                }
            }
        }

        if let Some((_local, remote)) = agent.get_selected_candidate_pair() {
            return Ok((remote.addr(), stats));
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(SignalingError::Timeout("ICE trickle"));
        }

        let wake_at = agent
            .poll_timeout()
            .into_iter()
            .chain(gather.next_deadline())
            .min()
            .unwrap_or_else(|| now + Duration::from_millis(100));
        let sleep_for = wake_at
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));

        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {
                agent.handle_timeout(Instant::now())?;
                emit_end_of_candidates_if_due(&mut gather, &local_candidate_tx);
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer_addr) = res?;
                let now = Instant::now();
                match gather.handle_datagram(&buf[..n], peer_addr, now) {
                    // Not from a configured STUN server: ordinary ICE traffic.
                    None => {
                        agent.handle_read(TaggedBytesMut {
                            now,
                            transport: TransportContext {
                                local_addr,
                                peer_addr,
                                transport_protocol: TransportProtocol::UDP,
                                ecn: None,
                            },
                            message: BytesMut::from(&buf[..n]),
                        })?;
                    }
                    // Gather traffic is consumed here and never handed to the ICE agent, so a
                    // spoofed/odd response cannot disturb connectivity checks.
                    Some(Ok(Some(mapped))) => {
                        match (CandidateServerReflexiveConfig {
                            base_config: CandidateConfig {
                                network: "udp".to_string(),
                                address: mapped.ip().to_string(),
                                port: mapped.port(),
                                component: 1,
                                ..Default::default()
                            },
                            rel_addr: local_addr.ip().to_string(),
                            rel_port: local_addr.port(),
                            url: Some(format!("stun:{peer_addr}")),
                        })
                        .new_candidate_server_reflexive()
                        {
                            Ok(candidate) => match agent.add_local_candidate(candidate.clone()) {
                                Ok(true) => {
                                    stats.local_candidates_gathered += 1;
                                    let _ = local_candidate_tx.send(
                                        LocalTrickleEvent::Candidate(candidate.marshal()),
                                    );
                                    tracing::debug!(%peer_addr, mapped = %mapped, "gathered server-reflexive ICE candidate");
                                }
                                Ok(false) => {}
                                Err(error) => tracing::warn!(
                                    %peer_addr,
                                    error = %SignalingError::Ice(error).redacted(),
                                    "failed to add server-reflexive ICE candidate; ignoring"
                                ),
                            },
                            Err(error) => tracing::warn!(
                                %peer_addr,
                                error = %SignalingError::Ice(error).redacted(),
                                "failed to construct server-reflexive ICE candidate; ignoring"
                            ),
                        }
                    }
                    Some(Ok(None)) => {}
                    Some(Err(error)) => tracing::warn!(
                        %peer_addr,
                        error = %error.redacted(),
                        "rejected STUN Binding response; ignoring"
                    ),
                }
                emit_end_of_candidates_if_due(&mut gather, &local_candidate_tx);
            }
            // `Some(..)` (not `msg`) so a closed trickle channel disables this branch instead of
            // making it ready with `None` forever — a busy loop.
            Some(msg) = candidate_rx.recv() => {
                match msg {
                    TrickleEvent::Candidate(line) => match unmarshal_candidate(&line) {
                        Ok(c) => {
                            let _ = agent.add_remote_candidate(c);
                            stats.candidates_applied += 1;
                        }
                        Err(_error) => {
                            stats.bad_candidates_seen += 1;
                            // Neither the candidate line nor the parser's own message can be
                            // logged. The line is a peer-supplied SDP candidate — it spells out
                            // that peer's host/reflexive IP addresses and ports — and
                            // `rtc_ice`'s `unmarshal_candidate` funnels every rejection through
                            // `Error::Other(String)`, whose text interpolates the peer's own
                            // candidate-type token verbatim (verified in rtc-ice 0.20.3,
                            // `src/candidate/mod.rs`'s `ErrUnknownCandidateType` arm). What is
                            // left is still enough to act on: the running reject count, the
                            // line's length, and its whitespace-field count — a count below 8 is
                            // exactly `rtc_ice`'s own "attribute too short" rejection, which
                            // separates a truncated line from a well-formed one this agent
                            // simply does not understand.
                            tracing::warn!(
                                bad_candidates_seen = stats.bad_candidates_seen,
                                candidate_len = line.len(),
                                candidate_fields = line.split_whitespace().count(),
                                "failed to unmarshal trickled ICE candidate; ignoring"
                            );
                        }
                    },
                    TrickleEvent::EndOfCandidates => stats.end_of_candidates_seen = true,
                }
            }
        }
    }
}

/// Expires gather state and, exactly once, tells the caller to publish end-of-candidates. A closed
/// local-trickle channel means the caller is no longer publishing (it aborted the drive) — not an
/// error.
fn emit_end_of_candidates_if_due(
    gather: &mut StunGather,
    local_candidate_tx: &mpsc::UnboundedSender<LocalTrickleEvent>,
) {
    if gather.poll_expiry(Instant::now()) {
        let _ = local_candidate_tx.send(LocalTrickleEvent::EndOfCandidates);
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket as StdUdpSocket;
    use std::thread;

    use rtc_stun::message::{Message as StunResponse, BINDING_REQUEST, BINDING_SUCCESS};

    use super::*;

    /// Builds one STUN message with `typ` and (for a success response) a mapped address.
    fn stun_message(transaction_id: TransactionId, typ: rtc_stun::message::MessageType) -> Vec<u8> {
        let mut message = StunResponse::new();
        message
            .build(&[Box::new(transaction_id), Box::new(typ)])
            .expect("build STUN message");
        message.raw
    }

    fn binding_success(transaction_id: TransactionId, mapped: SocketAddr) -> Vec<u8> {
        let mut message = StunResponse::new();
        message
            .build(&[
                Box::new(transaction_id),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: mapped.ip(),
                    port: mapped.port(),
                }),
            ])
            .expect("build Binding Success");
        message.raw
    }

    /// A one-shot UDP STUN responder that echoes the request's transaction id and reports the
    /// request's source address as the XOR-MAPPED-ADDRESS — the same exchange
    /// `spikes/s19-quic-transport/src/bin/stun-server.rs` performs, reduced to one request.
    fn spawn_stun_responder() -> (SocketAddr, thread::JoinHandle<()>) {
        let socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind fake STUN socket");
        let addr = socket.local_addr().expect("fake STUN local addr");
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, from) = socket.recv_from(&mut buf).expect("receive Binding Request");
            let mut request = StunResponse::new();
            request.raw = buf[..n].to_vec();
            request
                .decode()
                .expect("client sent a decodable STUN message");
            let response = binding_success(
                request.transaction_id,
                SocketAddr::new(from.ip(), from.port()),
            );
            socket
                .send_to(&response, from)
                .expect("send Binding Success");
        });
        (addr, handle)
    }

    /// The compatibility promise (td-c3badf): starting ICE is immediate and host-only — no STUN or
    /// TURN exchange happens before the offer/answer is published (review fix 1).
    #[tokio::test]
    async fn start_local_ice_is_immediate_and_host_only() {
        let bind_ip = IpAddr::from([127, 0, 0, 1]);
        let local_ice = start_local_ice(true, bind_ip)
            .await
            .expect("local ICE construction");

        assert!(
            local_ice.host_candidate_line.contains("typ host"),
            "expected a host candidate, got {:?}",
            local_ice.host_candidate_line
        );
        assert_eq!(
            local_ice.socket.local_addr().expect("local addr").ip(),
            bind_ip
        );
        let candidate =
            unmarshal_candidate(&local_ice.host_candidate_line).expect("host candidate");
        assert_eq!(candidate.candidate_type(), CandidateType::Host);
    }

    #[test]
    fn parse_binding_response_accepts_a_valid_response() {
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("server addr");
        let mapped: SocketAddr = "198.51.100.7:49152".parse().expect("mapped addr");
        let transaction_id = TransactionId::new();
        let raw = binding_success(transaction_id, mapped);
        assert_eq!(
            parse_binding_response(&raw, transaction_id, server).expect("valid response"),
            mapped
        );
    }

    #[test]
    fn parse_binding_response_rejects_a_wrong_transaction_id() {
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("server addr");
        let mapped: SocketAddr = "198.51.100.7:49152".parse().expect("mapped addr");
        let response_tid = TransactionId::new();
        let expected_tid = TransactionId::new();
        assert_ne!(response_tid, expected_tid);
        let raw = binding_success(response_tid, mapped);
        let error = parse_binding_response(&raw, expected_tid, server).unwrap_err();
        assert!(
            matches!(&error, SignalingError::Stun(message) if message.contains("transaction id")),
            "got {error:?}"
        );
    }

    #[test]
    fn parse_binding_response_rejects_a_non_success_message() {
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("server addr");
        let transaction_id = TransactionId::new();
        // A Binding *Request* must not be accepted as a gather response just because the
        // transaction id happens to match.
        let raw = stun_message(transaction_id, BINDING_REQUEST);
        let error = parse_binding_response(&raw, transaction_id, server).unwrap_err();
        assert!(
            matches!(&error, SignalingError::Stun(message) if message.contains("message type")),
            "got {error:?}"
        );
    }

    #[test]
    fn parse_binding_response_rejects_unusable_mapped_addresses() {
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("server addr");
        let transaction_id = TransactionId::new();
        let cases = [
            "0.0.0.0:0".parse().expect("v4 unspecified"),
            "0.0.0.0:49152".parse().expect("v4 unspecified"),
            "224.0.0.1:49152".parse().expect("v4 multicast"),
            "[2001:db8::1]:49152".parse().expect("v6 (wrong family)"),
        ];
        for mapped in cases {
            let raw = binding_success(transaction_id, mapped);
            let error = parse_binding_response(&raw, transaction_id, server)
                .expect_err("unusable mapped address must be rejected");
            assert!(
                matches!(error, SignalingError::Stun(_)),
                "unexpected error for {mapped}: {error:?}"
            );
        }
    }

    /// The gather state matches a response by transaction id and server, reports the mapped
    /// address, and then sends end-of-candidates exactly once.
    #[tokio::test]
    async fn stun_gather_matches_a_response_and_emits_end_of_candidates_once() {
        let (server, responder) = spawn_stun_responder();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind gather socket");
        let mut gather = StunGather::new(&[server], Instant::now());
        gather.send_requests(&socket).await;

        let mut buf = [0u8; 1500];
        let (n, from) = socket.recv_from(&mut buf).await.expect("receive response");
        let mapped = gather
            .handle_datagram(&buf[..n], from, Instant::now())
            .expect("from the configured server")
            .expect("valid response")
            .expect("mapped address");
        assert_eq!(
            mapped,
            socket.local_addr().expect("local addr"),
            "on loopback the mapped address is the socket's own address"
        );
        responder.join().expect("responder thread");

        assert!(gather.poll_expiry(Instant::now()), "must emit EOC once");
        assert!(
            !gather.poll_expiry(Instant::now()),
            "EOC must not be emitted twice"
        );
    }

    /// A spoofed response (right source address, wrong transaction id) is classified as gather
    /// traffic and rejected — it must never become a candidate or reach the ICE agent (review fix 3).
    #[tokio::test]
    async fn stun_gather_rejects_a_spoofed_transaction_id() {
        // A real bound socket that never answers, so `send_requests` succeeds and leaves the
        // exchange outstanding.
        let server_socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind silent server");
        let server = server_socket.local_addr().expect("server addr");
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind gather socket");
        let mut gather = StunGather::new(&[server], Instant::now());

        let fake = binding_success(
            TransactionId::new(),
            "198.51.100.7:49152".parse().expect("mapped"),
        );
        // Before a request is sent there is no outstanding exchange, so even a well-formed
        // response from the configured server produces no candidate.
        assert!(
            gather
                .handle_datagram(&fake, server, Instant::now())
                .expect("from the configured server")
                .is_ok(),
            "a response with no outstanding exchange produces no candidate, not an ICE read"
        );

        // With an outstanding exchange, a wrong transaction id is an explicit rejection.
        gather.send_requests(&socket).await;
        let error = gather
            .handle_datagram(&fake, server, Instant::now())
            .expect("from the configured server")
            .expect_err("wrong transaction id must be rejected");
        assert!(
            matches!(&error, SignalingError::Stun(message) if message.contains("transaction id")),
            "got {error:?}"
        );
    }

    /// A full drive over loopback with a **blackholed** STUN server still selects a host pair
    /// promptly: gathering must not gate the ICE phase (review fix 1).
    #[tokio::test]
    async fn blackholed_stun_does_not_delay_a_host_only_punch() {
        let mut a = start_local_ice(true, IpAddr::from([127, 0, 0, 1]))
            .await
            .expect("agent a");
        let mut b = start_local_ice(false, IpAddr::from([127, 0, 0, 1]))
            .await
            .expect("agent b");

        let b_line = unmarshal_candidate(&b.host_candidate_line).expect("b candidate");
        a.agent.add_remote_candidate(b_line).expect("add b");
        let a_line = unmarshal_candidate(&a.host_candidate_line).expect("a candidate");
        b.agent.add_remote_candidate(a_line).expect("add a");

        let (b_ufrag, b_pwd) = {
            let credentials = b.agent.get_local_credentials();
            (credentials.ufrag.clone(), credentials.pwd.clone())
        };
        let (a_ufrag, a_pwd) = {
            let credentials = a.agent.get_local_credentials();
            (credentials.ufrag.clone(), credentials.pwd.clone())
        };

        // Bind but never answer: every STUN request to this address is blackholed.
        let blackhole = StdUdpSocket::bind("127.0.0.1:0").expect("bind blackhole");
        let blackhole_addr = blackhole.local_addr().expect("blackhole addr");
        let now = Instant::now();

        let (_remote_tx_a, remote_rx_a) = mpsc::unbounded_channel();
        let (_remote_tx_b, remote_rx_b) = mpsc::unbounded_channel();
        let (local_tx_a, _local_rx_a) = mpsc::unbounded_channel();
        let (local_tx_b, _local_rx_b) = mpsc::unbounded_channel();

        let both = async {
            tokio::join!(
                drive_ice_agent_trickle(
                    &mut a.agent,
                    &a.socket,
                    true,
                    &b_ufrag,
                    &b_pwd,
                    remote_rx_a,
                    StunGather::new(&[blackhole_addr], now),
                    local_tx_a,
                    Duration::from_secs(10),
                ),
                drive_ice_agent_trickle(
                    &mut b.agent,
                    &b.socket,
                    false,
                    &a_ufrag,
                    &a_pwd,
                    remote_rx_b,
                    StunGather::new(&[blackhole_addr], now),
                    local_tx_b,
                    Duration::from_secs(10),
                ),
            )
        };
        let (a_result, b_result) = tokio::time::timeout(Duration::from_secs(3), both)
            .await
            .expect("a blackholed STUN server must not delay the host-only punch");
        let (_, a_stats) = a_result.expect("a selected");
        let (_, b_stats) = b_result.expect("b selected");
        assert_eq!(a_stats.local_candidates_gathered, 0);
        assert_eq!(b_stats.local_candidates_gathered, 0);
    }

    /// The drive itself sends the Binding Request and emits the validated srflx candidate and
    /// end-of-candidates on the local-trickle channel (the caller signs/publishes them).
    #[tokio::test]
    async fn drive_gathers_and_emits_a_server_reflexive_candidate() {
        let (server, responder) = spawn_stun_responder();
        let mut local = start_local_ice(true, IpAddr::from([127, 0, 0, 1]))
            .await
            .expect("local ICE");

        let (_remote_tx, remote_rx) = mpsc::unbounded_channel();
        let (local_tx, mut local_rx) = mpsc::unbounded_channel();
        let drive = drive_ice_agent_trickle(
            &mut local.agent,
            &local.socket,
            true,
            "remoteufrag",
            "remotepassword1234567890ab",
            remote_rx,
            StunGather::new(&[server], Instant::now()),
            local_tx,
            Duration::from_secs(10),
        );
        // The drive has no remote candidate, so it never selects; 1 s is enough for the STUN
        // exchange, after which the timeout cancels the future.
        let _ = tokio::time::timeout(Duration::from_secs(1), drive).await;
        responder.join().expect("responder thread");

        let mut events = Vec::new();
        while let Ok(event) = local_rx.try_recv() {
            events.push(event);
        }
        assert!(
            events.iter().any(|event| matches!(
                event,
                LocalTrickleEvent::Candidate(line) if line.contains("typ srflx")
            )),
            "expected an emitted srflx candidate, got {events:?}"
        );
        assert!(
            events.contains(&LocalTrickleEvent::EndOfCandidates),
            "expected end-of-candidates, got {events:?}"
        );
    }

    /// The relay path learns the peer's relayed address from the trickle stream: non-relay
    /// candidates and the end-of-candidates marker are skipped, and the `relay` candidate's
    /// address (not its private base address) is returned.
    #[tokio::test]
    async fn await_peer_relay_candidate_skips_other_candidates() {
        let host_line = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: "192.0.2.10".to_string(),
                port: 5000,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .expect("host candidate")
        .marshal();
        let relayed: SocketAddr = "203.0.113.7:49160".parse().expect("relayed addr");
        let relay_line = relay_candidate_line(
            relayed,
            "192.0.2.10:5000".parse().expect("base"),
            "203.0.113.1:3478".parse().expect("server"),
        )
        .expect("relay candidate");

        let (tx, rx) = mpsc::channel(8);
        tx.send(TrickleEvent::Candidate(host_line))
            .await
            .expect("send host");
        tx.send(TrickleEvent::EndOfCandidates)
            .await
            .expect("send eoc");
        tx.send(TrickleEvent::Candidate(relay_line))
            .await
            .expect("send relay");

        let found = await_peer_relay_candidate(rx, Duration::from_secs(1))
            .await
            .expect("relay candidate found");
        assert_eq!(found, relayed);
    }

    /// Pair selected before the shared deadline wins (td-870b25).
    #[test]
    fn window_decision_punches_on_a_pair_before_the_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3);
        assert_eq!(
            decide_after_window(true, true, Some(now + Duration::from_secs(1)), deadline),
            WindowDecision::Punch
        );
    }

    /// No pair at the deadline switches to the relay; a pair **present at the deadline check** wins,
    /// because the window bounds how long to wait, not whether an already-selected pair counts.
    /// Production records the deadline itself when its final poll observes a pair, so this is the
    /// tested policy the runtime actually applies.
    #[test]
    fn window_decision_relays_only_when_no_pair_is_present_at_the_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3);
        assert_eq!(
            decide_after_window(true, true, None, deadline),
            WindowDecision::Relay
        );
        assert_eq!(
            decide_after_window(true, true, Some(deadline), deadline),
            WindowDecision::Punch
        );
    }

    /// The punch window is validated before the deadline is computed: positive out-of-range and
    /// overflowing values are a configuration error, never a panic at `Instant + Duration`
    /// (td-870b25 review). Zero is the explicit relay-only mode and is accepted.
    #[test]
    fn punch_window_is_bounded_instead_of_overflowing_the_clock() {
        let now = Instant::now();
        for accepted in [
            Duration::ZERO,
            MIN_PUNCH_WINDOW,
            DEFAULT_PUNCH_WINDOW,
            MAX_PUNCH_WINDOW,
        ] {
            assert_eq!(
                punch_deadline(accepted, now).expect("accepted window"),
                now + accepted
            );
        }
        for rejected in [
            MIN_PUNCH_WINDOW - Duration::from_millis(1),
            MAX_PUNCH_WINDOW + Duration::from_millis(1),
            Duration::MAX,
        ] {
            assert!(
                matches!(
                    punch_deadline(rejected, now),
                    Err(SignalingError::PunchWindow { window, .. }) if window == rejected
                ),
                "expected a PunchWindow config error for {rejected:?}"
            );
        }
    }

    /// A zero window is the explicit relay-only mode (the lab's long-relay proof uses
    /// `PUNCH_WINDOW_MS=0`): the runtime skips the ICE attempt, so no pair is ever reported and
    /// the decision is Relay whenever an allocation exists. With no allocation there is no relay
    /// either, and the runtime turns that into an attempt failure rather than punching.
    #[test]
    fn zero_punch_window_is_relay_only() {
        let now = Instant::now();
        assert_eq!(
            punch_deadline(Duration::ZERO, now).expect("zero is the relay-only mode"),
            now
        );
        assert_eq!(
            decide_after_window(true, true, None, now),
            WindowDecision::Relay
        );
        assert_eq!(
            decide_after_window(true, false, None, now),
            WindowDecision::Punch
        );
    }

    /// No TURN configured is punch-only: there is no alternative, so a missing pair is not a
    /// switch to a relay that does not exist.
    #[test]
    fn window_decision_without_turn_is_punch_only() {
        let now = Instant::now();
        assert_eq!(
            decide_after_window(false, false, None, now),
            WindowDecision::Punch
        );
    }

    /// A failed allocation also leaves the attempt punch-only (the task's required semantics):
    /// log and keep punching rather than failing the connect.
    #[test]
    fn window_decision_with_a_failed_allocation_is_punch_only() {
        let now = Instant::now();
        assert_eq!(
            decide_after_window(true, false, None, now),
            WindowDecision::Punch
        );
    }

    /// The default window is 3 s, exposed on `IceConfig` so tests/lab runs can shorten it.
    #[test]
    fn default_punch_window_is_three_seconds() {
        assert_eq!(IceConfig::default().punch_window, Duration::from_secs(3));
    }

    /// The split sends ordinary candidates and the end-of-candidates marker to the ICE feed and
    /// withholds a peer `relay` candidate for the fallback (td-870b25).
    #[tokio::test]
    async fn split_routes_relay_candidates_away_from_the_ice_agent() {
        let host_line = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_string(),
                address: "192.0.2.10".to_string(),
                port: 5000,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .expect("host candidate")
        .marshal();
        let relay_line = relay_candidate_line(
            "203.0.113.7:49160".parse().expect("relayed addr"),
            "192.0.2.10:5000".parse().expect("base"),
            "203.0.113.1:3478".parse().expect("server"),
        )
        .expect("relay candidate");

        let (source_tx, source_rx) = mpsc::unbounded_channel();
        let (ice_tx, mut ice_rx) = mpsc::unbounded_channel();
        // Capacity 1, matching the production wiring: the tee uses `try_send`, so a second relay
        // line is dropped rather than buffered.
        let (relay_tx, mut relay_rx) = mpsc::channel(1);
        let split = tokio::spawn(split_relay_candidates(source_rx, ice_tx, relay_tx));

        source_tx
            .send(TrickleEvent::Candidate(host_line.clone()))
            .expect("send host");
        source_tx
            .send(TrickleEvent::Candidate(relay_line.clone()))
            .expect("send relay");
        source_tx
            .send(TrickleEvent::EndOfCandidates)
            .expect("send eoc");
        drop(source_tx);

        split.await.expect("split task");
        let ice: Vec<_> = std::iter::from_fn(|| ice_rx.try_recv().ok()).collect();
        let relay: Vec<_> = std::iter::from_fn(|| relay_rx.try_recv().ok()).collect();

        assert!(
            matches!(&ice[0], TrickleEvent::Candidate(line) if line == &host_line),
            "host candidate must reach the ICE agent, got {ice:?}"
        );
        assert!(
            ice.iter()
                .any(|event| matches!(event, TrickleEvent::EndOfCandidates)),
            "end-of-candidates must reach the ICE agent, got {ice:?}"
        );
        assert_no_relay_in_ice(&ice);
        assert!(
            matches!(&relay[..], [TrickleEvent::Candidate(line)] if line == &relay_line),
            "the relay candidate must go only to the fallback, got {relay:?}"
        );
    }

    fn assert_no_relay_in_ice(events: &[TrickleEvent]) {
        assert!(
            !events.iter().any(|event| matches!(
                event,
                TrickleEvent::Candidate(line) if line.contains("typ relay")
            )),
            "a relay candidate must never be fed to the ICE agent (checks would bypass TURN), got {events:?}"
        );
    }
}

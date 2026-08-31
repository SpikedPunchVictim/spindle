//! Standalone ICE punching (DESIGN.md §A8/A10.32), graduated from `spikes/s2-signaling`'s
//! `s2-connect.rs` (`start_local_ice`/`drive_ice_agent_trickle`), itself built on
//! `spikes/s19-quic-transport`'s leg 2. Not redesigned here — see that spike's module doc comment
//! for the empirical groundwork (`rtc_ice::agent::Agent` is sans-I/O: it "owns no sockets and no
//! clock"; the caller feeds it datagrams and sends whatever it emits; once a pair is selected, the
//! caller already holds the exact `std::net::UdpSocket` [`crate::quic::QuicServer::from_socket`]/
//! [`crate::quic::QuicClient::from_socket`] need). Only adapted to this crate's error type and
//! library conventions (no `println!`/`eprintln!` — callers decide what, if anything, to log).
//!
//! Loopback/LAN host candidates only in this slice — no STUN/TURN gathering (matching the spike's
//! own "Not exercised" scope; see this module's home crate's report for what that leaves unproven).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rtc_ice::agent::agent_config::AgentConfig as IceAgentConfig;
use rtc_ice::agent::Agent as IceAgent;
use rtc_ice::candidate::candidate_host::CandidateHostConfig;
use rtc_ice::candidate::{unmarshal_candidate, CandidateConfig};
use rtc_ice::state::ConnectionState as IceConnectionState;
use rtc_ice::Event as IceEvent;
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use sansio::Protocol as _;
use tokio::sync::mpsc;

use super::error::SignalingError;

/// A locally-gathered ICE agent plus the UDP socket it will punch through, not yet driven to a
/// selected pair (the remote ufrag/pwd aren't known until the offer/answer round trip completes —
/// see [`crate::signaling::client`]/[`crate::signaling::host`]).
pub struct LocalIce {
    pub agent: IceAgent,
    pub socket: tokio::net::UdpSocket,
    pub ufrag: String,
    pub pwd: String,
    /// This side's own single host candidate, already marshaled (SDP `a=candidate` line body) —
    /// loopback/LAN only, see the module doc comment.
    pub candidate_line: String,
}

/// Binds a UDP socket on `bind_ip` and constructs an [`IceAgent`] with one local host candidate
/// already added, but connectivity checks NOT yet started.
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
    let candidate_line = host_candidate.marshal();

    let credentials = agent.get_local_credentials();
    let ufrag = credentials.ufrag.clone();
    let pwd = credentials.pwd.clone();

    Ok(LocalIce {
        agent,
        socket: udp,
        ufrag,
        pwd,
        candidate_line,
    })
}

/// One decoded, already-verified trickled ICE message, handed from the envelope layer
/// ([`crate::signaling::wire`]) to [`drive_ice_agent_trickle`].
pub enum TrickleEvent {
    Candidate(String),
    EndOfCandidates,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct TrickleStats {
    /// How many trickled candidates this side actually fed into `add_remote_candidate` before (or
    /// after) selection.
    pub candidates_applied: u32,
    pub end_of_candidates_seen: bool,
    /// How many trickled `candidate` lines failed to unmarshal and were dropped (soft failure —
    /// matches `spikes/s2-signaling`'s `s2-connect.rs` precedent of warning and continuing rather
    /// than aborting the whole punch over one malformed line, e.g. from a future peer using a
    /// candidate-line extension this agent doesn't recognize yet).
    pub bad_candidates_seen: u32,
}

/// Drives `agent` to a selected candidate pair. `candidate_rx` is a third `tokio::select!` branch
/// alongside the UDP socket and the agent's own timers: candidates arrive asynchronously, one
/// envelope at a time, and are fed into `agent.add_remote_candidate` the moment they're decoded —
/// this is the trickle mechanic itself. Once a pair is selected, this returns immediately; any
/// not-yet-arrived candidate is simply never applied (harmless — a pair is already selected).
pub async fn drive_ice_agent_trickle(
    agent: &mut IceAgent,
    socket: &tokio::net::UdpSocket,
    mut candidate_rx: mpsc::UnboundedReceiver<TrickleEvent>,
    timeout: Duration,
) -> Result<(SocketAddr, TrickleStats), SignalingError> {
    let local_addr = socket.local_addr()?;
    let mut buf = vec![0u8; 2048];
    let deadline = Instant::now() + timeout;
    let mut stats = TrickleStats::default();

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

        if Instant::now() >= deadline {
            return Err(SignalingError::Timeout("ICE trickle"));
        }

        let wake_at = agent
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + Duration::from_millis(100));
        let sleep_for = wake_at
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));

        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {
                agent.handle_timeout(Instant::now())?;
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer_addr) = res?;
                agent.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr,
                        peer_addr,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: BytesMut::from(&buf[..n]),
                })?;
            }
            msg = candidate_rx.recv() => {
                match msg {
                    Some(TrickleEvent::Candidate(line)) => match unmarshal_candidate(&line) {
                        Ok(c) => {
                            let _ = agent.add_remote_candidate(c);
                            stats.candidates_applied += 1;
                        }
                        Err(error) => {
                            stats.bad_candidates_seen += 1;
                            tracing::warn!(
                                candidate = %line,
                                %error,
                                "failed to unmarshal trickled ICE candidate; ignoring"
                            );
                        }
                    },
                    Some(TrickleEvent::EndOfCandidates) => stats.end_of_candidates_seen = true,
                    None => {}
                }
            }
        }
    }
}

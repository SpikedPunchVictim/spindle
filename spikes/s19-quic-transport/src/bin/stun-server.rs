//! A minimal STUN (RFC 5389) Binding-Request responder for S19 leg 2 milestone 6 (NAT-punch
//! matrix, `docs/DESIGN.md` §A8/A10.32).
//!
//! `quic-peer --stun <addr>` needs a STUN server to learn each peer's server-reflexive
//! (NAT-mapped) address before ICE connectivity checks can find a punchable pair across the
//! namespace/iptables NAT harness (`s19-nat-run.sh`). Two options were on the table for that
//! server: install coturn via `apt` inside the container, or write a tiny binary against a Rust
//! STUN crate. This harness already depends on `rtc-stun` transitively via `rtc-ice` (see
//! `quic-peer.rs`'s `stun_gather`, which is the client side of the exact same protocol exchange
//! this binary answers) — reusing it here needs zero new dependencies, zero `apt-get`, and zero
//! extra image layers, at the cost of implementing only the one STUN feature this spike actually
//! needs (a bare Binding Request/Response, no long-term credentials, no TURN allocate/relay, no
//! `--random-fully`-defeating tricks). Coturn is the right call for a production TURN/STUN
//! deployment (leg 3 will need a real TURN relay for the symmetric-NAT case); for "does ICE
//! punching find a server-reflexive candidate," a ~50-line responder is the boring, minimal
//! choice and keeps the container image untouched.
//!
//! Protocol: for every UDP datagram that decodes as a STUN `BINDING_REQUEST`, reply with a
//! `BINDING_SUCCESS` response carrying the request's echoed transaction id and an
//! `XOR-MAPPED-ADDRESS` attribute set to the *source address of the request as this process saw
//! it* — which, when a NAT sits between the client and this server, is the NAT's public mapping,
//! exactly what RFC 5389 Binding is for. Anything that isn't a STUN message, or isn't a Binding
//! Request specifically, is logged and dropped.
//!
//! Usage: `stun-server [bind_addr]` (default `0.0.0.0:3478`, the IANA-assigned STUN port).
//! Blocking, single-threaded, no retries, no rate limiting — a spike tool, not a production STUN
//! server.

use std::net::UdpSocket;

use rtc_stun::message::{Message, BINDING_REQUEST, BINDING_SUCCESS};
use rtc_stun::xoraddr::XorMappedAddress;

fn main() -> std::io::Result<()> {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:3478".to_string());
    let socket = UdpSocket::bind(&bind_addr)?;
    eprintln!("stun-server: listening on {bind_addr}");

    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("stun-server: recv_from error: {e}");
                continue;
            }
        };

        let mut req = Message::new();
        req.raw = buf[..n].to_vec();
        if req.decode().is_err() {
            eprintln!("stun-server: dropping non-STUN datagram from {from} ({n} bytes)");
            continue;
        }
        if req.typ != BINDING_REQUEST {
            eprintln!(
                "stun-server: dropping non-Binding-Request STUN message from {from} (typ={:?})",
                req.typ
            );
            continue;
        }

        let mut resp = Message::new();
        let build_result = resp.build(&[
            Box::new(req.transaction_id),
            Box::new(BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: from.ip(),
                port: from.port(),
            }),
        ]);
        if let Err(e) = build_result {
            eprintln!("stun-server: failed to build Binding Success response for {from}: {e}");
            continue;
        }

        if let Err(e) = socket.send_to(&resp.raw, from) {
            eprintln!("stun-server: send_to {from} failed: {e}");
            continue;
        }
        eprintln!("stun-server: answered Binding Request from {from} (mapped address: {from})");
    }
}

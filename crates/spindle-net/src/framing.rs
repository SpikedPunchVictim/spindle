//! Length-prefixed framing for the VFS RPC control stream (DESIGN.md §A8: "One control stream
//! (VFS RPC) + data streams; 64 KiB chunks"). Generic over any `tokio::io::{AsyncRead,
//! AsyncWrite}` — this module has no QUIC dependency of its own; [`crate::quic`] hands it a
//! `quinn::{RecvStream, SendStream}` pair (both already implement the tokio traits), but any
//! other duplex byte stream works identically (this is what the unit tests below exercise,
//! against plain in-memory pipes, with no QUIC endpoint needed at all).
//!
//! # Wire format
//!
//! `<4-byte big-endian length prefix><payload>`, repeated for as many frames as the stream
//! carries. The length prefix counts payload bytes only (never itself).
//!
//! **Not yet in DESIGN.md §A8** — flagged in this slice's report as a docs-amendment finding: the
//! 4-byte-big-endian-length-prefix wire format is a fact a peer must implement correctly to
//! interoperate, same as the ALPN token ([`crate::quic::ALPN`]).
//!
//! # Frame size cap
//!
//! [`MAX_FRAME_LEN`] is 256 KiB. Headroom computation: the largest legitimate payload is one
//! `upload_chunk` request or one `read` reply, each capped at
//! [`spindle_proto::MAX_UPLOAD_CHUNK`]/[`spindle_proto::MAX_READ_CHUNK`] (64 KiB, DESIGN.md §A8).
//! Canonical CBOR adds only a handful of bytes of map/key/length overhead on top of that raw byte
//! string (a byte-string header, a handful of small-integer/text-string map keys and their
//! values) — nowhere close to another 64 KiB. 256 KiB is therefore roughly 4x the largest
//! legitimate frame: comfortably clear of any real request/reply, while still small enough that
//! an oversized length prefix is rejected *before* allocating a receive buffer for it (the
//! oversize check runs against the length prefix alone, never against attacker-controlled
//! payload bytes).
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum payload length this module will read or write in one frame, in bytes. See the module
/// doc comment's "Frame size cap" section for the headroom computation.
pub const MAX_FRAME_LEN: u32 = 256 * 1024;

/// Framing-layer failures. Every variant here is a protocol violation, not a
/// [`spindle_proto::ProtoError`] — [`crate::framing`] sits below the VFS RPC decode step entirely
/// (see [`read_frame`]'s doc comment for the clean-EOF-vs-truncation distinction the caller needs
/// to tell "peer hung up" from "peer is misbehaving or the stream is corrupt").
#[derive(Debug, Error)]
pub enum FramingError {
    /// The underlying stream returned an I/O error (not itself an EOF condition — see
    /// [`FramingError::Truncated`] for that).
    #[error("I/O error on the framed stream: {0}")]
    Io(#[from] std::io::Error),
    /// A frame's length prefix exceeded [`MAX_FRAME_LEN`]. Detected before any payload bytes are
    /// read, so an oversized claim never causes an oversized allocation.
    #[error("frame length {len} exceeds the {MAX_FRAME_LEN}-byte cap")]
    FrameTooLarge { len: u32 },
    /// The stream ended in the middle of a frame (after the length prefix started, before the
    /// full length prefix and payload were read) — distinct from a clean EOF between frames,
    /// which [`read_frame`] reports as `Ok(None)` rather than an error at all.
    #[error("stream ended in the middle of a frame")]
    Truncated,
}

/// Writes one length-prefixed frame and flushes it. `payload.len()` must not exceed
/// [`MAX_FRAME_LEN`] (checked here, not just on the read side — a caller that builds oversized
/// replies is a local bug, not a peer's fault, but this module refuses either way rather than
/// silently emitting a frame the peer's own [`read_frame`] would then reject).
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), FramingError> {
    let len =
        u32::try_from(payload.len()).map_err(|_| FramingError::FrameTooLarge { len: u32::MAX })?;
    if len > MAX_FRAME_LEN {
        return Err(FramingError::FrameTooLarge { len });
    }
    let mut header = Vec::with_capacity(4 + payload.len());
    header.extend_from_slice(&len.to_be_bytes());
    header.extend_from_slice(payload);
    writer.write_all(&header).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one length-prefixed frame. Three outcomes, deliberately distinct (the module doc
/// comment's whole point):
///
/// - `Ok(Some(payload))` — a complete frame.
/// - `Ok(None)` — the stream ended cleanly *between* frames (zero bytes read before EOF) — the
///   peer closed the control stream normally; not an error.
/// - `Err(FramingError::Truncated)` — the stream ended *inside* a frame (after at least one byte
///   of the length prefix was read); this is a protocol violation, not a graceful close.
/// - `Err(FramingError::FrameTooLarge { .. })` — the length prefix itself claims more than
///   [`MAX_FRAME_LEN`]; the payload is never read/allocated in this case.
///
/// The clean-EOF check reads exactly one byte first (via a single-byte buffer): a real `AsyncRead`
/// returns `Ok(0)` from that read if and only if the stream is at EOF (never for "no data yet,
/// try again" — that case parks the future instead), so this is a reliable way to distinguish "no
/// more frames" from "a frame started."
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, FramingError> {
    let mut len_buf = [0u8; 4];
    let n = reader.read(&mut len_buf[..1]).await?;
    if n == 0 {
        return Ok(None);
    }
    read_exact_or_truncated(reader, &mut len_buf[1..]).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FramingError::FrameTooLarge { len });
    }
    let mut payload = vec![0u8; len as usize];
    read_exact_or_truncated(reader, &mut payload).await?;
    Ok(Some(payload))
}

/// `AsyncReadExt::read_exact`, but an EOF partway through is reported as
/// [`FramingError::Truncated`] rather than the generic I/O error `read_exact` itself returns
/// (`UnexpectedEof`) — every other I/O error still passes through as [`FramingError::Io`].
async fn read_exact_or_truncated<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<(), FramingError> {
    match reader.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(FramingError::Truncated),
        Err(e) => Err(FramingError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{duplex, ReadBuf};

    #[tokio::test]
    async fn round_trips_a_frame() {
        let (mut a, mut b) = duplex(4096);
        write_frame(&mut a, b"hello, spindle").await.expect("write");
        let got = read_frame(&mut b)
            .await
            .expect("read")
            .expect("Some(frame)");
        assert_eq!(got, b"hello, spindle");
    }

    #[tokio::test]
    async fn round_trips_an_empty_frame() {
        let (mut a, mut b) = duplex(4096);
        write_frame(&mut a, b"").await.expect("write");
        let got = read_frame(&mut b)
            .await
            .expect("read")
            .expect("Some(frame)");
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn multiple_frames_in_sequence() {
        let (mut a, mut b) = duplex(4096);
        write_frame(&mut a, b"one").await.expect("write 1");
        write_frame(&mut a, b"two").await.expect("write 2");
        assert_eq!(
            read_frame(&mut b).await.expect("read 1").expect("Some"),
            b"one"
        );
        assert_eq!(
            read_frame(&mut b).await.expect("read 2").expect("Some"),
            b"two"
        );
    }

    /// An `AsyncRead` that yields the bytes of a fixed buffer exactly one byte per `poll_read`
    /// call, regardless of how much space the caller's `ReadBuf` offers — the harness this test
    /// module uses to prove [`read_frame`] is correct even when the underlying transport delivers
    /// data far more granularly than one read call per frame (a real QUIC/TCP stream can split
    /// delivery at any byte boundary, including mid-length-prefix and mid-payload).
    struct OneByteAtATime {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for OneByteAtATime {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.pos >= this.data.len() {
                return Poll::Ready(Ok(())); // EOF: no bytes appended to `buf`
            }
            buf.put_slice(&this.data[this.pos..this.pos + 1]);
            this.pos += 1;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn split_reads_across_the_length_prefix_and_payload() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&9u32.to_be_bytes());
        wire.extend_from_slice(b"nine-byte");
        let mut reader = OneByteAtATime { data: wire, pos: 0 };

        let got = read_frame(&mut reader)
            .await
            .expect("read")
            .expect("Some(frame)");
        assert_eq!(got, b"nine-byte");
    }

    #[tokio::test]
    async fn oversize_length_prefix_is_rejected_without_reading_payload() {
        let (mut a, mut b) = duplex(4096);
        let too_big = MAX_FRAME_LEN + 1;
        a.write_all(&too_big.to_be_bytes())
            .await
            .expect("write header");
        // Deliberately never write the (nonexistent) payload — proves the oversize check fires
        // from the length prefix alone, before any attempt to read/allocate payload bytes.
        drop(a);

        let err = read_frame(&mut b).await.expect_err("must reject oversize");
        match err {
            FramingError::FrameTooLarge { len } => assert_eq!(len, too_big),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn clean_eof_between_frames_is_ok_none() {
        let (a, mut b) = duplex(4096);
        drop(a); // close before writing anything at all
        let got = read_frame(&mut b).await.expect("clean EOF is not an error");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn truncated_mid_length_prefix_is_an_error_not_clean_eof() {
        let (mut a, mut b) = duplex(4096);
        a.write_all(&[0x00, 0x00])
            .await
            .expect("write partial header");
        drop(a); // close mid-length-prefix

        let err = read_frame(&mut b)
            .await
            .expect_err("truncation mid-prefix must not be Ok(None)");
        assert!(matches!(err, FramingError::Truncated));
    }

    #[tokio::test]
    async fn truncated_mid_payload_is_an_error_not_clean_eof() {
        let (mut a, mut b) = duplex(4096);
        a.write_all(&5u32.to_be_bytes())
            .await
            .expect("write header");
        a.write_all(b"ab").await.expect("write partial payload"); // only 2 of 5 promised bytes
        drop(a);

        let err = read_frame(&mut b)
            .await
            .expect_err("truncation mid-payload must not be Ok(None)");
        assert!(matches!(err, FramingError::Truncated));
    }

    #[tokio::test]
    async fn write_refuses_a_payload_over_the_cap() {
        let (mut a, _b) = duplex(4096);
        let oversized = vec![0u8; MAX_FRAME_LEN as usize + 1];
        let err = write_frame(&mut a, &oversized)
            .await
            .expect_err("must refuse to emit an oversized frame");
        match err {
            FramingError::FrameTooLarge { len } => assert_eq!(len, MAX_FRAME_LEN + 1),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }
}

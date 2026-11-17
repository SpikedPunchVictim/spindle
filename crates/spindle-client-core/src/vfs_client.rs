//! VFS RPC client over a control stream (DESIGN.md §A8, td-6e3e90).
//!
//! The host side of this protocol is [`spindle_host_core::serve_control_stream`]: one
//! length-prefixed canonical-CBOR [`VfsRequestEnvelope`] in, one [`VfsReply`] out, strictly
//! request/reply (no pipelining). This module owns the client half — framing, encode/decode, and
//! the typed error surface — so `spindle-client-core` callers never touch QUIC or the wire.
//!
//! Generic over the two byte-stream halves rather than tied to [`spindle_net::quic::ControlStream`]
//! so the same code drives a QUIC control stream in production and plain in-memory pipes in
//! tests. The transport is already authenticated by the session layer above this one; VFS RPC
//! carries no capability of its own.
//!
//! Uploads are a state machine (`upload_open` → `upload_chunk`* → `upload_commit`), with
//! `offset` strictly next-expected: a resumed session returns its current offset, and a chunk at
//! any other offset is refused by the host as `file_changed`. [`VfsClient::upload_file`] performs
//! the whole sequence for a caller that already has the bytes, hash, and manifest signature; the
//! lower-level methods are public for resumable transfers.

use spindle_net::framing::{read_frame, write_frame, FramingError};
use spindle_proto::vfs_rpc::{
    DirEntry, VfsErrorCode, VfsReply, VfsRequest, VfsRequestEnvelope, CURRENT_PROTOCOL_VERSION,
    MAX_READ_CHUNK, MAX_UPLOAD_CHUNK,
};
use spindle_proto::ProtoError;
use tokio::io::{AsyncRead, AsyncWrite};

/// Everything the client can refuse locally or learn from a peer refusal.
#[derive(Debug, thiserror::Error)]
pub enum VfsClientError {
    #[error("control-stream framing failed")]
    Framing(#[from] FramingError),
    #[error("the peer's reply is not decodable")]
    Wire(#[source] ProtoError),
    /// The host's typed `VfsReply::Error`; this is the peer's refusal, not a protocol error.
    #[error("host refused the request: {0:?}")]
    Peer(VfsErrorCode),
    #[error("host replied with a different operation than the request")]
    UnexpectedReply,
    #[error("upload offset mismatch: client expected {expected}, host reports {actual}")]
    OffsetMismatch { expected: u64, actual: u64 },
    #[error("upload chunk of {len} bytes exceeds the {MAX_UPLOAD_CHUNK}-byte cap")]
    ChunkTooLarge { len: usize },
    #[error("read length {len} is invalid; a read must request 1..={MAX_READ_CHUNK} bytes")]
    InvalidReadLen { len: u32 },
    #[error("host resumed upload at offset {offset}, beyond the supplied {len}-byte payload")]
    ResumeBeyondPayload { offset: u64, len: usize },
}

/// A request/reply VFS client bound to one control stream.
pub struct VfsClient<R, W> {
    recv: R,
    send: W,
}

impl<R, W> VfsClient<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Wraps the control stream's receive and send halves.
    pub fn new(recv: R, send: W) -> Self {
        Self { recv, send }
    }

    /// Sends one request and returns the decoded reply. A host-level refusal is
    /// [`VfsClientError::Peer`]; protocol failures are distinct variants.
    pub async fn request(&mut self, request: VfsRequest) -> Result<VfsReply, VfsClientError> {
        let envelope = VfsRequestEnvelope {
            v: CURRENT_PROTOCOL_VERSION,
            request,
        };
        write_frame(&mut self.send, &envelope.to_canonical_bytes()).await?;
        let Some(reply) = read_frame(&mut self.recv).await? else {
            return Err(VfsClientError::Framing(FramingError::Truncated));
        };
        let reply = VfsReply::from_canonical_bytes(&reply).map_err(VfsClientError::Wire)?;
        if let VfsReply::Error { code } = reply {
            return Err(VfsClientError::Peer(code));
        }
        Ok(reply)
    }

    /// One directory page. `None` cursor/limit use the host's defaults.
    pub async fn list(
        &mut self,
        path: impl Into<String>,
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
    ) -> Result<(Vec<DirEntry>, Option<Vec<u8>>), VfsClientError> {
        match self
            .request(VfsRequest::List {
                path: path.into(),
                cursor,
                limit,
            })
            .await?
        {
            VfsReply::List {
                entries,
                next_cursor,
            } => Ok((entries, next_cursor)),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    /// Metadata for one path.
    pub async fn stat(&mut self, path: impl Into<String>) -> Result<VfsReply, VfsClientError> {
        match self.request(VfsRequest::Stat { path: path.into() }).await? {
            reply @ VfsReply::Stat { .. } => Ok(reply),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    /// One chunk. The host caps `len` at `MAX_READ_CHUNK`.
    pub async fn read_at(
        &mut self,
        path: impl Into<String>,
        offset: u64,
        len: u32,
    ) -> Result<(Vec<u8>, bool), VfsClientError> {
        if len == 0 || len > MAX_READ_CHUNK {
            return Err(VfsClientError::InvalidReadLen { len });
        }
        match self
            .request(VfsRequest::Read {
                path: path.into(),
                offset,
                len,
            })
            .await?
        {
            VfsReply::Read { data, eof } => Ok((data, eof)),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    /// Reads a whole file by repeating [`Self::read_at`] until EOF. Unbounded by design at this
    /// layer — the caller chose a whole-file read; use `read_at` for streaming.
    pub async fn read_all(&mut self, path: impl Into<String>) -> Result<Vec<u8>, VfsClientError> {
        let path = path.into();
        let mut out = Vec::new();
        loop {
            let (chunk, eof) = self
                .read_at(path.clone(), out.len() as u64, MAX_READ_CHUNK)
                .await?;
            let empty = chunk.is_empty();
            out.extend_from_slice(&chunk);
            if eof {
                return Ok(out);
            }
            if empty {
                return Err(VfsClientError::UnexpectedReply);
            }
        }
    }

    pub async fn mkdir(&mut self, path: impl Into<String>) -> Result<(), VfsClientError> {
        match self
            .request(VfsRequest::Mkdir { path: path.into() })
            .await?
        {
            VfsReply::Mkdir => Ok(()),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    pub async fn delete(&mut self, path: impl Into<String>) -> Result<(), VfsClientError> {
        match self
            .request(VfsRequest::Delete { path: path.into() })
            .await?
        {
            VfsReply::Delete => Ok(()),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    /// Starts or resumes an upload. Returns `(session_id, next_expected_offset)`.
    pub async fn upload_open(
        &mut self,
        path: impl Into<String>,
        size: u64,
        hash: Vec<u8>,
        manifest_sig: Vec<u8>,
    ) -> Result<(Vec<u8>, u64), VfsClientError> {
        match self
            .request(VfsRequest::UploadOpen {
                path: path.into(),
                size,
                hash,
                manifest_sig,
            })
            .await?
        {
            VfsReply::UploadOpen { session_id, offset } => Ok((session_id, offset)),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    /// Appends one chunk at `offset`; returns the new next-expected offset.
    pub async fn upload_chunk(
        &mut self,
        session_id: &[u8],
        offset: u64,
        data: Vec<u8>,
    ) -> Result<u64, VfsClientError> {
        if data.len() > MAX_UPLOAD_CHUNK as usize {
            return Err(VfsClientError::ChunkTooLarge { len: data.len() });
        }
        match self
            .request(VfsRequest::UploadChunk {
                session_id: session_id.to_vec(),
                offset,
                data,
            })
            .await?
        {
            VfsReply::UploadChunk { offset } => Ok(offset),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    pub async fn upload_commit(&mut self, session_id: &[u8]) -> Result<(), VfsClientError> {
        match self
            .request(VfsRequest::UploadCommit {
                session_id: session_id.to_vec(),
            })
            .await?
        {
            VfsReply::UploadCommit => Ok(()),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    pub async fn upload_abort(&mut self, session_id: &[u8]) -> Result<(), VfsClientError> {
        match self
            .request(VfsRequest::UploadAbort {
                session_id: session_id.to_vec(),
            })
            .await?
        {
            VfsReply::UploadAbort => Ok(()),
            _ => Err(VfsClientError::UnexpectedReply),
        }
    }

    /// Opens/resumes, sends `data` from the host's next-expected offset in `MAX_UPLOAD_CHUNK`
    /// pieces, then commits. On a refusal that leaves the control stream in sync, the session is
    /// aborted best-effort before the original error is returned (a transport/wire failure cannot
    /// carry an abort, so it is returned without one). `hash`/`manifest_sig` are the caller's
    /// whole-file declarations; the host verifies both before the staged file is moved into place.
    pub async fn upload_file(
        &mut self,
        path: impl Into<String>,
        data: &[u8],
        hash: Vec<u8>,
        manifest_sig: Vec<u8>,
    ) -> Result<(), VfsClientError> {
        let (session_id, offset) = self
            .upload_open(path, data.len() as u64, hash, manifest_sig)
            .await?;
        match self.upload_from(&session_id, data, offset).await {
            Ok(()) => Ok(()),
            Err(error) => {
                if !matches!(error, VfsClientError::Framing(_) | VfsClientError::Wire(_)) {
                    let _ = self.upload_abort(&session_id).await;
                }
                Err(error)
            }
        }
    }

    async fn upload_from(
        &mut self,
        session_id: &[u8],
        data: &[u8],
        mut offset: u64,
    ) -> Result<(), VfsClientError> {
        if offset > data.len() as u64 {
            return Err(VfsClientError::ResumeBeyondPayload {
                offset,
                len: data.len(),
            });
        }
        while (offset as usize) < data.len() {
            let start = offset as usize;
            let end = (start + MAX_UPLOAD_CHUNK as usize).min(data.len());
            let next = self
                .upload_chunk(session_id, offset, data[start..end].to_vec())
                .await?;
            let expected = end as u64;
            if next != expected {
                return Err(VfsClientError::OffsetMismatch {
                    expected,
                    actual: next,
                });
            }
            offset = next;
        }
        self.upload_commit(session_id).await
    }
}

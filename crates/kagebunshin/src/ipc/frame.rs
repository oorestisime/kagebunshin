//! Wire framing: a 4-byte big-endian length, then that many bytes of JSON.
//!
//! Sync (std) and async (tokio) variants share the same encoding. Buffers are
//! zeroed on drop because later messages carry secret values. Decode errors
//! keep only serde's error category and position, never its message, which can
//! quote the offending input.

use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub const MAX_FRAME: usize = 1024 * 1024;
const HEADER: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer closed the connection cleanly between frames.
    #[error("connection closed")]
    Closed,
    #[error("connection closed in the middle of a frame")]
    Truncated,
    #[error("frame of {0} bytes exceeds the {MAX_FRAME}-byte limit")]
    TooLarge(usize),
    #[error("malformed frame ({category} error at line {line}, column {column})")]
    Decode {
        category: &'static str,
        line: usize,
        column: usize,
    },
    #[error("cannot encode frame")]
    Encode,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Counts the bytes written to it and keeps none.
struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serializes twice, once only to measure, so the buffer is allocated at
/// its final size: a growing Vec would leave unzeroed copies of the values
/// behind at each reallocation.
fn encode<T: Serialize>(msg: &T) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    encode_with(msg, true)
}

/// `msg` as JSON alone, with no length before it: the body of a request or
/// reply on the remote endpoint, where HTTP says how long it is. The same
/// limit, and zeroed on drop the same way.
pub(super) fn encode_json<T: Serialize>(msg: &T) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    encode_with(msg, false)
}

fn encode_with<T: Serialize>(msg: &T, header: bool) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, msg).map_err(|_| FrameError::Encode)?;
    let len = counter.0;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let header = if header { HEADER } else { 0 };
    let mut buf = Zeroizing::new(Vec::with_capacity(header + len));
    if header > 0 {
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
    serde_json::to_writer(&mut *buf, msg).map_err(|_| FrameError::Encode)?;
    if buf.len() != header + len {
        // The message changed between the passes; cannot happen for `&T`.
        return Err(FrameError::Encode);
    }
    Ok(buf)
}

pub(super) fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(body).map_err(|e| FrameError::Decode {
        category: match e.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        },
        line: e.line(),
        column: e.column(),
    })
}

fn body_len(header: [u8; HEADER]) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

fn eof_is_truncation(e: io::Error) -> FrameError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        FrameError::Truncated
    } else {
        FrameError::Io(e)
    }
}

pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let buf = encode(msg)?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let mut header = [0u8; HEADER];
    let mut got = 0;
    while got < HEADER {
        match r.read(&mut header[got..]) {
            Ok(0) if got == 0 => return Err(FrameError::Closed),
            Ok(0) => return Err(FrameError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    let mut body = Zeroizing::new(vec![0u8; body_len(header)?]);
    r.read_exact(&mut body).map_err(eof_is_truncation)?;
    decode(&body)
}

pub async fn write_frame_async<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let buf = encode(msg)?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame_async<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut header = [0u8; HEADER];
    let mut got = 0;
    while got < HEADER {
        match r.read(&mut header[got..]).await? {
            0 if got == 0 => return Err(FrameError::Closed),
            0 => return Err(FrameError::Truncated),
            n => got += n,
        }
    }
    let mut body = Zeroizing::new(vec![0u8; body_len(header)?]);
    r.read_exact(&mut body).await.map_err(eof_is_truncation)?;
    decode(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Canary, assert_no_canary};
    use serde::Deserialize;
    use std::io::Cursor;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        n: u32,
        s: String,
    }

    fn msg() -> Msg {
        Msg {
            n: 7,
            s: "héllo".into(),
        }
    }

    fn raw(len: u32, body: &[u8]) -> Vec<u8> {
        let mut v = len.to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn round_trip_sync() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg()).unwrap();
        write_frame(&mut buf, &msg()).unwrap();
        let mut r = Cursor::new(buf);
        assert_eq!(read_frame::<_, Msg>(&mut r).unwrap(), msg());
        assert_eq!(read_frame::<_, Msg>(&mut r).unwrap(), msg());
        assert!(matches!(
            read_frame::<_, Msg>(&mut r),
            Err(FrameError::Closed)
        ));
    }

    #[tokio::test]
    async fn round_trip_async() {
        let mut buf = Vec::new();
        write_frame_async(&mut buf, &msg()).await.unwrap();
        let mut r = buf.as_slice();
        assert_eq!(read_frame_async::<_, Msg>(&mut r).await.unwrap(), msg());
        assert!(matches!(
            read_frame_async::<_, Msg>(&mut r).await,
            Err(FrameError::Closed)
        ));
    }

    #[test]
    fn oversized_frames_are_refused_without_allocating() {
        let bytes = raw(u32::MAX, b"");
        assert!(matches!(
            read_frame::<_, Msg>(&mut bytes.as_slice()),
            Err(FrameError::TooLarge(n)) if n == u32::MAX as usize
        ));
        let huge = Msg {
            n: 0,
            s: "x".repeat(MAX_FRAME),
        };
        assert!(matches!(
            write_frame(&mut Vec::new(), &huge),
            Err(FrameError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn truncated_frames() {
        for bytes in [vec![0u8, 0], raw(10, b"{\"n\":")] {
            assert!(matches!(
                read_frame::<_, Msg>(&mut bytes.as_slice()),
                Err(FrameError::Truncated)
            ));
            assert!(matches!(
                read_frame_async::<_, Msg>(&mut bytes.as_slice()).await,
                Err(FrameError::Truncated)
            ));
        }
    }

    #[test]
    fn garbage_is_a_decode_error_that_does_not_quote_input() {
        let canary = Canary::new();
        let bodies = [
            b"not json".to_vec(),
            format!("\"{}\"", canary.value()).into_bytes(),
            format!("{{\"n\":1,\"s\":{{\"{}\":1}}}}", canary.value()).into_bytes(),
        ];
        for body in bodies {
            let bytes = raw(body.len() as u32, &body);
            let err = read_frame::<_, Msg>(&mut bytes.as_slice()).unwrap_err();
            assert!(matches!(err, FrameError::Decode { .. }), "{err:?}");
            assert_no_canary(&canary, &err.to_string());
            assert_no_canary(&canary, &format!("{err:?}"));
        }
    }
}

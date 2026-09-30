//! Bridges this crate's own [`crate::Transport`] (a non-blocking "try once"
//! primitive, matching this codebase's universal non-blocking-IPC
//! convention — see `kernel::ipc::try_recv`'s callers) to `embedded_io`'s
//! `Read`/`Write` traits, which `embedded_tls` requires and which have a
//! genuinely different contract: `embedded_io::Read::read` must *block*
//! until at least one byte is available, never return `Ok(0)` for "nothing
//! yet" (that specifically means end-of-stream there). Reconciling the two
//! is this module's only job — nothing here is TLS-specific.

use crate::{Transport, Yield};
use embedded_io::{ErrorKind, ErrorType, Read, Write};

/// Wraps a caller's `Transport` + `Yield` into the blocking `Read`/`Write`
/// pair `embedded_tls::blocking::TlsConnection` needs. Not exposed outside
/// this crate — callers hand `TlsConnection::open` a `Transport`/`Yield`
/// pair directly (via [`crate::TlsConnection::open`]) rather than
/// constructing this type themselves; it's purely an internal adapter.
pub(crate) struct BlockingIo<T, Y> {
    transport: T,
    yielder: Y,
}

impl<T, Y> BlockingIo<T, Y> {
    pub(crate) fn new(transport: T, yielder: Y) -> Self {
        Self { transport, yielder }
    }
}

/// Wraps a caller's `Transport::Error` so it can implement `embedded_io::Error`
/// without knowing anything about what that error actually is — every
/// transport error is reported as [`ErrorKind::Other`], since this crate has
/// no way to classify a caller-defined error type more precisely than that.
#[derive(Debug)]
pub(crate) struct TransportError<E>(pub E);

impl<E: core::fmt::Debug> core::fmt::Display for TransportError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "transport error: {:?}", self.0)
    }
}

impl<E: core::fmt::Debug> core::error::Error for TransportError<E> {}

impl<E: core::fmt::Debug> embedded_io::Error for TransportError<E> {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

impl<T: Transport, Y> ErrorType for BlockingIo<T, Y> {
    type Error = TransportError<T::Error>;
}

impl<T: Transport, Y: Yield> Read for BlockingIo<T, Y> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // `embedded_io::Read::read`'s contract: block until >=1 byte is
        // available, then return without waiting for more — `Transport`'s
        // own contract already matches that shape once wrapped in this
        // retry loop (`Ok(0)` from `Transport::read` means "nothing yet,"
        // not EOF — this transport has no EOF concept at all, so this loop
        // never terminates on its own; a real error is the only exit besides
        // getting data).
        loop {
            let n = self.transport.read(buf).map_err(TransportError)?;
            if n > 0 {
                return Ok(n);
            }
            self.yielder.yield_now();
        }
    }
}

impl<T: Transport, Y: Yield> Write for BlockingIo<T, Y> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // `Transport::write_all` already guarantees the whole buffer landed
        // (or failed) — so unlike `read`, no retry loop is needed here, and
        // the full length is always what was "written" on success.
        self.transport.write_all(buf).map_err(TransportError)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // `Transport` has no separate flush concept — `write_all` already
        // means "these bytes are on their way," the same synchronous
        // completion every IPC send in this codebase already has (there is
        // no OS-level write buffering to flush underneath it).
        Ok(())
    }
}

//! The actual TLS 1.3 client connection API — wraps `embedded_tls`'s
//! blocking connection type over this crate's [`crate::Transport`]/
//! [`crate::Yield`]/[`crate::Entropy`] traits (via [`crate::io::BlockingIo`]/
//! [`crate::rng::EntropyRng`]), and its `rustpki`-backed
//! `pki::CertVerifier` for real certificate-chain verification — never the
//! crate's default `NoVerify` (see this crate's own top-level doc comment
//! and `docs/RFC-TLS-APPROACH.md`'s Recommendation section for why leaving
//! that default in place would silently reintroduce the exact failure mode
//! the RFC warned against).
//!
//! **No wall-clock time**: `embedded_tls::config::NoClock` is used as this
//! connection's `TlsClock` — it always returns `None`, which
//! `pki::CertVerifier` treats as "skip the notBefore/notAfter check"
//! (confirmed by reading `verify_certificate`'s call site, which passes
//! `Clock::now()` straight into the certificate-time check). This is
//! explicit and visible here, not a silently-skipped check: Runix has no
//! wall-clock source anywhere yet (`SYS_TICKS` is boot-relative — see
//! `kernel/src/capabilities.rs`'s own token-expiry doc comment for the same
//! gap applied to capability tokens). A real `TlsClock` requires a real RTC
//! syscall first, out of scope here.
//!
//! **No client certificates / mTLS**: [`Provider::signer`] and
//! [`Provider::client_cert`] both use their trait defaults (`Unimplemented`/
//! `None`) — nothing in this crate's design needs a Runix process to
//! authenticate itself to a server via a client cert yet.

use crate::io::BlockingIo;
use crate::rng::EntropyRng;
use crate::{Entropy, Transport, Yield};
use embedded_tls::blocking::{Certificate, CryptoProvider, TlsContext, TlsVerifier};
use embedded_tls::pki::CertVerifier;
pub use embedded_tls::blocking::{Aes128GcmSha256 as CipherSuite, NoClock};
pub use embedded_tls::TlsConfig as Config;
pub use embedded_tls::TlsError as HandshakeError;

/// Cap on the total DER bytes of the server's certificate chain this
/// crate's verifier will accept — `embedded_tls::pki::CertVerifier`'s
/// `CERT_SIZE` const generic. 8 KiB comfortably covers a leaf plus one or
/// two intermediate certs (real chains commonly run 2-4 KiB); a chain that
/// doesn't fit is rejected outright (`HandshakeError::InsufficientSpace`),
/// never silently truncated.
pub const MAX_CHAIN_DER_LEN: usize = 8192;

/// Raw DER bytes of a trust-anchor (CA) certificate a caller supplies to
/// [`TlsConnection::open`]. Trust-anchor *provisioning* (a real,
/// build-time-signed set mirroring `citadel-integration`'s
/// `BootAllowlist`) is still unbuilt — see this crate's top-level doc
/// comment — so today a caller must already have these bytes from
/// somewhere. A sharper limit worth naming explicitly:
/// `embedded_tls::pki::CertVerifier` verifies against exactly **one** CA
/// per connection (see its own `new` constructor, which takes a single
/// `Certificate`), not a root store — a real multi-root trust store needs
/// either one connection attempt per candidate root or an upstream change
/// to this crate's dependency, neither of which exists yet.
pub type CertificateDer<'a> = &'a [u8];

struct Provider<'a, E: Entropy> {
    entropy: EntropyRng<E>,
    verifier: CertVerifier<'a, CipherSuite, NoClock, MAX_CHAIN_DER_LEN>,
}

impl<E: Entropy> CryptoProvider for Provider<'_, E> {
    type CipherSuite = CipherSuite;
    // Never actually constructed — `signer()` keeps the trait's default
    // (`Err(Unimplemented)`), so this type only needs to satisfy
    // `AsRef<[u8]>` to typecheck, not hold a real signature.
    type Signature = [u8; 0];

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        &mut self.entropy
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, HandshakeError> {
        Ok(&mut self.verifier)
    }
}

/// A TLS 1.3 client connection over a caller-supplied [`Transport`]. See
/// this module's doc comment for what's deliberately not supported yet
/// (wall-clock cert-expiry checking, client certificates, multi-root trust
/// anchors).
pub struct TlsConnection<'buf, T: Transport, Y: Yield> {
    inner: embedded_tls::blocking::TlsConnection<'buf, BlockingIo<T, Y>, CipherSuite>,
}

impl<'buf, T: Transport, Y: Yield> TlsConnection<'buf, T, Y> {
    /// `record_read_buf`/`record_write_buf` must each be sized to hold one
    /// full TLS record — see `embedded_tls::blocking::TlsConnection::new`'s
    /// own doc comment for the exact sizing rule (up to 16640 bytes for a
    /// maximal record; the larger of the two buffers is what encodes the
    /// handshake, so at least one must be handshake-sized). Sizing these
    /// for a real process means a real kernel-side heap-grant change — see
    /// this crate's own doc comment on why that's still open.
    pub fn new(
        transport: T,
        yielder: Y,
        record_read_buf: &'buf mut [u8],
        record_write_buf: &'buf mut [u8],
    ) -> Self {
        Self {
            inner: embedded_tls::blocking::TlsConnection::new(
                BlockingIo::new(transport, yielder),
                record_read_buf,
                record_write_buf,
            ),
        }
    }

    /// Performs the TLS 1.3 handshake, verifying the server's certificate
    /// chain against `trust_anchor` via `rustpki`'s real `CertVerifier` —
    /// never the crate's permissive default. `server_name` drives both SNI
    /// (sent to the server) and hostname verification (checked against the
    /// certificate's CN/SAN entries by `CertVerifier` itself).
    pub fn open(
        &mut self,
        config: &Config,
        trust_anchor: CertificateDer<'_>,
        entropy: impl Entropy,
    ) -> Result<(), HandshakeError> {
        let mut provider = Provider {
            entropy: EntropyRng(entropy),
            verifier: CertVerifier::new(Certificate::X509(trust_anchor)),
        };
        self.inner.open(TlsContext::new(config, &mut provider))
    }

    /// Encrypts and sends `buf` — see `embedded_tls::blocking::TlsConnection::write`'s
    /// own doc comment: bytes may be buffered internally; call [`Self::flush`]
    /// to force them out.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, HandshakeError> {
        self.inner.write(buf)
    }

    pub fn flush(&mut self) -> Result<(), HandshakeError> {
        self.inner.flush()
    }

    /// Reads and decrypts application data into `buf`.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, HandshakeError> {
        self.inner.read(buf)
    }
}

//! Bridges this crate's own [`crate::Entropy`] (a fallible,
//! `SYS_RANDOM`-shaped `Option<u64>` source) to `rand_core::RngCore` +
//! `CryptoRng`, which is what `embedded_tls::CryptoProvider::rng()` actually
//! requires (`embedded-tls` re-exports `rand_core::{CryptoRng,
//! CryptoRngCore}` directly — `CryptoRngCore` has a blanket impl for
//! anything implementing both, so implementing these two is sufficient).

use crate::Entropy;
use core::num::NonZeroU32;
use rand_core::{CryptoRng, Error, RngCore};

pub(crate) struct EntropyRng<E>(pub(crate) E);

impl<E: Entropy> EntropyRng<E> {
    /// The one place this crate actually fails closed on exhausted/denied
    /// entropy: `RngCore::fill_bytes`'s signature is infallible (per its own
    /// doc comment, "may panic if this is impossible" is the sanctioned
    /// response), and `embedded_tls`'s own internal key-generation paths
    /// call the infallible methods, not [`RngCore::try_fill_bytes`] — so a
    /// silent fallback here would be the one place this crate's whole
    /// fail-closed entropy story could quietly stop mattering. Panicking
    /// mid-handshake is the correct behavior, not a bug: proceeding with a
    /// TLS handshake using anything other than real entropy for ephemeral
    /// key material is worse than crashing.
    fn next_u64_or_panic(&mut self) -> u64 {
        self.0
            .next_u64()
            .expect("SYS_RANDOM denied or exhausted mid-TLS-handshake — failing closed")
    }
}

impl<E: Entropy> RngCore for EntropyRng<E> {
    fn next_u32(&mut self) -> u32 {
        self.next_u64_or_panic() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u64_or_panic()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64_or_panic().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        for chunk in dest.chunks_mut(8) {
            let Some(value) = self.0.next_u64() else {
                // No-`std` `rand_core::Error` construction — see that
                // type's own doc comment: `From<NonZeroU32>` is the only
                // constructor available without `std`. `CUSTOM_START` is
                // the documented start of the range reserved for a caller's
                // own error codes, which this is.
                return Err(Error::from(
                    NonZeroU32::new(Error::CUSTOM_START).expect("CUSTOM_START is nonzero"),
                ));
            };
            let bytes = value.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// Marker trait, no methods to implement — see `rand_core::CryptoRng`'s own
/// doc comment on what asserting this actually promises (this crate can't
/// verify it, only assert it; `SYS_RANDOM` is RDRAND-backed, a real hardware
/// CSPRNG source when present, see `kernel/src/entropy.rs`).
impl<E: Entropy> CryptoRng for EntropyRng<E> {}

#![no_main]

use ed25519_dalek::{SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use runix_capability_manager::CapabilityToken;

// Fixed, not `OsRng`-random: libFuzzer re-runs this target millions of
// times per session, and the property under test (no panic, ever) doesn't
// need a fresh keypair each time — a deterministic keypair keeps a crash
// reproducible against the exact same "genuine" signature it was tampered
// against.
const SEED: [u8; 32] = [7u8; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let signing_key = SigningKey::from_bytes(&SEED);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    // libFuzzer only hands us one raw byte slice — split it three ways so
    // the same properties `capability-manager/src/lib.rs`'s
    // `tests::properties` proptest module already checks (arbitrary
    // `now`/`resource`/`signature`) get corpus-driven coverage too, not
    // just randomized generation.
    let mut now_bytes = [0u8; 8];
    now_bytes.copy_from_slice(&data[..8]);
    let now = u64::from_le_bytes(now_bytes);
    let rest = &data[8..];
    let split = rest.len() / 2;
    let resource = String::from_utf8_lossy(&rest[..split]).into_owned();
    let signature = String::from_utf8_lossy(&rest[split..]).into_owned();

    let mut token = CapabilityToken::issue("subject", "resource", 0, 100, "key:1", &signing_key);
    token.signature = signature;

    // The actual property: no byte pattern, however malformed, may panic
    // `verify()` — including its `hex::decode(&self.signature)` call, the
    // exact spot docs/THREAT_MODEL.md's testing-rigor gap named as
    // unfuzzed. A reachable panic here is a denial-of-service on the
    // capability gate itself in a `panic = "abort"` kernel.
    let _ = token.verify(&verifying_key, &resource, now);
});

//! CITADEL runtime stub (L5 desktop / L4 mobile). Alpha scope is a stub only
//! — the real integration (MARSHAL boot evaluation, WORM chain, VIGIL health
//! checks) is a Beta/RC item once `opensecstack/sdk/rust` gets a MARSHAL/WORM
//! client (it doesn't have one yet — only `webhook.rs`'s HMAC verification).
//!
//! MARSHAL's actual gate order, per `citadel/docs/marshal-engine.md` and the
//! Go implementation (`citadel/internal/marshal/marshal.go`), is
//! **AuthN → AuthZ → NDS → AUGUR → WORM**. The desktop marketing site's
//! `marshalGates.ts` (Authority/Scope/Determinism/Evidence/Schema) is a
//! stale/aspirational naming with no implementation behind it — do not build
//! against it. VIGIL is also unimplemented upstream as of CITADEL v1.0.0
//! (design-stage only per `citadel/docs/vigil.md`), so any VIGIL binding
//! here is speculative until that lands.

#[derive(Debug, thiserror::Error)]
pub enum CitadelError {
    #[error("CITADEL integration not yet implemented")]
    Unimplemented,
}

pub struct CitadelRuntimeStub;

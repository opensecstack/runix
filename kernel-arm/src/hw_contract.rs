//! Small pure helpers for two hardware/loader contracts, kept in the lib
//! target so `cargo test --lib` can reach them (the code that applies them,
//! `mmu::install` and `net_process::setup`, is binary-only).

/// `SCTLR_EL1.M`: stage 1 MMU enable.
pub const SCTLR_M: u64 = 1 << 0;

/// `SCTLR_EL1.nTWE` (bit 18): when 0, an EL0 `wfe` traps to EL1 (EC 0x01)
/// instead of waiting. EL0 payloads (`net-driver-host-arm`'s panic handler
/// and the tail of `_start`, `el0_demo`, `el0_proof`'s payload) idle with
/// `wfe`, so this must be 1 or "idle forever" becomes a trap. Architecturally
/// the reset value is UNKNOWN, so it cannot be left to the core.
///
/// `nTWI` (bit 16) is deliberately not set: no EL0 code in this workspace
/// executes `wfi`.
pub const SCTLR_NTWE: u64 = 1 << 18;

/// The `SCTLR_EL1` value `mmu::install` writes: `current` with the MMU
/// enabled and EL0 `wfe` permitted. Only ORs bits in; every other bit of
/// `current` (including whatever the core reset to) is preserved.
pub const fn sctlr_with_mmu_and_el0_wfe(current: u64) -> u64 {
    current | SCTLR_M | SCTLR_NTWE
}

/// `net-driver-host-arm::NetBootInfo::mode` values.
pub const NET_MODE_TCP_PROOF: u64 = 0;
pub const NET_MODE_MARSHAL_REQUEST: u64 = 1;

/// Loader contract: `NetBootInfo.mode == MarshalRequest` exactly when request
/// bytes are supplied (only then are `MARSHAL_REQUEST_VA`/`MARSHAL_RESPONSE_VA`
/// mapped; the EL0 driver faults on first access otherwise). An unknown mode
/// is also rejected. Returns the error text for the loader's error path.
pub const fn check_net_mode(mode: u64, has_request_bytes: bool) -> Result<(), &'static str> {
    match (mode, has_request_bytes) {
        (NET_MODE_TCP_PROOF, false) | (NET_MODE_MARSHAL_REQUEST, true) => Ok(()),
        (NET_MODE_MARSHAL_REQUEST, false) => {
            Err("net boot info mode is MARSHAL-request but no request bytes were supplied")
        }
        (NET_MODE_TCP_PROOF, true) => {
            Err("net boot info mode is TCP-proof but request bytes were supplied")
        }
        _ => Err("net boot info has an unknown mode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sctlr_only_adds_m_and_ntwe() {
        // QEMU's cortex-a53 resets SCTLR_EL1 to 0x00C5_0838, which already has
        // nTWE set, so clear it: otherwise this test could not notice a helper
        // that forgot to set the bit.
        let reset = 0x00C5_0838u64 & !SCTLR_NTWE;
        assert_eq!(reset & SCTLR_NTWE, 0);
        let v = sctlr_with_mmu_and_el0_wfe(reset);
        assert_eq!(v & !(SCTLR_M | SCTLR_NTWE), reset & !(SCTLR_M | SCTLR_NTWE));
        assert_eq!(v & SCTLR_NTWE, SCTLR_NTWE);
        assert_eq!(v & SCTLR_M, SCTLR_M);
        assert_eq!(SCTLR_NTWE, 0x4_0000);
    }

    #[test]
    fn sctlr_preserves_all_other_bits_and_is_idempotent() {
        for cur in [0u64, u64::MAX, 0x1234_5678_9abc_def0] {
            let v = sctlr_with_mmu_and_el0_wfe(cur);
            assert_eq!(v & cur, cur);
            assert_eq!(sctlr_with_mmu_and_el0_wfe(v), v);
        }
        assert_eq!(sctlr_with_mmu_and_el0_wfe(0), 1 | (1 << 18));
    }

    #[test]
    fn net_mode_must_match_request_bytes() {
        assert!(check_net_mode(0, false).is_ok());
        assert!(check_net_mode(1, true).is_ok());
        assert!(check_net_mode(1, false).is_err());
        assert!(check_net_mode(0, true).is_err());
        assert!(check_net_mode(2, true).is_err());
        assert!(check_net_mode(u64::MAX, false).is_err());
    }
}

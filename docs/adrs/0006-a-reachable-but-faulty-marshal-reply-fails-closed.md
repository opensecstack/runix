# 0006: A reachable but faulty MARSHAL reply fails closed

**Status**: Accepted 2026-10-12. Refines
[0003](0003-unreachable-marshal-policy-is-per-action.md).

## Context

ADR 0003 made the "MARSHAL is unreachable" policy a per-action table
(`MarshalAction::unreachable_policy()`): `data.reset_usage` fails closed, and
`esim.enable`, `esim.delete`, `mvno.bind_profile`, `mvno.suspend_account` and
`mvno.reactivate_account` fail open. [ADR 0008](0008-esim-delete-and-mvno-reactivate-fail-closed-when-marshal-unreachable.md)
has since moved `esim.delete` and `mvno.reactivate_account` to fail closed, so only
`esim.enable`, `mvno.bind_profile` and `mvno.suspend_account` now fail open. Its fail-open reasoning is the bootstrap
deadlock: enabling an eSIM profile can be what provides the connectivity needed to
reach the gate, so a phone cannot ask first.

That reasoning only covers being unable to reach the gate. Both kernels, however,
classified every reply that was not a decoded Decision as `Unreachable`, including
replies that prove the proxy and the network were reached: a `200` with a
non-JSON or empty body, a bad content-length, a non-403 HTTP error such as 400 or
500, or a `403` whose body is not a `REFUSE`/`HARD_STOP` Decision (including
`403` with `EXECUTE`). On the wire these are `MarshalError::BadResponse` and
`MarshalError::Other` (`ipc/src/marshal.rs`). Treating them as an outage meant a
CITADEL, or anything able to make it answer badly, could turn the gate off for the
fail-open actions (and for `grid_sandbox::spawn_instance` on x86) simply by
answering with garbage. No bootstrap argument applies: the gate was reached and
the connectivity exists.

## Decision

1. **A reached-but-faulty reply is its own outcome, `ShadowMarshalOutcome::Faulty`**
   (`citadel-integration/src/lib.rs`). `MarshalError::BadResponse` and
   `MarshalError::Other` classify to it, on ARM
   (`marshal_action::classify_response`) and on x86
   (`grid_sandbox::shadow_marshal_evaluate`).
2. **`Faulty` blocks, under every policy.** All six mobile actions (`esim.enable`,
   `esim.delete`, `mvno.bind_profile`, `mvno.suspend_account`,
   `mvno.reactivate_account`, `data.reset_usage`) and x86
   `grid_sandbox::spawn_instance` (`MarshalEnforcementError::FaultyReply`) are
   denied regardless of the per-action unreachable table.
3. **The denial is the kernel's own and is audited.** Text:
   `DENIED (MARSHAL faulty reply: fail-closed)`; serial evaluation line
   `...: Faulty`; WORM entry `authorized=false`, like the fail-closed-unreachable
   denial (unlike `Refuse`/`HardStop` on mobile, which were not audited at the time;
   superseded by [0009](0009-bounded-worm-chain-and-denial-auditing.md) on this point). The data
   reset returns `RESET_DENIED_FAULTY = 11` (`kernel-arm/src/data_codes.rs`).
4. **The unreachable table is unchanged.** Genuinely unreachable cases (no proxy,
   no network device, connect failure `MarshalError::Unreachable`,
   `MarshalError::Timeout`, and a kernel-to-proxy `ipc` reply that is empty or
   merely incomplete when the wait budget ends) keep ADR 0003's per-action
   behaviour, pinned by the test `unreachable_policy_table_is_pinned`. `Refuse`,
   `HardStop`, `PolicyRefused` and local failures are unchanged.
5. **Malformed reply bytes are `Faulty` too.** `MarshalResponse::decode` returned
   `None` both for "not enough bytes yet" and for bytes that can never be a valid
   response, and both kernels classified the final `None` as `Unreachable`, so a
   garbled real `REFUSE` (or any malformed bytes) was fail-open for the five
   fail-open actions. `runix_ipc::marshal::MarshalResponse::decode_status` now
   returns `Complete`, `Incomplete` or `Malformed`. `Malformed` (unknown response
   tag, unknown outcome byte, unknown error kind, a declared length over
   `MAX_JSON_LEN` / `MAX_MESSAGE_LEN`, a non-UTF-8 message) is monotone (no later
   byte can repair it) and is decided as soon as the offending byte is present;
   every proper prefix of a valid encoding stays `Incomplete`. Both kernels map
   `Malformed` to `Faulty` (x86 as `Error(BadResponse)` from
   `marshal_client::recv_marshal_response`, ARM via `classify_decode`), with the
   same blocking and WORM audit as decision 3. `decode` is unchanged.

## Consequences

Better:

- A reachable CITADEL answering garbage can no longer admit an action. The class
  of "answered, but not with a Decision" is no longer silently equal to "down".
- The audit trail distinguishes `Faulty` from `Unreachable`.

Worse, or left open:

- **Availability hazard.** Every Runix request is `dry_run:true`. CITADEL's
  documentation describes a production setting, `CITADEL_DRY_RUN_ALLOWED=false`,
  under which a dry-run Kerkese is answered HTTP 400. The CITADEL source audited
  for [ADR 0007](0007-dry-run-true-stays-until-operator-identity.md) does not
  implement that setting, so this is a possible hazard, not a demonstrated one.
  If a deployment does enforce it, the 400 is a faulty reply, so every gated
  action is blocked, loudly, where it used to be silently allowed. A CITADEL
  outage that yields 5xx does the same. Deployments should confirm their CITADEL
  accepts dry-run Kerkese requests before enabling the gate.
- **Malformed bytes now fail closed; silence still does not.** A kernel-to-proxy
  reply that is merely incomplete when the wait budget is exhausted (silence, a
  stall, a connection closed mid-message) is a real timeout and stays
  `Unreachable` by design, so for the fail-open actions it still admits the
  action (after [0008](0008-esim-delete-and-mvno-reactivate-fail-closed-when-marshal-unreachable.md):
  `esim.enable`, `mvno.bind_profile`, `mvno.suspend_account`; `esim.delete` and
  `mvno.reactivate_account` now deny). The link is unauthenticated, so an attacker
  who controls it can still stall (timeout, so fail-open for those three, bounded only by the proxy
  hardening below) or forge a well-formed reply: for example six zero bytes decode
  as `Decision(Execute)`. Failing closed on malformed bytes only removes the
  accidental bypass; the real fix is authenticating the link.
- **Starvation residual.** `citadel_proxy` is now bounded (a 20 s idle allowance
  before the first request byte, then a 3 s total deadline for the rest of the frame, 2 s write timeout, at most 8 concurrent connections, excess closed
  immediately, oversized declared length rejected on the 4-byte prefix; CITADEL
  HTTP connect 1 s, total 3 s, a timeout being `MarshalError::Timeout`). Default
  listen address is `127.0.0.1:9000`. An attacker who can reach the listener (a
  local process, or the guest through QEMU guestfwd) can still hold 8
  connections open and reopen them every ~20 s, starving legitimate requests,
  which the kernel reads as unavailable and so fail-open for the three actions that
  still fail open (see 0008). There
  is no per-peer limit. The real fix is controlling who can reach the listener
  or authenticating the link.
- The verdict is still unauthenticated and `dry_run` is still `true`; this
  change does not make an `Execute` a live approval.
- **The x86 kernel client cannot detect a closed connection.** If the proxy
  closes the connection without replying, `net-driver-host` keeps answering the
  kernel's receive with an empty `Data` (it never reports EOF, because the socket
  stays open in CloseWait), which the client reads as "nothing yet" and so waits
  out its whole poll budget (2,000,000 polls in `marshal_client.rs`), effectively
  unbounded in a test. A prompt `Unreachable` would need `net-driver-host` to
  report EOF and the `ipc::sockets` wire format to carry it. `kernel-arm` is
  bounded (64 yields). This is why a stalled or dropped request looks like a hang,
  not a failure; CI bounds the `marshal_proxy_e2e` step with a timeout and prints
  the proxy's stderr for that reason.

## Alternatives considered

- **Fail-closed except `esim.enable`.** Keeps the bootstrap exception. Rejected: the
  bootstrap argument is about reaching the gate, and a faulty reply shows the gate
  was reached, so the exception has no basis here; it would also leave a
  garbage-reply bypass for the action that switches the active subscription.
- **Leave as is.** Rejected: any reply that is not a valid Decision, including
  a CITADEL bug or a hostile in-path party, would disable the gate for five
  actions, which is the bypass lever ADR 0003 set out to remove for the reset.

## Revisit when

- The kernel-to-proxy link is authenticated; then reconsider whether an
  incomplete reply at budget end should still be `Unreachable`.
- A CITADEL deployment is found that answers dry-run requests with a non-403
  error (for example one that enforces the documented `CITADEL_DRY_RUN_ALLOWED=false`,
  see [ADR 0007](0007-dry-run-true-stays-until-operator-identity.md)), which would
  make this blocking unusable there.
- The maintainers decide any open row of ADR 0003's table, or a bootstrap exception
  or offline grant is designed.
- A per-peer limit or restriction on who may reach the proxy listener exists.

## References

- `ipc/src/marshal.rs` (`MarshalResponse::decode_status`, `ResponseDecode`)
- `kernel/src/marshal_client.rs` (`recv_marshal_response`)
- `kernel-arm/src/marshal_action.rs` (`classify_response`, `classify_decode`, `enforce`)
- `kernel-arm/src/data_codes.rs` (`RESET_DENIED_FAULTY`)
- `kernel/src/grid_sandbox.rs` (`MarshalEnforcementError::FaultyReply`)
- `citadel-integration/src/lib.rs` (`ShadowMarshalOutcome::Faulty`)
- `desktop/src/citadel/proxy.rs` (`ProxyLimits`), `desktop/src/citadel/transport.rs`
- `kernel/tests/grid_sandbox_marshal_shadow.rs` (case 2b, `shadow-faulty`; case 2c,
  `shadow-malformed`)
- `.github/workflows/ci.yml` (the garbage 200 / HTTP 500 ARM boot step, and the
  malformed-reply ARM boot step)
- [0003](0003-unreachable-marshal-policy-is-per-action.md),
  `docs/MARSHAL-ENFORCEMENT-POLICY.md`, `docs/STATUS.md` "MARSHAL gate for mobile"

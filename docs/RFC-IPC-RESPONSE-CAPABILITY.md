# RFC: capability-scoping the *receive* side of IPC

**Status**: proposal for repo owner review. No code written yet. This is the
gate before any fix for `docs/THREAT_MODEL.md`'s "`SYS_IPC_RECV` has
no capability check" finding, and before any code that assumes response
confidentiality on this IPC layer is built — which
`docs/RFC-TLS-APPROACH.md` already names as a dependency of its own
recommendation.

## Context

CLAUDE.md's capability-security rule is "never reach for a resource with
ambient authority — route access through `capability-manager` tokens." The
filesystem IPC surface obeys that rule in one direction and violates it in
the other.

**Asking is gated.** `blk-driver-host/src/main.rs`'s
`handle_read_ipc_request`/`handle_write_ipc_request` each take a
`&CapabilityToken` and verify it against a `file:<name>` resource before
touching the device, on top of the coarser `port:<n>` grant the kernel's
`SYS_IPC_SEND` gate already enforces (`kernel/src/syscall.rs`'s
`authorized_for_port`). The token travels inside the request itself
(`ipc/src/fs.rs`: `FsRequest::Read { name, token }`).

**Answering is not.** The reply goes out over one fixed port shared by every
client:

```rust
// blk-driver-host/src/main.rs
fn send_fs_response(response: &FsResponse) {
    for byte in response.encode() {
        let _ = syscall::ipc_send(FS_RESPONSE_PORT, byte);
    }
}
```

`FS_RESPONSE_PORT` is the constant `9`, agreed by convention with
`kernel/src/main.rs`'s `BLK_FS_RESPONSE_PORT`. And the receive side of
the kernel is one line, with no check of any kind:

```rust
// kernel/src/syscall.rs
SYS_IPC_RECV => ipc::try_recv(arg1 as usize).map_or(u64::MAX, u64::from),
```

Compare `SYS_IPC_SEND`, `SYS_IPC_SEND_LOCK` and `SYS_IPC_SEND_UNLOCK`, which
all call `authorized_for_port` first, verified: each is guarded by
`if !authorized_for_port(port) { return u64::MAX; }`.
`SYS_IPC_RECV` is the only IPC syscall in the table with no gate, and
`blk-driver-host/src/syscall.rs` documents that asymmetry rather than
assuming it away ("No capability check on the receive side (matching
`kernel/src/syscall.rs`'s real behavior today)").

The consequence is the finding: **any process that can issue `SYS_IPC_RECV`
on port 9 can drain another client's file contents**, whether or not it ever
held a `file:<name>` token. `kernel/src/ipc.rs`'s `try_recv` is a
`VecDeque::pop_front` on a shared queue — first caller to ask wins the byte.
The per-file token gates the question, not the answer. That is ambient
authority on the read path, arrived at by omission rather than by decision.

Three properties of the actual implementation constrain every fix below, and
each was verified against the code rather than assumed:

1. **Ports are a fixed array of 16, allocated statically at module init.**
   `kernel/src/ipc.rs`'s `PORT_COUNT: usize = 16`, `CHANNEL_CAPACITY: usize
   = 32`, and a `lazy_static!` building `[Mutex<Channel>; 16]` plus
   `[Mutex<bool>; 16]` for the send locks. There is no allocate-a-port call
   anywhere. Port numbers are compile-time constants duplicated on both
   sides of the kernel/ring-3 boundary by convention, not negotiated:
   `8`/`9`/`10` for the filesystem (`blk-driver-host/src/main.rs`),
   `11`/`12` for sockets (`net-driver-host/src/main.rs`). Ports `3`-`7` and
   `13`-`15` are unused today; `0`-`2` are boot-demo ports.
2. **The channel has no framing.** A `Channel` is `queue: VecDeque<u8>` and
   nothing more. The kernel has no concept of a message, a sender, or a
   recipient — the per-port advisory send lock (`begin_send`/`end_send`)
   exists precisely *because* the kernel cannot tell one sender's bytes
   from another's, and closes the interleaving hazard with mutual exclusion
   rather than with identity. That earlier fix is the right precedent for
   shape (extend the port model with a small, explicit primitive) and also
   the right warning about what it did *not* buy: exclusion is not
   attribution.
3. **The kernel has no process identity.** `struct Thread`
   (`kernel/src/scheduler.rs`) has a guard page, a stack pointer,
   `capability`, `extra_capabilities`, an optional `AddressSpace`, and an
   optional kernel entry stack. There is no thread id, no pid, nothing
   stable a channel could be addressed to. The only identity a running
   thread has today is *the set of tokens it holds*
   (`current_capability`/`current_extra_capabilities`).

`net-driver-host` has the sibling shape of the same gap: `ipc/src/sockets.rs`
says the wire format "alone can't distinguish *which caller* opened a given
handle when multiple processes share the same fixed request/response ports —
see `net-driver-host/src/main.rs`'s `run_socket_ipc_server` doc comment for
that scoping caveat and why the capability gate is on the *port*, not the
handle."

**Scope opinion, stated rather than gestured at: this is one problem, not
two, and it should be fixed once in the IPC layer.** Both drivers have a
fixed request port, a fixed response port shared by all clients, an
in-band token or handle that names a resource, and no way to bind either to
a caller — because the layer underneath them has no caller to bind to.
Fixing it per-driver would mean writing the same attribution logic twice, in
two freestanding binaries that share no code, for the same missing kernel
primitive. The two surfaces do differ in one respect worth keeping in view:
`blk-driver-host`'s exposure is *confidentiality of a response already
computed*, while `net-driver-host`'s is additionally *authority over a
long-lived handle* (`SocketRequest::{Connect,Send,Recv,Close}` all name a
handle any caller could name). A fix that gives responses a per-client
destination solves the first outright and is a necessary precondition for
the second, but the sockets handle table still needs its own
owner-of-this-handle check on top. One RFC, one primitive, one extra
driver-local check in `net-driver-host`.

## Options

### Option A: per-client response ports, authorized by a second token, plus a symmetric receive-side gate

**Design**: two changes that only work together.

*Kernel side*: `SYS_IPC_RECV` calls `authorized_for_port` exactly as
`SYS_IPC_SEND` does, against the same `port:<n>` resource
(`kernel/src/capabilities.rs`), returning `u64::MAX` on denial — the
same indistinguishable-failure convention the rest of the ABI uses. This is
a handful of lines and makes the receive side stop being an ambient-authority
hole in the abstract: a process with no token for port 9 can no longer read
port 9 at all.

*Driver side*: that alone does not separate two clients who both legitimately
hold `port:9`, so the response port stops being one shared constant. Each
client is spawned with a capability for its *own* response port (one of the
free slots, `3`-`7`/`13`-`15`), and `FsRequest` gains a response-port field
plus a second token scoped to that port. `blk-driver-host` already links
`capability-manager` and already verifies file tokens per request, so it can
verify the response-port token with the same verifying key and refuse to
answer on a port the requester cannot prove it owns. A client cannot name
someone else's response port, because it cannot produce a signed token for
it.

**Why it survives contact with the code**: nothing here needs dynamic port
allocation, a new syscall, message framing, or thread identity. The ports
already exist in the static array; the capability convention already exists;
the driver already does token verification per request. It is the smallest
change that actually delivers "only the client that asked receives the
answer."

**Cost, honestly**: it does not scale past a handful of clients — 16 ports
total, 8 already spoken for, so this supports roughly 8 capability-separated
clients *across the whole system*, shared with `net-driver-host`'s needs.
Raising `PORT_COUNT` is a one-constant change but every port is a
permanently-allocated `Mutex<Channel>` plus `Mutex<bool>`, so the array is a
fixed cost paid at boot whether or not the ports are used. Client-to-
response-port assignment becomes a spawn-time decision in
`kernel/src/main.rs`, which means the set of possible clients is fixed at
build time — fine for Alpha, wrong the moment a dynamically-launched T3
module wants a file. It also widens the `ipc` wire format (a
cross-boundary-payload change, so it belongs in the typed `ipc` crate per
CLAUDE.md, which it does) and adds a second `CapabilityToken` to every
request — and a token is already over a kilobyte encoded
(`kernel/src/ipc.rs`), against a 32-byte channel, so request latency
roughly doubles on a path that T1's <300ms MARSHAL budget also has to fit
inside.

### Option B: correlation IDs in the wire format, enforced by the kernel at `SYS_IPC_RECV`

**Design**: the client generates a session/correlation id, the driver echoes
it on the response, and `SYS_IPC_RECV` only dequeues bytes belonging to a
message tagged with an id the calling thread holds a valid token for.

**This does not survive contact with `kernel/src/ipc.rs`, and the reason is
structural rather than effortful.** A `Channel` is a `VecDeque<u8>`; `try_recv`
pops one byte. There is no message the kernel could read a tag off, because
there are no messages — there is a byte queue that two ring-3 processes have
agreed to interpret. To enforce a correlation id the kernel would have to
parse `FsResponse`'s encoding (`ipc/src/fs.rs`), or a framing header layered
beneath it, which means either (a) the kernel links `runix-ipc` and learns
the filesystem wire format — putting `blk-driver-host`'s protocol inside the
privileged microkernel, and then `net-driver-host`'s next to it, for every
future service — or (b) a generic length-prefix-plus-id frame is added to
`Channel`, which is most of Option C's work with none of Option C's payoff.
Option (a) is the layering violation this RFC was asked to judge:
unacceptable, not marginal. This is an L1 microkernel whose entire claim is
that services live in user space; the byte-channel's ignorance of payload is
the property that keeps it small. And it would be new parsing of
attacker-influenced bytes on a `panic = "abort"` privileged path, which
CLAUDE.md's `unsafe`/kernel rule treats as a security-bug class, not a
crash-risk class.

**Listed and rejected**, not carried forward. The one idea worth salvaging
from it: a correlation id in the *wire format*, enforced entirely by the
driver, is cheap and worth having for request/response matching hygiene —
but it is not a security control, because a hostile receiver drains bytes off
the shared queue before any driver-level check can run.

### Option C: a real session/handle IPC primitive

**Design**: the abstraction `docs/THREAT_MODEL.md` gestures at, given
an actual shape.

Three kernel-side pieces. First, `Thread` gets a stable identity — a
monotonic `ThreadId` assigned in `Thread::new`, which it does not have today
(`kernel/src/scheduler.rs`). This is small in isolation and is the
piece everything else needs. Second, `ipc.rs` gains a dynamic channel table
alongside the fixed 16: a `Mutex<BTreeMap<SessionId, Session>>` where a
`Session` is a `VecDeque<u8>` plus an `owner: ThreadId` plus a `server:
ThreadId`. The fixed array stays exactly as it is — boot demos, the existing
request ports, and every current test keep working unchanged, the same
additive discipline `extra_capabilities` followed when `Thread` needed a
second capability. Third, three syscalls: `SYS_IPC_SESSION_OPEN` (a client
presents a token for a server's *request* port, the kernel mints a session,
records the caller's `ThreadId` as owner, and returns the `SessionId` in
RAX), and `SYS_IPC_SESSION_SEND`/`SYS_IPC_SESSION_RECV`, which check that
the calling thread is the session's owner or its server before touching the
queue. The client learns its session id from a register, so nothing has to
be negotiated in-band. The server learns which session a request arrived on
from the syscall, so `blk-driver-host` replies into that session rather than
onto a shared port, and `net-driver-host` can finally bind a socket handle
to a session owner — closing `ipc/src/sockets.rs`'s caveat with the
same primitive rather than a second one.

The check at recv time is then an ownership comparison on kernel-owned state,
not content inspection: the kernel still never looks at a byte's meaning.
That is the difference between C and B, and it is the whole reason C is
acceptable where B is not.

**Cost, honestly**: this is the largest of the three by a wide margin, and it
lands in the most safety-critical crate in the repo. It needs per-session
send locks (or a per-session equivalent of `begin_send`/`end_send` —
the interleaving hazard does not disappear just because the channel is
private, since a server and a client both write to it), a teardown story
(sessions must be reaped when either endpoint exits, or a long-running
system leaks them — and `reap_zombies` currently has no session concept), a
bound on sessions per thread so a hostile client cannot exhaust kernel
memory by opening sessions in a loop, and a decision about whether
`SessionId`s are reused (they must not be, or a stale id becomes a
confused-deputy handle). It also forces a real decision about how a
`ThreadId` relates to a token's `subject` field (`capability-manager/src/lib.rs`),
which today is signed but never checked against anything — see Open
Questions. Every existing test touching IPC should keep passing untouched,
which is a genuine advantage of the additive shape, but the new primitive
needs its own QEMU-native proofs in the `kernel/tests/blk_fs_concurrent.rs`
mould: two clients, interleaved, each receiving exactly its own bytes and
provably never the other's.

## Recommendation

**Option A now, as an explicitly-time-boxed step, with Option C as the
declared destination and a written trigger for moving to it. Option B
rejected outright.**

Reasoning:

1. **The receive-side gate in Option A is unconditionally correct and should
   land regardless of which option wins.** `SYS_IPC_RECV` being the one IPC
   syscall with no capability check is an asymmetry with no defender —
   `SYS_IPC_SEND_UNLOCK` already got a check on a *subtler* argument. Under
   Option C the same check protects the legacy fixed ports that will keep
   existing. It is never wasted work.
2. **Option A is buildable against the kernel as it actually is**, with no
   new syscall, no dynamic allocation, and no new kernel-side state — using
   three mechanisms (static ports, the `port:<n>` convention, driver-side
   token verification) that all exist and are all already tested.
3. **Option A's ceiling is low and visible, which is what makes it safe to
   take.** It runs out at roughly eight capability-separated clients and
   requires every client to be known at build time. That is not a subtle
   limitation that could quietly calcify; it is a wall someone hits on a
   specific, predictable day.
4. **Option C is the right architecture and the wrong thing to start with
   today.** It is a genuine redesign of the most privileged crate in the
   tree, and it depends on a thread-identity primitive that does not exist.
   Building thread identity *first*, on its own, is a strictly smaller and
   independently valuable piece of work — and it is what makes Option C a
   design rather than a name-drop.
5. **The trigger for moving to C should be written down now, not discovered
   later.** Move when any one of: a dynamically-spawned (rather than
   boot-time-known) process needs a capability-separated response; free port
   slots drop below two; or `net-driver-host` needs real per-handle owner
   attribution rather than per-port. The third is the most likely to fire
   first, because the sockets surface hands out long-lived handles that
   Option A does not scope at all.

One thing Option A must not be allowed to do is *look* like it closed the
whole finding. It closes response confidentiality for a fixed, small,
build-time-known set of clients. It does not give the system caller identity,
and `docs/THREAT_MODEL.md`'s entry should be amended rather than deleted.

## What changes under Option A (prose only — no code written yet)

- `kernel/src/syscall.rs`'s `SYS_IPC_RECV` arm stops being a bare
  `ipc::try_recv` and gains the same `authorized_for_port` check the three
  send-side syscalls already share, with the same `u64::MAX`-on-denial
  convention and a doc comment explaining that receiving from a port is a
  privilege distinct from sending to it, not a symmetry nicety. The constant
  block's comments need updating too: the table is currently described in a
  way that leaves the recv gap implicit.
- Every existing `SYS_IPC_RECV` caller must be audited for whether it holds a
  token for the port it reads, because after this change an unauthorized
  receive silently returns "empty" — indistinguishable from a port with
  nothing queued, which is correct for a hostile caller and confusing for a
  legitimate one that was never granted a token. `blk-driver-host` reads
  `FS_REQUEST_PORT` and `FS_WRITE_REQUEST_PORT` and is currently spawned with
  tokens for its device range and its *response* port
  (`kernel/src/main.rs`) — it will need request-port receive tokens it does
  not hold today, or it stops serving the moment this lands. The same audit
  applies to `net-driver-host`, `grid-sandbox-host`, and every kernel test
  that receives. This is the change's real risk and should be treated as a
  cross-crate contract change per CLAUDE.md's restart-checklist rule: check
  both sides before continuing.
- `blk-driver-host/src/syscall.rs`'s `ipc_try_recv` doc comment, which
  today documents the absence of a receive-side check as intentional, becomes
  wrong and must be rewritten to describe the new gate.
- `ipc/src/fs.rs`'s `FsRequest` variants gain a response-port number and a
  second `CapabilityToken` scoped to `port:<that number>`. This is a typed
  `ipc` crate change, shared by both platform trees, not a hand-rolled layout
  on either side. `MAX_*` size constants need revisiting, since a second
  embedded token is another kilobyte-ish on a 32-byte channel.
- `blk-driver-host`'s `run_fs_ipc_server` verifies that second token before
  answering, and `send_fs_response` takes the destination port as an argument
  instead of using the `FS_RESPONSE_PORT` constant. A request whose
  response-port token fails to verify gets `FsError::Unauthorized` — sent
  where? Nowhere safe, which is the honest answer: the driver should drop it
  and log, since replying on the claimed port is exactly the leak this
  prevents.
- `kernel/src/main.rs`'s spawn path issues each FS client its own
  response-port token alongside its file token, and the port-constant block
  grows a documented allocation map of which of the 16 ports are
  spoken for, so the next service does not pick a colliding number by hand.
- `net-driver-host` gets the receive-side gate for free but no handle
  attribution — `ipc/src/sockets.rs`'s caveat stays true and should be
  updated to say explicitly that the port gate is now two-way while handle
  ownership remains unscoped, so the remaining gap is not mistaken for closed.
- `docs/THREAT_MODEL.md`'s entry is amended, not removed: the
  ambient-receive half closes, the no-caller-identity half stays open, with
  the Option C trigger conditions recorded as its revisit trigger.
- `docs/STATUS.md`'s filesystem-driver section gains a subsection in the same
  shape as its existing "closing a concurrency hazard that lived in the IPC
  layer" entry, stating plainly what is and is not confidential.

## Open questions

- **What should `CapabilityToken::subject` mean?** It is signed
  (`capability-manager/src/lib.rs`) but `verify` never checks it, and the
  kernel never compares it to anything — today's values are descriptive
  strings like `"thread:sender"` and `"blk-driver-host"`
  (`kernel/src/main.rs`). Option C's `ThreadId` is the first thing that
  could make `subject` load-bearing. Whether a token should authenticate its
  *holder* as well as its resource is a real capability-model question —
  classic capability systems say no (possession is the authority), and
  binding a token to a thread id makes it non-delegable, which may be a
  feature or a foreclosure. Leaning toward keeping possession-based
  semantics and putting ownership in the session table rather than in the
  token, but this deserves the repo owner's call.
- **Is `PORT_COUNT = 16` worth raising as a stopgap under Option A?** Each
  port is a permanently-held `Mutex<Channel>` plus `Mutex<bool>`; raising it
  to 64 is a one-constant change with a bounded memory cost, and it buys
  Option A meaningfully more headroom. It also makes the wall arrive later
  and less visibly, which argues against.
- **Does the receive-side gate break any currently-passing kernel test, and
  which?** Not enumerated across `kernel/tests/`. This should be answered by
  a build, not by reading, before the change is attempted — it is the
  cheapest possible early signal about the change's real blast radius.
- **Does a second embedded token per request threaten T1's <300ms MARSHAL
  budget?** One byte per syscall, a 32-byte channel, and roughly double the
  request size — the same concern `docs/RFC-TLS-APPROACH.md`'s last open
  question raises about handshake bytes. If a bulk-transfer IPC path is
  coming anyway, Option A's cost argument changes and Option C's relative
  cost drops.
- **Does session teardown interact with `reap_zombies`?** Under Option C,
  a session outliving either endpoint is both a leak and a confused-deputy
  risk. There is no session concept in `scheduler.rs` today; reaping was not
  traced in enough detail to say how invasive adding one would be.
- **Should the response-port token under Option A be a distinct resource
  kind** (say `respond-on:<n>`) rather than reusing `port:<n>`? Reusing it
  keeps one convention, but it means a token that authorizes *receiving*
  responses also authorizes *sending* on that port, which is more authority
  than the client needs.

## References

- `docs/THREAT_MODEL.md` — the finding this RFC responds to
- `kernel/src/syscall.rs` — syscall table, `authorized_for_port`, the three
  gated send-side arms, the ungated `SYS_IPC_RECV`
- `kernel/src/ipc.rs` — the send-lock precedent and its reasoning, the
  fixed 16 ports, static channel/lock arrays, `begin_send`/`end_send`,
  `try_recv`
- `kernel/src/scheduler.rs` — `Thread` (note the absence of any id),
  `spawn_ring3_process_with_capabilities`,
  `current_capability`/`current_extra_capabilities`
- `kernel/src/capabilities.rs` — the `port:<n>` resource convention
- `kernel/src/main.rs` — port constants, the response-port token issued to
  `blk-driver-host` today
- `blk-driver-host/src/main.rs` — port constants, per-file token checks,
  `send_fs_response`, `run_fs_ipc_server`
- `blk-driver-host/src/syscall.rs` — `ipc_try_recv`'s "no capability
  check on the receive side" note
- `ipc/src/fs.rs` — `FsRequest`/`FsResponse` wire types
- `ipc/src/sockets.rs` — the sibling caller-attribution gap
- `capability-manager/src/lib.rs` — `CapabilityToken` fields, what is
  signed, what `verify` actually checks
- `kernel/tests/blk_fs_concurrent.rs` — the shape a proof of this fix should
  follow
- `docs/RFC-TLS-APPROACH.md` — cites `ipc/src/sockets.rs` and depends
  on this layer's confidentiality
- `docs/RFC-VERIFIER-IDENTITY.md` — house style for this document

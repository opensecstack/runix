//! Inter-process communication primitives (Alpha: "Basic IPC") — fixed-count
//! byte channels addressed by small integer port ids. `send`/`recv` block by
//! spin-yielding through the cooperative scheduler rather than blocking a
//! CPU outright; a real wait/wake queue (so a blocked thread isn't burning
//! its turn just to check "still empty?") is a later refinement once the
//! scheduler is timer-preemptive.
//!
//! **Per-port send locks — the fix for a real, concrete corruption hazard**
//! (see `blk-driver-host/src/main.rs`'s `run_fs_ipc_server`'s own doc
//! comment, which named this exact gap before it was closed): a caller
//! sending a multi-byte message (e.g. a `runix_ipc::fs::FsRequest`) does so
//! one byte per `SYS_IPC_SEND` syscall, with no message framing at this
//! layer — `send`'s own byte-at-a-time queue has no notion of "this byte
//! belongs to that message." A real FAT32 filesystem request already
//! exceeds [`CHANNEL_CAPACITY`] on its own (an `FsRequest`'s embedded
//! `CapabilityToken` alone is over a kilobyte once encoded — see
//! `runix_ipc::fs`'s own size constants), so a *single* sender's message
//! routinely needs [`send`] to block (spin-yield) partway through — the
//! cooperative scheduler's only chance to switch to another thread while
//! that message is still incomplete. If a *second* sender is also mid-send
//! to the *same* port at that exact moment, its bytes land in the channel
//! interleaved with the first sender's still-unfinished message: the
//! receiver then decodes a franken-message built from both senders' bytes,
//! not a corrupted-looking one it could safely reject — nothing in the
//! wire format can detect this after the fact, since the resulting byte
//! stream can still parse as some *other*, wrong, but perfectly
//! well-formed request. [`begin_send`]/[`end_send`] close this by giving
//! each port an advisory mutual-exclusion lock a sender holds for the
//! entire duration of one logical message: a second sender's
//! [`begin_send`] on the same port blocks (spin-yields) until the first
//! calls [`end_send`], so two senders' byte streams can never interleave
//! into each other, only ever land back-to-back, in full.

use crate::scheduler::ThreadId;
use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use spin::Mutex;

const PORT_COUNT: usize = 16;
const CHANNEL_CAPACITY: usize = 32;

struct Channel {
    queue: VecDeque<u8>,
}

lazy_static! {
    static ref CHANNELS: [Mutex<Channel>; PORT_COUNT] =
        core::array::from_fn(|_| Mutex::new(Channel {
            queue: VecDeque::new()
        }));
    /// `true` while some sender is mid-message on that port — see this
    /// module's own doc comment. A plain `bool` behind a `spin::Mutex`, not
    /// an atomic flag: correctness here only needs "one holder at a time,"
    /// which a lock already gives for free, and every other piece of
    /// shared state in this file is already a `spin::Mutex` — no reason for
    /// this one gap to be the sole exception.
    static ref SEND_LOCKS: [Mutex<bool>; PORT_COUNT] = core::array::from_fn(|_| Mutex::new(false));
}

/// Blocks (spin-yielding) until `port`'s send lock is free, then claims it.
/// Every caller that sends more than one logically-related byte to the same
/// port — i.e. every real, multi-byte wire message — must call this before
/// its first [`send`] and [`end_send`] after its last, or its message is not
/// protected against interleaving with a concurrent sender on the same
/// port. See this module's own doc comment for the exact hazard this
/// closes.
pub fn begin_send(port: usize) {
    loop {
        {
            let mut locked = SEND_LOCKS[port].lock();
            if !*locked {
                *locked = true;
                return;
            }
        }
        crate::scheduler::yield_now();
    }
}

/// Releases `port`'s send lock, claimed by an earlier [`begin_send`] on the
/// same port from the same thread — this module trusts the caller to pair
/// these correctly (the same cooperative-scheduling trust model every other
/// syscall in this kernel already places on its caller; a caller that never
/// calls this permanently starves every other sender on that port, a
/// liveness bug for that caller to avoid, not a memory-safety one).
pub fn end_send(port: usize) {
    *SEND_LOCKS[port].lock() = false;
}

/// Blocks (spin-yielding) until there's room, then enqueues `byte` on `port`.
pub fn send(port: usize, byte: u8) {
    loop {
        {
            let mut channel = CHANNELS[port].lock();
            if channel.queue.len() < CHANNEL_CAPACITY {
                channel.queue.push_back(byte);
                return;
            }
        }
        crate::scheduler::yield_now();
    }
}

/// Non-blocking: `None` if `port` currently has nothing queued.
pub fn try_recv(port: usize) -> Option<u8> {
    CHANNELS[port].lock().queue.pop_front()
}

/// Peeks whether `port` currently has anything queued, without popping —
/// `syscall.rs`'s `SYS_IPC_RECV` arm checks this *before* paying for
/// `authorized_for_port`'s real Ed25519 verification, so a busy-poll loop
/// spinning on an empty port (this codebase's universal `SYS_IPC_RECV`
/// calling convention — see e.g. `net_driver_sockets.rs`'s `recv_response`,
/// `blk-driver-host`'s `run_fs_ipc_server`) pays the old, cheap
/// lock-and-check cost on every empty iteration instead of a full
/// signature verification on every single one. Confirmed as a real,
/// measured problem, not a guess: with the check unconditional, a single
/// `net_driver_sockets.rs` run took long enough under QEMU/TCG that it
/// looked indistinguishable from a hang (minutes to cross a few tens of
/// thousands of otherwise-empty polls) before this fix.
pub fn is_empty(port: usize) -> bool {
    CHANNELS[port].lock().queue.is_empty()
}

/// Blocks (spin-yielding) until a byte is available on `port`.
pub fn recv(port: usize) -> u8 {
    loop {
        if let Some(byte) = try_recv(port) {
            return byte;
        }
        crate::scheduler::yield_now();
    }
}

// ---------------------------------------------------------------------
// Session/handle IPC primitive ("Option C",
// `docs/RFC-IPC-RESPONSE-CAPABILITY.md`) — a dynamic alternative to the
// fixed `PORT_COUNT`-port array above, additive alongside it: every fixed
// port keeps working completely unchanged, this is a second, independent
// mechanism a thread opts into, not a replacement. See the RFC (and this
// change's own plan) for the full design and cost discussion; this doc
// comment covers only what a reader needs to trust the implementation.
//
// A `Session` is addressed by the same fixed `server_port` convention the
// array above already uses (`port:<n>` capability resource strings, see
// `capabilities::port_resource`) — opening or accepting a session on
// `server_port` requires exactly the capability a thread would need to
// `SYS_IPC_SEND`/`SYS_IPC_RECV` on that port directly today. No new
// capability-manager resource kind exists or is needed.
//
// Two kernel-owned locks below (`SESSIONS`, `PENDING_BY_PORT`), always
// taken independently of each other and of `SCHEDULER`'s lock **except**
// in one direction: `scheduler::reap_zombies` (which holds `SCHEDULER`'s
// lock for its whole duration) calls `reap_sessions_for`, which takes
// these locks *while* `SCHEDULER`'s is held. Every other caller here
// (the session syscalls) only ever touches `SCHEDULER` indirectly, via
// `scheduler::current_thread_id()`, which takes and fully releases that
// lock *before* returning — so by the time any function in this section
// takes `SESSIONS`/`PENDING_BY_PORT`, `SCHEDULER`'s lock is already gone.
// `SCHEDULER` → `SESSIONS`/`PENDING_BY_PORT` is therefore the only order
// that ever occurs; nothing here must ever be changed to call back into
// `current_thread_id` (or anything else that locks `SCHEDULER`) while
// already holding either of these two locks, or that invariant breaks.

/// A dynamically-opened IPC channel's identity — unlike a fixed `port:
/// usize`, never reused (a stale, reused id would let an unrelated later
/// session be silently treated as a confused-deputy handle to an old one).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionId(u64);

impl SessionId {
    /// Marshals a raw `u64` syscall argument/return value into a
    /// `SessionId` — deliberately infallible and total: a `u64` that was
    /// never actually issued by [`session_open`] just fails to find
    /// anything in `SESSIONS` at lookup time (the same "not found" outcome
    /// as a stale/torn-down id), rather than needing a separate
    /// construction-time validity check.
    pub fn from_u64(raw: u64) -> Self {
        SessionId(raw)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Same queue-capacity convention [`CHANNEL_CAPACITY`] already sets for
/// fixed ports — a session is used exactly the same way (one logical
/// message at a time, `begin`/`end`-locked), so there's no reason for a
/// different bound here.
const SESSION_CHANNEL_CAPACITY: usize = CHANNEL_CAPACITY;
/// Hard ceiling on live sessions system-wide — without this, a thread that
/// keeps calling `SYS_IPC_SESSION_OPEN` in a loop without ever finishing
/// (or exiting, which would reap its own sessions) grows this table
/// forever; unlike the fixed port array, this one is heap-backed with no
/// natural size limit otherwise.
const MAX_LIVE_SESSIONS: usize = 64;
/// A *per-owner* ceiling on top of the global one — without this, one
/// hostile-or-buggy thread alone could still consume the entire global
/// budget, starving every other legitimate client of the ability to open a
/// session at all.
const MAX_SESSIONS_PER_OWNER: usize = 8;

/// Which of a session's two participants a caller is, established once by
/// [`role_of`] and used to route every subsequent `send`/`recv`/lock call to
/// the correct directional lane below — see [`Session`]'s own doc comment
/// for why a session needs two lanes instead of one shared queue.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Owner,
    Server,
}

/// A session used to be one shared `VecDeque<u8>` both participants read and
/// wrote — a real, shipped bug: `session_try_recv` only checked that the
/// *caller* was a participant (owner or server), never that the *byte* in
/// front of the queue was written by the *other* participant. A caller that
/// sent a request and then immediately polled `RECV` for the reply (the
/// obvious, correct-looking way to write a client — see
/// `kernel/src/marshal_client.rs`'s `evaluate`) could race the server's own
/// `ACCEPT`+`RECV` and dequeue its own just-sent bytes back out, silently
/// destroying its own request before the real server ever saw it. Caught via
/// `net-driver-host`'s sockets IPC migration hanging with the server
/// reporting "accepted session" but never "decoded request" — root-caused
/// with a temporary `serial_println!` in `session_try_recv` showing a
/// client's own `RECV` firing with a non-empty queue *before* the session
/// had even been accepted (`server: None`), i.e. reading back its own
/// unconsumed send. `kernel/tests/ipc_session.rs`'s own isolation test never
/// caught this because it's an echo test (client sends "AAAA", expects
/// "AAAA" back) — a client accidentally reading back its own bytes instead
/// of a real server echo produces the exact same passing assertion, so the
/// test was blind to this failure mode by construction. Two separate
/// directional queues make the bug structurally impossible rather than
/// relying on call-ordering discipline from every future caller.
struct Session {
    /// Bytes the owner has sent, waiting for the server to `RECV` them.
    owner_to_server: VecDeque<u8>,
    /// Bytes the server has sent, waiting for the owner to `RECV` them.
    server_to_owner: VecDeque<u8>,
    /// Advisory send-lock guarding a multi-byte message from the owner —
    /// separate from [`Session::server_send_locked`] so the two directions
    /// never block each other; each lock only ever needs to exclude a
    /// second sender speaking for the *same* role, which two directional
    /// queues already make impossible to confuse with the other role.
    owner_send_locked: bool,
    /// Advisory send-lock guarding a multi-byte message from the server.
    server_send_locked: bool,
    /// The thread that called `SYS_IPC_SESSION_OPEN` for this session.
    owner: ThreadId,
    /// Bound lazily, by whichever thread's `SYS_IPC_SESSION_ACCEPT` first
    /// claims this session (see `session_accept`) — `None` until then.
    /// This, not pinning a server identity at open time, is deliberate: the
    /// kernel has no way to know which thread (if any) will ever accept a
    /// freshly opened session, since nothing pre-registers "the server for
    /// port N" anywhere today.
    server: Option<ThreadId>,
    /// Which fixed port's capability convention gates this session — both
    /// `SYS_IPC_SESSION_OPEN` and `SYS_IPC_SESSION_ACCEPT` check
    /// `authorized_for_port(server_port)` (via `syscall::authorized_for_port`)
    /// before this `Session` is even created/claimed; stored here only so
    /// [`session_send`]/[`session_recv`]/lock functions don't need it
    /// passed in separately by a caller that may not remember it.
    #[allow(dead_code)] // kept for symmetry/future use; not yet read post-accept
    server_port: usize,
}

lazy_static! {
    static ref SESSIONS: Mutex<BTreeMap<SessionId, Session>> = Mutex::new(BTreeMap::new());
    /// FIFO of sessions opened but not yet accepted, keyed by `server_port`
    /// — what makes `SYS_IPC_SESSION_ACCEPT` possible without the server
    /// already knowing a `SessionId`: it asks "what's pending for the port
    /// I serve," the same shape a real listen/accept primitive has.
    static ref PENDING_BY_PORT: Mutex<BTreeMap<usize, VecDeque<SessionId>>> = Mutex::new(BTreeMap::new());
}

/// `SYS_IPC_SESSION_OPEN`'s implementation, called only after
/// `syscall::dispatch` has already confirmed the caller holds a capability
/// authorizing `server_port` (same `authorized_for_port` check
/// `SYS_IPC_SEND`/`SYS_IPC_SESSION_ACCEPT` use) — this function trusts that
/// and does no capability checking of its own, matching every other
/// function in this file (the fixed-port `send`/`recv` above check
/// nothing either; authorization is `syscall::dispatch`'s job).
pub fn session_open(server_port: usize, owner: ThreadId) -> Option<SessionId> {
    let mut sessions = SESSIONS.lock();
    if sessions.len() >= MAX_LIVE_SESSIONS {
        return None;
    }
    let owner_count = sessions.values().filter(|s| s.owner == owner).count();
    if owner_count >= MAX_SESSIONS_PER_OWNER {
        return None;
    }
    let id = SessionId(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed));
    sessions.insert(
        id,
        Session {
            owner_to_server: VecDeque::new(),
            server_to_owner: VecDeque::new(),
            owner_send_locked: false,
            server_send_locked: false,
            owner,
            server: None,
            server_port,
        },
    );
    drop(sessions);
    PENDING_BY_PORT
        .lock()
        .entry(server_port)
        .or_default()
        .push_back(id);
    Some(id)
}

/// Peeks whether anything is currently pending (opened, not yet accepted)
/// for `server_port`, without popping — `syscall.rs`'s
/// `SYS_IPC_SESSION_ACCEPT` arm checks this *before* paying for
/// `authorized_for_port`'s real Ed25519 verification, the same precedent
/// [`is_empty`] already set for `SYS_IPC_RECV`. Without this,
/// `net-driver-host`'s `run_socket_ipc_server` had to throttle its own
/// `SESSION_ACCEPT` polling to once every 10,000 loop iterations purely to
/// avoid paying a full signature check on every otherwise-empty poll — a
/// real, measured latency floor on how quickly any client's session gets
/// accepted at all, incompatible with `grid_sandbox.rs`'s
/// `SHADOW_MARSHAL_MAX_ITERS`'s hard <300ms T1 real-time budget. With this
/// pre-check, a server can poll `SESSION_ACCEPT` every iteration again, the
/// same way every other server in this codebase polls `SYS_IPC_RECV`.
pub fn session_pending(server_port: usize) -> bool {
    PENDING_BY_PORT
        .lock()
        .get(&server_port)
        .is_some_and(|queue| !queue.is_empty())
}

/// `SYS_IPC_SESSION_ACCEPT`'s implementation — same trust posture as
/// [`session_open`] (caller already authorized for `server_port`).
/// Non-blocking: `None` if nothing is currently pending for this port.
pub fn session_accept(server_port: usize, server: ThreadId) -> Option<SessionId> {
    let id = PENDING_BY_PORT
        .lock()
        .get_mut(&server_port)
        .and_then(VecDeque::pop_front)?;
    if let Some(session) = SESSIONS.lock().get_mut(&id) {
        session.server = Some(server);
    }
    Some(id)
}

/// Which role `thread` plays in `session`, if any — the O(1) check every
/// session syscall past `OPEN`/`ACCEPT` uses instead of re-verifying a
/// capability token, per this module's own perf reasoning (see `is_empty`'s
/// doc comment for the precedent: an unconditional Ed25519 verification on a
/// busy-poll path is a real, measured cost this design avoids by caching
/// identity once). Also what routes every `send`/`recv`/lock call to the
/// correct directional lane — see [`Session`]'s doc comment for why this
/// replaced a single boolean "is a participant" check.
fn role_of(session: &Session, thread: ThreadId) -> Option<Role> {
    if session.owner == thread {
        Some(Role::Owner)
    } else if session.server == Some(thread) {
        Some(Role::Server)
    } else {
        None
    }
}

/// `SYS_IPC_SESSION_SEND`'s implementation. `None` if `session_id` doesn't
/// exist or `caller` is neither its owner nor its accepted server —
/// deliberately the same outcome for both (see this file's fixed-port
/// functions' own "fail-closed, indistinguishable" convention, inherited
/// here). Writes into the lane the *other* participant reads from — an
/// owner's send always lands in `owner_to_server`, a server's always in
/// `server_to_owner`, so the sender can never read its own bytes back out
/// (see [`Session`]'s doc comment). Spin-yields on a full queue, exactly
/// like [`send`].
pub fn session_send(session_id: SessionId, caller: ThreadId, byte: u8) -> bool {
    loop {
        {
            let mut sessions = SESSIONS.lock();
            let Some(session) = sessions.get_mut(&session_id) else {
                return false;
            };
            let Some(role) = role_of(session, caller) else {
                return false;
            };
            let queue = match role {
                Role::Owner => &mut session.owner_to_server,
                Role::Server => &mut session.server_to_owner,
            };
            if queue.len() < SESSION_CHANNEL_CAPACITY {
                queue.push_back(byte);
                return true;
            }
        }
        crate::scheduler::yield_now();
    }
}

/// `SYS_IPC_SESSION_RECV`'s implementation — non-blocking, same
/// owner-or-server check as [`session_send`]. Reads from the lane the
/// *other* participant writes into — an owner always reads `server_to_owner`,
/// a server always reads `owner_to_server` — so this can never return a
/// byte the caller itself sent (see [`Session`]'s doc comment for the bug
/// this fixes).
pub fn session_try_recv(session_id: SessionId, caller: ThreadId) -> Option<u8> {
    let mut sessions = SESSIONS.lock();
    let session = sessions.get_mut(&session_id)?;
    let role = role_of(session, caller)?;
    let queue = match role {
        Role::Owner => &mut session.server_to_owner,
        Role::Server => &mut session.owner_to_server,
    };
    queue.pop_front()
}

/// `SYS_IPC_SESSION_SEND_LOCK`'s implementation — same advisory-lock shape
/// as [`begin_send`], scoped to one session's *directional lane* instead of
/// one fixed port — an owner's lock only ever excludes another sender
/// speaking as the owner, never the server's own independent send lock (see
/// [`Session`]'s doc comment for why the two directions are fully
/// independent). Returns `false` (rather than blocking forever) if
/// `session_id` doesn't exist or `caller` isn't a participant, so a caller
/// can't spin-yield on a session that will never unlock because it was
/// never theirs to lock.
pub fn session_begin_send(session_id: SessionId, caller: ThreadId) -> bool {
    loop {
        {
            let mut sessions = SESSIONS.lock();
            let Some(session) = sessions.get_mut(&session_id) else {
                return false;
            };
            let Some(role) = role_of(session, caller) else {
                return false;
            };
            let locked = match role {
                Role::Owner => &mut session.owner_send_locked,
                Role::Server => &mut session.server_send_locked,
            };
            if !*locked {
                *locked = true;
                return true;
            }
        }
        crate::scheduler::yield_now();
    }
}

/// `SYS_IPC_SESSION_SEND_UNLOCK`'s implementation. `false` under the same
/// conditions [`session_begin_send`] would refuse to lock in the first
/// place — this module trusts correct pairing from a legitimate
/// participant, same as [`end_send`], but still refuses a caller with no
/// standing on this session at all (unlike `end_send`, which has no
/// identity concept to check against).
pub fn session_end_send(session_id: SessionId, caller: ThreadId) -> bool {
    let mut sessions = SESSIONS.lock();
    let Some(session) = sessions.get_mut(&session_id) else {
        return false;
    };
    let Some(role) = role_of(session, caller) else {
        return false;
    };
    match role {
        Role::Owner => session.owner_send_locked = false,
        Role::Server => session.server_send_locked = false,
    }
    true
}

/// Removes every session `thread` owned or served, and purges any of its
/// still-pending (not-yet-accepted) opens out of `PENDING_BY_PORT` — called
/// once per exiting thread from `scheduler::reap_zombies`. See this
/// section's own top-of-file doc comment for the lock-ordering invariant
/// this call site depends on (`SCHEDULER`'s lock may already be held by the
/// caller; this function must never try to re-acquire it, directly or
/// transitively).
pub fn reap_sessions_for(thread: ThreadId) {
    // Pending-queue cleanup must happen first, while `SESSIONS` still has
    // every entry to consult — a pending (not-yet-accepted) session has no
    // server yet by definition, so only its owner exiting can make it
    // stale. Locks `SESSIONS` then `PENDING_BY_PORT`, nested — the only
    // place in this file that nests these two; every other function here
    // takes them sequentially (lock, drop, lock the other), never nested,
    // so this establishes the sole nesting order and nothing else risks
    // acquiring them in reverse.
    {
        let sessions = SESSIONS.lock();
        let mut pending = PENDING_BY_PORT.lock();
        for queue in pending.values_mut() {
            queue.retain(|id| {
                sessions
                    .get(id)
                    .is_some_and(|session| session.owner != thread)
            });
        }
    }
    SESSIONS
        .lock()
        .retain(|_, session| session.owner != thread && session.server != Some(thread));
}

#!/usr/bin/env python3
"""Host-side half of net_driver_sockets_concurrent.rs's proof.

Same role `tcp_proof_listener.py` plays for `net_driver_tcp.rs`/
`net_driver_sockets.rs` (a real listener QEMU's `guestfwd` bridges a
guest-initiated connection to), but accepts *two* connections on the same
listening port rather than one -- proving two concurrently open sockets in
`net-driver-host`'s sockets IPC server don't clobber each other's state
needs two genuinely simultaneous, independently-observable TCP
conversations, not just two sequential ones each torn down before the next
opens.

Reuses a single `guestfwd` route (same target `tcp_proof_listener.py`
already uses, `10.0.2.100:9000`, bridged here instead of to that script) --
QEMU's `guestfwd` spawns a fresh bridge command for every new
guest-initiated TCP connection to that destination regardless of how many
prior connections to it are still open, so two connections opened by the
guest without closing the first still each get their own bridged `nc`
process talking to their own `accept()`ed socket here. This avoids relying
on whether repeating `guestfwd=` twice in one `-netdev user` string is
parsed as two independent rules or one overwriting the other -- one rule
is all this needs.

Each connection uses its own PING/PONG pair (distinct from each other, and
from `tcp_proof_listener.py`'s own) so a bug that accidentally routed
socket A's bytes to socket B's connection (or vice versa) would show up
here as a byte mismatch, not silently pass. Accepts connection 1 and
connection 2 in whatever order they actually arrive (both are already
established test connections by the time either sends data — the ordering
`net_driver_sockets_concurrent.rs` itself proves independence with is on
the *guest* side, not this listener's accept order) and matches each
against *both* known PING values rather than assuming which one arrives
first.
"""

import socket
import sys

HOST = "127.0.0.1"
PORT = 9002

PAIRS = {
    b"RUNIX-SOCK-A-PING": b"RUNIX-SOCK-A-PONG",
    b"RUNIX-SOCK-B-PING": b"RUNIX-SOCK-B-PONG",
}


def handle_one(conn) -> bool:
    # Longest known PING is used as the read size; a short read on a real
    # TCP stream still returns whatever's arrived so far, which is fine —
    # this listener only compares against the two known-exact values, not
    # against a fixed byte count.
    max_len = max(len(p) for p in PAIRS)
    received = conn.recv(max_len)
    pong = PAIRS.get(received)
    if pong is None:
        print(
            f"two_socket_proof_listener: FAIL -- unrecognized payload {received!r}",
            file=sys.stderr,
        )
        return False
    conn.sendall(pong)
    return True


def main() -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(2)

    ok = True
    for _ in range(2):
        conn, _addr = server.accept()
        try:
            if not handle_one(conn):
                ok = False
        finally:
            conn.close()
    server.close()

    if ok:
        print("two_socket_proof_listener: PASS -- both connections received exact PING, sent PONG")
        return 0
    print("two_socket_proof_listener: FAIL", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

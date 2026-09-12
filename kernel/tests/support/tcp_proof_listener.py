#!/usr/bin/env python3
"""Host-side half of net_driver_tcp.rs's Phase 2b proof.

SLIRP (QEMU's `-netdev user` backend) has no built-in TCP listener to
connect to, so proving `net-driver-host`'s smoltcp TCP client actually
works needs a real listener running on the *host* the guest can reach.
QEMU's `guestfwd` option bridges a guest-initiated TCP connection to a
given host command's stdin/stdout (see `.github/workflows/ci.yml`'s
`kernel-tests` job for the exact `-netdev ...,guestfwd=tcp:10.0.2.100:9000-cmd:'nc 127.0.0.1 9001'`
invocation) -- `nc` there is just the bridge; this script is the real
listener it connects to on 127.0.0.1:9001.

Deliberately plain, dependency-free Python (guaranteed present on
`ubuntu-latest`, no extra CI install step needed) rather than a shell
one-liner: exact byte-for-byte comparison of what's received, matching
this codebase's "real round-trip, exact bytes checked" discipline for
every other proof (`is_arp_reply`, the ICMP echo check) rather than "a
connection happened, presumably fine."

Accepts exactly one connection, checks it received exactly
b"RUNIX-TCP-PROOF-PING", replies with exactly b"RUNIX-TCP-PROOF-PONG",
then exits -- a real, independent assertion on the host side, not just
trusting the guest's own self-reported result byte. If only one direction
of the round-trip is broken, this and the guest's own check disagree,
which is itself useful signal.
"""

import socket
import sys

HOST = "127.0.0.1"
PORT = 9001
PING = b"RUNIX-TCP-PROOF-PING"
PONG = b"RUNIX-TCP-PROOF-PONG"


def main() -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    conn, _addr = server.accept()
    try:
        received = conn.recv(len(PING))
        if received != PING:
            print(
                f"tcp_proof_listener: FAIL -- expected {PING!r}, got {received!r}",
                file=sys.stderr,
            )
            return 1
        conn.sendall(PONG)
        print("tcp_proof_listener: PASS -- received exact PING, sent PONG")
        return 0
    finally:
        conn.close()
        server.close()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Host-side half of net_driver_dns_mock.rs's deterministic DNS proof.

QEMU's SLIRP forwards a guest UDP datagram sent to the gateway address
10.0.2.2 to the *host's* loopback, so a plain UDP socket bound on
127.0.0.1:53 receives the guest's DNS query -- no `guestfwd` (which has no
UDP support) needed. This script answers any A query for any name with one
A record, 192.0.2.53 (TEST-NET-1, RFC 5737: can never be a real internet
answer), so the guest-side assertion on that exact address proves the
answer came from here and not from a real resolver.

Binding port 53 needs privilege on Linux (run via sudo in CI). Dependency-
free, like tcp_proof_listener.py.

Usage: mock_dns.py   (env: MOCK_DNS_ADDR default 127.0.0.1,
                      MOCK_DNS_PORT default 53, MOCK_DNS_TIMEOUT secs
                      default 120)
Exits 0 after answering one A query; exits 1 on timeout or malformed query.
"""

import os
import socket
import sys

ANSWER_IP = bytes([192, 0, 2, 53])


def build_response(query: bytes):
    """Returns the reply for an A/IN query, or None if not answerable."""
    if len(query) < 17:
        return None
    # Walk the QNAME labels (no compression in a query's first question).
    i = 12
    while i < len(query) and query[i] != 0:
        i += query[i] + 1
    qend = i + 5  # root label + QTYPE(2) + QCLASS(2)
    if i >= len(query) or qend > len(query):
        return None
    qtype = int.from_bytes(query[i + 1 : i + 3], "big")
    if qtype != 1:  # A only
        return None
    return (
        query[:2]  # ID
        + b"\x81\x80"  # QR, RD, RA, NOERROR
        + b"\x00\x01\x00\x01\x00\x00\x00\x00"  # QD=1 AN=1 NS=0 AR=0
        + query[12:qend]  # question, copied verbatim
        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"  # ptr, A, IN, TTL 60, len 4
        + ANSWER_IP
    )


def main() -> int:
    addr = os.environ.get("MOCK_DNS_ADDR", "127.0.0.1")
    port = int(os.environ.get("MOCK_DNS_PORT", "53"))
    timeout = float(os.environ.get("MOCK_DNS_TIMEOUT", "120"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((addr, port))
    sock.settimeout(timeout)
    print(f"mock_dns: listening on {addr}:{port}", flush=True)
    while True:
        try:
            data, peer = sock.recvfrom(512)
        except socket.timeout:
            print("mock_dns: FAIL -- timed out with no answerable query", file=sys.stderr)
            return 1
        reply = build_response(data)
        if reply is None:
            # Not an A query (e.g. AAAA): ignore and keep waiting.
            print(f"mock_dns: ignoring unanswerable datagram from {peer}", flush=True)
            continue
        sock.sendto(reply, peer)
        print(f"mock_dns: PASS -- answered A query from {peer} with 192.0.2.53", flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())

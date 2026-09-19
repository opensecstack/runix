#!/usr/bin/env python3
"""Host-side half of marshal_tcp_roundtrip.rs's proof.

Proves `kernel::marshal_client`'s new socket-based transport (see that
module's own doc comment) actually carries a `runix_ipc::marshal::
MarshalRequest`/`MarshalResponse` pair over a real TCP connection, the same
way `tcp_proof_listener.py` proves `net-driver-host`'s TCP client works
before any real service exists behind it. Reached the same way that script
is: QEMU's `guestfwd` bridges a guest-initiated connection to `nc`, which
this script is the real listener behind (see `.github/workflows/ci.yml`'s
`marshal_tcp_roundtrip` step for the exact invocation).

**This is not a MARSHAL proxy, a MARSHAL client, or a stand-in for
either.** It exists purely to answer the wire format on the other end of a
real socket, the same test-only role `marshal_ipc_roundtrip.rs`'s old
`fake_proxy_thread` played for the previous port-channel transport. No real
governance logic lives here: the canned response is a fixed, hardcoded
`MarshalOutcome::Refuse` (wire byte `1`), chosen deliberately (not
`Execute`) so a future accidental wiring-up of this exact listener as if it
were real governance would fail closed, not open.

# Wire format (must match `ipc/src/marshal.rs` exactly)

`MarshalRequest`: `u32` little-endian length prefix, then that many bytes of
opaque `kerkese_json`.

`MarshalResponse::Decision`: tag byte `0`, then outcome byte (`0`=Execute,
`1`=Refuse, `2`=HardStop), then a `u32` little-endian length prefix and that
many bytes of opaque `decision_json` — see `MarshalResponse::encode`'s
`Decision` arm.
"""

import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = 9003

FAKE_KERKESE_JSON = b'{"kerkese_version":"1.0","action":{"type":"TEST_ACTION"}}'
FAKE_DECISION_JSON = b'{"outcome":"REFUSE","reasons":["test-only fake proxy"]}'

OUTCOME_REFUSE = 1


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"peer closed after {len(buf)} of {n} expected bytes")
        buf += chunk
    return buf


def recv_marshal_request(conn: socket.socket) -> bytes:
    length_bytes = recv_exact(conn, 4)
    (length,) = struct.unpack("<I", length_bytes)
    return recv_exact(conn, length)


def encode_marshal_response_refuse(decision_json: bytes) -> bytes:
    out = bytearray()
    out.append(0)  # MarshalResponse::Decision tag
    out.append(OUTCOME_REFUSE)
    out.extend(struct.pack("<I", len(decision_json)))
    out.extend(decision_json)
    return bytes(out)


def main() -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    conn, _addr = server.accept()
    try:
        kerkese_json = recv_marshal_request(conn)
        if kerkese_json != FAKE_KERKESE_JSON:
            print(
                f"marshal_proof_listener: FAIL -- expected {FAKE_KERKESE_JSON!r}, "
                f"got {kerkese_json!r}",
                file=sys.stderr,
            )
            return 1
        conn.sendall(encode_marshal_response_refuse(FAKE_DECISION_JSON))
        print(
            "marshal_proof_listener: PASS -- received exact MarshalRequest, "
            "sent a canned Refuse MarshalResponse"
        )
        return 0
    finally:
        conn.close()
        server.close()


if __name__ == "__main__":
    sys.exit(main())

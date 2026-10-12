#!/usr/bin/env python3
"""Host-side half of grid_sandbox_marshal_shadow.rs's "configured, listener
present" case.

Same test-only role `marshal_proof_listener.py` plays for
`marshal_tcp_roundtrip.rs`: **not a MARSHAL proxy, a MARSHAL client, or a
stand-in for either.** It exists purely to answer the wire format on the
other end of a real socket, from `grid_sandbox::spawn_instance`'s own
shadow-mode MARSHAL evaluation. Unlike `marshal_proof_listener.py`, this
script does not check the received `kerkese_json` against one fixed,
hardcoded value: `grid_sandbox::shadow_marshal_evaluate` builds its request
from the real `instance_id` being spawned (`"shadow-configured"` for this
test), and this script's only job is to prove that request actually arrives
and gets a real `MarshalResponse::Decision { outcome: Refuse, .. }` back —
not to validate its exact bytes. The canned response is a fixed, hardcoded
`MarshalOutcome::Refuse` (wire byte `1`), same "fail closed, not open"
reasoning `marshal_proof_listener.py`'s own doc comment gives.

# Wire format (must match `ipc/src/marshal.rs` exactly)

`MarshalRequest`: `u32` little-endian length prefix, then that many bytes of
opaque `kerkese_json`.

`MarshalResponse::Decision`: tag byte `0`, then outcome byte (`0`=Execute,
`1`=Refuse, `2`=HardStop), then a `u32` little-endian length prefix and that
many bytes of opaque `decision_json`.

`MarshalResponse::Error`: tag byte `1`, then an error kind byte (`2` =
`BadResponse`), then a `u16` little-endian length prefix and that many bytes
of message.

The listener serves THREE connections (each guest-side `spawn_instance`
evaluation is its own `guestfwd` `nc` connection): the first gets the canned
Refuse Decision, the second an ipc-level `Error(BadResponse)` (a reached but
faulty reply, which enforcement must block as `Faulty`), the third raw
MALFORMED bytes (first byte 0x7f, no valid tag, then padding), which the
kernel's streaming decoder classifies `Malformed` and must also block as
`Faulty` (not retry into a fail-open timeout).
"""

import socket
import struct
import sys

HOST = "127.0.0.1"
PORT = 9004

DECISION_JSON = b'{"outcome":"REFUSE","reasons":["test-only shadow-mode stand-in listener"]}'

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


def encode_marshal_response_bad_response(msg: bytes) -> bytes:
    out = bytearray()
    out.append(1)  # MarshalResponse::Error tag
    out.append(2)  # MarshalError::BadResponse tag
    out.extend(struct.pack("<H", len(msg)))
    out.extend(msg)
    return bytes(out)


def malformed_reply() -> bytes:
    # 0x7f is not a MarshalResponse tag (0 = Decision, 1 = Error).
    return b"\x7f" + b"\x00" * 15


def main() -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(3)

    try:
        for i in range(3):
            conn, _addr = server.accept()
            try:
                kerkese_json = recv_marshal_request(conn)
                print(
                    f"grid_sandbox_marshal_shadow_listener: received shadow evaluation request "
                    f"{i + 1} ({len(kerkese_json)} bytes): {kerkese_json!r}",
                    file=sys.stderr,
                )
                if i == 0:
                    conn.sendall(encode_marshal_response_refuse(DECISION_JSON))
                    print(
                        "grid_sandbox_marshal_shadow_listener: sent a canned Refuse "
                        "MarshalResponse"
                    )
                elif i == 2:
                    conn.sendall(malformed_reply())
                    print(
                        "grid_sandbox_marshal_shadow_listener: sent canned MALFORMED "
                        "reply bytes (unknown tag 0x7f)"
                    )
                else:
                    conn.sendall(
                        encode_marshal_response_bad_response(
                            b"test-only faulty reply (BadResponse)"
                        )
                    )
                    print(
                        "grid_sandbox_marshal_shadow_listener: sent a canned "
                        "Error(BadResponse) MarshalResponse"
                    )
            finally:
                conn.close()
        print("grid_sandbox_marshal_shadow_listener: PASS -- served all three connections")
        return 0
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())

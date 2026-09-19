#!/usr/bin/env python3
"""Host-side mock CITADEL HTTP endpoint for marshal_proxy_e2e.rs's proof.

**This is not CITADEL, MARSHAL, or any stand-in for real governance
logic.** It exists purely to give the real, compiled `citadel_proxy`
binary (`desktop/src/bin/citadel_proxy.rs`) something to POST a Kerkese
envelope to via `RUNIX_CITADEL_URL`, so that binary's real
`HttpKerkeseTransport` has a live HTTP endpoint to round-trip against --
the same test-only role `marshal_proof_listener.py` plays for the raw
`MarshalRequest`/`MarshalResponse` wire format, one layer further out.

Accepts exactly one HTTP/1.1 request (any method/path/body -- this script
doesn't inspect or validate the Kerkese JSON `citadel_proxy` forwards,
that's `citadel_proxy`'s and `HttpKerkeseTransport`'s job to get right,
not this stand-in's), and always replies with a canned, well-formed
`EXECUTE` Decision, then exits.

The canned Decision body is copied byte-for-byte from
`desktop/src/citadel/proxy.rs`'s own `CANNED_EXECUTE_RESPONSE` test
fixture -- already proven there to deserialize successfully as a real
`citadel_kerkese_core::decision::Decision` and translate to
`MarshalOutcome::Execute`, so this script reuses exactly that body rather
than hand-rolling a new one that might not actually parse.
"""

import socket
import sys

HOST = "127.0.0.1"
PORT = 9105

# Copied byte-for-byte from desktop/src/citadel/proxy.rs's
# CANNED_EXECUTE_RESPONSE -- keep in sync with that fixture if it changes.
DECISION_JSON = (
    b'{"execution_id":"00000000-0000-0000-0000-000000000000",'
    b'"outcome":"EXECUTE","gates":[],"reasons":[],'
    b'"ts_utc":"2026-07-26T12:00:01Z"}'
)


def read_http_request(conn: socket.socket) -> bytes:
    """Reads headers + Content-Length body. Good enough for a test double
    talking to `reqwest`, not a real HTTP parser -- same scope
    `desktop/src/citadel/proxy.rs`'s own test-only `read_http_request`
    helper has."""
    buf = b""
    chunk = 4096
    header_end = None
    while header_end is None:
        data = conn.recv(chunk)
        if not data:
            return buf
        buf += data
        pos = buf.find(b"\r\n\r\n")
        if pos != -1:
            header_end = pos + 4

    headers = buf[:header_end].decode("latin1").lower()
    content_length = 0
    for line in headers.split("\r\n"):
        if line.startswith("content-length:"):
            content_length = int(line.split(":", 1)[1].strip())
            break

    while len(buf) < header_end + content_length:
        data = conn.recv(chunk)
        if not data:
            break
        buf += data

    return buf[header_end:]


def main() -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    conn, _addr = server.accept()
    try:
        read_http_request(conn)
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(DECISION_JSON)).encode("ascii") + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + DECISION_JSON
        )
        conn.sendall(response)
        print(
            "mock_citadel_server: PASS -- served one canned EXECUTE Decision "
            "to a real HTTP client"
        )
        return 0
    finally:
        conn.close()
        server.close()


if __name__ == "__main__":
    sys.exit(main())

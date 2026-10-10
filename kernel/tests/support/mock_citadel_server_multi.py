#!/usr/bin/env python3
"""Multi-request sibling of mock_citadel_server.py.

Same test-only role and the same canned EXECUTE Decision (imported from the
original, not copied), but serves MANY sequential HTTP connections instead of
exactly one and then exiting. The kernel-arm Execute boot step needs this:
since Beta item 3.4 the EL0 walk performs seven MARSHAL evaluations per boot
(eSIM enable/delete plus the three MVNO syscalls), each one a fresh
guestfwd connection to a fresh citadel_proxy request, so a one-shot mock would
leave every evaluation after the first `Unreachable`.

Not CITADEL, MARSHAL or any stand-in for governance logic: it never inspects
the Kerkese envelope beyond logging its `action.type` to stderr for
debugging. Runs until killed (CI backgrounds it; the runner tears it down).

Usage: mock_citadel_server_multi.py [port]   (default: mock_citadel_server.PORT)
"""

import json
import socket
import sys

import mock_citadel_server as single


def serve_one(conn: socket.socket) -> None:
    body = single.read_http_request(conn)
    if not body:
        # Connection opened and closed (or a bare probe) with no request.
        return
    try:
        action_type = json.loads(body)["action"]["type"]
    except (ValueError, KeyError, TypeError):
        action_type = "<unparseable>"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(single.DECISION_JSON)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + single.DECISION_JSON
    )
    conn.sendall(response)
    print(
        f"mock_citadel_server_multi: served canned EXECUTE for action.type={action_type}",
        file=sys.stderr,
        flush=True,
    )


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else single.PORT
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((single.HOST, port))
    server.listen(8)
    print(f"mock_citadel_server_multi: listening on {single.HOST}:{port}", file=sys.stderr, flush=True)
    while True:
        conn, _addr = server.accept()
        try:
            serve_one(conn)
        except OSError as err:
            print(f"mock_citadel_server_multi: connection error: {err}", file=sys.stderr, flush=True)
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())

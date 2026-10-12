#!/usr/bin/env python3
"""Multi-request sibling of mock_citadel_server.py.

Same test-only role and the same canned EXECUTE Decision (imported from the
original, not copied), but serves MANY sequential HTTP connections instead of
exactly one and then exiting. The kernel-arm Execute boot step needs this:
since Beta item 3.4 the EL0 walk performs seven MARSHAL evaluations per boot
(eSIM enable/delete plus the three MVNO syscalls), each one a fresh
guestfwd connection to a fresh citadel_proxy request, so a one-shot mock would
leave every evaluation after the first `Unreachable`.

Not CITADEL, MARSHAL or any stand-in for governance logic. By default it
answers 200 + EXECUTE to everything. Optionally it can mimic the one HTTP
quirk of the real CITADEL handler (handlers/marshal.go) that a 200-only mock
can never exercise: REFUSE and HARD_STOP are answered with HTTP 403 and the
full Decision JSON body. Per-action behaviour is chosen by action.type prefix
(repeatable flags):

  --status403-refuse PREFIX     403 + REFUSE Decision for matching action types
  --status403-hardstop PREFIX   403 + HARD_STOP Decision for matching types
  --garbage PREFIX              HTTP 200 with a NON-JSON body (a reached but
                                faulty reply) for matching action types
  --http500 PREFIX              HTTP 500 (non-403 HTTP error) for matching types

Everything else gets 200 + EXECUTE. Precedence: http500, garbage, HARD_STOP,
then REFUSE.

Runs until killed (CI backgrounds it; the runner tears it down).

Usage: mock_citadel_server_multi.py [port] [--status403-refuse P]... [--status403-hardstop P]...
       [--garbage P]... [--http500 P]...
(port default: mock_citadel_server.PORT)
"""

import argparse
import json
import socket
import sys

import mock_citadel_server as single


def decision_body(outcome: str) -> bytes:
    """The canned EXECUTE body with only `outcome` swapped (same shape)."""
    return single.DECISION_JSON.replace(b'"EXECUTE"', b'"' + outcome.encode("ascii") + b'"')


GARBAGE_BODY = b"<<not json: faulty MARSHAL reply>>"
HTTP500_BODY = b"internal server error"


def choose(action_type: str, refuse: list, hardstop: list, garbage=(), http500=()):
    """Returns (status line, outcome) for an action type. Outcome `GARBAGE`
    / `HTTP500` mean "answer with the canned faulty body instead of a Decision"."""
    if any(action_type.startswith(p) for p in http500):
        return b"500 Internal Server Error", "HTTP500"
    if any(action_type.startswith(p) for p in garbage):
        return b"200 OK", "GARBAGE"
    if any(action_type.startswith(p) for p in hardstop):
        return b"403 Forbidden", "HARD_STOP"
    if any(action_type.startswith(p) for p in refuse):
        return b"403 Forbidden", "REFUSE"
    return b"200 OK", "EXECUTE"


def serve_one(conn: socket.socket, refuse: list, hardstop: list, garbage=(), http500=()) -> None:
    body = single.read_http_request(conn)
    if not body:
        # Connection opened and closed (or a bare probe) with no request.
        return
    try:
        action_type = json.loads(body)["action"]["type"]
    except (ValueError, KeyError, TypeError):
        action_type = "<unparseable>"
    status, outcome = choose(action_type, refuse, hardstop, garbage, http500)
    if outcome == "GARBAGE":
        payload = GARBAGE_BODY
    elif outcome == "HTTP500":
        payload = HTTP500_BODY
    else:
        payload = decision_body(outcome)
    response = (
        b"HTTP/1.1 " + status + b"\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + payload
    )
    conn.sendall(response)
    print(
        f"mock_citadel_server_multi: served {status.decode()} {outcome} for action.type={action_type}",
        file=sys.stderr,
        flush=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("port", nargs="?", type=int, default=single.PORT)
    ap.add_argument("--status403-refuse", action="append", default=[], metavar="PREFIX")
    ap.add_argument("--status403-hardstop", action="append", default=[], metavar="PREFIX")
    ap.add_argument("--garbage", action="append", default=[], metavar="PREFIX")
    ap.add_argument("--http500", action="append", default=[], metavar="PREFIX")
    args = ap.parse_args()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((single.HOST, args.port))
    server.listen(8)
    print(f"mock_citadel_server_multi: listening on {single.HOST}:{args.port}", file=sys.stderr, flush=True)
    while True:
        conn, _addr = server.accept()
        try:
            serve_one(
                conn,
                args.status403_refuse,
                args.status403_hardstop,
                args.garbage,
                args.http500,
            )
        except OSError as err:
            print(f"mock_citadel_server_multi: connection error: {err}", file=sys.stderr, flush=True)
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())

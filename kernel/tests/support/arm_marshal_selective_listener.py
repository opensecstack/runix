#!/usr/bin/env python3
"""Selective, multi-connection MARSHAL stand-in for kernel-arm's boot tests.

Test-only, same role as grid_sandbox_marshal_shadow_listener.py (whose wire
format helpers are reused here, not copied -- that script is unchanged because
other tests use it) but for the kernel-arm EL0 walk, which since Beta item 3.4
performs several MARSHAL evaluations per boot (eSIM enable/delete and the three
MVNO syscalls). That script Refuses everything and serves a single connection,
so it can only ever prove the first gated syscall; this one:

  * serves MANY sequential connections (one per kernel evaluation),
  * parses each request's Kerkese JSON `action.type`,
  * answers REFUSE (outcome byte 1) when the type starts with any `--refuse`
    prefix, else EXECUTE (outcome byte 0),
  * logs every decision to stderr.

Usage: arm_marshal_selective_listener.py [port] [--refuse PREFIX]...
  port        default 9004 (matches the guestfwd target in ci.yml)
  --refuse P  repeatable; e.g. `--refuse esim.` or `--refuse mvno.suspend_account`

Runs until killed. Not a MARSHAL proxy or client.

Wire format (must match ipc/src/marshal.rs): request = u32 LE length + JSON;
response = tag 0, outcome byte, u32 LE length + decision JSON.
"""

import json
import socket
import struct
import sys

import grid_sandbox_marshal_shadow_listener as shadow

HOST = "127.0.0.1"
DEFAULT_PORT = 9004

OUTCOME_EXECUTE = 0
OUTCOME_REFUSE = 1

DECISION_REFUSE = b'{"outcome":"REFUSE","reasons":["test-only selective stand-in listener"]}'
DECISION_EXECUTE = b'{"outcome":"EXECUTE","reasons":["test-only selective stand-in listener"]}'


def encode_response(outcome: int, decision_json: bytes) -> bytes:
    out = bytearray()
    out.append(0)  # MarshalResponse::Decision tag
    out.append(outcome)
    out.extend(struct.pack("<I", len(decision_json)))
    out.extend(decision_json)
    return bytes(out)


def action_type_of(kerkese_json: bytes) -> str:
    try:
        return str(json.loads(kerkese_json)["action"]["type"])
    except (ValueError, KeyError, TypeError):
        return ""


def decide(action_type: str, refuse_prefixes: list) -> int:
    """REFUSE when the type starts with any configured prefix, else EXECUTE."""
    for prefix in refuse_prefixes:
        if action_type.startswith(prefix):
            return OUTCOME_REFUSE
    return OUTCOME_EXECUTE


def parse_args(argv: list):
    port = DEFAULT_PORT
    refuse = []
    i = 0
    while i < len(argv):
        if argv[i] == "--refuse":
            if i + 1 >= len(argv):
                raise SystemExit("--refuse needs a prefix argument")
            refuse.append(argv[i + 1])
            i += 2
        else:
            port = int(argv[i])
            i += 1
    return port, refuse


def serve_one(conn: socket.socket, refuse: list) -> None:
    kerkese_json = shadow.recv_marshal_request(conn)
    action_type = action_type_of(kerkese_json)
    outcome = decide(action_type, refuse)
    decision = DECISION_REFUSE if outcome == OUTCOME_REFUSE else DECISION_EXECUTE
    conn.sendall(encode_response(outcome, decision))
    print(
        f"arm_marshal_selective_listener: action.type={action_type!r} -> "
        f"{'REFUSE' if outcome == OUTCOME_REFUSE else 'EXECUTE'}",
        file=sys.stderr,
        flush=True,
    )


def main() -> int:
    port, refuse = parse_args(sys.argv[1:])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(8)
    print(
        f"arm_marshal_selective_listener: listening on {HOST}:{port}, refuse prefixes {refuse!r}",
        file=sys.stderr,
        flush=True,
    )
    while True:
        conn, _addr = server.accept()
        try:
            serve_one(conn, refuse)
        except (OSError, ConnectionError) as err:
            print(f"arm_marshal_selective_listener: connection error: {err}", file=sys.stderr, flush=True)
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())

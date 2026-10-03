//! A real, live TLS 1.3 handshake against a real server on the public
//! internet — the actual bar for "this crate's handshake wiring works,"
//! not just "it compiles against `embedded-tls`'s types." Runs over `std`'s
//! `TcpStream` (this is a host-side integration test, not something that
//! runs in a freestanding ring-3 process — no Runix IPC transport exists to
//! test against yet, since no consumer process exists, per this crate's own
//! `README`/doc comment on what's still unbuilt).
//!
//! `tests/fixtures/example_com_root.der` is "AAA Certificate Services"
//! (Comodo/Sectigo's long-standing self-signed legacy root, exported from
//! this machine's own Windows trusted-root store) — the *actual* trust
//! anchor `example.com`'s real, live certificate chain terminates at.
//! Confirmed by inspecting the full chain the server genuinely sends
//! (`openssl s_client -connect example.com:443 -showcerts`, 2026-09-27):
//! leaf `example.com` -> `Cloudflare TLS Issuing ECC CA 3` ->
//! `SSL.com TLS Transit ECC CA R2` -> `SSL.com TLS ECC Root CA 2022`, and
//! that fourth, last entry is itself cross-signed by "AAA Certificate
//! Services", not self-signed — confirmed by `openssl verify -partial_chain
//! -trusted <aaa root> <that fourth cert>`. Getting this wrong is exactly
//! how this test first failed while writing it: trusting the fourth cert
//! directly (its own subject, not its actual issuer) made
//! `embedded_tls::pki::CertVerifier` try to verify that cert's signature
//! against its *own* public key instead of its real issuer's, which
//! obviously fails (`TlsError::DecodeError`, from a key-type/byte-shape
//! mismatch) — a real, instructive bug in how this test was first written,
//! not in `tls-client`'s own code.
//!
//! **This is inherently fragile against certificate rotation** — if
//! `example.com`'s issuing chain changes (a new intermediate, a different
//! cross-sign), this test starts failing for a reason that has nothing to
//! do with this crate's own code. That's an accepted, explicit tradeoff for
//! a one-time-strength proof that the wiring performs a real handshake
//! against a real server, not a permanent CI gate — `#[ignore]`d for
//! exactly that reason; run it deliberately with `cargo test -- --ignored`
//! when re-verifying this crate's wiring, not on every CI run.

use runix_tls_client::{Entropy, TlsConnection, Yield};
use std::io::Read as _;
use std::net::TcpStream;

struct StdTransport(TcpStream);

impl runix_tls_client::Transport for StdTransport {
    type Error = std::io::Error;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // A real blocking `TcpStream` never returns `Ok(0)` for "nothing
        // yet" the way this trait's contract wants (it blocks in the OS
        // instead) — which is fine here: it still satisfies the contract
        // (`Ok(0)` only ever meaning "try again," which for a blocking
        // socket just never happens), it's just that the "try again" loop
        // in `io::BlockingIo` never actually needs to retry against this
        // particular `Transport` impl.
        self.0.read(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        std::io::Write::write_all(&mut self.0, buf)
    }
}

struct NoYield;
impl Yield for NoYield {
    fn yield_now(&mut self) {
        // No scheduler to cooperate with in a plain OS thread — a blocking
        // `TcpStream::read` already yields the OS thread while waiting.
    }
}

struct OsEntropy;
impl Entropy for OsEntropy {
    fn next_u64(&mut self) -> Option<u64> {
        getrandom::u64().ok()
    }
}

#[test]
#[ignore = "hits the live public internet and a real, rotation-prone CA chain — see this file's own doc comment"]
fn real_tls13_handshake_against_example_com() {
    let stream = TcpStream::connect("example.com:443").expect("TCP connect to example.com:443");
    stream
        .set_nodelay(true)
        .expect("set_nodelay on a real TcpStream");

    let root_ca = include_bytes!("fixtures/example_com_root.der");

    // Max TLS record size per `embedded_tls::blocking::TlsConnection::new`'s
    // own doc comment — real buffer sizing for a genuine Runix ring-3
    // consumer is exactly the still-open "heap-grant mechanism" item this
    // crate's own doc comment names, not decided here.
    let mut read_buf = vec![0u8; 16640];
    let mut write_buf = vec![0u8; 16640];

    let mut conn = TlsConnection::new(StdTransport(stream), NoYield, &mut read_buf, &mut write_buf);

    let config = runix_tls_client::Config::new().with_server_name("example.com");

    conn.open(&config, root_ca, OsEntropy)
        .expect("real TLS 1.3 handshake against example.com, verified against its real root CA");

    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    conn.write(request).expect("write HTTP request over TLS");
    conn.flush().expect("flush HTTP request");

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            Err(_) => break, // peer closing the connection surfaces as an error here, not a clean EOF
        }
        if response.len() > 65536 {
            break; // safety valve, not expected to trigger for example.com's real response
        }
    }

    let response_text = String::from_utf8_lossy(&response);
    assert!(
        response_text.starts_with("HTTP/1.1") || response_text.starts_with("HTTP/1.0"),
        "expected a real decrypted HTTP response, got: {:?}",
        &response_text[..response_text.len().min(200)]
    );
    assert!(
        response_text.contains("Example Domain") || response_text.contains("200"),
        "expected example.com's real page content or a 200 status in the decrypted response, got: {:?}",
        &response_text[..response_text.len().min(500)]
    );
}

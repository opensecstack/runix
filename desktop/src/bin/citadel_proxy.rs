//! Standalone binary: the TCP-facing CITADEL/MARSHAL proxy process.
//!
//! Listens on `CITADEL_PROXY_LISTEN_ADDR` (default
//! [`runix_desktop::citadel::proxy::DEFAULT_LISTEN_ADDR`]), accepts
//! `runix_ipc::marshal::MarshalRequest`s, forwards their carried
//! `kerkese_json` to CITADEL via
//! [`runix_desktop::citadel::HttpKerkeseTransport`] (configured from
//! `RUNIX_CITADEL_URL`, see that type's doc comment — this binary fails
//! closed rather than guessing an endpoint if it's unset), and writes back
//! a `MarshalResponse`.
//!
//! All the actual TCP/decode/encode/transport logic lives in
//! [`runix_desktop::citadel::proxy`] (`desktop/src/citadel/proxy.rs`) — this
//! `main` is deliberately thin so that logic stays independently testable
//! without spawning this binary as a subprocess.

use runix_desktop::citadel::proxy;
use runix_desktop::citadel::HttpKerkeseTransport;

fn main() {
    let listen_addr = std::env::var(proxy::LISTEN_ADDR_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| proxy::DEFAULT_LISTEN_ADDR.to_string());

    let transport = HttpKerkeseTransport::from_env();

    eprintln!("citadel_proxy: listening on {listen_addr}");
    if let Err(e) = proxy::serve(&listen_addr, transport) {
        eprintln!("citadel_proxy: fatal error binding {listen_addr}: {e}");
        std::process::exit(1);
    }
}

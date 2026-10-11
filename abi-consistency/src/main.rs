//! Checks that constants and wire layouts duplicated by hand between
//! `kernel/` and the standalone ring-3 hosts have not drifted.
//!
//! Usage: `cargo run -p abi-consistency [-- <repo-root>]` (defaults to the
//! repo this crate lives in). Exits non-zero, naming both files, on any
//! mismatch, missing constant, or unparsable value.

use abi_consistency::{compare, loc, parse_struct_fields, ConstTable, Loc};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const G: &str = "grid-sandbox-host/src/main.rs";
const N: &str = "net-driver-host/src/main.rs";
const NV: &str = "net-driver-host/src/virtio.rs";
const NS: &str = "net-driver-host/src/smoltcp_device.rs";
const NSYS: &str = "net-driver-host/src/syscall.rs";
const B: &str = "blk-driver-host/src/main.rs";
const BV: &str = "blk-driver-host/src/virtio.rs";
const BSYS: &str = "blk-driver-host/src/syscall.rs";
const KM: &str = "kernel/src/main.rs";
const KG: &str = "kernel/src/grid_sandbox.rs";
const KS: &str = "kernel/src/syscall.rs";

/// (host file, host const, kernel file, kernel const). Host is the
/// reference side; the kernel loader must map exactly what the host
/// expects.
const KERNEL_PAIRS: &[(&str, &str, &str, &str)] = &[
    // grid-sandbox-host
    (G, "HEAP_START", KM, "GRID_SANDBOX_HEAP_START"),
    (G, "HEAP_START", KG, "HEAP_START"),
    (G, "HEAP_SIZE", KM, "GRID_SANDBOX_HEAP_SIZE"),
    (G, "HEAP_SIZE", KG, "HEAP_SIZE"),
    (G, "GRID_INFO_VA", KM, "GRID_INFO_VA"),
    (G, "GRID_INFO_VA", KG, "INFO_VA"),
    (G, "GRID_GROW_RESULT_OFFSET", KM, "GRID_GROW_RESULT_OFFSET"),
    (G, "GRID_GROW_RESULT_OFFSET", KG, "GROW_RESULT_OFFSET"),
    (G, "GRID_GROW_RESULT_SUCCEEDED", KG, "GROW_RESULT_SUCCEEDED"),
    (G, "GRID_GROW_RESULT_FAILED", KG, "GROW_RESULT_FAILED"),
    // net-driver-host
    (N, "HEAP_START", KM, "NET_HEAP_START"),
    (N, "HEAP_SIZE", KM, "NET_HEAP_SIZE"),
    (N, "NET_INFO_VA", KM, "NET_INFO_VA"),
    (N, "NET_RXQ_VA", KM, "NET_RXQ_VA"),
    (N, "NET_TXQ_VA", KM, "NET_TXQ_VA"),
    (N, "NET_RXBUF_VA", KM, "NET_RXBUF_VA"),
    (N, "NET_TXBUF_VA", KM, "NET_TXBUF_VA"),
    (NS, "RX_BUFFER_COUNT", KM, "NET_RX_BUFFER_COUNT"),
    (NS, "TX_BUFFER_COUNT", KM, "NET_TX_BUFFER_COUNT"),
    (NV, "QUEUE_ALIGN", KM, "NET_QUEUE_ALIGN"),
    // blk-driver-host (the kernel reuses NET_QUEUE_ALIGN for blk queues)
    (B, "HEAP_START", KM, "BLK_HEAP_START"),
    (B, "HEAP_SIZE", KM, "BLK_HEAP_SIZE"),
    (B, "BLK_INFO_VA", KM, "BLK_INFO_VA"),
    (B, "BLK_QUEUE_VA", KM, "BLK_QUEUE_VA"),
    (B, "BLK_REQBUF_VA", KM, "BLK_REQBUF_VA"),
    (B, "FS_SERVER_PORT", KM, "BLK_FS_SERVER_PORT"),
    (B, "BLK_RESULT_OFFSET", KM, "BLK_RESULT_OFFSET"),
    (B, "BLK_FAT32_RESULT_OFFSET", KM, "BLK_FAT32_RESULT_OFFSET"),
    (B, "BLK_RESULT_PASS", KM, "BLK_RESULT_PASS"),
    (B, "BLK_RESULT_FAIL", KM, "BLK_RESULT_FAIL"),
    (BV, "QUEUE_ALIGN", KM, "NET_QUEUE_ALIGN"),
];

/// Constant name as spelled in `kernel/tests/*.rs` -> host reference.
/// Every test file that defines one of these names must agree with the
/// host. (Per-test stack sizes legitimately differ and are not listed.)
const TEST_NAMES: &[(&str, &str, &str)] = &[
    ("GRID_INFO_VA", G, "GRID_INFO_VA"),
    ("PAYLOAD_HEAP_START", G, "HEAP_START"),
    ("NET_HEAP_START", N, "HEAP_START"),
    ("NET_HEAP_SIZE", N, "HEAP_SIZE"),
    ("NET_INFO_VA", N, "NET_INFO_VA"),
    ("NET_RXQ_VA", N, "NET_RXQ_VA"),
    ("NET_TXQ_VA", N, "NET_TXQ_VA"),
    ("NET_RXBUF_VA", N, "NET_RXBUF_VA"),
    ("NET_TXBUF_VA", N, "NET_TXBUF_VA"),
    ("NET_QUEUE_ALIGN", NV, "QUEUE_ALIGN"),
    ("NET_RESULT_OFFSET", N, "NET_RESULT_OFFSET"),
    ("NET_TCP_RESULT_OFFSET", N, "NET_TCP_RESULT_OFFSET"),
    ("NET_DHCP_RESULT_OFFSET", N, "NET_DHCP_RESULT_OFFSET"),
    ("NET_DHCP_ADDR_OFFSET", N, "NET_DHCP_ADDR_OFFSET"),
    ("NET_DNS_RESULT_OFFSET", N, "NET_DNS_RESULT_OFFSET"),
    ("NET_DNS_ADDR_OFFSET", N, "NET_DNS_ADDR_OFFSET"),
    ("NET_RESULT_PASS", N, "NET_RESULT_PASS"),
    ("SOCKETS_SERVER_PORT", N, "SOCKETS_SERVER_PORT"),
    ("BLK_HEAP_START", B, "HEAP_START"),
    ("BLK_HEAP_SIZE", B, "HEAP_SIZE"),
    ("BLK_INFO_VA", B, "BLK_INFO_VA"),
    ("BLK_QUEUE_VA", B, "BLK_QUEUE_VA"),
    ("BLK_REQBUF_VA", B, "BLK_REQBUF_VA"),
    ("BLK_QUEUE_ALIGN", BV, "QUEUE_ALIGN"),
    ("BLK_RESULT_OFFSET", B, "BLK_RESULT_OFFSET"),
    ("BLK_FAT32_RESULT_OFFSET", B, "BLK_FAT32_RESULT_OFFSET"),
    ("BLK_RESULT_PASS", B, "BLK_RESULT_PASS"),
    ("FS_SERVER_PORT", B, "FS_SERVER_PORT"),
];

/// Files whose every `SYS_*` const must equal `kernel/src/syscall.rs`'s
/// const of the same name (kernel/tests/*.rs are added automatically).
const SYSCALL_FILES: &[&str] = &[G, NSYS, BSYS];

/// (struct name, host file, kernel file); kernel/tests/*.rs mirrors are
/// compared against the host too, but only as a field *prefix*: a test that
/// predates later trailing fields (zero-filled boot page) stays valid.
const STRUCTS: &[(&str, &str, &str)] = &[("NetBootInfo", N, KM), ("BlkBootInfo", B, KM)];

struct Repo {
    root: PathBuf,
    src: HashMap<String, Result<String, String>>,
}

impl Repo {
    fn text(&mut self, rel: &str) -> Result<&str, String> {
        let root = self.root.clone();
        self.src
            .entry(rel.to_string())
            .or_insert_with(|| {
                std::fs::read_to_string(root.join(rel))
                    .map_err(|e| format!("{rel}: cannot read: {e}"))
            })
            .as_ref()
            .map(String::as_str)
            .map_err(Clone::clone)
    }

    fn table(&mut self, rel: &str) -> Result<ConstTable, String> {
        self.text(rel).map(ConstTable::from_source)
    }

    fn value(&mut self, l: &Loc) -> Result<i128, String> {
        self.table(&l.file)?.value(&l.name)
    }

    fn test_files(&self) -> Result<Vec<String>, String> {
        let dir = self.root.join("kernel/tests");
        let mut v: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| format!("kernel/tests: cannot read dir: {e}"))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
            .map(|e| format!("kernel/tests/{}", e.file_name().to_string_lossy()))
            .collect();
        v.sort();
        Ok(v)
    }
}

/// Run every check; returns (number of checks, failure messages).
fn run(root: &Path) -> (usize, Vec<String>) {
    let mut repo = Repo {
        root: root.to_path_buf(),
        src: HashMap::new(),
    };
    let mut checks = 0;
    let mut fails = Vec::new();
    let pair = |repo: &mut Repo, a: Loc, b: Loc, checks: &mut usize, fails: &mut Vec<String>| {
        *checks += 1;
        let (av, bv) = (repo.value(&a), repo.value(&b));
        if let Err(e) = compare(&a, av, &b, bv) {
            fails.push(e);
        }
    };

    for (hf, hc, kf, kc) in KERNEL_PAIRS {
        pair(&mut repo, loc(hf, hc), loc(kf, kc), &mut checks, &mut fails);
    }

    let tests = match repo.test_files() {
        Ok(t) => t,
        Err(e) => {
            fails.push(e);
            Vec::new()
        }
    };
    for t in &tests {
        let table = match repo.table(t) {
            Ok(x) => x,
            Err(e) => {
                fails.push(e);
                continue;
            }
        };
        for (tn, hf, hc) in TEST_NAMES {
            if table.contains(tn) {
                pair(&mut repo, loc(hf, hc), loc(t, tn), &mut checks, &mut fails);
            }
        }
    }

    // Syscall numbers: every SYS_* in a host/test file must exist in the
    // kernel with the same value.
    let mut sys_files: Vec<String> = SYSCALL_FILES.iter().map(|s| s.to_string()).collect();
    sys_files.extend(tests.iter().cloned());
    for f in &sys_files {
        let table = match repo.table(f) {
            Ok(x) => x,
            Err(e) => {
                fails.push(e);
                continue;
            }
        };
        for name in table.names().into_iter().filter(|n| n.starts_with("SYS_")) {
            pair(
                &mut repo,
                loc(f, name),
                loc(KS, name),
                &mut checks,
                &mut fails,
            );
        }
        if SYSCALL_FILES.contains(&f.as_str())
            && !table.names().iter().any(|n| n.starts_with("SYS_"))
        {
            fails.push(format!(
                "{f}: no SYS_* constants found (parser or file layout changed?)"
            ));
        }
    }

    // Boot-info struct layouts (field names, order, types, array lengths).
    let ns = repo.table(NS).unwrap_or_default();
    for (sname, host, kernel) in STRUCTS {
        let mut sides: Vec<String> = vec![kernel.to_string()];
        for t in &tests {
            if repo
                .text(t)
                .is_ok_and(|s| s.contains(&format!("struct {sname} ")))
            {
                sides.push(t.clone());
            }
        }
        let host_fields = fields(&mut repo, host, sname, &ns);
        for other in sides {
            checks += 1;
            let other_fields = fields(&mut repo, &other, sname, &ns);
            match (host_fields.as_ref(), other_fields.as_ref()) {
                (Ok(h), Ok(o)) if h == o || (other.starts_with("kernel/tests/") && h.starts_with(o)) => {}
                (Ok(h), Ok(o)) => fails.push(format!(
                    "MISMATCH: struct {sname} differs between {host} and {other}\n    {host}: {h:?}\n    {other}: {o:?}"
                )),
                (Err(e), _) | (_, Err(e)) => fails.push(format!("struct {sname} ({host} vs {other}): {e}")),
            }
        }
    }
    (checks, fails)
}

fn fields(
    repo: &mut Repo,
    file: &str,
    sname: &str,
    extra: &ConstTable,
) -> Result<Vec<(String, String)>, String> {
    let own = repo.table(file)?;
    let src = repo.text(file)?.to_string();
    let env = |n: &str| own.value(n).or_else(|_| extra.value(n));
    parse_struct_fields(&src, sname, &env).map_err(|e| format!("{file}: {e}"))
}

fn main() -> ExitCode {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
    let (checks, fails) = run(&root);
    if fails.is_empty() {
        println!("abi-consistency: {checks} checks passed");
        ExitCode::SUCCESS
    } else {
        for f in &fails {
            eprintln!("abi-consistency: {f}");
        }
        eprintln!("abi-consistency: {} of {checks} checks FAILED", fails.len());
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real repo must be consistent (so `cargo test --workspace` also
    /// catches drift, not only the dedicated CI step).
    #[test]
    fn repo_constants_are_consistent() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let (checks, fails) = run(&root);
        assert!(checks > 100, "suspiciously few checks ran: {checks}");
        assert!(fails.is_empty(), "{}", fails.join("\n"));
    }
}

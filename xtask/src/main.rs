//! `cargo run -p xtask -- build [--release]` builds the kernel for
//! `x86_64-unknown-none` and wraps it into a bootable BIOS disk image.
//! `cargo run -p xtask -- run [--release]` does the same, then boots it in
//! QEMU with the serial port wired to stdio.
//! `cargo run -p xtask -- test-runner <path-to-test-binary> [...]` is not
//! meant to be invoked by hand — it's what `kernel/.cargo/config.toml`'s
//! `runner` points `cargo test` at, so `cargo test` (run from `kernel/`)
//! boots each `tests/*.rs` integration test for real in QEMU and reports
//! pass/fail from the isa-debug-exit device instead of a host-native
//! process exit code.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live directly under the repo root")
        .to_path_buf()
}

fn build_kernel(root: &Path, release: bool) -> PathBuf {
    let kernel_dir = root.join("kernel");
    let mut cmd = Command::new("cargo");
    // `--target` explicit, not relied on as a `.cargo/config.toml`
    // ambient default: kernel/.cargo/config.toml deliberately has none
    // (see the "config leak" note in the top-level README) — without this,
    // `cargo build` here silently targets the host instead of
    // x86_64-unknown-none, producing confusing, unrelated-looking errors
    // (e.g. naked-asm codegen failures) rather than an obvious "wrong
    // target" one.
    cmd.current_dir(&kernel_dir)
        .arg("build")
        .arg("--target")
        .arg("x86_64-unknown-none");
    if release {
        cmd.arg("--release");
    }
    let status = cmd
        .status()
        .expect("failed to invoke cargo for the kernel build");
    if !status.success() {
        panic!("kernel build failed (exit status: {status})");
    }
    let profile = if release { "release" } else { "debug" };
    kernel_dir
        .join("target")
        .join("x86_64-unknown-none")
        .join(profile)
        .join("runix-kernel")
}

fn build_image(root: &Path, release: bool) -> PathBuf {
    let kernel_path = build_kernel(root, release);
    image_from_binary(root, &kernel_path, "runix-bios.img")
}

/// Wraps an already-built freestanding ELF (any of them — the kernel's own
/// binary, or one of `kernel/tests/*.rs`'s standalone test binaries) into a
/// bootable BIOS image. `image_name` keeps concurrent `build`/`run` and
/// `test-runner` invocations from clobbering each other's output file.
fn image_from_binary(root: &Path, binary_path: &Path, image_name: &str) -> PathBuf {
    let out_dir = root.join("target");
    std::fs::create_dir_all(&out_dir).expect("failed to create target/ output dir");
    let bios_path = out_dir.join(image_name);
    bootloader::BiosBoot::new(binary_path)
        .create_disk_image(&bios_path)
        .unwrap_or_else(|e| panic!("failed to build BIOS boot image from {binary_path:?}: {e}"));
    bios_path
}

/// Windows' winget-installed QEMU doesn't reliably end up on `PATH` for
/// every shell (a `PATH` update to the registry doesn't retroactively apply
/// to already-running shells, including whatever long-lived one is invoking
/// `cargo test`) — fall back to the default winget install location rather
/// than making every contributor's shell session state this xtask's problem.
const WINDOWS_FALLBACK_QEMU: &str = r"C:\Program Files\qemu\qemu-system-x86_64.exe";

fn qemu_command() -> Command {
    if Command::new("qemu-system-x86_64")
        .arg("--version")
        .output()
        .is_ok()
    {
        return Command::new("qemu-system-x86_64");
    }
    if cfg!(windows) && Path::new(WINDOWS_FALLBACK_QEMU).exists() {
        return Command::new(WINDOWS_FALLBACK_QEMU);
    }
    Command::new("qemu-system-x86_64") // let the real invocation's error speak
}

fn run_qemu(bios_path: &Path, exit_device: bool) -> ExitStatus {
    let mut cmd = qemu_command();
    cmd.arg("-drive")
        .arg(format!("format=raw,file={}", bios_path.display()))
        .arg("-serial")
        .arg("stdio")
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        // Gives every boot/test a real virtio-net PCI device to find —
        // `kernel/src/pci.rs`'s enumeration (the first slice of network
        // stack work; see README) has something concrete to look for
        // instead of only being exercisable once a real driver exists.
        // Explicit `-netdev`/`-device` rather than relying on QEMU's
        // default NIC: the default is an e1000, not virtio-net, and
        // "whatever QEMU defaults to" isn't a stable thing to test against.
        .arg("-netdev")
        .arg("user,id=net0")
        .arg("-device")
        .arg("virtio-net-pci,netdev=net0");
    if exit_device {
        cmd.arg("-device")
            .arg("isa-debug-exit,iobase=0xf4,iosize=0x04");
    }
    cmd.status()
        .expect("failed to launch qemu-system-x86_64 — is QEMU installed and on PATH?")
}

/// `isa-debug-exit` makes QEMU itself exit with `(value << 1) | 1`, where
/// `value` is whatever the guest wrote to port 0xf4 — see
/// `kernel/src/qemu_exit.rs`. Translate that back into the plain 0-pass /
/// 1-fail exit code `cargo test`'s `runner` protocol expects.
fn exit_code_from_qemu(status: ExitStatus) -> i32 {
    const SUCCESS: i32 = (0x10 << 1) | 1; // QemuExitCode::Success
    const FAILED: i32 = (0x11 << 1) | 1; // QemuExitCode::Failed

    match status.code() {
        Some(SUCCESS) => 0,
        Some(FAILED) => {
            eprintln!("test-runner: kernel reported test failure");
            1
        }
        Some(other) => {
            eprintln!(
                "test-runner: unexpected QEMU exit code {other} (expected {SUCCESS} or {FAILED} \
                 from isa-debug-exit — did the test binary forget to call qemu_exit::exit_qemu, \
                 or hang instead of exiting?)"
            );
            1
        }
        None => {
            eprintln!("test-runner: QEMU exited without a status code (killed by signal?)");
            1
        }
    }
}

fn main() {
    let root = workspace_root();

    let mut positional: Vec<String> = Vec::new();
    let mut release = false;
    for arg in env::args().skip(1) {
        if arg == "--release" {
            release = true;
        } else {
            positional.push(arg);
        }
    }

    let action = positional
        .first()
        .cloned()
        .unwrap_or_else(|| "build".to_string());

    match action.as_str() {
        "build" => {
            let bios_path = build_image(&root, release);
            println!("built BIOS image: {}", bios_path.display());
        }
        "run" => {
            let bios_path = build_image(&root, release);
            let status = run_qemu(&bios_path, false);
            std::process::exit(status.code().unwrap_or(1));
        }
        "test-runner" => {
            // Cargo's `runner` protocol invokes us as
            // `<runner> <path-to-test-binary> [args cargo/libtest wants to
            // pass the test binary]`. We don't use a libtest harness at all
            // (each `tests/*.rs` file is its own bootable kernel, not a
            // `#[test]`-annotated function), so anything past the binary
            // path is irrelevant here and intentionally ignored.
            let test_binary = positional.get(1).unwrap_or_else(|| {
                eprintln!(
                    "test-runner: expected a path to a test binary as the first argument \
                     (this is meant to be invoked by `cargo test` via kernel/.cargo/config.toml's \
                     `runner`, not by hand)"
                );
                std::process::exit(1);
            });
            let bios_path = image_from_binary(&root, Path::new(test_binary), "test-bios.img");
            let status = run_qemu(&bios_path, true);
            std::process::exit(exit_code_from_qemu(status));
        }
        other => {
            eprintln!(
                "unknown xtask action '{other}' (expected 'build', 'run', or 'test-runner', \
                 optionally with --release)"
            );
            std::process::exit(1);
        }
    }
}

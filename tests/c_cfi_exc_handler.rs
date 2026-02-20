//! Integration tests for exc_handler with clang CFI-instrumented C binaries.
//!
//! These tests build a C crash dummy binary (compiled with Homebrew LLVM clang
//! using `-fsanitize=cfi -fno-sanitize-trap=cfi -flto -fvisibility=hidden`) and
//! run it under exc_handler to verify that CFI-detected control flow violations
//! from C binaries are handled correctly.
//!
//! CFI requires Homebrew LLVM clang — Apple clang does not support `-fsanitize=cfi`.
//! In diagnostic mode (`-fno-sanitize-trap=cfi`), the UBSan runtime is linked and
//! populates `___crashreporter_info__` with the CFI error report before aborting.
//!
//! All CFI crashes in diagnostic mode arrive as `EXC_CRASH` (exception type 10) →
//! signal 6 (SIGABRT) → `NotExploitable`.
//!
//! Tests skip gracefully if:
//! - Homebrew LLVM clang is not installed or the build fails
//! - exc_handler probe fails (missing debugger entitlement)

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Builds the C CFI crash dummy binary with Homebrew LLVM clang.
/// Returns the binary path on success, or None if the build fails.
fn build_c_cfi_crash_dummy() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir.join("test-fixtures").join("c-cfi");

    let source = crate_dir.join("crash_dummy.c");
    if !source.exists() {
        eprintln!("SKIP: test-fixtures/c-cfi/crash_dummy.c not found");
        return None;
    }

    let output = Command::new("make")
        .arg("-C")
        .arg(&crate_dir)
        .arg("clean")
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!("SKIP: make clean failed");
        return None;
    }

    let output = Command::new("make")
        .arg("-C")
        .arg(&crate_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("not found") || stderr.contains("SKIP") {
            eprintln!("SKIP: Homebrew LLVM clang not available (Apple clang does not support CFI)");
        } else {
            eprintln!(
                "SKIP: c-cfi-crash-dummy build failed (exit {:?}):\n{}",
                output.status.code(),
                stderr
            );
        }
        return None;
    }

    let binary = crate_dir.join("c-cfi-crash-dummy");
    if binary.exists() {
        Some(binary)
    } else {
        eprintln!(
            "SKIP: c-cfi-crash-dummy binary not found at {}",
            binary.display()
        );
        None
    }
}

/// Cached C CFI binary path. Built once per test process.
fn c_cfi_crash_dummy_path() -> Option<&'static PathBuf> {
    static BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    BINARY.get_or_init(build_c_cfi_crash_dummy).as_ref()
}

/// Unique lock file path per test to avoid conflicts during parallel execution.
fn unique_lock_file(test_name: &str) -> String {
    format!(
        "{}/crashrustler-c-cfi-{}-{}.lck",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    )
}

/// Probes whether exc_handler can function (needs debug entitlement on macOS).
fn probe_exc_handler(test_name: &str) -> bool {
    let lock_file = format!(
        "{}/crashrustler-c-cfi-probe-{}-{}.lck",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_exc_handler"))
        .arg(env!("CARGO_BIN_EXE_crash_dummy"))
        .arg("exit0")
        .env("CR_QUIET", "1")
        .env("CR_NO_LOG", "1")
        .env("CR_LOCK_FILE", &lock_file)
        .output();

    let _ = std::fs::remove_file(&lock_file);

    match output {
        Ok(o) => {
            if o.status.code() != Some(0) {
                eprintln!(
                    "SKIPPED {test_name}: exc_handler probe returned {:?} (missing entitlement?)",
                    o.status.code()
                );
                false
            } else {
                true
            }
        }
        Err(e) => {
            eprintln!("SKIPPED {test_name}: exc_handler probe failed: {e}");
            false
        }
    }
}

/// Runs exc_handler with the C CFI crash dummy binary.
fn run_exc_handler_c_cfi(
    crash_mode: &str,
    test_name: &str,
    extra_envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    let cfi_binary = c_cfi_crash_dummy_path()?;

    if !probe_exc_handler(test_name) {
        return None;
    }

    let lock_file = unique_lock_file(test_name);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_exc_handler"));
    cmd.arg(cfi_binary)
        .arg(crash_mode)
        .env("CR_QUIET", "1")
        .env("CR_LOCK_FILE", &lock_file);

    let has_log_dir = extra_envs.iter().any(|(k, _)| *k == "CR_LOG_DIR");
    let has_no_log = extra_envs.iter().any(|(k, _)| *k == "CR_NO_LOG");
    if !has_log_dir && !has_no_log {
        let _ = std::fs::create_dir_all("./crashlogs");
        cmd.env("CR_LOG_DIR", "./crashlogs");
    }

    for &(k, v) in extra_envs {
        cmd.env(k, v);
    }

    let output = cmd.output().expect("failed to execute exc_handler");
    let _ = std::fs::remove_file(&lock_file);

    Some(output)
}

/// Runs exc_handler with C CFI binary, writes crash log to a known path, returns content.
fn run_and_read_crash_log(crash_mode: &str, test_name: &str) -> Option<String> {
    let log_path = format!(
        "{}/crashrustler-c-cfi-{}-{}.crashlog.txt",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output =
        run_exc_handler_c_cfi(crash_mode, test_name, &[("CR_LOG_PATH", log_path.as_str())])?;

    let code = output.status.code().unwrap_or(-1);
    assert!(
        code >= 0,
        "{test_name}: exc_handler exited with unexpected code {code}"
    );

    let content = std::fs::read_to_string(&log_path).ok();
    let _ = std::fs::remove_file(&log_path);
    content
}

// ============================================================================
// Exit code tests — CFI diagnostic mode → EXC_CRASH → SIGABRT → exit code 6
// ============================================================================

#[test]
fn c_cfi_icall_returns_signal() {
    let Some(output) = run_exc_handler_c_cfi("cfi_icall", "c_cfi_icall", &[]) else {
        return;
    };
    assert_eq!(output.status.code(), Some(6));
}

// ============================================================================
// Crash log content tests — verify ___crashreporter_info__ extraction
// ============================================================================

#[test]
fn c_cfi_icall_crash_log() {
    let Some(log) = run_and_read_crash_log("cfi_icall", "c_cfi_icall_log") else {
        return;
    };

    assert!(
        log.contains("Thread 0 Crashed"),
        "Expected 'Thread 0 Crashed' in crash log:\n{log}"
    );
    assert!(
        log.contains("NOT_EXPLOITABLE"),
        "Expected 'NOT_EXPLOITABLE' in crash log:\n{log}"
    );
    assert!(
        log.contains("Application Specific Information:"),
        "Expected 'Application Specific Information:' section in crash log:\n{log}"
    );
    assert!(
        log.contains("runtime error:"),
        "Expected 'runtime error:' in CFI report:\n{log}"
    );
    assert!(
        log.contains("control flow integrity check"),
        "Expected 'control flow integrity check' in CFI report:\n{log}"
    );
}

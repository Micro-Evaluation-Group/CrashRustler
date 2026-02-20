//! Integration tests for exc_handler with clang TSan-instrumented C binaries.
//!
//! These tests build a C crash dummy binary (compiled with `clang -fsanitize=thread`)
//! and run it under exc_handler to verify that TSan-detected data races from C binaries
//! are handled correctly, including `__crash_info` section extraction.
//!
//! TSan detects the race and calls `abort()`, so all TSan crashes arrive
//! as `EXC_CRASH` (exception type 10) → signal 6 (SIGABRT) → `NotExploitable`.
//!
//! Tests skip gracefully if:
//! - clang is not available or the build fails
//! - exc_handler probe fails (missing debugger entitlement)

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Builds the C TSan crash dummy binary with clang -fsanitize=thread.
/// Returns the binary path on success, or None if the build fails.
fn build_c_tsan_crash_dummy() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir.join("test-fixtures").join("c-tsan");

    let source = crate_dir.join("crash_dummy.c");
    if !source.exists() {
        eprintln!("SKIP: test-fixtures/c-tsan/crash_dummy.c not found");
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
        eprintln!(
            "SKIP: c-tsan-crash-dummy build failed (exit {:?}):\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    let binary = crate_dir.join("c-tsan-crash-dummy");
    if binary.exists() {
        Some(binary)
    } else {
        eprintln!(
            "SKIP: c-tsan-crash-dummy binary not found at {}",
            binary.display()
        );
        None
    }
}

/// Cached C TSan binary path. Built once per test process.
fn c_tsan_crash_dummy_path() -> Option<&'static PathBuf> {
    static BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    BINARY.get_or_init(build_c_tsan_crash_dummy).as_ref()
}

/// Unique lock file path per test to avoid conflicts during parallel execution.
fn unique_lock_file(test_name: &str) -> String {
    format!(
        "{}/crashrustler-c-tsan-{}-{}.lck",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    )
}

/// Probes whether exc_handler can function (needs debug entitlement on macOS).
fn probe_exc_handler(test_name: &str) -> bool {
    let lock_file = format!(
        "{}/crashrustler-c-tsan-probe-{}-{}.lck",
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

/// Runs exc_handler with the C TSan crash dummy binary.
fn run_exc_handler_c_tsan(
    crash_mode: &str,
    test_name: &str,
    extra_envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    let tsan_binary = c_tsan_crash_dummy_path()?;

    if !probe_exc_handler(test_name) {
        return None;
    }

    let lock_file = unique_lock_file(test_name);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_exc_handler"));
    cmd.arg(tsan_binary)
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

/// Runs exc_handler with C TSan binary, writes crash log to a known path, returns content.
fn run_and_read_crash_log(crash_mode: &str, test_name: &str) -> Option<String> {
    let log_path = format!(
        "{}/crashrustler-c-tsan-{}-{}.crashlog.txt",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output =
        run_exc_handler_c_tsan(crash_mode, test_name, &[("CR_LOG_PATH", log_path.as_str())])?;

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
// Exit code tests — all TSan crashes → EXC_CRASH → SIGABRT → exit code 6
// ============================================================================

#[test]
fn c_tsan_data_race_returns_signal() {
    let Some(output) = run_exc_handler_c_tsan("data_race", "c_tsan_data_race", &[]) else {
        return;
    };
    assert_eq!(output.status.code(), Some(6));
}

#[test]
fn c_tsan_heap_race_returns_signal() {
    let Some(output) = run_exc_handler_c_tsan("heap_race", "c_tsan_heap_race", &[]) else {
        return;
    };
    assert_eq!(output.status.code(), Some(6));
}

// ============================================================================
// Crash log content tests — verify __crash_info section extraction
// ============================================================================

#[test]
fn c_tsan_data_race_crash_log() {
    let Some(log) = run_and_read_crash_log("data_race", "c_tsan_data_race_log") else {
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
        log.contains("data race"),
        "Expected 'data race' in TSan report:\n{log}"
    );
}

#[test]
fn c_tsan_heap_race_crash_log() {
    let Some(log) = run_and_read_crash_log("heap_race", "c_tsan_heap_race_log") else {
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
        log.contains("data race"),
        "Expected 'data race' in TSan report:\n{log}"
    );
}

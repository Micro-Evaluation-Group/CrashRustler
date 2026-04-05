//! Integration tests for ASan crash report extraction with multiple sanitizer-instrumented
//! dynamic libraries loaded simultaneously.
//!
//! These tests verify that exc_handler correctly extracts the sanitizer error report
//! from the ASan runtime when multiple ASan-instrumented dylibs are loaded but only
//! one triggers a violation. The crash dummy links lib_safe.dylib (valid operations)
//! and lib_buggy.dylib (heap-buffer-overflow), calls safe first, then buggy.
//!
//! This validates that the crash reporter info extraction iterates correctly and
//! returns the report from the triggering module, not from a non-faulting module.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Builds the multi-lib ASan crash dummy and its two dynamic libraries.
fn build_multilib_crash_dummy() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_dir = manifest_dir.join("test-fixtures").join("c-asan-multilib");

    if !fixture_dir.join("main.c").exists() {
        eprintln!("SKIP: test-fixtures/c-asan-multilib/main.c not found");
        return None;
    }

    let output = Command::new("make")
        .arg("-C")
        .arg(&fixture_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        eprintln!(
            "SKIP: c-asan-multilib build failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    let binary = fixture_dir.join("c-asan-multilib-crash-dummy");
    if binary.exists() {
        Some(binary)
    } else {
        eprintln!("SKIP: c-asan-multilib-crash-dummy not found after build");
        None
    }
}

fn multilib_crash_dummy_path() -> Option<&'static PathBuf> {
    static BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    BINARY.get_or_init(build_multilib_crash_dummy).as_ref()
}

/// Probes whether exc_handler works (has entitlement).
fn probe_exc_handler() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        let output = Command::new(env!("CARGO_BIN_EXE_exc_handler"))
            .arg(env!("CARGO_BIN_EXE_crash_dummy"))
            .arg("exit0")
            .env("CR_QUIET", "1")
            .env("CR_NO_LOG", "1")
            .output()
            .ok();
        match output {
            Some(o) => o.status.code() == Some(0),
            None => false,
        }
    })
}

fn run_multilib_test(test_name: &str) -> Option<(i32, String)> {
    if !probe_exc_handler() {
        eprintln!("SKIP: exc_handler probe failed");
        return None;
    }
    let binary = multilib_crash_dummy_path()?;

    let log_path = format!(
        "{}/crashrustler-multilib-{}-{}.crashlog.txt",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output = Command::new(env!("CARGO_BIN_EXE_exc_handler"))
        .arg(binary)
        .env("CR_LOG_PATH", &log_path)
        .output()
        .expect("failed to spawn exc_handler");

    let code = output.status.code().unwrap_or(-1);
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let _ = std::fs::remove_file(&log_path);

    Some((code, log))
}

#[test]
fn multilib_asan_returns_signal() {
    let Some((code, _)) = run_multilib_test("exit_code") else {
        return;
    };
    // ASan abort → SIGABRT → exit code 6
    assert_eq!(code, 6);
}

#[test]
fn multilib_asan_crash_log_contains_heap_buffer_overflow() {
    let Some((_, log)) = run_multilib_test("crash_log") else {
        return;
    };

    assert!(
        log.contains("Application Specific Information:"),
        "Expected 'Application Specific Information:' in crash log:\n{log}"
    );
    assert!(
        log.contains("heap-buffer-overflow"),
        "Expected 'heap-buffer-overflow' in ASan report:\n{log}"
    );
}

#[test]
fn multilib_asan_crash_log_identifies_buggy_module() {
    let Some((_, log)) = run_multilib_test("buggy_module") else {
        return;
    };

    // The ASan report must reference lib_buggy.c, not lib_safe.c
    assert!(
        log.contains("buggy_heap_overflow"),
        "Expected 'buggy_heap_overflow' in ASan report — report should identify the buggy module:\n{log}"
    );
    assert!(
        log.contains("lib_buggy.c"),
        "Expected 'lib_buggy.c' in ASan report — report should reference the source file:\n{log}"
    );
}

#[test]
fn multilib_asan_crash_log_does_not_blame_safe_module() {
    let Some((_, log)) = run_multilib_test("safe_module") else {
        return;
    };

    // Extract the Application Specific Information section
    let asi = log
        .split("Application Specific Information:")
        .nth(1)
        .unwrap_or("");

    // The safe library should not appear as the error source in the ASan report.
    // It may appear in the binary images list, but NOT in the error report itself.
    assert!(
        !asi.contains("safe_heap_operation"),
        "ASan report should NOT reference 'safe_heap_operation' — wrong module identified:\n{asi}"
    );
}

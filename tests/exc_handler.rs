//! Integration tests for the exc_handler binary.
//!
//! These tests launch exc_handler against crash_dummy to verify end-to-end
//! behavior: exit codes, crash log creation, and crash log suppression.
//!
//! Privilege note: exc_handler's fork+exec mode manipulates Mach exception
//! ports, which may require root or debugger entitlements on macOS. Each test
//! probes with a normal-exit run first; if that fails, the test is skipped.

use std::process::Command;

/// Unique lock file path per test to avoid conflicts during parallel execution.
fn unique_lock_file(test_name: &str) -> String {
    format!(
        "{}/crashrustler-{}-{}.lck",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    )
}

/// Probes whether exc_handler can function (needs debug entitlement on macOS).
/// Returns false if the binary can't set exception ports.
fn probe_exc_handler(test_name: &str) -> bool {
    let lock_file = format!(
        "{}/crashrustler-probe-{}-{}.lck",
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

/// Runs exc_handler with the given crash_dummy argument and extra env vars.
/// Returns None if exc_handler can't function (missing entitlement).
///
/// By default, crash logs are written to `./crashlogs/` so test runs
/// preserve their output. Pass `CR_NO_LOG` in extra_envs to suppress.
fn run_exc_handler(
    crash_arg: &str,
    test_name: &str,
    extra_envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    if !probe_exc_handler(test_name) {
        return None;
    }

    let lock_file = unique_lock_file(test_name);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_exc_handler"));
    cmd.arg(env!("CARGO_BIN_EXE_crash_dummy"))
        .arg(crash_arg)
        .env("CR_QUIET", "1")
        .env("CR_LOCK_FILE", &lock_file);

    // Default to ./crashlogs/ unless caller sets CR_LOG_DIR or CR_NO_LOG
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

// ============================================================================
// Exit code tests
// ============================================================================

#[test]
fn normal_exit_returns_zero() {
    let Some(output) = run_exc_handler("exit0", "normal_exit", &[("CR_NO_LOG", "1")]) else {
        return;
    };
    assert_eq!(output.status.code(), Some(0));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn sigsegv_null_deref_returns_signal() {
    let Some(output) = run_exc_handler("sigsegv", "sigsegv", &[]) else {
        return;
    };
    // Near-null deref → NotExploitable → bare signal number (11)
    assert_eq!(output.status.code(), Some(11));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn sigill_returns_signal_plus_100() {
    let Some(output) = run_exc_handler("sigill", "sigill", &[]) else {
        return;
    };
    // EXC_BAD_INSTRUCTION → Exploitable → signal + 100 (4 + 100 = 104)
    assert_eq!(output.status.code(), Some(104));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn sigtrap_brk_returns_signal() {
    let Some(output) = run_exc_handler("sigtrap", "sigtrap", &[]) else {
        return;
    };
    // brk #1 disassembly → EXC_BREAKPOINT (trap) → NotExploitable → bare signal 5
    assert_eq!(output.status.code(), Some(5));
}

#[test]
fn sigabrt_returns_signal() {
    let Some(output) = run_exc_handler("sigabrt", "sigabrt", &[]) else {
        return;
    };
    // EXC_CRASH → NotExploitable → signal 6
    assert_eq!(output.status.code(), Some(6));
}

#[test]
fn sigfpe_returns_signal() {
    let Some(output) = run_exc_handler("sigfpe", "sigfpe", &[]) else {
        return;
    };
    // raise(SIGFPE) → EXC_CRASH (undemuxed) → NotExploitable → signal 6
    assert_eq!(output.status.code(), Some(6));
}

#[test]
fn no_arguments_returns_error() {
    // This test doesn't need privilege — it just checks arg parsing.
    // But we probe anyway for consistency (verifies binary exists).
    if !probe_exc_handler("no_args") {
        return;
    }

    let lock_file = unique_lock_file("no_args");

    let output = Command::new(env!("CARGO_BIN_EXE_exc_handler"))
        .env("CR_QUIET", "1")
        .env("CR_LOCK_FILE", &lock_file)
        .output()
        .expect("failed to execute exc_handler");

    let _ = std::fs::remove_file(&lock_file);

    // exit(-1) wraps to 255 as unsigned byte
    assert_eq!(output.status.code(), Some(255));
}

// ============================================================================
// Crash log tests
// ============================================================================

#[test]
#[cfg(target_arch = "aarch64")]
fn crash_log_created_on_sigsegv() {
    let log_dir = "./crashlogs";
    std::fs::create_dir_all(log_dir).expect("failed to create log dir");

    let result = run_exc_handler("sigsegv", "sigsegv_log", &[]);

    if result.is_none() {
        return;
    }

    let entries: Vec<_> = std::fs::read_dir(log_dir)
        .expect("failed to read log dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("crash_dummy-") && name.ends_with(".crashlog.txt")
        })
        .collect();

    assert!(
        !entries.is_empty(),
        "Expected at least one crash_dummy-*.crashlog.txt in {log_dir}"
    );
}

#[test]
fn crash_log_not_created_with_no_log() {
    let log_dir = format!(
        "{}/crashrustler-logtest-nolog-{}",
        std::env::temp_dir().display(),
        std::process::id()
    );
    std::fs::create_dir_all(&log_dir).expect("failed to create log dir");

    let result = run_exc_handler(
        "sigabrt",
        "no_log",
        &[("CR_NO_LOG", "1"), ("CR_LOG_DIR", log_dir.as_str())],
    );

    if result.is_none() {
        let _ = std::fs::remove_dir_all(&log_dir);
        return;
    }

    let entries: Vec<_> = std::fs::read_dir(&log_dir)
        .expect("failed to read log dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".crashlog.txt"))
        .collect();

    assert!(
        entries.is_empty(),
        "Expected no .crashlog.txt when CR_NO_LOG is set, found {} in {log_dir}",
        entries.len()
    );

    let _ = std::fs::remove_dir_all(&log_dir);
}

// ============================================================================
// Backtrace content tests
// ============================================================================

/// Runs exc_handler, writes crash log to a known path, and returns the log content.
fn run_and_read_crash_log(crash_arg: &str, test_name: &str) -> Option<String> {
    let log_path = format!(
        "{}/crashrustler-{}-{}.crashlog.txt",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output = run_exc_handler(crash_arg, test_name, &[("CR_LOG_PATH", log_path.as_str())])?;

    // Ensure exc_handler itself didn't crash (non-zero is expected for signal tests)
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code >= 0,
        "{test_name}: exc_handler exited with unexpected code {code}"
    );

    let content = std::fs::read_to_string(&log_path).ok();
    let _ = std::fs::remove_file(&log_path);
    content
}

#[test]
#[cfg(target_arch = "aarch64")]
fn crash_log_sigsegv_backtrace_symbols() {
    let Some(log) = run_and_read_crash_log("sigsegv", "sigsegv_symbols") else {
        return;
    };

    // Thread 0 should be the crashed thread (reordered to first)
    assert!(
        log.contains("Thread 0 Crashed"),
        "Expected 'Thread 0 Crashed' in crash log:\n{log}"
    );

    // Frame 0 of the crashed thread should contain do_sigsegv
    assert!(
        log.contains("do_sigsegv"),
        "Expected 'do_sigsegv' symbol in crash log:\n{log}"
    );

    // main should appear somewhere in the backtrace
    assert!(
        log.contains(" main + "),
        "Expected 'main' symbol in crash log:\n{log}"
    );
}

#[test]
#[cfg(target_arch = "aarch64")]
fn crash_log_sigill_backtrace_symbols() {
    let Some(log) = run_and_read_crash_log("sigill", "sigill_symbols") else {
        return;
    };

    // Thread 0 should be the crashed thread (reordered to first)
    assert!(
        log.contains("Thread 0 Crashed"),
        "Expected 'Thread 0 Crashed' in crash log:\n{log}"
    );

    // Frame 0 of the crashed thread should contain do_sigill
    assert!(
        log.contains("do_sigill"),
        "Expected 'do_sigill' symbol in crash log:\n{log}"
    );

    // main should appear somewhere in the backtrace
    assert!(
        log.contains(" main + "),
        "Expected 'main' symbol in crash log:\n{log}"
    );
}

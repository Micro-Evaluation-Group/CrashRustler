//! Integration tests for exc_handler's attach-by-PID mode.
//!
//! These tests exercise the `--attach-pid` code path by spawning crash dummies
//! with `--wait` (which prints PID to stdout and blocks on SIGUSR1), attaching
//! exc_handler to the running process, then signaling the dummy to proceed with
//! the crash.
//!
//! Attach mode requires the `com.apple.security.get-task-allow` entitlement for
//! `task_for_pid()`. Tests skip gracefully if the entitlement is missing.

use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

const SIGUSR1: i32 = 30;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

/// Guard that kills and reaps a child process on drop, preventing leaked
/// processes if a test panics or returns early.
struct ProcessGuard(Option<Child>);

impl ProcessGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Unique lock file path per test to avoid conflicts during parallel execution.
fn unique_lock_file(test_name: &str) -> String {
    format!(
        "{}/crashrustler-attach-{}-{}.lck",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    )
}

/// Probes whether exc_handler's attach mode can function on this system.
/// Spawns crash_dummy with `--wait sigabrt`, attaches exc_handler, and sends
/// SIGUSR1. Cached via OnceLock since the probe is expensive.
///
/// Attach mode requires the `com.apple.security.get-task-allow` entitlement
/// for `task_for_pid()`. This entitlement is only present when exc_handler has
/// been codesigned with `entitlements/exc_handler.entitlements`. On CI runners
/// and unsigned builds, the probe will fail and all attach-mode tests will be
/// skipped — this is expected and not a test failure.
fn probe_attach_mode() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        let lock_file = format!(
            "{}/crashrustler-attach-probe-{}.lck",
            std::env::temp_dir().display(),
            std::process::id()
        );

        let result = run_attach_mode_inner(
            env!("CARGO_BIN_EXE_crash_dummy"),
            "sigabrt",
            &[("CR_NO_LOG", "1"), ("CR_LOCK_FILE", lock_file.as_str())],
        );
        let _ = std::fs::remove_file(&lock_file);

        match result {
            Some(output) => {
                let code = output.status.code().unwrap_or(-1);
                if code == 6 {
                    true
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("failed to get task for pid") {
                        eprintln!(
                            "SKIP attach tests: task_for_pid() failed — exc_handler is not \
                             codesigned with com.apple.security.get-task-allow entitlement \
                             (expected on CI runners and unsigned builds)"
                        );
                    } else if stderr.contains("failed to set exception ports") {
                        eprintln!(
                            "SKIP attach tests: task_set_exception_ports() failed — \
                             insufficient Mach port privileges"
                        );
                    } else {
                        eprintln!(
                            "SKIP attach tests: probe returned exit code {code} (expected 6)\n\
                             stderr: {}",
                            stderr.lines().take(5).collect::<Vec<_>>().join("\n  ")
                        );
                    }
                    false
                }
            }
            None => {
                eprintln!(
                    "SKIP attach tests: probe failed to execute — could not spawn \
                     crash dummy or exc_handler"
                );
                false
            }
        }
    })
}

/// Core attach-mode orchestration. Spawns a crash dummy with `--wait`, reads
/// its PID from stdout, launches exc_handler with `--attach-pid`, waits for
/// exc_handler's "attached to pid" stderr message, then sends SIGUSR1 to
/// trigger the crash.
fn run_attach_mode_inner(
    dummy_binary: &str,
    crash_arg: &str,
    extra_envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    // 1. Spawn the crash dummy with --wait, piping stdout for the PID.
    let mut dummy = Command::new(dummy_binary)
        .args(["--wait", crash_arg])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn crash dummy");
    let mut dummy_guard = ProcessGuard::new(dummy);

    // 2. Read PID from the dummy's first stdout line.
    let stdout = dummy_guard.0.as_mut().unwrap().stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut pid_line = String::new();
    if reader.read_line(&mut pid_line).is_err() || pid_line.trim().is_empty() {
        eprintln!("attach: failed to read PID from crash dummy stdout");
        return None;
    }
    let target_pid: i32 = match pid_line.trim().parse() {
        Ok(pid) => pid,
        Err(_) => {
            eprintln!(
                "attach: invalid PID from crash dummy: {:?}",
                pid_line.trim()
            );
            return None;
        }
    };

    // 3. Launch exc_handler in attach mode, piping stderr to detect readiness.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_exc_handler"));
    cmd.arg("--attach-pid")
        .arg(target_pid.to_string())
        .stderr(Stdio::piped());

    for &(k, v) in extra_envs {
        cmd.env(k, v);
    }

    let mut exc = cmd.spawn().expect("failed to spawn exc_handler");
    let mut exc_guard = ProcessGuard::new(exc);

    // 4. Wait for exc_handler to print "attached to pid" on stderr, confirming
    //    that exception ports are installed and it's ready.
    let exc_stderr = exc_guard.0.as_mut().unwrap().stderr.take().unwrap();
    let mut exc_reader = std::io::BufReader::new(exc_stderr);
    let mut line = String::new();
    let ready = loop {
        line.clear();
        match exc_reader.read_line(&mut line) {
            Ok(0) => break false, // EOF — exc_handler exited early
            Ok(_) => {
                if line.contains("attached to pid") {
                    break true;
                }
            }
            Err(_) => break false,
        }
    };

    if !ready {
        eprintln!("attach: exc_handler did not produce readiness message");
        return None;
    }

    // 5. Signal the dummy to proceed with the crash.
    unsafe { kill(target_pid, SIGUSR1) };

    // 6. Wait for exc_handler to finish processing the exception.
    let exc_child = exc_guard.0.take().unwrap();
    let output = exc_child
        .wait_with_output()
        .expect("failed to wait for exc_handler");

    // 7. Clean up the dummy (ProcessGuard handles kill+wait on drop).
    Some(output)
}

/// Runs exc_handler in attach mode against the workspace crash_dummy binary.
fn run_attach(
    crash_arg: &str,
    test_name: &str,
    extra_envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    if !probe_attach_mode() {
        return None;
    }

    let lock_file = unique_lock_file(test_name);

    let mut envs: Vec<(&str, &str)> = vec![("CR_LOCK_FILE", lock_file.as_str())];

    let has_log_dir = extra_envs.iter().any(|(k, _)| *k == "CR_LOG_DIR");
    let has_no_log = extra_envs.iter().any(|(k, _)| *k == "CR_NO_LOG");
    if !has_log_dir && !has_no_log {
        let _ = std::fs::create_dir_all("./crashlogs");
        envs.push(("CR_LOG_DIR", "./crashlogs"));
    }

    envs.extend_from_slice(extra_envs);

    let output = run_attach_mode_inner(env!("CARGO_BIN_EXE_crash_dummy"), crash_arg, &envs);
    let _ = std::fs::remove_file(&lock_file);
    output
}

/// Runs exc_handler in attach mode, writes crash log to a known path, returns content.
fn run_attach_and_read_crash_log(crash_arg: &str, test_name: &str) -> Option<String> {
    let log_path = format!(
        "{}/crashrustler-attach-{}-{}.crashlog.txt",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output = run_attach(crash_arg, test_name, &[("CR_LOG_PATH", log_path.as_str())])?;

    let code = output.status.code().unwrap_or(-1);
    assert!(
        code >= 0,
        "{test_name}: exc_handler exited with unexpected code {code}"
    );

    let content = std::fs::read_to_string(&log_path).ok();
    let _ = std::fs::remove_file(&log_path);
    content
}

/// Runs exc_handler in attach mode against an external binary (sanitizer dummies).
fn run_attach_external(
    dummy_binary: &str,
    crash_arg: &str,
    test_name: &str,
    extra_envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    if !probe_attach_mode() {
        return None;
    }

    let lock_file = unique_lock_file(test_name);

    let mut envs: Vec<(&str, &str)> = vec![("CR_LOCK_FILE", lock_file.as_str())];

    let has_log_dir = extra_envs.iter().any(|(k, _)| *k == "CR_LOG_DIR");
    let has_no_log = extra_envs.iter().any(|(k, _)| *k == "CR_NO_LOG");
    if !has_log_dir && !has_no_log {
        let _ = std::fs::create_dir_all("./crashlogs");
        envs.push(("CR_LOG_DIR", "./crashlogs"));
    }

    envs.extend_from_slice(extra_envs);

    let output = run_attach_mode_inner(dummy_binary, crash_arg, &envs);
    let _ = std::fs::remove_file(&lock_file);
    output
}

/// Runs exc_handler in attach mode against an external binary, returns crash log.
fn run_attach_external_and_read_crash_log(
    dummy_binary: &str,
    crash_arg: &str,
    test_name: &str,
) -> Option<String> {
    let log_path = format!(
        "{}/crashrustler-attach-{}-{}.crashlog.txt",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output = run_attach_external(
        dummy_binary,
        crash_arg,
        test_name,
        &[("CR_LOG_PATH", log_path.as_str())],
    )?;

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
// Rust ASan binary builder (reuses pattern from asan_exc_handler.rs)
// ============================================================================

fn build_asan_crash_dummy() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir.join("test-fixtures").join("asan");

    if !crate_dir.join("Cargo.toml").exists() {
        eprintln!("SKIP: test-fixtures/asan/Cargo.toml not found");
        return None;
    }

    let target_dir = manifest_dir.join("target").join("asan");

    let output = Command::new("cargo")
        .arg("build")
        .arg("--release")
        .current_dir(&crate_dir)
        .env("RUSTFLAGS", "-Zsanitizer=address")
        .env("CARGO_TARGET_DIR", &target_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        eprintln!(
            "SKIP: asan-crash-dummy build failed (exit {:?}):\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    let binary = target_dir.join("release").join("asan-crash-dummy");
    if binary.exists() {
        Some(binary)
    } else {
        eprintln!(
            "SKIP: asan-crash-dummy binary not found at {}",
            binary.display()
        );
        None
    }
}

fn asan_crash_dummy_path() -> Option<&'static PathBuf> {
    static BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    BINARY.get_or_init(build_asan_crash_dummy).as_ref()
}

// ============================================================================
// C ASan binary builder (reuses pattern from c_asan_exc_handler.rs)
// ============================================================================

fn build_c_asan_crash_dummy() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir.join("test-fixtures").join("c-asan");

    let source = crate_dir.join("crash_dummy.c");
    if !source.exists() {
        eprintln!("SKIP: test-fixtures/c-asan/crash_dummy.c not found");
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
            "SKIP: c-asan-crash-dummy build failed (exit {:?}):\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    let binary = crate_dir.join("c-asan-crash-dummy");
    if binary.exists() {
        Some(binary)
    } else {
        eprintln!(
            "SKIP: c-asan-crash-dummy binary not found at {}",
            binary.display()
        );
        None
    }
}

fn c_asan_crash_dummy_path() -> Option<&'static PathBuf> {
    static BINARY: OnceLock<Option<PathBuf>> = OnceLock::new();
    BINARY.get_or_init(build_c_asan_crash_dummy).as_ref()
}

// ============================================================================
// Attach-mode exit code tests (crash_dummy)
// ============================================================================

#[test]
#[cfg(target_arch = "aarch64")]
fn attach_sigsegv_returns_signal() {
    let Some(output) = run_attach("sigsegv", "attach_sigsegv", &[]) else {
        return;
    };
    // Near-null deref → NotExploitable → bare signal number (11)
    assert_eq!(output.status.code(), Some(11));
}

#[test]
fn attach_sigabrt_returns_signal() {
    let Some(output) = run_attach("sigabrt", "attach_sigabrt", &[]) else {
        return;
    };
    // EXC_CRASH → NotExploitable → signal 6
    assert_eq!(output.status.code(), Some(6));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn attach_sigill_returns_signal_plus_100() {
    let Some(output) = run_attach("sigill", "attach_sigill", &[]) else {
        return;
    };
    // EXC_BAD_INSTRUCTION → Exploitable → signal + 100 (4 + 100 = 104)
    assert_eq!(output.status.code(), Some(104));
}

// ============================================================================
// Attach-mode crash log content tests (crash_dummy)
// ============================================================================

#[test]
#[cfg(target_arch = "aarch64")]
fn attach_sigsegv_crash_log_symbols() {
    let Some(log) = run_attach_and_read_crash_log("sigsegv", "attach_sigsegv_symbols") else {
        return;
    };

    assert!(
        log.contains("Thread 0 Crashed"),
        "Expected 'Thread 0 Crashed' in crash log:\n{log}"
    );
    assert!(
        log.contains("do_sigsegv"),
        "Expected 'do_sigsegv' symbol in crash log:\n{log}"
    );
    assert!(
        log.contains(" main + "),
        "Expected 'main' symbol in crash log:\n{log}"
    );
}

// ============================================================================
// Attach-mode Rust ASan tests
// ============================================================================

#[test]
fn attach_asan_heap_overflow_returns_signal() {
    let Some(asan_binary) = asan_crash_dummy_path() else {
        return;
    };
    let Some(output) = run_attach_external(
        asan_binary.to_str().unwrap(),
        "heap_overflow",
        "attach_asan_heap_overflow",
        &[],
    ) else {
        return;
    };
    // ASan abort → SIGABRT → exit code 6
    assert_eq!(output.status.code(), Some(6));
}

#[test]
fn attach_asan_heap_overflow_crash_log() {
    let Some(asan_binary) = asan_crash_dummy_path() else {
        return;
    };
    let Some(log) = run_attach_external_and_read_crash_log(
        asan_binary.to_str().unwrap(),
        "heap_overflow",
        "attach_asan_heap_overflow_log",
    ) else {
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
        log.contains("heap-buffer-overflow"),
        "Expected 'heap-buffer-overflow' in ASan report:\n{log}"
    );
}

// ============================================================================
// Attach-mode C ASan tests
// ============================================================================

#[test]
fn attach_c_asan_heap_overflow_returns_signal() {
    let Some(c_asan_binary) = c_asan_crash_dummy_path() else {
        return;
    };
    let Some(output) = run_attach_external(
        c_asan_binary.to_str().unwrap(),
        "heap_overflow",
        "attach_c_asan_heap_overflow",
        &[],
    ) else {
        return;
    };
    // ASan abort → SIGABRT → exit code 6
    assert_eq!(output.status.code(), Some(6));
}

#[test]
fn attach_c_asan_heap_overflow_crash_log() {
    let Some(c_asan_binary) = c_asan_crash_dummy_path() else {
        return;
    };
    let Some(log) = run_attach_external_and_read_crash_log(
        c_asan_binary.to_str().unwrap(),
        "heap_overflow",
        "attach_c_asan_heap_overflow_log",
    ) else {
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
        log.contains("heap-buffer-overflow"),
        "Expected 'heap-buffer-overflow' in ASan report:\n{log}"
    );
}

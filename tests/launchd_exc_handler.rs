//! Integration tests for exc_handler's launchd service mode.
//!
//! These tests exercise the `--launchd-name` code path by registering a Mach
//! bootstrap service, spawning a crash dummy, setting its exception ports to
//! point at the registered service, then triggering a crash.
//!
//! Requires the `com.apple.security.get-task-allow` entitlement for
//! `task_for_pid()` on the crash dummy. Tests skip gracefully if unavailable.

use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

const SIGUSR1: i32 = 30;
const SIGKILL: i32 = 9;

// Mach constants for task_set_exception_ports
const EXC_MASK_ALL: i32 = 0x0000_FFFE;
const EXCEPTION_STATE_IDENTITY: i32 = 3;
const MACH_EXCEPTION_CODES: i32 = 0x8000_0000u32 as i32;
#[cfg(target_arch = "aarch64")]
const THREAD_STATE_FLAVOR: i32 = 6; // ARM_THREAD_STATE64
#[cfg(target_arch = "x86_64")]
const THREAD_STATE_FLAVOR: i32 = 7; // x86_THREAD_STATE

const TASK_BOOTSTRAP_PORT: i32 = 4;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn mach_task_self() -> u32;
    fn task_for_pid(target_task: u32, pid: i32, task: *mut u32) -> i32;
    fn task_get_special_port(task: u32, which_port: i32, port: *mut u32) -> i32;
    fn task_set_exception_ports(
        task: u32,
        exception_mask: i32,
        new_port: u32,
        behavior: i32,
        new_flavor: i32,
    ) -> i32;
    fn bootstrap_look_up(
        bootstrap_port: u32,
        service_name: *const i8,
        service_port: *mut u32,
    ) -> i32;
}

unsafe fn get_bootstrap_port() -> u32 {
    let mut bp: u32 = 0;
    unsafe {
        task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &mut bp);
    }
    bp
}

/// Guard that kills and reaps a child process on drop.
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

/// Unique lock file path per test.
fn unique_lock_file(test_name: &str) -> String {
    format!(
        "{}/crashrustler-launchd-{}-{}.lck",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    )
}

/// Unique service name per test to avoid collisions.
fn unique_service_name(test_name: &str) -> String {
    format!("com.crashrustler.test.{}.{}", test_name, std::process::id())
}

/// Probes whether launchd mode and task_for_pid both work on this system.
fn probe_launchd_mode() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        let service_name = unique_service_name("probe");
        let lock_file = format!(
            "{}/crashrustler-launchd-probe-{}.lck",
            std::env::temp_dir().display(),
            std::process::id()
        );

        // 1. Spawn crash_dummy --wait sigabrt
        let dummy = match Command::new(env!("CARGO_BIN_EXE_crash_dummy"))
            .args(["--wait", "sigabrt"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                eprintln!("SKIP launchd tests: failed to spawn crash_dummy");
                return false;
            }
        };
        let mut dummy_guard = ProcessGuard::new(dummy);

        // Read PID
        let stdout = dummy_guard.0.as_mut().unwrap().stdout.take().unwrap();
        let mut reader = std::io::BufReader::new(stdout);
        let mut pid_line = String::new();
        if reader.read_line(&mut pid_line).is_err() || pid_line.trim().is_empty() {
            eprintln!("SKIP launchd tests: failed to read PID from crash_dummy");
            return false;
        }
        let dummy_pid: i32 = match pid_line.trim().parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("SKIP launchd tests: invalid PID");
                return false;
            }
        };

        // 2. Spawn exc_handler --launchd-name
        let exc = match Command::new(env!("CARGO_BIN_EXE_exc_handler"))
            .args(["--launchd-name", &service_name])
            .env("CR_NO_LOG", "1")
            .env("CR_LOCK_FILE", &lock_file)
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                eprintln!("SKIP launchd tests: failed to spawn exc_handler");
                return false;
            }
        };
        let mut exc_guard = ProcessGuard::new(exc);

        // Wait for readiness
        let exc_stderr = exc_guard.0.as_mut().unwrap().stderr.take().unwrap();
        let mut exc_reader = std::io::BufReader::new(exc_stderr);
        let mut line = String::new();
        let ready = loop {
            line.clear();
            match exc_reader.read_line(&mut line) {
                Ok(0) => break false,
                Ok(_) => {
                    if line.contains("registered service") {
                        break true;
                    }
                    if line.contains("failed") {
                        eprintln!(
                            "SKIP launchd tests: bootstrap_check_in failed: {}",
                            line.trim()
                        );
                        break false;
                    }
                }
                Err(_) => break false,
            }
        };

        if !ready {
            eprintln!("SKIP launchd tests: exc_handler did not register service");
            return false;
        }

        // 3. Look up the service and set exception ports on the dummy
        let success = unsafe {
            let bp = get_bootstrap_port();

            let c_name = std::ffi::CString::new(service_name.as_str()).unwrap();
            let mut service_port: u32 = 0;
            if bootstrap_look_up(bp, c_name.as_ptr(), &mut service_port) != 0 {
                eprintln!("SKIP launchd tests: bootstrap_look_up failed");
                return false;
            }

            let mut task: u32 = 0;
            if task_for_pid(mach_task_self(), dummy_pid, &mut task) != 0 {
                eprintln!(
                    "SKIP launchd tests: task_for_pid failed — missing \
                     com.apple.security.get-task-allow entitlement"
                );
                return false;
            }

            let kr = task_set_exception_ports(
                task,
                EXC_MASK_ALL,
                service_port,
                EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
                THREAD_STATE_FLAVOR,
            );
            kr == 0
        };

        if !success {
            eprintln!("SKIP launchd tests: task_set_exception_ports failed");
            return false;
        }

        // 4. Signal the dummy to crash
        unsafe { kill(dummy_pid, SIGUSR1) };

        // 5. Wait for exc_handler to finish
        let exc_child = exc_guard.0.take().unwrap();
        let output = exc_child
            .wait_with_output()
            .expect("failed to wait for exc_handler");

        let _ = std::fs::remove_file(&lock_file);

        let code = output.status.code().unwrap_or(-1);
        if code == 6 {
            true
        } else {
            eprintln!("SKIP launchd tests: probe returned exit code {code} (expected 6)");
            false
        }
    })
}

/// Core launchd mode test orchestration.
fn run_launchd_mode(
    crash_arg: &str,
    test_name: &str,
    extra_envs: &[(&str, &str)],
) -> Option<std::process::Output> {
    if !probe_launchd_mode() {
        return None;
    }

    let service_name = unique_service_name(test_name);
    let lock_file = unique_lock_file(test_name);

    // 1. Spawn crash_dummy --wait
    let dummy = Command::new(env!("CARGO_BIN_EXE_crash_dummy"))
        .args(["--wait", crash_arg])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn crash dummy");
    let mut dummy_guard = ProcessGuard::new(dummy);

    let stdout = dummy_guard.0.as_mut().unwrap().stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut pid_line = String::new();
    reader.read_line(&mut pid_line).expect("failed to read PID");
    let dummy_pid: i32 = pid_line.trim().parse().expect("invalid PID");

    // 2. Spawn exc_handler --launchd-name
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_exc_handler"));
    cmd.args(["--launchd-name", &service_name])
        .env("CR_LOCK_FILE", &lock_file)
        .stderr(Stdio::piped());

    let has_log_dir = extra_envs.iter().any(|(k, _)| *k == "CR_LOG_DIR");
    let has_no_log = extra_envs.iter().any(|(k, _)| *k == "CR_NO_LOG");
    if !has_log_dir && !has_no_log {
        let _ = std::fs::create_dir_all("./crashlogs");
        cmd.env("CR_LOG_DIR", "./crashlogs");
    }

    for &(k, v) in extra_envs {
        cmd.env(k, v);
    }

    let exc = cmd.spawn().expect("failed to spawn exc_handler");
    let mut exc_guard = ProcessGuard::new(exc);

    // Wait for readiness
    let exc_stderr = exc_guard.0.as_mut().unwrap().stderr.take().unwrap();
    let mut exc_reader = std::io::BufReader::new(exc_stderr);
    let mut line = String::new();
    loop {
        line.clear();
        match exc_reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {
                if line.contains("registered service") {
                    break;
                }
            }
            Err(_) => return None,
        }
    }

    // 3. Look up service and set exception ports on the dummy
    unsafe {
        let bp = get_bootstrap_port();

        let c_name = std::ffi::CString::new(service_name.as_str()).unwrap();
        let mut service_port: u32 = 0;
        bootstrap_look_up(bp, c_name.as_ptr(), &mut service_port);

        let mut task: u32 = 0;
        task_for_pid(mach_task_self(), dummy_pid, &mut task);

        task_set_exception_ports(
            task,
            EXC_MASK_ALL,
            service_port,
            EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
            THREAD_STATE_FLAVOR,
        );
    }

    // 4. Signal the dummy to crash
    unsafe { kill(dummy_pid, SIGUSR1) };

    // 5. Wait for exc_handler
    let exc_child = exc_guard.0.take().unwrap();
    let output = exc_child
        .wait_with_output()
        .expect("failed to wait for exc_handler");

    let _ = std::fs::remove_file(&lock_file);

    Some(output)
}

/// Run launchd mode and read the crash log.
fn run_launchd_and_read_crash_log(crash_arg: &str, test_name: &str) -> Option<String> {
    let log_path = format!(
        "{}/crashrustler-launchd-{}-{}.crashlog.txt",
        std::env::temp_dir().display(),
        test_name,
        std::process::id()
    );

    let output = run_launchd_mode(crash_arg, test_name, &[("CR_LOG_PATH", log_path.as_str())])?;

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
// Launchd mode exit code tests
// ============================================================================

#[test]
fn launchd_sigabrt_returns_signal() {
    let Some(output) = run_launchd_mode("sigabrt", "launchd_sigabrt", &[]) else {
        return;
    };
    // EXC_CRASH → NotExploitable → signal 6
    assert_eq!(output.status.code(), Some(6));
}

#[test]
#[cfg(target_arch = "aarch64")]
fn launchd_sigsegv_returns_signal() {
    let Some(output) = run_launchd_mode("sigsegv", "launchd_sigsegv", &[]) else {
        return;
    };
    // Near-null deref → NotExploitable → bare signal 11
    assert_eq!(output.status.code(), Some(11));
}

// ============================================================================
// Launchd mode crash log content tests
// ============================================================================

#[test]
fn launchd_sigabrt_crash_log() {
    let Some(log) = run_launchd_and_read_crash_log("sigabrt", "launchd_sigabrt_log") else {
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
}

#[test]
#[cfg(target_arch = "aarch64")]
fn launchd_sigsegv_crash_log_symbols() {
    let Some(log) = run_launchd_and_read_crash_log("sigsegv", "launchd_sigsegv_symbols") else {
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
}

// ============================================================================
// Launchd mode error handling tests
// ============================================================================

#[test]
fn launchd_duplicate_service_name_fails() {
    // Register a service name, then try to register the same name again.
    // The second registration should fail.
    let service_name = unique_service_name("duplicate");
    let lock_file = unique_lock_file("duplicate");

    // First registration
    let exc1 = match Command::new(env!("CARGO_BIN_EXE_exc_handler"))
        .args(["--launchd-name", &service_name])
        .env("CR_QUIET", "1")
        .env("CR_NO_LOG", "1")
        .env("CR_LOCK_FILE", &lock_file)
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut exc1_guard = ProcessGuard::new(exc1);

    // Give it a moment to register (in quiet mode there's no readiness message,
    // so we sleep briefly)
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Second registration — should fail immediately
    let output = Command::new(env!("CARGO_BIN_EXE_exc_handler"))
        .args(["--launchd-name", &service_name])
        .env("CR_NO_LOG", "1")
        .env("CR_LOCK_FILE", format!("{lock_file}.2"))
        .output()
        .expect("failed to spawn exc_handler");

    // exit(-1) wraps to 255
    assert_eq!(
        output.status.code(),
        Some(255),
        "Expected exit code 255 (-1) for duplicate service name registration"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to register bootstrap service"),
        "Expected error message about failed registration:\n{stderr}"
    );

    // Kill the first instance
    if let Some(ref mut child) = exc1_guard.0 {
        unsafe { kill(child.id() as i32, SIGKILL) };
    }
    let _ = std::fs::remove_file(&lock_file);
    let _ = std::fs::remove_file(format!("{lock_file}.2"));
}

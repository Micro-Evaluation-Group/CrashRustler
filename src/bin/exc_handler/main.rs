//! exc_handler: Mach exception handler binary.
//!
//! Intercepts Mach exceptions from a child process, analyzes them for
//! exploitability, generates crash logs, and exits with coded return values.
//!
//! Exit codes:
//!   0      — No crash (child exited normally)
//!  -1      — Error
//!  -2      — Non-crash signal (SIGTERM, SIGKILL, etc.)
//!  signal  — Crash, not exploitable
//!  signal+100 — Crash, exploitable

mod ffi;
mod handler;
mod image_enum;
mod mach_msg;
mod remote_memory;
mod thread_enum;

use std::ffi::CString;

use ffi::*;
use mach_msg::ExcHandlerState;

/// Configuration from CR_* environment variables and CLI flags.
pub struct Config {
    /// PID to attach to (CR_ATTACH_PID, default 0 = fork+exec mode).
    pub attach_pid: i32,
    /// Suppress output (CR_QUIET).
    pub quiet: bool,
    /// Directory for crash logs (CR_LOG_DIR, default "./crashlogs/").
    pub log_dir: String,
    /// Explicit log file path (CR_LOG_PATH).
    pub log_path: Option<String>,
    /// Don't write crash logs (CR_NO_LOG).
    pub no_log: bool,
    /// Lock file path (CR_LOCK_FILE, default "./cr.lck").
    pub lock_file: String,
    /// PID file path (CR_PID_FILE).
    pub pid_file: Option<String>,
    /// Current test case identifier (CR_CURRENT_CASE).
    pub current_case: Option<String>,
    /// File to write current case to (CR_CASE_FILE).
    pub case_file: Option<String>,
    /// Path to the test case file (CR_TEST_CASE_PATH).
    pub test_case_path: Option<String>,
    /// Additional log info string (CR_LOG_INFO).
    pub log_info: Option<String>,
    /// Treat read-access crashes as exploitable (CR_EXPLOITABLE_READS).
    pub exploitable_reads: bool,
    /// Treat JIT crashes as exploitable (CR_EXPLOITABLE_JIT).
    pub exploitable_jit: bool,
    /// Ignore frame pointer inconsistency (CR_IGNORE_FRAME_POINTER).
    pub ignore_frame_pointer: bool,
    /// Don't kill child on exit (CR_NO_KILL_CHILD).
    pub no_kill_child: bool,
    /// Machine-readable output (CR_MACHINE_READABLE).
    pub machine_readable: bool,
    /// Launchd service name for bootstrap registration (CR_REGISTER_LAUNCHD_NAME).
    pub launchd_service_name: Option<String>,
}

/// CLI flag overrides (all Option — None means "not specified on CLI").
struct CliOverrides {
    attach_pid: Option<i32>,
    quiet: Option<bool>,
    log_dir: Option<String>,
    log_path: Option<String>,
    no_log: Option<bool>,
    lock_file: Option<String>,
    pid_file: Option<String>,
    current_case: Option<String>,
    case_file: Option<String>,
    test_case_path: Option<String>,
    log_info: Option<String>,
    exploitable_reads: Option<bool>,
    exploitable_jit: Option<bool>,
    ignore_frame_pointer: Option<bool>,
    no_kill_child: Option<bool>,
    machine_readable: Option<bool>,
    launchd_service_name: Option<String>,
    /// Positional args after `--` or after all flags.
    target_args: Vec<String>,
}

fn print_help() {
    println!(
        "\
exc_handler - Mach exception handler for macOS crash analysis

USAGE:
    exc_handler [OPTIONS] <PROGRAM> [ARGS...]
    exc_handler --attach-pid <PID>
    exc_handler --launchd-name <NAME>

OPTIONS:
    -h, --help                    Print help information
    -V, --version                 Print version
    -q, --quiet                   Suppress diagnostic output
        --no-log                  Don't write crash logs
        --log-dir <DIR>           Directory for crash logs [default: ./crashlogs/]
        --log-path <PATH>         Explicit crash log file path
        --lock-file <PATH>        Lock file path [default: ./cr.lck]
        --pid-file <PATH>         Write child PID to file
        --attach-pid <PID>        Attach to existing process
        --current-case <ID>       Test case identifier
        --case-file <PATH>        File to write current case to
        --test-case-path <PATH>   Path to the test case file
        --log-info <INFO>         Additional log info string
        --exploitable-reads       Treat read-access crashes as exploitable
        --exploitable-jit         Treat JIT crashes as exploitable
        --ignore-frame-pointer    Ignore frame pointer inconsistency
        --no-kill-child           Don't kill child on exit
        --machine-readable        Machine-readable output
        --launchd-name <NAME>     Register as a Mach bootstrap service and wait
                                  for exceptions from clients that look up this name

ENVIRONMENT:
    All options can also be set via CR_* environment variables.
    CLI flags take precedence over environment variables.

    CR_ATTACH_PID, CR_QUIET, CR_LOG_DIR, CR_LOG_PATH, CR_NO_LOG,
    CR_LOCK_FILE, CR_PID_FILE, CR_CURRENT_CASE, CR_CASE_FILE,
    CR_TEST_CASE_PATH, CR_LOG_INFO, CR_EXPLOITABLE_READS,
    CR_EXPLOITABLE_JIT, CR_IGNORE_FRAME_POINTER,
    CR_NO_KILL_CHILD, CR_MACHINE_READABLE,
    CR_REGISTER_LAUNCHD_NAME

EXIT CODES:
     0    No crash (child exited normally)
    -1    Error
    -2    Non-crash signal (SIGTERM, SIGKILL, etc.)
     N    Crash signal number (not exploitable)
     N+100 Crash signal number (exploitable)"
    );
}

fn parse_args() -> CliOverrides {
    let mut cli = CliOverrides {
        attach_pid: None,
        quiet: None,
        log_dir: None,
        log_path: None,
        no_log: None,
        lock_file: None,
        pid_file: None,
        current_case: None,
        case_file: None,
        test_case_path: None,
        log_info: None,
        exploitable_reads: None,
        exploitable_jit: None,
        ignore_frame_pointer: None,
        no_kill_child: None,
        machine_readable: None,
        launchd_service_name: None,
        target_args: Vec::new(),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        if arg == "--" {
            cli.target_args.extend_from_slice(&args[i + 1..]);
            break;
        }

        if arg == "--help" || arg == "-h" {
            print_help();
            std::process::exit(0);
        }

        if arg == "--version" || arg == "-V" {
            println!("exc_handler {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }

        // Try to parse --flag=value form
        if let Some(rest) = arg.strip_prefix("--") {
            if let Some((key, value)) = rest.split_once('=') {
                match key {
                    "attach-pid" => {
                        cli.attach_pid = value.parse().ok();
                    }
                    "log-dir" => cli.log_dir = Some(value.to_string()),
                    "log-path" => cli.log_path = Some(value.to_string()),
                    "lock-file" => cli.lock_file = Some(value.to_string()),
                    "pid-file" => cli.pid_file = Some(value.to_string()),
                    "current-case" => cli.current_case = Some(value.to_string()),
                    "case-file" => cli.case_file = Some(value.to_string()),
                    "test-case-path" => cli.test_case_path = Some(value.to_string()),
                    "log-info" => cli.log_info = Some(value.to_string()),
                    "launchd-name" => cli.launchd_service_name = Some(value.to_string()),
                    _ => {
                        eprintln!("exc_handler: unknown option '--{key}'");
                        eprintln!("Run 'exc_handler --help' for usage information.");
                        std::process::exit(-1);
                    }
                }
                i += 1;
                continue;
            }

            // --flag or --flag <value> form
            match rest {
                "quiet" => cli.quiet = Some(true),
                "no-log" => cli.no_log = Some(true),
                "exploitable-reads" => cli.exploitable_reads = Some(true),
                "exploitable-jit" => cli.exploitable_jit = Some(true),
                "ignore-frame-pointer" => cli.ignore_frame_pointer = Some(true),
                "no-kill-child" => cli.no_kill_child = Some(true),
                "machine-readable" => cli.machine_readable = Some(true),
                // String/int flags that consume the next argument
                "attach-pid" | "log-dir" | "log-path" | "lock-file" | "pid-file"
                | "current-case" | "case-file" | "test-case-path" | "log-info" | "launchd-name" => {
                    i += 1;
                    if i >= args.len() {
                        eprintln!("exc_handler: '--{rest}' requires a value");
                        std::process::exit(-1);
                    }
                    let value = &args[i];
                    match rest {
                        "attach-pid" => cli.attach_pid = value.parse().ok(),
                        "log-dir" => cli.log_dir = Some(value.to_string()),
                        "log-path" => cli.log_path = Some(value.to_string()),
                        "lock-file" => cli.lock_file = Some(value.to_string()),
                        "pid-file" => cli.pid_file = Some(value.to_string()),
                        "current-case" => cli.current_case = Some(value.to_string()),
                        "case-file" => cli.case_file = Some(value.to_string()),
                        "test-case-path" => cli.test_case_path = Some(value.to_string()),
                        "log-info" => cli.log_info = Some(value.to_string()),
                        "launchd-name" => cli.launchd_service_name = Some(value.to_string()),
                        _ => unreachable!(),
                    }
                }
                _ => {
                    eprintln!("exc_handler: unknown option '--{rest}'");
                    eprintln!("Run 'exc_handler --help' for usage information.");
                    std::process::exit(-1);
                }
            }
            i += 1;
            continue;
        }

        // Short flags
        if arg == "-q" {
            cli.quiet = Some(true);
            i += 1;
            continue;
        }

        // First non-flag arg starts target_args
        cli.target_args.extend_from_slice(&args[i..]);
        break;
    }

    cli
}

impl Config {
    fn from_cli_and_env(cli: &CliOverrides) -> Self {
        let env_str =
            |name: &str| -> Option<String> { std::env::var(name).ok().filter(|s| !s.is_empty()) };
        let env_bool = |name: &str| -> bool { std::env::var(name).is_ok() };
        let env_int = |name: &str| -> i32 {
            std::env::var(name)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        };

        Config {
            attach_pid: cli.attach_pid.unwrap_or_else(|| env_int("CR_ATTACH_PID")),
            quiet: cli.quiet.unwrap_or_else(|| env_bool("CR_QUIET")),
            log_dir: cli
                .log_dir
                .clone()
                .or_else(|| env_str("CR_LOG_DIR"))
                .unwrap_or_else(|| "./crashlogs/".into()),
            log_path: cli.log_path.clone().or_else(|| env_str("CR_LOG_PATH")),
            no_log: cli.no_log.unwrap_or_else(|| env_bool("CR_NO_LOG")),
            lock_file: cli
                .lock_file
                .clone()
                .or_else(|| env_str("CR_LOCK_FILE"))
                .unwrap_or_else(|| "./cr.lck".into()),
            pid_file: cli.pid_file.clone().or_else(|| env_str("CR_PID_FILE")),
            current_case: cli
                .current_case
                .clone()
                .or_else(|| env_str("CR_CURRENT_CASE")),
            case_file: cli.case_file.clone().or_else(|| env_str("CR_CASE_FILE")),
            test_case_path: cli
                .test_case_path
                .clone()
                .or_else(|| env_str("CR_TEST_CASE_PATH")),
            log_info: cli.log_info.clone().or_else(|| env_str("CR_LOG_INFO")),
            exploitable_reads: cli
                .exploitable_reads
                .unwrap_or_else(|| env_bool("CR_EXPLOITABLE_READS")),
            exploitable_jit: cli
                .exploitable_jit
                .unwrap_or_else(|| env_bool("CR_EXPLOITABLE_JIT")),
            ignore_frame_pointer: cli
                .ignore_frame_pointer
                .unwrap_or_else(|| env_bool("CR_IGNORE_FRAME_POINTER")),
            no_kill_child: cli
                .no_kill_child
                .unwrap_or_else(|| env_bool("CR_NO_KILL_CHILD")),
            machine_readable: cli
                .machine_readable
                .unwrap_or_else(|| env_bool("CR_MACHINE_READABLE")),
            launchd_service_name: cli
                .launchd_service_name
                .clone()
                .or_else(|| env_str("CR_REGISTER_LAUNCHD_NAME")),
        }
    }
}

fn main() {
    let cli = parse_args();
    let config = Config::from_cli_and_env(&cli);

    if config.attach_pid != 0 {
        // Attach mode
        std::process::exit(run_attach_mode(&config));
    } else if config.launchd_service_name.is_some() {
        // Launchd service mode
        std::process::exit(run_launchd_mode(&config));
    } else if cli.target_args.is_empty() {
        eprintln!("Error: no program specified");
        eprintln!("Run 'exc_handler --help' for usage information.");
        std::process::exit(-1);
    } else {
        // Fork+exec mode
        std::process::exit(run_fork_exec_mode(&cli.target_args, &config));
    }
}

/// Attach mode: attach to an existing process by PID.
///
/// Polls with a 100ms timeout so we can detect normal process exit via
/// `kill(pid, 0)` (the target is not our child, so `waitpid` is not available).
fn run_attach_mode(config: &Config) -> i32 {
    let pid = config.attach_pid;

    // Get task port for the target PID
    let task = match task_from_pid(pid) {
        Some(t) => t,
        None => {
            eprintln!("exc_handler: failed to get task for pid {pid}");
            return -1;
        }
    };

    // Allocate exception port
    let exception_port = match allocate_exception_port() {
        Some(p) => p,
        None => {
            eprintln!("exc_handler: failed to allocate exception port");
            return -1;
        }
    };

    // Set exception ports on the target task
    let kr = unsafe {
        task_set_exception_ports(
            task,
            EXC_MASK_ALL,
            exception_port,
            EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
            THREAD_STATE_FLAVOR,
        )
    };
    if kr != KERN_SUCCESS {
        eprintln!("exc_handler: failed to set exception ports: {kr}");
        return -1;
    }

    // Write lock file
    let _ = std::fs::write(&config.lock_file, "");

    if !config.quiet {
        eprintln!("exc_handler: attached to pid {pid}, waiting for exceptions...");
    }

    // Wait for exception or process exit.
    // Poll with a 100ms timeout so we can detect normal exit via kill(pid, 0).
    let mut state = ExcHandlerState {
        exception_port,
        original_bootstrap_port: 0,
        server_port: 0,
        exception_received: false,
        exception_data: None,
        pending_reply: None,
    };

    let exit_code = loop {
        match mach_msg::serve_one_message(&mut state, exception_port, 100) {
            Ok(true) => {
                let code = if let Some(ref exc) = state.exception_data {
                    handler::handle_exception(exc, config)
                } else {
                    -1
                };

                // Destroy the exception port so the follow-up EXC_CRASH
                // has nowhere to go and won't block the target thread.
                unsafe { mach_port_destroy(mach_task_self(), exception_port) };

                // Reply KERN_FAILURE so kernel delivers the signal.
                mach_msg::send_exception_reply(&mut state);

                break code;
            }
            Ok(false) => {
                // Port transfer — shouldn't happen in attach mode
                break -1;
            }
            Err(kr) if kr == ffi::MACH_RCV_TIMED_OUT => {
                // Timeout — check if the target process is still alive.
                // We can't use waitpid (not our child), so probe with kill(pid, 0).
                if unsafe { kill(pid, 0) } != 0 {
                    // Process is gone — exited normally without an exception
                    if !config.quiet {
                        eprintln!("exc_handler: pid {pid} exited without exception");
                    }
                    break 0;
                }
                // Process still running — loop and try again
            }
            Err(kr) => {
                eprintln!("exc_handler: mach_msg failed: {kr}");
                break -1;
            }
        }
    };

    cleanup_attach(config);
    exit_code
}

/// Launchd service mode: register a Mach bootstrap service name and wait
/// for exceptions from any process whose exception ports are set to this service.
///
/// This enables monitoring launchd-managed daemons: configure the target service's
/// exception ports to point to the registered service name, and exc_handler will
/// catch crashes from any process that sends exceptions to this port.
///
/// The service port doubles as the exception port — `bootstrap_check_in` returns
/// a receive right, and exception messages arrive directly on it.
fn run_launchd_mode(config: &Config) -> i32 {
    let service_name = config.launchd_service_name.as_ref().unwrap();

    // Register the service name with the Mach bootstrap server.
    // This gives us a receive right on a port associated with the service name.
    let service_port = match ffi::bootstrap_register_service(service_name) {
        Some(p) => p,
        None => {
            eprintln!(
                "exc_handler: failed to register bootstrap service '{service_name}' \
                 (name may already be in use or launchd plist not configured)"
            );
            return -1;
        }
    };

    // Insert a send right so we can use it as an exception port
    let kr = unsafe {
        mach_port_insert_right(
            mach_task_self(),
            service_port,
            service_port,
            MACH_MSG_TYPE_MAKE_SEND,
        )
    };
    if kr != KERN_SUCCESS {
        eprintln!("exc_handler: failed to insert send right on service port: {kr}");
        return -1;
    }

    // Write lock file
    let _ = std::fs::write(&config.lock_file, "");

    if !config.quiet {
        eprintln!("exc_handler: registered service '{service_name}', waiting for exceptions...");
    }

    // Wait for exception messages on the service port.
    // Block indefinitely — this is a long-running listener.
    let mut state = ExcHandlerState {
        exception_port: service_port,
        original_bootstrap_port: 0,
        server_port: 0,
        exception_received: false,
        exception_data: None,
        pending_reply: None,
    };

    let exit_code = match mach_msg::serve_one_message(&mut state, service_port, 0) {
        Ok(true) => {
            let code = if let Some(ref exc) = state.exception_data {
                handler::handle_exception(exc, config)
            } else {
                -1
            };

            // Reply with KERN_FAILURE so the kernel delivers the signal
            mach_msg::send_exception_reply(&mut state);
            code
        }
        Ok(false) => {
            // Port transfer — not expected in launchd mode
            eprintln!("exc_handler: unexpected port transfer in launchd mode");
            -1
        }
        Err(kr) => {
            eprintln!("exc_handler: mach_msg failed on service port: {kr}");
            -1
        }
    };

    cleanup_attach(config);
    exit_code
}

/// Cleanup for attach mode: remove lock file.
fn cleanup_attach(config: &Config) {
    if let Ok(c_path) = CString::new(config.lock_file.as_str()) {
        unsafe { unlink(c_path.as_ptr()) };
    }
}

/// Fork+exec mode: fork a child, exec the target, and catch exceptions.
fn run_fork_exec_mode(target_args: &[String], config: &Config) -> i32 {
    // 1. Save original bootstrap port
    let mut original_bootstrap: MachPortT = 0;
    let kr = unsafe { task_get_bootstrap_port(mach_task_self(), &mut original_bootstrap) };
    if kr != KERN_SUCCESS {
        eprintln!("exc_handler: failed to get bootstrap port: {kr}");
        return -1;
    }

    // 2. Allocate exception port and server port
    let exception_port = match allocate_exception_port() {
        Some(p) => p,
        None => {
            eprintln!("exc_handler: failed to allocate exception port");
            return -1;
        }
    };

    let mut server_port: MachPortT = 0;
    let kr =
        unsafe { mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut server_port) };
    if kr != KERN_SUCCESS {
        eprintln!("exc_handler: failed to allocate server port: {kr}");
        return -1;
    }
    unsafe {
        mach_port_insert_right(
            mach_task_self(),
            server_port,
            server_port,
            MACH_MSG_TYPE_MAKE_SEND,
        );
    }

    // 3. Install signal handlers to ignore SIGUSR1/SIGUSR2
    unsafe {
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, SIG_IGN);
    }

    // 4. Replace bootstrap port with our server port (bootstrap trick)
    let kr = unsafe { task_set_bootstrap_port(mach_task_self(), server_port) };
    if kr != KERN_SUCCESS {
        eprintln!("exc_handler: failed to set bootstrap port: {kr}");
        return -1;
    }

    // 5. Fork
    let child_pid = unsafe { fork() };

    if child_pid < 0 {
        eprintln!("exc_handler: fork failed");
        // Restore bootstrap port
        unsafe { task_set_bootstrap_port(mach_task_self(), original_bootstrap) };
        return -1;
    }

    if child_pid == 0 {
        // === CHILD PROCESS ===
        run_child(target_args);
    }

    // === PARENT PROCESS ===

    // Restore our bootstrap port
    unsafe { task_set_bootstrap_port(mach_task_self(), original_bootstrap) };

    if !config.quiet {
        eprintln!(
            "exc_handler: launched {} (pid {child_pid}), waiting for exceptions...",
            target_args[0]
        );
    }

    // Write PID file if requested
    if let Some(ref pid_file) = config.pid_file {
        let _ = std::fs::write(pid_file, format!("{child_pid}\n"));
    }

    // Create lock file
    let _ = std::fs::write(&config.lock_file, "");

    // 6. Wait for messages: first the port transfer, then the exception
    let mut state = ExcHandlerState {
        exception_port,
        original_bootstrap_port: original_bootstrap,
        server_port,
        exception_received: false,
        exception_data: None,
        pending_reply: None,
    };

    // Serve the port transfer message from the child (arrives on server_port)
    match mach_msg::serve_one_message(&mut state, server_port, 0) {
        Ok(false) => {
            // Port transfer handled — now wait for exception
        }
        Ok(true) => {
            // Got an exception immediately (unlikely but handle it)
            let exit_code = if let Some(ref exc) = state.exception_data {
                handler::handle_exception(exc, config)
            } else {
                -1
            };
            mach_msg::send_exception_reply(&mut state);
            cleanup(child_pid, config);
            return exit_code;
        }
        Err(kr) => {
            eprintln!("exc_handler: port transfer failed: {kr}");
            cleanup(child_pid, config);
            return -1;
        }
    }

    // Wait for exception or child exit.
    // Poll with a 100ms timeout so we can detect normal child exit via waitpid.
    let exit_code = loop {
        match mach_msg::serve_one_message(&mut state, exception_port, 100) {
            Ok(true) => {
                // Child thread is suspended — handle_exception can read its memory.
                let code = if let Some(ref exc) = state.exception_data {
                    handler::handle_exception(exc, config)
                } else {
                    -1
                };

                // Destroy the exception port so the follow-up EXC_CRASH
                // (triggered when the signal kills the process) has nowhere
                // to go and won't block the child thread.
                unsafe { mach_port_destroy(mach_task_self(), exception_port) };

                // Reply KERN_FAILURE so kernel delivers the signal (kills the child).
                mach_msg::send_exception_reply(&mut state);

                // Kill child if not config.no_kill_child (belt + suspenders)
                if !config.no_kill_child {
                    unsafe { kill(child_pid, SIGKILL) };
                }

                // Wait for child to actually exit
                let mut status: i32 = 0;
                unsafe { waitpid(child_pid, &mut status, 0) };

                break code;
            }
            Ok(false) => {
                // Another port transfer — unexpected
                break -1;
            }
            Err(kr) if kr == ffi::MACH_RCV_TIMED_OUT => {
                // Timeout — check if child has exited
                let mut status: i32 = 0;
                let waited = unsafe { waitpid(child_pid, &mut status, 1) }; // WNOHANG
                if waited > 0 {
                    // Child exited without a Mach exception
                    break if status & 0x7f == 0 {
                        0 // normal exit
                    } else {
                        -2 // non-crash signal
                    };
                }
                // Child still running — loop and try again
            }
            Err(_kr) => {
                // Real mach_msg error
                let mut status: i32 = 0;
                let waited = unsafe { waitpid(child_pid, &mut status, 1) }; // WNOHANG
                break if waited > 0 && status & 0x7f == 0 {
                    0
                } else {
                    -1
                };
            }
        }
    };

    cleanup(child_pid, config);
    exit_code
}

/// Child process: request ports from parent, set exception ports, exec target.
fn run_child(target_args: &[String]) -> ! {
    // The child inherits the server_port as its bootstrap port.
    // Send a transfer_ports request to get the exception port and real bootstrap port.

    let mut bootstrap: MachPortT = 0;
    unsafe { task_get_bootstrap_port(mach_task_self(), &mut bootstrap) };

    // Send transfer_ports request (msgh_id = 2408)
    // We need to allocate a reply port
    let mut reply_port: MachPortT = 0;
    unsafe {
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut reply_port);
    }

    // Send request and receive reply
    #[repr(C)]
    struct TransferMsg {
        request: mach_msg::TransferPortsRequest,
    }

    let mut msg = TransferMsg {
        request: mach_msg::TransferPortsRequest {
            header: MachMsgHeaderT {
                msgh_bits: 0x00001513, // send + make_send_once for local
                msgh_size: std::mem::size_of::<mach_msg::TransferPortsRequest>() as u32,
                msgh_remote_port: bootstrap,
                msgh_local_port: reply_port,
                msgh_voucher_port: 0,
                msgh_id: 2408,
            },
        },
    };

    // Send the request
    let kr = unsafe {
        mach_msg(
            &mut msg.request.header,
            MACH_SEND_MSG,
            msg.request.header.msgh_size,
            0,
            0,
            MACH_MSG_TIMEOUT_NONE,
            0,
        )
    };

    if kr != KERN_SUCCESS {
        eprintln!("exc_handler child: failed to send transfer request: {kr}");
        std::process::exit(-1);
    }

    // Receive the reply. Buffer must be larger than TransferPortsReply
    // to accommodate the kernel-appended message trailer.
    #[repr(C)]
    struct TransferReplyBuf {
        reply: mach_msg::TransferPortsReply,
        _trailer: [u8; 128],
    }

    let mut reply_buf = TransferReplyBuf {
        reply: mach_msg::TransferPortsReply {
            header: MachMsgHeaderT {
                msgh_bits: 0,
                msgh_size: 0,
                msgh_remote_port: 0,
                msgh_local_port: 0,
                msgh_voucher_port: 0,
                msgh_id: 0,
            },
            body: MachMsgBodyT {
                msgh_descriptor_count: 0,
            },
            exception_port: MachMsgPortDescriptorT {
                name: 0,
                pad1: 0,
                pad2: 0,
                disposition: 0,
                msg_type: 0,
            },
            bootstrap_port: MachMsgPortDescriptorT {
                name: 0,
                pad1: 0,
                pad2: 0,
                disposition: 0,
                msg_type: 0,
            },
            ndr: NDR_RECORD,
            return_code: 0,
        },
        _trailer: [0u8; 128],
    };

    let kr = unsafe {
        mach_msg(
            &mut reply_buf.reply.header,
            MACH_RCV_MSG,
            0,
            std::mem::size_of::<TransferReplyBuf>() as u32,
            reply_port,
            MACH_MSG_TIMEOUT_NONE,
            0,
        )
    };

    if kr != KERN_SUCCESS {
        eprintln!("exc_handler child: failed to receive transfer reply: {kr}");
        std::process::exit(-1);
    }

    let exc_port = reply_buf.reply.exception_port.name;
    let real_bootstrap = reply_buf.reply.bootstrap_port.name;

    // Restore real bootstrap port
    unsafe { task_set_bootstrap_port(mach_task_self(), real_bootstrap) };

    // Set exception ports on ourselves
    let kr = unsafe {
        task_set_exception_ports(
            mach_task_self(),
            EXC_MASK_ALL,
            exc_port,
            EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
            THREAD_STATE_FLAVOR,
        )
    };

    if kr != KERN_SUCCESS {
        eprintln!("exc_handler child: failed to set exception ports: {kr}");
        std::process::exit(-1);
    }

    // Exec the target program
    let c_args: Vec<CString> = target_args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect();
    let c_arg_ptrs: Vec<*const i8> = c_args
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        execvp(c_arg_ptrs[0], c_arg_ptrs.as_ptr());
    }

    // If we get here, exec failed
    eprintln!(
        "exc_handler: failed to exec {}",
        target_args.first().map(|s| s.as_str()).unwrap_or("???")
    );
    std::process::exit(-1);
}

/// Allocates a Mach port with receive right and inserts a send right.
fn allocate_exception_port() -> Option<MachPortT> {
    unsafe {
        let mut port: MachPortT = 0;
        let kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mut port);
        if kr != KERN_SUCCESS {
            return None;
        }
        let kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        if kr != KERN_SUCCESS {
            return None;
        }
        Some(port)
    }
}

/// Cleanup: remove lock file, PID file.
fn cleanup(_child_pid: i32, config: &Config) {
    // Remove lock file
    if let Ok(c_path) = CString::new(config.lock_file.as_str()) {
        unsafe { unlink(c_path.as_ptr()) };
    }
    // Remove PID file
    if let Some(ref pid_file) = config.pid_file
        && let Ok(c_path) = CString::new(pid_file.as_str())
    {
        unsafe { unlink(c_path.as_ptr()) };
    }
}

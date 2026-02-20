//! Crash dummy: exits or crashes on command.
//!
//! Used by integration tests to exercise exc_handler's crash detection.
//! Accepts one CLI arg to select the crash type.
//!
//! When `--wait` is passed, prints its PID to stdout and blocks until
//! SIGUSR1 is received, allowing exc_handler to attach via PID before
//! the crash is triggered.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let wait = args.iter().any(|a| a == "--wait");
    let arg = args
        .iter()
        .find(|a| a.as_str() != "--wait")
        .cloned()
        .unwrap_or_else(|| {
            eprintln!("Usage: crash_dummy [--wait] <exit0|sigsegv|sigill|sigtrap|sigabrt|sigfpe>");
            std::process::exit(2);
        });

    if wait {
        wait_for_signal();
    }

    match arg.as_str() {
        "exit0" => std::process::exit(0),
        "sigsegv" => do_sigsegv(),
        "sigill" => do_sigill(),
        "sigtrap" => do_sigtrap(),
        "sigabrt" => do_raise(6),
        "sigfpe" => do_raise(8),
        other => {
            eprintln!("Unknown crash type: {other}");
            std::process::exit(2);
        }
    }
}

const SIGUSR1: i32 = 30;

unsafe extern "C" {
    fn raise(sig: i32) -> i32;
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    fn pause() -> i32;
    fn getpid() -> i32;
}

extern "C" fn sigusr1_handler(_sig: i32) {}

/// Prints the process PID to stdout and blocks until SIGUSR1 is received.
fn wait_for_signal() {
    unsafe { signal(SIGUSR1, sigusr1_handler) };
    let pid = unsafe { getpid() };
    println!("{pid}");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    unsafe { pause() };
}

/// Raises a POSIX signal. Falls back to exit if raise somehow returns.
fn do_raise(sig: i32) {
    unsafe { raise(sig) };
    std::process::exit(sig);
}

// --- ARM64 assembly crash triggers ---

#[cfg(target_arch = "aarch64")]
fn do_sigsegv() {
    unsafe {
        std::arch::asm!(
            "mov x0, #0",
            "ldr x0, [x0]",
            out("x0") _,
            options(nostack),
        );
    }
}

#[cfg(target_arch = "aarch64")]
fn do_sigill() {
    unsafe {
        std::arch::asm!("udf #0xdead", options(nostack, noreturn));
    }
}

#[cfg(target_arch = "aarch64")]
fn do_sigtrap() {
    unsafe {
        std::arch::asm!("brk #1", options(nostack));
    }
}

// --- x86_64 assembly crash triggers ---

#[cfg(target_arch = "x86_64")]
fn do_sigsegv() {
    unsafe {
        std::arch::asm!(
            "xor rax, rax",
            "mov rax, [rax]",
            out("rax") _,
            options(nostack),
        );
    }
}

#[cfg(target_arch = "x86_64")]
fn do_sigill() {
    unsafe {
        std::arch::asm!("ud2", options(nostack, noreturn));
    }
}

#[cfg(target_arch = "x86_64")]
fn do_sigtrap() {
    unsafe {
        std::arch::asm!("int3", options(nostack));
    }
}

// --- Fallback for other architectures ---

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn do_sigsegv() {
    do_raise(11);
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn do_sigill() {
    do_raise(4);
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn do_sigtrap() {
    do_raise(5);
}

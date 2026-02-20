//! ASan crash dummy: triggers AddressSanitizer-detected memory errors.
//!
//! Used by integration tests to exercise exc_handler's handling of ASan-detected
//! crashes. Accepts one CLI arg to select the crash mode.
//!
//! Must be compiled with `RUSTFLAGS="-Zsanitizer=address"` on nightly Rust.
//!
//! When `--wait` is passed, prints its PID to stdout and blocks until
//! SIGUSR1 is received, allowing exc_handler to attach via PID before
//! the crash is triggered.

const SIGUSR1: i32 = 30;

unsafe extern "C" {
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let wait = args.iter().any(|a| a == "--wait");
    let arg = args
        .iter()
        .find(|a| a.as_str() != "--wait")
        .cloned()
        .unwrap_or_else(|| {
            eprintln!(
                "Usage: asan-crash-dummy [--wait] <heap_overflow|heap_uaf|stack_overflow|stack_uaf>"
            );
            std::process::exit(2);
        });

    if wait {
        wait_for_signal();
    }

    match arg.as_str() {
        "heap_overflow" => do_heap_overflow(),
        "heap_uaf" => do_heap_uaf(),
        "stack_overflow" => do_stack_overflow(),
        "stack_uaf" => do_stack_uaf(),
        other => {
            eprintln!("Unknown crash mode: {other}");
            std::process::exit(2);
        }
    }
}

/// Heap buffer overflow: write 1 byte past the end of a Vec allocation.
#[inline(never)]
fn do_heap_overflow() {
    let v: Vec<u8> = vec![0u8; 64];
    let ptr = v.as_ptr();
    let len = v.len();
    std::hint::black_box(&v);
    unsafe {
        std::ptr::write_volatile(ptr.add(len) as *mut u8, 0x41);
    }
    std::hint::black_box(&v);
}

/// Heap use-after-free: read through a dangling pointer after dropping a Vec.
#[inline(never)]
fn do_heap_uaf() {
    let ptr: *const u8;
    {
        let v: Vec<u8> = vec![0xBBu8; 64];
        ptr = v.as_ptr();
        std::hint::black_box(&v);
    }
    // Vec is dropped, ptr is dangling
    let val = unsafe { std::ptr::read_volatile(ptr) };
    std::hint::black_box(val);
}

/// Stack buffer overflow: write past the end of a stack array.
#[inline(never)]
fn do_stack_overflow() {
    let buf = [0u8; 16];
    let ptr = buf.as_ptr();
    std::hint::black_box(&buf);
    unsafe {
        std::ptr::write_volatile(ptr.add(16) as *mut u8, 0x42);
    }
    std::hint::black_box(&buf);
}

/// Stack use-after-free: read from a pointer to a local after it goes out of scope.
#[inline(never)]
fn do_stack_uaf() {
    let ptr: *const u8;
    {
        let local = [0xCCu8; 16];
        ptr = local.as_ptr();
        std::hint::black_box(&local);
    }
    // local is out of scope
    let val = unsafe { std::ptr::read_volatile(ptr) };
    std::hint::black_box(val);
}

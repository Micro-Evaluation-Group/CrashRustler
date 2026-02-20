//! TSan crash dummy: triggers ThreadSanitizer-detected data races.
//!
//! Used by integration tests to exercise exc_handler's handling of TSan-detected
//! crashes. Accepts one CLI arg to select the crash mode.
//!
//! Must be compiled with `RUSTFLAGS="-Zsanitizer=thread"` on nightly Rust,
//! using `-Zbuild-std --target aarch64-apple-darwin` (TSan requires build-std on macOS).
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
            eprintln!("Usage: tsan-crash-dummy [--wait] <data_race|heap_race>");
            std::process::exit(2);
        });

    if wait {
        wait_for_signal();
    }

    match arg.as_str() {
        "data_race" => do_data_race(),
        "heap_race" => do_heap_race(),
        other => {
            eprintln!("Unknown crash mode: {other}");
            std::process::exit(2);
        }
    }
}

/// Data race on a static mut: two threads increment a shared counter without synchronization.
#[inline(never)]
fn do_data_race() {
    static mut COUNTER: u64 = 0;

    let t1 = std::thread::spawn(|| {
        for _ in 0..1000 {
            unsafe {
                COUNTER += 1;
            }
            std::hint::black_box(unsafe { COUNTER });
        }
    });

    let t2 = std::thread::spawn(|| {
        for _ in 0..1000 {
            unsafe {
                COUNTER += 1;
            }
            std::hint::black_box(unsafe { COUNTER });
        }
    });

    t1.join().unwrap();
    t2.join().unwrap();
    std::hint::black_box(unsafe { COUNTER });
}

/// Data race on heap-allocated data: two threads read/write through raw pointers
/// to a shared heap allocation without synchronization.
#[inline(never)]
fn do_heap_race() {
    let data = Box::into_raw(Box::new(0u64));

    let ptr1 = data as usize;
    let ptr2 = data as usize;

    let t1 = std::thread::spawn(move || {
        let p = ptr1 as *mut u64;
        for _ in 0..1000 {
            unsafe {
                *p += 1;
            }
            std::hint::black_box(unsafe { *p });
        }
    });

    let t2 = std::thread::spawn(move || {
        let p = ptr2 as *mut u64;
        for _ in 0..1000 {
            unsafe {
                *p += 1;
            }
            std::hint::black_box(unsafe { *p });
        }
    });

    t1.join().unwrap();
    t2.join().unwrap();
    unsafe {
        std::hint::black_box(*data);
        drop(Box::from_raw(data));
    }
}

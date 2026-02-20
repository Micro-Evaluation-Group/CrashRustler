use crate::crash_rustler::CrashRustler;
use crate::types::*;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

// -----------------------------------------------------------------
// 1. Signal handling FFI (macOS aarch64)
// -----------------------------------------------------------------
mod crash_ffi {
    use std::ffi::c_void;

    /// macOS aarch64: sigjmp_buf = int[_JBLEN + 1] where _JBLEN = 48
    pub type SigJmpBuf = [i32; 49];

    pub const SA_SIGINFO: i32 = 0x0040;
    pub const SA_ONSTACK: i32 = 0x0001;
    pub const SIGSTKSZ: usize = 131072;

    pub const SIGSEGV: i32 = 11;
    pub const SIGBUS: i32 = 10;
    pub const SIGILL: i32 = 4;
    pub const SIGFPE: i32 = 8;
    pub const SIGTRAP: i32 = 5;
    pub const SIGABRT: i32 = 6;

    #[repr(C)]
    pub struct SigAction {
        pub sa_sigaction: Option<extern "C" fn(i32, *mut SigInfo, *mut c_void)>,
        pub sa_mask: u32, // sigset_t on macOS = u32
        pub sa_flags: i32,
    }

    #[repr(C)]
    pub struct SigInfo {
        pub si_signo: i32,
        pub si_errno: i32,
        pub si_code: i32,
        pub si_pid: i32,
        pub si_uid: u32,
        pub si_status: i32,
        pub si_addr: *mut c_void,
    }

    #[repr(C)]
    pub struct SigAltStack {
        pub ss_sp: *mut c_void,
        pub ss_size: usize,
        pub ss_flags: i32,
    }

    unsafe extern "C" {
        pub fn sigaction(sig: i32, act: *const SigAction, oact: *mut SigAction) -> i32;
        pub fn sigsetjmp(env: *mut i32, savesigs: i32) -> i32;
        pub fn siglongjmp(env: *mut i32, val: i32) -> !;
        pub fn sigaltstack(ss: *const SigAltStack, oss: *mut SigAltStack) -> i32;
        pub fn raise(sig: i32) -> i32;
    }
}

// -----------------------------------------------------------------
// 2. Crash harness (global state + signal handler + catch_crash)
// -----------------------------------------------------------------
static CRASH_MUTEX: Mutex<()> = Mutex::new(());
static CAUGHT_SIGNAL: AtomicI32 = AtomicI32::new(0);
static FAULT_ADDR: AtomicU64 = AtomicU64::new(0);
static mut JUMP_BUF: crash_ffi::SigJmpBuf = [0i32; 49];

/// Async-signal-safe handler: stores signal info and recovers via siglongjmp.
extern "C" fn crash_handler(sig: i32, info: *mut crash_ffi::SigInfo, _ctx: *mut std::ffi::c_void) {
    CAUGHT_SIGNAL.store(sig, Ordering::SeqCst);
    if !info.is_null() {
        FAULT_ADDR.store(unsafe { (*info).si_addr as u64 }, Ordering::SeqCst);
    }
    unsafe { crash_ffi::siglongjmp(std::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) };
}

/// Installs signal handlers, runs the crash-trigger closure, catches the
/// resulting signal via sigsetjmp/siglongjmp, and returns (signal, fault_addr).
fn catch_crash<F: FnOnce()>(f: F) -> (i32, u64) {
    let _lock = CRASH_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    CAUGHT_SIGNAL.store(0, Ordering::SeqCst);
    FAULT_ADDR.store(0, Ordering::SeqCst);

    // Allocate alternate signal stack
    let mut alt_stack_buf = vec![0u8; crash_ffi::SIGSTKSZ];
    let new_ss = crash_ffi::SigAltStack {
        ss_sp: alt_stack_buf.as_mut_ptr().cast(),
        ss_size: crash_ffi::SIGSTKSZ,
        ss_flags: 0,
    };
    let mut old_ss = crash_ffi::SigAltStack {
        ss_sp: std::ptr::null_mut(),
        ss_size: 0,
        ss_flags: 0,
    };
    unsafe { crash_ffi::sigaltstack(&new_ss, &mut old_ss) };

    // Install crash_handler for all crash signals
    let signals = [
        crash_ffi::SIGSEGV,
        crash_ffi::SIGBUS,
        crash_ffi::SIGILL,
        crash_ffi::SIGFPE,
        crash_ffi::SIGTRAP,
        crash_ffi::SIGABRT,
    ];

    let new_action = crash_ffi::SigAction {
        sa_sigaction: Some(crash_handler),
        sa_mask: 0,
        sa_flags: crash_ffi::SA_SIGINFO | crash_ffi::SA_ONSTACK,
    };

    let mut old_actions: Vec<crash_ffi::SigAction> = signals
        .iter()
        .map(|_| crash_ffi::SigAction {
            sa_sigaction: None,
            sa_mask: 0,
            sa_flags: 0,
        })
        .collect();

    for (i, &sig) in signals.iter().enumerate() {
        unsafe {
            crash_ffi::sigaction(sig, &new_action, &mut old_actions[i]);
        }
    }

    // sigsetjmp returns 0 on direct call, non-zero when recovered via siglongjmp
    let jumped = unsafe { crash_ffi::sigsetjmp(std::ptr::addr_of_mut!(JUMP_BUF).cast(), 1) };
    if jumped == 0 {
        f();
    }

    // Restore original signal handlers
    for (i, &sig) in signals.iter().enumerate() {
        unsafe {
            crash_ffi::sigaction(sig, &old_actions[i], std::ptr::null_mut());
        }
    }

    // Restore original sigaltstack
    unsafe { crash_ffi::sigaltstack(&old_ss, std::ptr::null_mut()) };

    // Keep alt_stack_buf alive until after sigaltstack restore
    drop(alt_stack_buf);

    (
        CAUGHT_SIGNAL.load(Ordering::SeqCst),
        FAULT_ADDR.load(Ordering::SeqCst),
    )
}

// -----------------------------------------------------------------
// 3. CrashKind + ARM64 inline asm triggers
// -----------------------------------------------------------------
#[derive(Debug, Clone, Copy)]
enum CrashKind {
    /// Null pointer dereference via `ldr x0, [xzr]` → SIGSEGV
    BadAccess,
    /// Permanently undefined instruction `udf #0xdead` → SIGILL
    BadInstruction,
    /// raise(SIGFPE) — ARM64 doesn't hardware-trap integer div-by-zero
    Arithmetic,
    /// Breakpoint instruction `brk #1` → SIGTRAP
    Breakpoint,
    /// raise(SIGABRT) — same path as a real abort
    Abort,
}

#[inline(never)]
fn trigger_crash(kind: CrashKind) {
    match kind {
        CrashKind::BadAccess => unsafe {
            // Load from address 0 (null pointer dereference) → SIGSEGV
            std::arch::asm!(
                "mov x0, #0",
                "ldr x0, [x0]",
                out("x0") _,
                options(nostack),
            );
        },
        CrashKind::BadInstruction => unsafe {
            std::arch::asm!("udf #0xdead", options(nostack, noreturn));
        },
        CrashKind::Arithmetic => {
            unsafe { crash_ffi::raise(crash_ffi::SIGFPE) };
        }
        CrashKind::Breakpoint => unsafe {
            std::arch::asm!("brk #1", options(nostack));
        },
        CrashKind::Abort => {
            unsafe { crash_ffi::raise(crash_ffi::SIGABRT) };
        }
    }
}

// -----------------------------------------------------------------
// 4. Crash trait + build_crash_report helper
// -----------------------------------------------------------------
trait Crash {
    fn process_name(&self) -> &str;
    fn crash_symbols(&self) -> Vec<&str>;

    fn crash(&self, kind: CrashKind) -> CrashRustler {
        let (signal, fault_addr) = catch_crash(|| trigger_crash(kind));
        let symbols = self.crash_symbols();
        build_crash_report(signal, fault_addr, self.process_name(), &symbols)
    }
}

/// Builds a fully populated CrashRustler from caught crash data.
/// `symbols` is the call chain in frame order (frame 0 = crash site).
fn build_crash_report(signal: i32, fault_addr: u64, name: &str, symbols: &[&str]) -> CrashRustler {
    let mut cr = CrashRustler::default();

    // Process info
    cr.process_name = Some(name.into());
    cr.executable_path = Some(format!("/Users/testuser/build/{name}"));
    cr.pid = 12345;
    cr.ppid = 1;

    // Architecture: ARM64, native 64-bit
    cr.cpu_type = CpuType::ARM64;
    cr.is_64_bit = true;
    cr.is_native = true;

    // Map caught signal → exception type + codes
    cr.signal = signal as u32;
    match signal {
        11 => {
            // SIGSEGV → EXC_BAD_ACCESS (KERN_INVALID_ADDRESS)
            cr.exception_type = 1;
            cr.exception_code = vec![1, fault_addr as i64];
            cr.exception_code_count = 2;
        }
        4 => {
            // SIGILL → EXC_BAD_INSTRUCTION
            cr.exception_type = 2;
            cr.exception_code = vec![1];
            cr.exception_code_count = 1;
        }
        8 => {
            // SIGFPE → EXC_ARITHMETIC (EXC_ARM_FP_DZ)
            cr.exception_type = 3;
            cr.exception_code = vec![2];
            cr.exception_code_count = 1;
        }
        5 => {
            // SIGTRAP → EXC_BREAKPOINT
            cr.exception_type = 6;
            cr.exception_code = vec![1];
            cr.exception_code_count = 1;
        }
        6 => {
            // SIGABRT → EXC_CRASH
            cr.exception_type = 10;
            cr.exception_code = vec![0];
            cr.exception_code_count = 1;
        }
        _ => {}
    }

    // Binary image address ranges
    let app_base: u64 = 0x1_0000_0000;
    let app_end: u64 = 0x1_0001_0000;
    let sys_kernel_base: u64 = 0x1_8000_0000;
    let sys_kernel_end: u64 = 0x1_8000_8000;
    let sys_dyld_base: u64 = 0x1_8001_0000;
    let sys_dyld_end: u64 = 0x1_8001_8000;

    // ARM64 thread state: flavor 6, 68 u32 words
    // Layout: x0-x28 (pairs 0..57), fp(58-59), lr(60-61), sp(62-63), pc(64-65), cpsr(66)
    let mut regs = vec![0u32; 68];
    let pc_addr = app_base + 0x100;
    let lr_addr = app_base + 0x200;
    let sp_val: u64 = 0x16F5E_0000;
    let fp_val: u64 = 0x16F5E_0100;
    regs[64] = pc_addr as u32;
    regs[65] = (pc_addr >> 32) as u32;
    regs[60] = lr_addr as u32;
    regs[61] = (lr_addr >> 32) as u32;
    regs[62] = sp_val as u32;
    regs[63] = (sp_val >> 32) as u32;
    regs[58] = fp_val as u32;
    regs[59] = (fp_val >> 32) as u32;
    regs[66] = 0x6000_0000; // NZCV flags

    cr.thread_state = ThreadState {
        flavor: 6,
        registers: regs,
    };

    // ARM64 exception state: FAR at state[0..1]
    let far_lo = fault_addr as u32;
    let far_hi = (fault_addr >> 32) as u32;
    cr.exception_state = ExceptionState {
        state: vec![far_lo, far_hi, 0, 0],
        count: 4,
    };
    cr.thread_exception_state = vec![far_lo, far_hi, 0, 0];
    cr.thread_exception_state_count = 4;

    // Three binary images: app, libsystem_kernel, libdyld
    cr.add_binary_image(BinaryImage {
        name: name.into(),
        path: format!("/Users/testuser/build/{name}"),
        uuid: Some("AAAA-1111-2222-3333-4444".into()),
        base_address: app_base,
        end_address: app_end,
        arch: Some("arm64".into()),
        identifier: Some(name.into()),
        version: Some("1.0".into()),
    });
    cr.add_binary_image(BinaryImage {
        name: "libsystem_kernel.dylib".into(),
        path: "/usr/lib/system/libsystem_kernel.dylib".into(),
        uuid: Some("BBBB-5555-6666-7777-8888".into()),
        base_address: sys_kernel_base,
        end_address: sys_kernel_end,
        arch: Some("arm64".into()),
        identifier: Some("libsystem_kernel.dylib".into()),
        version: Some("1.0".into()),
    });
    cr.add_binary_image(BinaryImage {
        name: "libdyld.dylib".into(),
        path: "/usr/lib/system/libdyld.dylib".into(),
        uuid: Some("CCCC-9999-AAAA-BBBB-CCCC".into()),
        base_address: sys_dyld_base,
        end_address: sys_dyld_end,
        arch: Some("arm64".into()),
        identifier: Some("libdyld.dylib".into()),
        version: Some("1.0".into()),
    });

    // Thread 0: main thread, not crashed, 2 system frames
    let thread0 = ThreadBacktrace {
        thread_number: 0,
        thread_name: Some("main".into()),
        thread_id: Some(100),
        is_crashed: false,
        frames: vec![
            BacktraceFrame {
                frame_number: 0,
                image_name: "libsystem_kernel.dylib".into(),
                address: sys_kernel_base + 0x100,
                symbol_name: Some("mach_msg_trap".into()),
                symbol_offset: 8,
                source_file: None,
                source_line: None,
            },
            BacktraceFrame {
                frame_number: 1,
                image_name: "libdyld.dylib".into(),
                address: sys_dyld_base + 0x200,
                symbol_name: Some("start".into()),
                symbol_offset: 4,
                source_file: None,
                source_line: None,
            },
        ],
    };

    // Thread 1: crashed thread, method chain frames + unsymbolicated + system
    let mut crashed_frames = Vec::new();
    for (i, &sym) in symbols.iter().enumerate() {
        let addr = app_base + 0x100 + (i as u64 * 0x40);
        crashed_frames.push(BacktraceFrame {
            frame_number: i as u32,
            image_name: name.into(),
            address: addr,
            symbol_name: Some(sym.into()),
            symbol_offset: 12,
            source_file: if i == 0 {
                Some("src/main.rs".into())
            } else {
                None
            },
            source_line: if i == 0 { Some(42) } else { None },
        });
    }
    // Unsymbolicated app frame (tests offset-from-base fallback)
    let unsym_idx = symbols.len();
    crashed_frames.push(BacktraceFrame {
        frame_number: unsym_idx as u32,
        image_name: name.into(),
        address: app_base + 0x500,
        symbol_name: None,
        symbol_offset: 0,
        source_file: None,
        source_line: None,
    });
    // System frame at end
    crashed_frames.push(BacktraceFrame {
        frame_number: (unsym_idx + 1) as u32,
        image_name: "libsystem_kernel.dylib".into(),
        address: sys_kernel_base + 0x300,
        symbol_name: Some("__pthread_start".into()),
        symbol_offset: 0,
        source_file: None,
        source_line: None,
    });

    let thread1 = ThreadBacktrace {
        thread_number: 1,
        thread_name: Some("crash-thread".into()),
        thread_id: Some(200),
        is_crashed: true,
        frames: crashed_frames,
    };

    cr.backtraces = vec![thread0, thread1];
    cr.crashed_thread_number = 1;

    // Post-processing
    cr.extract_crashing_address();
    cr.finalize_binary_images();
    cr.cleanse_paths();

    cr
}

// -----------------------------------------------------------------
// 5. Three math structs with chained call depth
// -----------------------------------------------------------------

struct Adder {
    value: i64,
}

impl Adder {
    #[inline(never)]
    fn add(&self, x: i64) -> i64 {
        self.value + x
    }

    #[inline(never)]
    fn increment(&self) -> i64 {
        self.add(1)
    }

    #[inline(never)]
    fn double(&self) -> i64 {
        self.increment() + self.increment()
    }

    #[inline(never)]
    fn add_squared(&self, x: i64) -> i64 {
        self.double() + x * x
    }

    #[inline(never)]
    fn sum_with(&self, other: i64) -> i64 {
        self.add_squared(other) + other
    }
}

struct Multiplier {
    factor: i64,
}

impl Multiplier {
    #[inline(never)]
    fn multiply(&self, x: i64) -> i64 {
        self.factor * x
    }

    #[inline(never)]
    fn power_of_two(&self) -> i64 {
        self.multiply(self.multiply(1))
    }

    #[inline(never)]
    fn square(&self) -> i64 {
        self.power_of_two()
    }

    #[inline(never)]
    fn cube(&self) -> i64 {
        self.square() * self.factor
    }

    #[inline(never)]
    fn product_with(&self, a: i64, b: i64) -> i64 {
        self.cube() + a * b
    }
}

struct Bitwise {
    bits: u64,
}

impl Bitwise {
    #[inline(never)]
    fn and(&self, mask: u64) -> u64 {
        self.bits & mask
    }

    #[inline(never)]
    fn shift_left(&self, n: u32) -> u64 {
        self.and(0xFFFF_FFFF) << n
    }

    #[inline(never)]
    fn or(&self, mask: u64) -> u64 {
        self.shift_left(0) | mask
    }

    #[inline(never)]
    fn xor(&self, mask: u64) -> u64 {
        self.or(0) ^ mask
    }

    #[inline(never)]
    fn count_ones(&self) -> u32 {
        self.xor(0).count_ones()
    }
}

// -----------------------------------------------------------------
// 6. Crash trait implementations
// -----------------------------------------------------------------
impl Crash for Adder {
    fn process_name(&self) -> &str {
        "Adder"
    }
    fn crash_symbols(&self) -> Vec<&str> {
        vec!["add", "increment", "double", "add_squared", "sum_with"]
    }
}

impl Crash for Multiplier {
    fn process_name(&self) -> &str {
        "Multiplier"
    }
    fn crash_symbols(&self) -> Vec<&str> {
        vec!["multiply", "power_of_two", "square", "cube", "product_with"]
    }
}

impl Crash for Bitwise {
    fn process_name(&self) -> &str {
        "Bitwise"
    }
    fn crash_symbols(&self) -> Vec<&str> {
        vec!["and", "shift_left", "or", "xor", "count_ones"]
    }
}

// -----------------------------------------------------------------
// 7. Tests
// -----------------------------------------------------------------

/// Null pointer dereference via `ldr x0, [xzr]` → SIGSEGV
#[test]
fn adder_bad_access() {
    let a = Adder { value: 10 };

    // Chain all math methods and verify arithmetic
    // add(1)=11, increment()=11, double()=22, add_squared(5)=47, sum_with(5)=52
    let result = a.sum_with(5);
    assert_eq!(result, 52);

    // Trigger real SIGSEGV and build crash report
    let cr = a.crash(CrashKind::BadAccess);

    // Signal and exception
    assert_eq!(cr.signal, 11);
    assert_eq!(cr.signal_name(), "SIGSEGV");
    assert_eq!(cr.exception_type_description(), "EXC_BAD_ACCESS");
    assert!(cr.crashed_due_to_bad_memory_access());

    // Exception codes
    let codes = cr.exception_codes_description();
    assert!(codes.contains("KERN_INVALID_ADDRESS"));

    // ARM64 thread state
    let ts = cr.thread_state_description();
    assert!(ts.contains("ARM Thread State (64-bit)"));

    // Backtrace: all 5 method symbols present, crashed thread marker
    let bt = cr.backtrace_description();
    assert!(bt.contains("Thread 1 Crashed:"));
    assert!(bt.contains("add"));
    assert!(bt.contains("increment"));
    assert!(bt.contains("double"));
    assert!(bt.contains("add_squared"));
    assert!(bt.contains("sum_with"));
    // Unsymbolicated frame shows offset-from-base fallback
    assert!(bt.contains("0x100000000 + "));
    // Source location on frame 0
    assert!(bt.contains("(src/main.rs:42)"));

    // cleanse_paths sanitized /Users/testuser/ → /Users/USER/
    assert!(
        cr.executable_path
            .as_ref()
            .unwrap()
            .contains("/Users/USER/")
    );

    // Problem dictionary
    let pd = cr.problem_dictionary();
    assert_eq!(
        pd.get("arch").and_then(|v| match v {
            PlistValue::String(s) => Some(s.as_str()),
            _ => None,
        }),
        Some("arm64")
    );
    assert_eq!(
        pd.get("signal_name").and_then(|v| match v {
            PlistValue::String(s) => Some(s.as_str()),
            _ => None,
        }),
        Some("SIGSEGV")
    );
    assert_eq!(
        pd.get("app_name").and_then(|v| match v {
            PlistValue::String(s) => Some(s.as_str()),
            _ => None,
        }),
        Some("Adder")
    );
    let exc_type_val = pd.get("exception_type").and_then(|v| match v {
        PlistValue::String(s) => Some(s.as_str()),
        _ => None,
    });
    assert_eq!(exc_type_val, Some("EXC_BAD_ACCESS"));
}

/// raise(SIGFPE) → EXC_ARITHMETIC (ARM64 doesn't hardware-trap div-by-zero)
#[test]
fn multiplier_arithmetic() {
    let m = Multiplier { factor: 3 };

    // Chain: multiply(1)=3, multiply(3)=9, power_of_two()=9,
    // square()=9, cube()=27, product_with(2,3)=33
    let result = m.product_with(2, 3);
    assert_eq!(result, 33);

    let cr = m.crash(CrashKind::Arithmetic);

    assert_eq!(cr.signal, 8);
    assert_eq!(cr.signal_name(), "SIGFPE");
    assert_eq!(cr.exception_type_description(), "EXC_ARITHMETIC");
    assert!(!cr.crashed_due_to_bad_memory_access());

    // ARM64 FP divide-by-zero code
    let codes = cr.exception_codes_description();
    assert_eq!(codes, "EXC_ARM_FP_DZ (divide by zero)");

    // Backtrace symbols
    let bt = cr.backtrace_description();
    assert!(bt.contains("multiply"));
    assert!(bt.contains("power_of_two"));
    assert!(bt.contains("square"));
    assert!(bt.contains("cube"));
    assert!(bt.contains("product_with"));

    // Pre-signature dictionary has crashed_thread backtrace
    let psd = cr.pre_signature_dictionary();
    assert!(psd.contains_key("crashed_thread"));
    let ct = psd.get("crashed_thread").unwrap();
    if let PlistValue::Dict(d) = ct {
        assert!(d.contains_key("backtrace"));
    } else {
        panic!("crashed_thread should be a Dict");
    }

    // Description dictionary has all three top-level keys
    let dd = cr.description_dictionary();
    assert!(dd.contains_key("report"));
    assert!(dd.contains_key("presignature"));
    assert!(dd.contains_key("context"));
}

/// raise(SIGABRT) → EXC_CRASH
#[test]
fn bitwise_abort() {
    let b = Bitwise { bits: 0xFF00_FF00 };

    // Chain: and(0xFFFF_FFFF)=0xFF00_FF00, shift_left(0)=0xFF00_FF00,
    // or(0)=0xFF00_FF00, xor(0)=0xFF00_FF00, count_ones()=16
    let result = b.count_ones();
    assert_eq!(result, 16);

    let cr = b.crash(CrashKind::Abort);

    assert_eq!(cr.signal, 6);
    assert_eq!(cr.signal_name(), "SIGABRT");
    assert_eq!(cr.exception_type_description(), "EXC_CRASH");

    // Backtrace symbols
    let bt = cr.backtrace_description();
    assert!(bt.contains("and"));
    assert!(bt.contains("shift_left"));
    assert!(bt.contains("or"));
    assert!(bt.contains("xor"));
    assert!(bt.contains("count_ones"));

    // Binary images description: Apple marker (+) on system paths
    let bid = cr.binary_images_description();
    assert!(bid.contains("+libsystem_kernel.dylib"));
    assert!(bid.contains("+libdyld.dylib"));

    // finalize_binary_images sorted by base_address
    assert!(cr.binary_images[0].base_address < cr.binary_images[1].base_address);
    assert!(cr.binary_images[1].base_address < cr.binary_images[2].base_address);

    // Problem dictionary: arch_64=true, arch_translated=false
    let pd = cr.problem_dictionary();
    assert_eq!(
        pd.get("arch_64").and_then(|v| match v {
            PlistValue::Bool(b) => Some(*b),
            _ => None,
        }),
        Some(true)
    );
    assert_eq!(
        pd.get("arch_translated").and_then(|v| match v {
            PlistValue::Bool(b) => Some(*b),
            _ => None,
        }),
        Some(false)
    );
}

/// `brk #1` → SIGTRAP → EXC_BREAKPOINT
#[test]
fn adder_breakpoint() {
    let a = Adder { value: 7 };

    // Chain: add(1)=8, increment()=8, double()=16, add_squared(3)=25, sum_with(3)=28
    let result = a.sum_with(3);
    assert_eq!(result, 28);

    let cr = a.crash(CrashKind::Breakpoint);

    assert_eq!(cr.signal, 5);
    assert_eq!(cr.signal_name(), "SIGTRAP");
    assert_eq!(cr.exception_type_description(), "EXC_BREAKPOINT");

    // Backtrace frame count and symbols
    let bt = cr.backtrace_description();
    assert!(bt.contains("add"));
    assert!(bt.contains("sum_with"));
    assert!(bt.contains("Thread 1 Crashed:"));

    // Thread state contains specific register values
    let ts = cr.thread_state_description();
    assert!(ts.contains("ARM Thread State (64-bit)"));
    // pc = 0x100000100
    assert!(ts.contains("0x0000000100000100"));
    // lr = 0x100000200
    assert!(ts.contains("0x0000000100000200"));
    // sp = 0x16f5e0000
    assert!(ts.contains("0x000000016f5e0000"));
}

/// `udf #0xdead` → SIGILL → EXC_BAD_INSTRUCTION
#[test]
fn multiplier_bad_instruction() {
    let m = Multiplier { factor: 2 };

    // Chain: multiply(1)=2, multiply(2)=4, power_of_two()=4,
    // square()=4, cube()=8, product_with(3,4)=20
    let result = m.product_with(3, 4);
    assert_eq!(result, 20);

    let cr = m.crash(CrashKind::BadInstruction);

    assert_eq!(cr.signal, 4);
    assert_eq!(cr.signal_name(), "SIGILL");
    assert_eq!(cr.exception_type_description(), "EXC_BAD_INSTRUCTION");

    // Backtrace symbols
    let bt = cr.backtrace_description();
    assert!(bt.contains("multiply"));
    assert!(bt.contains("product_with"));
    assert!(bt.contains("Thread 1 Crashed:"));

    // binary_image_for_address: in-range returns image, out-of-range returns None
    assert!(cr.binary_image_for_address(0x1_0000_0500).is_some());
    assert!(cr.binary_image_for_address(0xDEAD_BEEF).is_none());
}

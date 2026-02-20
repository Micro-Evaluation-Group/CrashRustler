use crate::*;

/// Helper: builds a default CrashRustler with common fields pre-populated (x86_64).
pub(crate) fn make_test_cr() -> CrashRustler {
    let mut cr = CrashRustler::default();
    cr.pid = 1234;
    cr.ppid = 1;
    cr.process_name = Some("TestApp".into());
    cr.executable_path = Some("/Applications/TestApp.app/Contents/MacOS/TestApp".into());
    cr.parent_process_name = Some("launchd".into());
    cr.parent_executable_path = Some("/sbin/launchd".into());
    cr.is_64_bit = true;
    cr.is_native = true;
    cr.cpu_type = CpuType::X86_64;
    cr.exception_type = 1; // EXC_BAD_ACCESS
    cr.exception_code = vec![2, 0x7fff_dead_beef];
    cr.exception_code_count = 2;
    cr.signal = 11; // SIGSEGV
    cr.crashed_thread_number = 0;
    cr
}

/// Helper: builds a default CrashRustler with ARM64 CPU type.
pub(crate) fn make_test_cr_arm64() -> CrashRustler {
    let mut cr = make_test_cr();
    cr.cpu_type = CpuType::ARM64;
    cr
}

use crate::crash_rustler::CrashRustler;
use crate::types::*;

impl CrashRustler {
    /// Creates a new CrashRustler from pre-gathered crash data.
    ///
    /// The binary (exc_handler) is responsible for all Mach/system calls.
    /// This constructor is pure data — no FFI.
    ///
    /// Equivalent to -[CrashReport initWithTask:exceptionType:exceptionCode:
    /// exceptionCodeCount:thread:threadStateFlavor:threadState:threadStateCount:]
    pub fn new(params: CrashParams) -> Self {
        let exception_code_count = params.exception_codes.len() as u32;
        let mut cr = Self {
            task: params.task,
            pid: params.pid,
            ppid: params.ppid,
            uid: params.uid,
            is_64_bit: params.is_64_bit,
            thread: params.thread,
            thread_state: params.thread_state,
            exception_state: params.exception_state,
            process_name: params.process_name,
            executable_path: params.executable_path,
            r_process_pid: params.r_process_pid,
            date: params.date,
            awake_system_uptime: params.awake_system_uptime,
            cpu_type: params.cpu_type,
            crashed_thread_number: -1,
            performing_autopsy: false,
            is_native: true,
            exception_type: params.exception_type,
            exception_code_count,
            exception_code: params.exception_codes,
            ..Default::default()
        };

        // For EXC_CRASH (type 10): extract embedded exception type and signal
        // from the exception code bits. This is pure arithmetic — no FFI needed.
        if cr.exception_type == 10 && !cr.exception_code.is_empty() {
            let code0 = cr.exception_code[0] as u64;
            let embedded_type = ((code0 >> 20) & 0xf) as i32;
            if embedded_type != 0 {
                cr.exception_type = embedded_type;
            }
            cr.signal = ((code0 >> 24) & 0xff) as u32;
            // Mask off the signal/type bits, keeping lower 20 bits
            cr.exception_code[0] = (cr.exception_code[0] as u64 & 0xf_ffff) as i64;
        }

        cr
    }

    /// Stub initializer for corpse-based crash reports.
    /// Returns None — corpse handling is done elsewhere in the crash reporter daemon.
    /// Equivalent to -[CrashReport initWithCorpse:length:task:...]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_corpse(
        _corpse: u64,
        _length: u64,
        _task: u32,
        _exception_type: i32,
        _exception_codes: &[i64],
        _thread: u32,
        _thread_state_flavor: u32,
        _thread_state: &[u32],
    ) -> Option<Self> {
        // ObjC implementation returns nil
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_params() -> CrashParams {
        CrashParams {
            task: 100,
            pid: 1234,
            ppid: 1,
            uid: 501,
            is_64_bit: true,
            thread: 200,
            thread_state: ThreadState {
                flavor: 6,
                registers: vec![],
            },
            exception_state: ExceptionState {
                state: vec![],
                count: 0,
            },
            process_name: Some("test".to_string()),
            executable_path: Some("/usr/bin/test".to_string()),
            r_process_pid: 0,
            date: Some("2026-03-23".to_string()),
            awake_system_uptime: 1000,
            cpu_type: CpuType::ARM64,
            exception_type: 1, // EXC_BAD_ACCESS
            exception_codes: vec![2, 0x42],
        }
    }

    #[test]
    fn new_populates_basic_fields() {
        let params = make_params();
        let cr = CrashRustler::new(params);
        assert_eq!(cr.task, 100);
        assert_eq!(cr.pid, 1234);
        assert_eq!(cr.ppid, 1);
        assert_eq!(cr.uid, 501);
        assert!(cr.is_64_bit);
        assert_eq!(cr.thread, 200);
        assert_eq!(cr.process_name, Some("test".to_string()));
        assert_eq!(cr.executable_path, Some("/usr/bin/test".to_string()));
        assert_eq!(cr.cpu_type, CpuType::ARM64);
        assert_eq!(cr.exception_type, 1);
        assert_eq!(cr.exception_code, vec![2, 0x42]);
        assert_eq!(cr.exception_code_count, 2);
    }

    #[test]
    fn new_sets_defaults_for_derived_fields() {
        let cr = CrashRustler::new(make_params());
        assert_eq!(cr.crashed_thread_number, -1);
        assert!(!cr.performing_autopsy);
        assert!(cr.is_native);
        assert_eq!(cr.signal, 0);
    }

    #[test]
    fn new_exc_crash_extracts_embedded_type() {
        let mut params = make_params();
        params.exception_type = 10; // EXC_CRASH
        // Encode embedded type=1 (EXC_BAD_ACCESS) and signal=11 (SIGSEGV)
        // code0 format: [signal:8][type:4][subcode:20]
        params.exception_codes = vec![((11i64 << 24) | (1i64 << 20) | 0x42), 0];
        let cr = CrashRustler::new(params);
        assert_eq!(cr.exception_type, 1); // extracted from bits
        assert_eq!(cr.signal, 11); // extracted from bits
        assert_eq!(cr.exception_code[0], 0x42); // lower 20 bits preserved
    }

    #[test]
    fn new_exc_crash_zero_embedded_type_preserves_type_10() {
        let mut params = make_params();
        params.exception_type = 10;
        // Embedded type is 0 → exception_type stays 10
        params.exception_codes = vec![((6i64 << 24) | 0), 0];
        let cr = CrashRustler::new(params);
        assert_eq!(cr.exception_type, 10);
        assert_eq!(cr.signal, 6); // SIGABRT
    }

    #[test]
    fn new_exc_crash_empty_codes_no_panic() {
        let mut params = make_params();
        params.exception_type = 10;
        params.exception_codes = vec![];
        let cr = CrashRustler::new(params);
        assert_eq!(cr.exception_type, 10); // unchanged, no codes to extract from
    }

    #[test]
    fn new_non_crash_exception_no_signal_extraction() {
        let mut params = make_params();
        params.exception_type = 1; // EXC_BAD_ACCESS, not EXC_CRASH
        params.exception_codes = vec![0x0b10_0042, 0]; // would decode to signal 11 if misinterpreted
        let cr = CrashRustler::new(params);
        assert_eq!(cr.exception_type, 1); // unchanged
        assert_eq!(cr.signal, 0); // no extraction for non-EXC_CRASH
        assert_eq!(cr.exception_code[0], 0x0b10_0042); // codes unchanged
    }

    #[test]
    fn new_from_corpse_returns_none() {
        let result = CrashRustler::new_from_corpse(0, 0, 0, 0, &[], 0, 0, &[]);
        assert!(result.is_none());
    }
}

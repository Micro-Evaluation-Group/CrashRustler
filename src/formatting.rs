use crate::crash_rustler::CrashRustler;

impl CrashRustler {
    /// Returns the human-readable POSIX signal name for the crash signal.
    /// Maps signals 0-31 to their standard names (SIGHUP, SIGINT, etc.).
    /// Unknown signals are formatted as "Signal N".
    /// Equivalent to -[CrashReport signalName]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::CrashRustler;
    ///
    /// let mut cr = CrashRustler::default();
    /// cr.signal = 11;
    /// assert_eq!(cr.signal_name(), "SIGSEGV");
    ///
    /// cr.signal = 6;
    /// assert_eq!(cr.signal_name(), "SIGABRT");
    ///
    /// cr.signal = 99;
    /// assert_eq!(cr.signal_name(), "Signal 99");
    /// ```
    pub fn signal_name(&self) -> String {
        match self.signal {
            0 => String::new(),
            1 => "SIGHUP".into(),
            2 => "SIGINT".into(),
            3 => "SIGQUIT".into(),
            4 => "SIGILL".into(),
            5 => "SIGTRAP".into(),
            6 => "SIGABRT".into(),
            7 => "SIGEMT".into(),
            8 => "SIGFPE".into(),
            9 => "SIGKILL".into(),
            10 => "SIGBUS".into(),
            11 => "SIGSEGV".into(),
            12 => "SIGSYS".into(),
            13 => "SIGPIPE".into(),
            14 => "SIGALRM".into(),
            15 => "SIGTERM".into(),
            16 => "SIGURG".into(),
            17 => "SIGSTOP".into(),
            18 => "SIGTSTP".into(),
            19 => "SIGCONT".into(),
            20 => "SIGCHLD".into(),
            21 => "SIGTTIN".into(),
            22 => "SIGTTOU".into(),
            23 => "SIGIO".into(),
            24 => "SIGXCPU".into(),
            25 => "SIGXFSZ".into(),
            26 => "SIGVTALRM".into(),
            27 => "SIGPROF".into(),
            28 => "SIGWINCH".into(),
            29 => "SIGINFO".into(),
            30 => "SIGUSR1".into(),
            31 => "SIGUSR2".into(),
            n => format!("Signal {n}"),
        }
    }

    /// Returns the human-readable Mach exception type name.
    /// Maps standard exception types 1-13 to names like EXC_BAD_ACCESS.
    /// Unknown types are formatted as hex.
    /// Equivalent to -[CrashReport exceptionTypeDescription]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::CrashRustler;
    ///
    /// let mut cr = CrashRustler::default();
    /// cr.exception_type = 1;
    /// assert_eq!(cr.exception_type_description(), "EXC_BAD_ACCESS");
    ///
    /// cr.exception_type = 6;
    /// assert_eq!(cr.exception_type_description(), "EXC_BREAKPOINT");
    /// ```
    pub fn exception_type_description(&self) -> String {
        match self.exception_type {
            1 => "EXC_BAD_ACCESS".into(),
            2 => "EXC_BAD_INSTRUCTION".into(),
            3 => "EXC_ARITHMETIC".into(),
            4 => "EXC_EMULATION".into(),
            5 => "EXC_SOFTWARE".into(),
            6 => "EXC_BREAKPOINT".into(),
            7 => "EXC_SYSCALL".into(),
            8 => "EXC_MACH_SYSCALL".into(),
            9 => "EXC_RPC_ALERT".into(),
            10 => "EXC_CRASH".into(),
            11 => "EXC_RESOURCE".into(),
            12 => "EXC_GUARD".into(),
            13 => "EXC_CORPSE_NOTIFY".into(),
            n => format!("{n:08X}"),
        }
    }

    /// Returns a human-readable description of the exception codes.
    /// For EXC_BAD_ACCESS: maps code\[0\] to KERN_PROTECTION_FAILURE or
    /// KERN_INVALID_ADDRESS with the faulting address from code\[1\].
    /// For EXC_ARITHMETIC: maps code\[0\]=1 to EXC_I386_DIV.
    /// Otherwise formats all codes as hex values joined by commas.
    /// Equivalent to -[CrashReport exceptionCodesDescription]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::{CrashRustler, CpuType};
    ///
    /// let mut cr = CrashRustler::default();
    /// cr.exception_type = 1; // EXC_BAD_ACCESS
    /// cr.exception_code = vec![2, 0x7fff_dead_beef]; // KERN_PROTECTION_FAILURE
    /// assert_eq!(
    ///     cr.exception_codes_description(),
    ///     "KERN_PROTECTION_FAILURE at 0x00007fffdeadbeef"
    /// );
    ///
    /// cr.exception_code = vec![1, 0x0]; // KERN_INVALID_ADDRESS
    /// assert_eq!(
    ///     cr.exception_codes_description(),
    ///     "KERN_INVALID_ADDRESS at 0x0000000000000000"
    /// );
    /// ```
    pub fn exception_codes_description(&self) -> String {
        if self.exception_code.is_empty() {
            return String::new();
        }

        let code0 = self.exception_code[0];

        // EXC_BAD_ACCESS special formatting
        if self.exception_type == 1 {
            if code0 == 2 && self.exception_code.len() > 1 {
                return format!(
                    "KERN_PROTECTION_FAILURE at 0x{:016x}",
                    self.exception_code[1] as u64
                );
            }
            if code0 == 1 && self.exception_code.len() > 1 {
                return format!(
                    "KERN_INVALID_ADDRESS at 0x{:016x}",
                    self.exception_code[1] as u64
                );
            }
            // GPF is x86-specific
            if code0 == 0xd && self.is_x86_cpu() {
                return "EXC_I386_GPFLT".into();
            }
        }

        // EXC_ARITHMETIC special formatting
        if self.exception_type == 3 {
            if self.is_x86_cpu() && code0 == 1 {
                return "EXC_I386_DIV (divide by zero)".into();
            }
            if self.is_arm_cpu() {
                return match code0 {
                    1 => "EXC_ARM_FP_IO (invalid operation)".into(),
                    2 => "EXC_ARM_FP_DZ (divide by zero)".into(),
                    3 => "EXC_ARM_FP_OF (overflow)".into(),
                    4 => "EXC_ARM_FP_UF (underflow)".into(),
                    5 => "EXC_ARM_FP_IX (inexact)".into(),
                    6 => "EXC_ARM_FP_ID (input denormal)".into(),
                    _ => format!("0x{:016x}", code0 as u64),
                };
            }
        }

        // Default: format all codes as hex
        self.exception_code
            .iter()
            .map(|c| format!("0x{:016x}", *c as u64))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Returns the CPU type as a human-readable string.
    /// Maps: X86, PPC, X86-64, PPC-64, or hex for unknown.
    /// Equivalent to -[CrashReport _cpuTypeDescription]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::{CrashRustler, CpuType};
    ///
    /// let mut cr = CrashRustler::default();
    /// cr.cpu_type = CpuType::ARM64;
    /// assert_eq!(cr.cpu_type_description(), "ARM-64");
    /// assert_eq!(cr.short_arch_name(), "arm64");
    ///
    /// cr.cpu_type = CpuType::X86_64;
    /// assert_eq!(cr.cpu_type_description(), "X86-64");
    /// assert_eq!(cr.short_arch_name(), "x86_64");
    /// ```
    pub fn cpu_type_description(&self) -> String {
        match self.cpu_type.0 {
            7 => "X86".into(),
            18 => "PPC".into(),
            12 => "ARM".into(),
            0x100_0007 => "X86-64".into(),
            0x100_0012 => "PPC-64".into(),
            0x100_000c => "ARM-64".into(),
            n => format!("{n:08X}"),
        }
    }

    /// Returns the short architecture name for the CPU type.
    /// Maps: i386, ppc, x86_64, ppc64, or falls back to cpu_type_description.
    /// Equivalent to -[CrashReport _shortArchName]
    pub fn short_arch_name(&self) -> String {
        match self.cpu_type.0 {
            7 => "i386".into(),
            18 => "ppc".into(),
            12 => "arm".into(),
            0x100_0007 => "x86_64".into(),
            0x100_0012 => "ppc64".into(),
            0x100_000c => "arm64".into(),
            _ => self.cpu_type_description(),
        }
    }

    /// Normalizes whitespace in a string by splitting on whitespace/newline
    /// characters and rejoining with single spaces.
    /// Returns empty string for None input.
    /// Equivalent to -[CrashReport _spacifyString:]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::CrashRustler;
    ///
    /// assert_eq!(
    ///     CrashRustler::spacify_string(Some("hello   world\n\tfoo")),
    ///     "hello world foo"
    /// );
    /// assert_eq!(CrashRustler::spacify_string(None), "");
    /// ```
    pub fn spacify_string(s: Option<&str>) -> String {
        match s {
            None => String::new(),
            Some(s) => s.split_whitespace().collect::<Vec<_>>().join(" "),
        }
    }

    /// Replaces newlines in a string with padded newlines for crash report
    /// formatting alignment. Strips leading newline if present.
    /// Equivalent to -[CrashReport stringByPaddingNewlinesInString:]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::CrashRustler;
    ///
    /// assert_eq!(
    ///     CrashRustler::string_by_padding_newlines("line1\nline2\nline3"),
    ///     "line1\n    line2\n    line3"
    /// );
    /// ```
    pub fn string_by_padding_newlines(s: &str) -> String {
        let result = s.replace('\n', "\n    ");
        if let Some(stripped) = result.strip_prefix('\n') {
            stripped.to_string()
        } else {
            result
        }
    }

    /// Trims whitespace from a string. If the trimmed result is empty,
    /// returns "[column N]" where N is the original string length.
    /// This preserves column-alignment information for empty content.
    /// Equivalent to -[CrashReport stringByTrimmingColumnSensitiveWhitespacesInString:]
    pub fn string_by_trimming_column_sensitive_whitespace(s: &str) -> String {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            format!("[column {}]", s.len())
        } else {
            trimmed.to_string()
        }
    }

    /// Returns true if the given path is an Apple system path.
    /// Checks: /System, /usr/lib, /usr/bin, /usr/sbin, /bin, /sbin.
    /// Equivalent to -[CrashReport pathIsApple:]
    pub fn path_is_apple(path: &str) -> bool {
        path.starts_with("/System")
            || path.starts_with("/usr/lib")
            || path.starts_with("/usr/bin")
            || path.starts_with("/usr/sbin")
            || path.starts_with("/bin")
            || path.starts_with("/sbin")
    }

    /// Returns true if the bundle identifier belongs to Apple.
    /// Checks: "com.apple." prefix, "commpage" prefix, or equals "Ozone"/"Motion".
    /// Equivalent to -[CrashReport bundleIdentifierIsApple:]
    pub fn bundle_identifier_is_apple(bundle_id: &str) -> bool {
        bundle_id.starts_with("com.apple.")
            || bundle_id.starts_with("commpage")
            || bundle_id == "Ozone"
            || bundle_id == "Motion"
    }

    /// Returns true if this is an Apple application, checking both
    /// the executable path and the bundle identifier.
    /// Equivalent to -[CrashReport isAppleApplication]
    pub fn is_apple_application(&self) -> bool {
        if let Some(path) = self.executable_path()
            && Self::path_is_apple(path)
        {
            return true;
        }
        if let Some(bundle_id) = self.bundle_identifier() {
            return Self::bundle_identifier_is_apple(bundle_id);
        }
        false
    }

    /// Appends an error message to the internal error log.
    /// Creates the log on first call, appends with newline on subsequent calls.
    /// Equivalent to -[CrashReport recordInternalError:]
    pub fn record_internal_error(&mut self, error: &str) {
        match &mut self.internal_error {
            Some(existing) => {
                existing.push('\n');
                existing.push_str(error);
            }
            None => {
                self.internal_error = Some(error.to_string());
            }
        }
    }

    /// Reduces a u64 value to two significant figures.
    /// Used for approximate memory statistics in crash reports.
    /// Equivalent to -[CrashReport reduceToTwoSigFigures:]
    pub fn reduce_to_two_sig_figures(value: u64) -> u64 {
        if value == 0 {
            return 0;
        }
        let digits = (value as f64).log10() as u32 + 1;
        if digits <= 2 {
            return value;
        }
        let divisor = 10u64.pow(digits - 2);
        (value / divisor) * divisor
    }
}

#[cfg(test)]
mod tests {
    use crate::crash_rustler::CrashRustler;
    use crate::test_helpers::*;
    use crate::types::*;

    // =========================================================================
    // 5. descriptions — Signal, exception, CPU descriptions
    // =========================================================================
    mod descriptions {
        use super::*;

        #[test]
        fn signal_name_zero() {
            let mut cr = make_test_cr();
            cr.signal = 0;
            assert_eq!(cr.signal_name(), "");
        }

        #[test]
        fn signal_name_all_named() {
            let expected = [
                (1, "SIGHUP"),
                (2, "SIGINT"),
                (3, "SIGQUIT"),
                (4, "SIGILL"),
                (5, "SIGTRAP"),
                (6, "SIGABRT"),
                (7, "SIGEMT"),
                (8, "SIGFPE"),
                (9, "SIGKILL"),
                (10, "SIGBUS"),
                (11, "SIGSEGV"),
                (12, "SIGSYS"),
                (13, "SIGPIPE"),
                (14, "SIGALRM"),
                (15, "SIGTERM"),
                (16, "SIGURG"),
                (17, "SIGSTOP"),
                (18, "SIGTSTP"),
                (19, "SIGCONT"),
                (20, "SIGCHLD"),
                (21, "SIGTTIN"),
                (22, "SIGTTOU"),
                (23, "SIGIO"),
                (24, "SIGXCPU"),
                (25, "SIGXFSZ"),
                (26, "SIGVTALRM"),
                (27, "SIGPROF"),
                (28, "SIGWINCH"),
                (29, "SIGINFO"),
                (30, "SIGUSR1"),
                (31, "SIGUSR2"),
            ];
            let mut cr = make_test_cr();
            for (sig, name) in expected {
                cr.signal = sig;
                assert_eq!(cr.signal_name(), name, "signal={sig}");
            }
        }

        #[test]
        fn signal_name_unknown() {
            let mut cr = make_test_cr();
            cr.signal = 32;
            assert_eq!(cr.signal_name(), "Signal 32");
            cr.signal = 100;
            assert_eq!(cr.signal_name(), "Signal 100");
        }

        #[test]
        fn exception_type_description_all_known() {
            let cases = [
                (1, "EXC_BAD_ACCESS"),
                (2, "EXC_BAD_INSTRUCTION"),
                (3, "EXC_ARITHMETIC"),
                (4, "EXC_EMULATION"),
                (5, "EXC_SOFTWARE"),
                (6, "EXC_BREAKPOINT"),
                (7, "EXC_SYSCALL"),
                (8, "EXC_MACH_SYSCALL"),
                (9, "EXC_RPC_ALERT"),
                (10, "EXC_CRASH"),
                (11, "EXC_RESOURCE"),
                (12, "EXC_GUARD"),
                (13, "EXC_CORPSE_NOTIFY"),
            ];
            let mut cr = make_test_cr();
            for (et, desc) in cases {
                cr.exception_type = et;
                assert_eq!(cr.exception_type_description(), desc, "type={et}");
            }
        }

        #[test]
        fn exception_type_description_unknown() {
            let mut cr = make_test_cr();
            cr.exception_type = 99;
            assert_eq!(cr.exception_type_description(), "00000063");
        }

        #[test]
        fn exception_codes_description_empty() {
            let mut cr = make_test_cr();
            cr.exception_code = vec![];
            assert_eq!(cr.exception_codes_description(), "");
        }

        #[test]
        fn exception_codes_bad_access_protection_failure() {
            let mut cr = make_test_cr();
            cr.exception_type = 1;
            cr.exception_code = vec![2, 0x7fff_0000_1234];
            assert_eq!(
                cr.exception_codes_description(),
                "KERN_PROTECTION_FAILURE at 0x00007fff00001234"
            );
        }

        #[test]
        fn exception_codes_bad_access_invalid_address() {
            let mut cr = make_test_cr();
            cr.exception_type = 1;
            cr.exception_code = vec![1, 0x42];
            assert_eq!(
                cr.exception_codes_description(),
                "KERN_INVALID_ADDRESS at 0x0000000000000042"
            );
        }

        #[test]
        fn exception_codes_bad_access_gpf() {
            let mut cr = make_test_cr();
            cr.exception_type = 1;
            cr.exception_code = vec![0xd];
            assert_eq!(cr.exception_codes_description(), "EXC_I386_GPFLT");
        }

        #[test]
        fn exception_codes_arithmetic_div_zero() {
            let mut cr = make_test_cr();
            cr.exception_type = 3;
            cr.exception_code = vec![1];
            assert_eq!(
                cr.exception_codes_description(),
                "EXC_I386_DIV (divide by zero)"
            );
        }

        #[test]
        fn exception_codes_generic_hex() {
            let mut cr = make_test_cr();
            cr.exception_type = 5; // EXC_SOFTWARE
            cr.exception_code = vec![0xdead, 0xbeef];
            assert_eq!(
                cr.exception_codes_description(),
                "0x000000000000dead, 0x000000000000beef"
            );
        }

        #[test]
        fn cpu_type_description_known() {
            let mut cr = make_test_cr();
            let cases = [
                (CpuType::X86, "X86"),
                (CpuType::POWERPC, "PPC"),
                (CpuType::X86_64, "X86-64"),
                (CpuType::POWERPC64, "PPC-64"),
            ];
            for (ct, desc) in cases {
                cr.cpu_type = ct;
                assert_eq!(cr.cpu_type_description(), desc);
            }
        }

        #[test]
        fn cpu_type_description_unknown() {
            let mut cr = make_test_cr();
            cr.cpu_type = CpuType(999);
            assert_eq!(cr.cpu_type_description(), "000003E7");
        }

        #[test]
        fn short_arch_name_known() {
            let mut cr = make_test_cr();
            let cases = [
                (CpuType::X86, "i386"),
                (CpuType::POWERPC, "ppc"),
                (CpuType::X86_64, "x86_64"),
                (CpuType::POWERPC64, "ppc64"),
            ];
            for (ct, name) in cases {
                cr.cpu_type = ct;
                assert_eq!(cr.short_arch_name(), name);
            }
        }

        #[test]
        fn short_arch_name_unknown_falls_back() {
            let mut cr = make_test_cr();
            cr.cpu_type = CpuType(999);
            // Falls back to cpu_type_description
            assert_eq!(cr.short_arch_name(), "000003E7");
        }

        #[test]
        fn cpu_type_description_arm() {
            let mut cr = make_test_cr();
            cr.cpu_type = CpuType::ARM;
            assert_eq!(cr.cpu_type_description(), "ARM");
            cr.cpu_type = CpuType::ARM64;
            assert_eq!(cr.cpu_type_description(), "ARM-64");
        }

        #[test]
        fn short_arch_name_arm() {
            let mut cr = make_test_cr();
            cr.cpu_type = CpuType::ARM;
            assert_eq!(cr.short_arch_name(), "arm");
            cr.cpu_type = CpuType::ARM64;
            assert_eq!(cr.short_arch_name(), "arm64");
        }

        #[test]
        fn exception_codes_bad_access_gpf_not_on_arm64() {
            let mut cr = make_test_cr_arm64();
            cr.exception_type = 1;
            cr.exception_code = vec![0xd];
            // ARM64 does not recognize 0xd as GPF — falls through to hex
            assert_eq!(cr.exception_codes_description(), "0x000000000000000d");
        }

        #[test]
        fn exception_codes_arithmetic_arm64_fp_dz() {
            let mut cr = make_test_cr_arm64();
            cr.exception_type = 3;
            cr.exception_code = vec![2];
            assert_eq!(
                cr.exception_codes_description(),
                "EXC_ARM_FP_DZ (divide by zero)"
            );
        }

        #[test]
        fn exception_codes_arithmetic_arm64_fp_io() {
            let mut cr = make_test_cr_arm64();
            cr.exception_type = 3;
            cr.exception_code = vec![1];
            assert_eq!(
                cr.exception_codes_description(),
                "EXC_ARM_FP_IO (invalid operation)"
            );
        }

        #[test]
        fn exception_codes_arithmetic_arm64_unknown() {
            let mut cr = make_test_cr_arm64();
            cr.exception_type = 3;
            cr.exception_code = vec![99];
            assert_eq!(cr.exception_codes_description(), "0x0000000000000063");
        }
    }

    // =========================================================================
    // 6. string_utils — Static string formatting
    // =========================================================================
    mod string_utils {
        use super::*;

        #[test]
        fn spacify_string_none() {
            assert_eq!(CrashRustler::spacify_string(None), "");
        }

        #[test]
        fn spacify_string_empty() {
            assert_eq!(CrashRustler::spacify_string(Some("")), "");
        }

        #[test]
        fn spacify_string_normal() {
            assert_eq!(
                CrashRustler::spacify_string(Some("hello world")),
                "hello world"
            );
        }

        #[test]
        fn spacify_string_multi_whitespace() {
            assert_eq!(
                CrashRustler::spacify_string(Some("hello   world   foo")),
                "hello world foo"
            );
        }

        #[test]
        fn spacify_string_tabs_newlines() {
            assert_eq!(
                CrashRustler::spacify_string(Some("hello\t\nworld")),
                "hello world"
            );
        }

        #[test]
        fn string_by_padding_newlines_no_newlines() {
            assert_eq!(CrashRustler::string_by_padding_newlines("hello"), "hello");
        }

        #[test]
        fn string_by_padding_newlines_with_newlines() {
            assert_eq!(
                CrashRustler::string_by_padding_newlines("line1\nline2\nline3"),
                "line1\n    line2\n    line3"
            );
        }

        #[test]
        fn string_by_padding_newlines_leading_newline() {
            assert_eq!(
                CrashRustler::string_by_padding_newlines("\nline1"),
                "    line1"
            );
        }

        #[test]
        fn trimming_column_sensitive_normal() {
            assert_eq!(
                CrashRustler::string_by_trimming_column_sensitive_whitespace("  hello  "),
                "hello"
            );
        }

        #[test]
        fn trimming_column_sensitive_all_whitespace() {
            assert_eq!(
                CrashRustler::string_by_trimming_column_sensitive_whitespace("     "),
                "[column 5]"
            );
        }

        #[test]
        fn trimming_column_sensitive_empty() {
            assert_eq!(
                CrashRustler::string_by_trimming_column_sensitive_whitespace(""),
                "[column 0]"
            );
        }

        #[test]
        fn path_is_apple_system() {
            assert!(CrashRustler::path_is_apple(
                "/System/Library/Frameworks/AppKit.framework"
            ));
        }

        #[test]
        fn path_is_apple_usr_lib() {
            assert!(CrashRustler::path_is_apple("/usr/lib/libSystem.B.dylib"));
        }

        #[test]
        fn path_is_apple_usr_bin() {
            assert!(CrashRustler::path_is_apple("/usr/bin/file"));
        }

        #[test]
        fn path_is_apple_usr_sbin() {
            assert!(CrashRustler::path_is_apple("/usr/sbin/notifyd"));
        }

        #[test]
        fn path_is_apple_bin() {
            assert!(CrashRustler::path_is_apple("/bin/sh"));
        }

        #[test]
        fn path_is_apple_sbin() {
            assert!(CrashRustler::path_is_apple("/sbin/launchd"));
        }

        #[test]
        fn path_is_apple_applications_not_apple() {
            assert!(!CrashRustler::path_is_apple("/Applications/Foo.app"));
        }

        #[test]
        fn bundle_identifier_is_apple_com_apple() {
            assert!(CrashRustler::bundle_identifier_is_apple("com.apple.Safari"));
        }

        #[test]
        fn bundle_identifier_is_apple_commpage() {
            assert!(CrashRustler::bundle_identifier_is_apple("commpage"));
            assert!(CrashRustler::bundle_identifier_is_apple("commpage64"));
        }

        #[test]
        fn bundle_identifier_is_apple_ozone() {
            assert!(CrashRustler::bundle_identifier_is_apple("Ozone"));
        }

        #[test]
        fn bundle_identifier_is_apple_motion() {
            assert!(CrashRustler::bundle_identifier_is_apple("Motion"));
        }

        #[test]
        fn bundle_identifier_is_apple_not_apple() {
            assert!(!CrashRustler::bundle_identifier_is_apple(
                "com.google.Chrome"
            ));
            assert!(!CrashRustler::bundle_identifier_is_apple(
                "org.mozilla.firefox"
            ));
        }

        #[test]
        fn reduce_to_two_sig_figures_zero() {
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(0), 0);
        }

        #[test]
        fn reduce_to_two_sig_figures_small() {
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(1), 1);
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(42), 42);
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(99), 99);
        }

        #[test]
        fn reduce_to_two_sig_figures_three_digits() {
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(100), 100);
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(123), 120);
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(999), 990);
        }

        #[test]
        fn reduce_to_two_sig_figures_large() {
            assert_eq!(CrashRustler::reduce_to_two_sig_figures(12345), 12000);
        }

        #[test]
        fn sanitize_path_user_path() {
            assert_eq!(
                CrashRustler::sanitize_path("/Users/kurtis/foo/bar"),
                "/Users/USER/foo/bar"
            );
        }

        #[test]
        fn sanitize_path_system_unchanged() {
            assert_eq!(
                CrashRustler::sanitize_path("/System/Library/Frameworks/foo"),
                "/System/Library/Frameworks/foo"
            );
        }

        #[test]
        fn sanitize_path_users_no_trailing_slash() {
            // /Users/kurtis (no slash after username) — no substitution
            assert_eq!(
                CrashRustler::sanitize_path("/Users/kurtis"),
                "/Users/kurtis"
            );
        }
    }

    // =========================================================================
    // 13. mac_roman — Character encoding
    // =========================================================================
    mod mac_roman {
        use crate::crash_rustler::mac_roman_to_char;

        #[test]
        fn ascii_passthrough() {
            for b in 0..0x80u8 {
                assert_eq!(mac_roman_to_char(b), b as char);
            }
        }

        #[test]
        fn known_characters() {
            // 0x80 = Ä
            assert_eq!(mac_roman_to_char(0x80), '\u{00C4}');
            // 0xCA = non-breaking space
            assert_eq!(mac_roman_to_char(0xCA), '\u{00A0}');
            // 0xDB = €
            assert_eq!(mac_roman_to_char(0xDB), '\u{20AC}');
        }
    }
}

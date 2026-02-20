use std::collections::{HashMap, HashSet};

use crate::types::*;

/// CrashRustler: Rust equivalent of CrashWrangler's CrashReport Objective-C class.
///
/// This struct captures all the state needed to represent a macOS crash report,
/// including process information, exception details, thread backtraces,
/// binary image mappings, and crash analysis metadata.
#[derive(Debug)]
pub struct CrashRustler {
    // -- Process identification --
    /// Process ID of the crashed process.
    pub pid: i32,
    /// Parent process ID.
    pub ppid: i32,
    /// User ID of the crashed process.
    pub uid: u32,
    /// Mach task port for the crashed process.
    pub task: u32,
    /// Name of the crashed process (derived from executable path).
    pub process_name: Option<String>,
    /// Full path to the crashed process executable.
    pub executable_path: Option<String>,
    /// Name of the parent process.
    pub parent_process_name: Option<String>,
    /// Full path to the parent process executable.
    pub parent_executable_path: Option<String>,
    /// Name of the responsible process (may differ from parent).
    pub responsible_process_name: Option<String>,
    /// PID of the responsible process (`responsibility_get_pid_responsible_for_pid`).
    pub r_process_pid: i32,
    /// Crash date as a formatted string.
    pub date: Option<String>,

    // -- Exception information --
    /// Mach exception type (e.g., 1 = `EXC_BAD_ACCESS`).
    pub exception_type: i32,
    /// Mach exception codes (architecture-specific sub-codes).
    pub exception_code: Vec<i64>,
    /// Number of valid exception codes.
    pub exception_code_count: u32,
    /// POSIX signal number (e.g., 11 = `SIGSEGV`).
    pub signal: u32,
    /// Virtual address that caused the crash (for `EXC_BAD_ACCESS`).
    pub crashing_address: u64,

    // -- Thread information --
    /// Mach thread port of the crashing thread.
    pub thread: u32,
    /// Thread ID from `thread_identifier_info` or crash annotations.
    pub thread_id: Option<u64>,
    /// Index of the crashed thread in [`backtraces`](Self::backtraces), or -1 if unknown.
    pub crashed_thread_number: i32,
    /// Register state of the crashed thread.
    pub thread_state: ThreadState,
    /// Exception state from the faulting thread.
    pub exception_state: ExceptionState,
    /// Raw exception state registers (architecture-specific).
    pub thread_exception_state: Vec<u32>,
    /// Number of valid words in `thread_exception_state`.
    pub thread_exception_state_count: u32,
    /// Backtraces for all threads in the crashed process.
    pub backtraces: Vec<ThreadBacktrace>,

    // -- CPU and architecture --
    /// CPU type of the crashed process.
    pub cpu_type: CpuType,
    /// Whether the process is 64-bit.
    pub is_64_bit: bool,
    /// Whether the process runs natively (not under Rosetta translation).
    pub is_native: bool,
    /// Raw architecture value from the Mach-O header.
    pub architecture: u64,

    // -- Binary image information --
    /// All binary images loaded in the crashed process.
    pub binary_images: Vec<BinaryImage>,
    /// Binary image hints from `___crashreporter_binary_image_hints__`.
    pub binary_image_hints: Vec<String>,
    /// UUID of the main executable binary.
    pub binary_uuid: Option<String>,
    /// Name of the binary image currently being processed.
    pub current_binary_image: Option<String>,
    /// Set of binary image keys already processed (for deduplication).
    pub attempted_binary_images: HashSet<String>,
    /// Count of errors encountered during binary image processing.
    pub binary_image_error_count: u32,
    /// Whether binary image post-processing (sorting, enrichment) is done.
    pub binary_image_post_processing_complete: bool,
    /// Whether all binary images have been enumerated.
    pub completed_all_binary_images: bool,
    /// Longest binary identifier string length (for formatting alignment).
    pub max_binary_identifier_length: u32,

    // -- Application metadata --
    /// Environment variables of the crashed process.
    pub environment: HashMap<String, String>,
    /// Crash report notes (e.g., translocated process, OS update).
    pub notes: Option<String>,
    /// Process version info (`CFBundleShortVersionString`, `CFBundleVersion`).
    pub process_version_dictionary: HashMap<String, String>,
    /// Build version info (`ProjectName`, `SourceVersion`, `BuildVersion`).
    pub build_version_dictionary: HashMap<String, String>,
    /// OS version info (`ProductVersion`, `BuildVersion`, `ProductName`).
    pub os_version_dictionary: HashMap<String, String>,
    /// App Store Adam ID.
    pub adam_id: Option<String>,
    /// App Store software version external identifier.
    pub software_version_external_identifier: Option<String>,
    /// Path used to reopen/relaunch the application.
    pub reopen_path: Option<String>,
    /// Launch Services application information dictionary.
    /// Contains keys such as `CFBundleIdentifier` and display name.
    pub ls_application_information: Option<HashMap<String, String>>,
    /// Whether the application has an App Store receipt.
    pub has_receipt: bool,
    /// Whether the process was running from a translocated path.
    pub is_translocated_process: bool,

    // -- Application specific info --
    /// Application-specific crash info from `___crashreporter_info__` or `__crash_info`.
    pub application_specific_info: Option<String>,
    /// Application-specific backtrace strings from crash annotations.
    pub application_specific_backtraces: Vec<String>,
    /// Application-specific signature strings for crash grouping.
    pub application_specific_signature_strings: Vec<String>,
    /// Dialog mode hint from crash annotations (version 4+).
    pub application_specific_dialog_mode: Option<String>,

    // -- Crash reporter info --
    /// Accumulated internal error messages.
    pub internal_error: Option<String>,
    /// Rosetta translation thread info (for non-native processes).
    pub rosetta_info: Option<String>,
    /// Dyld error string (from `dyld_all_image_infos` or `__crash_info`).
    pub dyld_error_string: Option<String>,
    /// Additional dyld error info for presignature.
    pub dyld_error_info: Option<String>,
    /// Whether to attempt legacy dyld error string extraction.
    pub extract_legacy_dyld_error_string: bool,
    /// Whether a fatal dyld error occurred on launch.
    pub fatal_dyld_error_on_launch: bool,
    /// Exec failure error (set when `___NEW_PROCESS_COULD_NOT_BE_EXECD___` is detected).
    pub exec_failure_error: Option<String>,

    // -- Code signing --
    /// Code signing status flags (bit 0x1000000 = `CS_KILLED`).
    pub cs_status: u32,
    /// Description of code signing invalidity messages.
    pub code_sign_invalid_messages_description: Option<String>,

    // -- External modifications --
    /// External modification info (task_for_pid callers, injected libraries).
    pub ext_mod_info: ExternalModInfo,

    // -- Timing --
    /// System uptime (awake time) at crash, in seconds.
    pub awake_system_uptime: u64,
    /// Sleep/wake UUID for correlating crashes with sleep events.
    pub sleep_wake_uuid: Option<String>,

    // -- Sandbox --
    /// Sandbox container path for the crashed process.
    pub sandbox_container: Option<String>,

    // -- VM map --
    /// Human-readable VM region map of the crashed process.
    pub vm_map_string: Option<String>,
    /// Summary of VM region statistics.
    pub vm_summary_string: Option<String>,

    // -- ObjC info --
    /// ObjC selector name if the crash occurred in `objc_msgSend*`.
    pub objc_selector_name: Option<String>,

    // -- Misc --
    /// Path to a third-party bundle involved in the crash.
    pub third_party_bundle_path: Option<String>,
    /// Anonymous UUID for crash report deduplication.
    pub anon_uuid: Option<String>,
    /// Whether this report is for a corpse (post-mortem) analysis.
    pub performing_autopsy: bool,
    /// Whether the executable path needs correction after resolution.
    pub executable_path_needs_correction: bool,
    /// Whether the process name needs correction after resolution.
    pub process_name_needs_correction: bool,
    /// Previous OS build version if crash occurred during an OS update.
    pub in_update_previous_os_build: Option<String>,
    /// Raw item info record data from Launch Services.
    pub item_info_record: Option<Vec<u8>>,
    /// Exit snapshot data from the process.
    pub exit_snapshot: Option<Vec<u8>>,
    /// Length of the exit snapshot data.
    pub exit_snapshot_length: u32,
    /// Exit payload data from the process.
    pub exit_payload: Option<Vec<u8>>,
    /// Length of the exit payload data.
    pub exit_payload_length: u32,
    /// Work queue thread limits hit at time of crash.
    pub work_queue_limits: Option<WorkQueueLimits>,
    /// PID of the process that terminated this process.
    pub terminator_pid: i32,
    /// Name of the process that terminated this process.
    pub terminator_proc: Option<String>,
    /// Reason string from the terminating process.
    pub terminator_reason: Option<String>,
}

impl Default for CrashRustler {
    fn default() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            task: 0,
            process_name: None,
            executable_path: None,
            parent_process_name: None,
            parent_executable_path: None,
            responsible_process_name: None,
            r_process_pid: 0,
            date: None,
            exception_type: 0,
            exception_code: Vec::new(),
            exception_code_count: 0,
            signal: 0,
            crashing_address: 0,
            thread: 0,
            thread_id: None,
            crashed_thread_number: -1,
            thread_state: ThreadState {
                flavor: 0,
                registers: Vec::new(),
            },
            exception_state: ExceptionState {
                state: Vec::new(),
                count: 0,
            },
            thread_exception_state: Vec::new(),
            thread_exception_state_count: 0,
            backtraces: Vec::new(),
            cpu_type: CpuType(0),
            is_64_bit: false,
            is_native: false,
            architecture: 0,
            binary_images: Vec::new(),
            binary_image_hints: Vec::new(),
            binary_uuid: None,
            current_binary_image: None,
            attempted_binary_images: HashSet::new(),
            binary_image_error_count: 0,
            binary_image_post_processing_complete: false,
            completed_all_binary_images: false,
            max_binary_identifier_length: 0,
            environment: HashMap::new(),
            notes: None,
            process_version_dictionary: HashMap::new(),
            build_version_dictionary: HashMap::new(),
            os_version_dictionary: HashMap::new(),
            adam_id: None,
            software_version_external_identifier: None,
            reopen_path: None,
            ls_application_information: None,
            has_receipt: false,
            is_translocated_process: false,
            application_specific_info: None,
            application_specific_backtraces: Vec::new(),
            application_specific_signature_strings: Vec::new(),
            application_specific_dialog_mode: None,
            internal_error: None,
            rosetta_info: None,
            dyld_error_string: None,
            dyld_error_info: None,
            extract_legacy_dyld_error_string: false,
            fatal_dyld_error_on_launch: false,
            exec_failure_error: None,
            cs_status: 0,
            code_sign_invalid_messages_description: None,
            ext_mod_info: ExternalModInfo {
                description: None,
                warnings: None,
                dictionary: HashMap::new(),
            },
            awake_system_uptime: 0,
            sleep_wake_uuid: None,
            sandbox_container: None,
            vm_map_string: None,
            vm_summary_string: None,
            objc_selector_name: None,
            third_party_bundle_path: None,
            anon_uuid: None,
            performing_autopsy: false,
            executable_path_needs_correction: false,
            process_name_needs_correction: false,
            in_update_previous_os_build: None,
            item_info_record: None,
            exit_snapshot: None,
            exit_snapshot_length: 0,
            exit_payload: None,
            exit_payload_length: 0,
            work_queue_limits: None,
            terminator_pid: 0,
            terminator_proc: None,
            terminator_reason: None,
        }
    }
}

/// Converts a MacRoman byte to its Unicode character equivalent.
/// MacRoman bytes 0x00-0x7F map to ASCII. Bytes 0x80-0xFF map to
/// specific Unicode codepoints used by classic Mac OS.
pub(crate) fn mac_roman_to_char(b: u8) -> char {
    if b < 0x80 {
        return b as char;
    }
    // MacRoman high-byte mapping to Unicode codepoints
    const MAC_ROMAN_HIGH: [u16; 128] = [
        0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, // 80-87
        0x00E0, 0x00E2, 0x00E4, 0x00E3, 0x00E5, 0x00E7, 0x00E9, 0x00E8, // 88-8F
        0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3, // 90-97
        0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC, // 98-9F
        0x2020, 0x00B0, 0x00A2, 0x00A3, 0x00A7, 0x2022, 0x00B6, 0x00DF, // A0-A7
        0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6, 0x00D8, // A8-AF
        0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202, 0x2211, // B0-B7
        0x220F, 0x03C0, 0x222B, 0x00AA, 0x00BA, 0x03A9, 0x00E6, 0x00F8, // B8-BF
        0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB, // C0-C7
        0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152, 0x0153, // C8-CF
        0x2013, 0x2014, 0x201C, 0x201D, 0x2018, 0x2019, 0x00F7, 0x25CA, // D0-D7
        0x00FF, 0x0178, 0x2044, 0x20AC, 0x2039, 0x203A, 0xFB01, 0xFB02, // D8-DF
        0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA, 0x00C1, // E0-E7
        0x00CB, 0x00C8, 0x00CD, 0x00CE, 0x00CF, 0x00CC, 0x00D3, 0x00D4, // E8-EF
        0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6, 0x02DC, // F0-F7
        0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB, 0x02C7, // F8-FF
    ];
    char::from_u32(MAC_ROMAN_HIGH[(b - 0x80) as usize] as u32).unwrap_or('?')
}

#[cfg(test)]
mod tests {
    use crate::*;

    mod default_impl {
        use super::*;

        #[test]
        fn all_fields_initialized() {
            let cr = CrashRustler::default();
            assert_eq!(cr.pid, 0);
            assert_eq!(cr.ppid, 0);
            assert_eq!(cr.uid, 0);
            assert_eq!(cr.task, 0);
            assert!(cr.process_name.is_none());
            assert!(cr.executable_path.is_none());
            assert!(cr.parent_process_name.is_none());
            assert!(cr.parent_executable_path.is_none());
            assert!(cr.responsible_process_name.is_none());
            assert_eq!(cr.r_process_pid, 0);
            assert!(cr.date.is_none());
            assert_eq!(cr.exception_type, 0);
            assert!(cr.exception_code.is_empty());
            assert_eq!(cr.exception_code_count, 0);
            assert_eq!(cr.signal, 0);
            assert_eq!(cr.crashing_address, 0);
            assert_eq!(cr.thread, 0);
            assert!(cr.thread_id.is_none());
            assert_eq!(cr.crashed_thread_number, -1);
            assert_eq!(cr.thread_state.flavor, 0);
            assert!(cr.thread_state.registers.is_empty());
            assert!(cr.exception_state.state.is_empty());
            assert_eq!(cr.exception_state.count, 0);
            assert!(cr.backtraces.is_empty());
            assert_eq!(cr.cpu_type, CpuType(0));
            assert!(!cr.is_64_bit);
            assert!(!cr.is_native);
            assert_eq!(cr.architecture, 0);
            assert!(cr.binary_images.is_empty());
            assert!(cr.binary_image_hints.is_empty());
            assert!(cr.binary_uuid.is_none());
            assert!(cr.current_binary_image.is_none());
            assert!(cr.attempted_binary_images.is_empty());
            assert_eq!(cr.binary_image_error_count, 0);
            assert!(!cr.binary_image_post_processing_complete);
            assert!(!cr.completed_all_binary_images);
            assert_eq!(cr.max_binary_identifier_length, 0);
            assert!(cr.environment.is_empty());
            assert!(cr.notes.is_none());
            assert!(cr.process_version_dictionary.is_empty());
            assert!(cr.build_version_dictionary.is_empty());
            assert!(cr.os_version_dictionary.is_empty());
            assert!(cr.adam_id.is_none());
            assert!(cr.software_version_external_identifier.is_none());
            assert!(cr.reopen_path.is_none());
            assert!(cr.ls_application_information.is_none());
            assert!(!cr.has_receipt);
            assert!(!cr.is_translocated_process);
            assert!(cr.application_specific_info.is_none());
            assert!(cr.application_specific_backtraces.is_empty());
            assert!(cr.application_specific_signature_strings.is_empty());
            assert!(cr.application_specific_dialog_mode.is_none());
            assert!(cr.internal_error.is_none());
            assert!(cr.rosetta_info.is_none());
            assert!(cr.dyld_error_string.is_none());
            assert!(cr.dyld_error_info.is_none());
            assert!(!cr.extract_legacy_dyld_error_string);
            assert!(!cr.fatal_dyld_error_on_launch);
            assert!(cr.exec_failure_error.is_none());
            assert_eq!(cr.cs_status, 0);
            assert!(cr.code_sign_invalid_messages_description.is_none());
            assert!(cr.ext_mod_info.description.is_none());
            assert!(cr.ext_mod_info.warnings.is_none());
            assert!(cr.ext_mod_info.dictionary.is_empty());
            assert_eq!(cr.awake_system_uptime, 0);
            assert!(cr.sleep_wake_uuid.is_none());
            assert!(cr.sandbox_container.is_none());
            assert!(cr.vm_map_string.is_none());
            assert!(cr.vm_summary_string.is_none());
            assert!(cr.objc_selector_name.is_none());
            assert!(cr.third_party_bundle_path.is_none());
            assert!(cr.anon_uuid.is_none());
            assert!(!cr.performing_autopsy);
            assert!(!cr.executable_path_needs_correction);
            assert!(!cr.process_name_needs_correction);
            assert!(cr.in_update_previous_os_build.is_none());
            assert!(cr.item_info_record.is_none());
            assert!(cr.exit_snapshot.is_none());
            assert_eq!(cr.exit_snapshot_length, 0);
            assert!(cr.exit_payload.is_none());
            assert_eq!(cr.exit_payload_length, 0);
            assert!(cr.work_queue_limits.is_none());
            assert_eq!(cr.terminator_pid, 0);
            assert!(cr.terminator_proc.is_none());
            assert!(cr.terminator_reason.is_none());
        }
    }
}

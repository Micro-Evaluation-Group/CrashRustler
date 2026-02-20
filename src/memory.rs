use std::collections::HashMap;

use crate::crash_rustler::{CrashRustler, mac_roman_to_char};
use crate::types::*;

impl MappedMemory {
    /// Reads a slice of bytes from this mapped region at the given virtual address.
    /// Returns None if the range is out of bounds.
    pub fn read_bytes(&self, address: u64, len: usize) -> Option<&[u8]> {
        let offset = address.checked_sub(self.base_address)? as usize;
        let end = offset.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        Some(&self.data[offset..end])
    }

    /// Returns true if this region contains the given address.
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.base_address && address < self.base_address + self.data.len() as u64
    }
}

impl CrashRustler {
    /// Reads a pointer-sized value from mapped process memory at the given address.
    /// Returns 0 if the read fails (address out of range).
    /// Equivalent to -[CrashReport _readAddressFromMemory:atAddress:]
    pub fn read_address_from_memory(&self, memory: &MappedMemory, address: u64) -> u64 {
        memory.read_pointer(address, self.is_64_bit).unwrap_or(0)
    }

    /// Reads a pointer-sized value from mapped memory at a symbol's address.
    /// `symbol_address` is the start of the symbol's range (from CSSymbolGetRange).
    /// Equivalent to -[CrashReport _readAddressFromMemory:atSymbol:]
    pub fn read_address_from_memory_at_symbol(
        &self,
        memory: &MappedMemory,
        symbol_address: u64,
    ) -> u64 {
        self.read_address_from_memory(memory, symbol_address)
    }

    /// Reads a null-terminated string from pre-mapped memory regions.
    /// Searches through the provided mapped regions for the requested address.
    /// Tries UTF-8 decoding first; falls back to MacRoman encoding.
    /// Returns None for address 0 or if the address is not in any mapped region.
    /// Equivalent to -[CrashReport _readStringFromMemory:atAddress:]
    pub fn read_string_from_memory(
        &self,
        address: u64,
        mapped_regions: &[MappedMemory],
    ) -> Option<String> {
        if address == 0 {
            return None;
        }

        // Find the mapped region containing this address
        let region = mapped_regions
            .iter()
            .find(|r| r.contains_address(address))?;

        let offset = (address - region.base_address) as usize;
        let available = &region.data[offset..];

        // Find null terminator, cap at 0x4000 bytes
        let max_len = available.len().min(0x4000);
        let bytes = &available[..max_len];
        let len = bytes.iter().position(|&b| b == 0).unwrap_or(max_len);
        let bytes = &bytes[..len];

        if bytes.is_empty() {
            return None;
        }

        // Try UTF-8 first
        if let Ok(s) = std::str::from_utf8(bytes) {
            return Some(s.to_string());
        }

        // Fall back to MacRoman
        Some(bytes.iter().map(|&b| mac_roman_to_char(b)).collect())
    }

    // =========================================================================
    // Crash reporter info methods
    // =========================================================================

    /// Builds the crash reporter info status string from a dictionary of PID→status entries
    /// and any accumulated internal errors. In CrashWrangler this updates a global C string
    /// read by the crash reporter daemon; here it returns the composed string.
    /// Equivalent to -[CrashReport _updateCrashReporterInfoFromCRIDict]
    pub fn build_crash_reporter_info(
        cri_dict: &HashMap<i32, String>,
        cri_errors: &[String],
    ) -> String {
        let mut result = String::new();
        for value in cri_dict.values() {
            result.push_str(value);
        }
        if !cri_errors.is_empty() {
            let joined = cri_errors.join("\n");
            result.push_str(&format!("ReportCrash Internal Errors: {joined}"));
        }
        result
    }

    /// Appends an internal error to the crash reporter error list.
    /// Formats as "\[executablePath\] error" or "\[notfound\] error".
    /// Equivalent to -[CrashReport _appendCrashReporterInfoInternalError:]
    pub fn append_crash_reporter_info_internal_error(&mut self, error: &str) {
        let path = self.executable_path.as_deref().unwrap_or("notfound");
        let formatted = format!("[{path}] {error}");
        self.record_internal_error(&formatted);
    }

    /// Builds the crash reporter status string for this process.
    /// If ppid is 0: "Analyzing process {name} ({pid}, path={path}),
    ///   couldn't determine parent process pid"
    /// Otherwise: "Analyzing process {name} ({pid}, path={path}),
    ///   parent process {parentName} ({ppid}, path={parentPath})"
    /// Equivalent to -[CrashReport _setCrashReporterInfo]
    pub fn crash_reporter_info_string(&self) -> String {
        let name = self.process_name.as_deref().unwrap_or("");
        let path = self.executable_path.as_deref().unwrap_or("notfound");
        if self.ppid == 0 {
            format!(
                "Analyzing process {name} ({}, path={path}), \
                 couldn't determine parent process pid",
                self.pid
            )
        } else {
            let parent_name = self.parent_process_name.as_deref().unwrap_or("");
            let parent_path = self.parent_executable_path.as_deref().unwrap_or("notfound");
            format!(
                "Analyzing process {name} ({}, path={path}), \
                 parent process {parent_name} ({}, path={parent_path})",
                self.pid, self.ppid
            )
        }
    }

    /// Appends a string to the appropriate application-specific info field.
    /// If the process is not native (Rosetta-translated) and the source binary
    /// is little-endian, appends to rosetta_info instead. Otherwise appends to
    /// application_specific_info.
    /// Equivalent to -[CrashReport _appendApplicationSpecificInfo:withSymbolOwner:]
    pub fn append_application_specific_info(&mut self, info: &str, is_source_little_endian: bool) {
        if info.is_empty() {
            return;
        }
        let formatted = format!("{info}\n");
        if !self.is_native && is_source_little_endian {
            match &mut self.rosetta_info {
                Some(existing) => existing.push_str(&formatted),
                None => self.rosetta_info = Some(formatted),
            }
        } else {
            match &mut self.application_specific_info {
                Some(existing) => existing.push_str(&formatted),
                None => self.application_specific_info = Some(formatted),
            }
        }
    }

    /// Extracts crash reporter info from the ___crashreporter_info__ symbol.
    /// Reads the pointer at the symbol address, then reads the C string it points to
    /// from pre-mapped memory regions.
    /// Equivalent to -[CrashReport _extractCrashReporterInfoFromSymbolOwner:withMemory:]
    pub fn extract_crash_reporter_info(
        &mut self,
        memory: &MappedMemory,
        symbol_address: u64,
        is_source_little_endian: bool,
        mapped_regions: &[MappedMemory],
    ) {
        let ptr = self.read_address_from_memory(memory, symbol_address);
        if ptr != 0
            && let Some(info_string) = self.read_string_from_memory(ptr, mapped_regions)
        {
            self.append_application_specific_info(&info_string, is_source_little_endian);
        }
    }

    /// Extracts crash annotations from the __DATA __crash_info section data.
    /// Parses the crashreporter_annotations_t struct.
    /// String pointers are resolved from pre-mapped memory regions.
    /// Equivalent to -[CrashReport _extractCrashReporterAnnotationsFromSymbolOwner:withMemory:]
    pub fn extract_crash_reporter_annotations(
        &mut self,
        crash_info_data: &[u8],
        is_source_little_endian: bool,
        mapped_regions: &[MappedMemory],
    ) {
        if crash_info_data.len() < 16 {
            return;
        }

        let read_u64 = |offset: usize| -> u64 {
            if offset + 8 > crash_info_data.len() {
                return 0;
            }
            let bytes: [u8; 8] = crash_info_data[offset..offset + 8].try_into().unwrap();
            u64::from_le_bytes(bytes)
        };

        let version = read_u64(0);
        if version == 0 {
            return;
        }

        // Field at offset 8: message pointer
        let message_ptr = read_u64(8);
        if message_ptr != 0
            && let Some(msg) = self.read_string_from_memory(message_ptr, mapped_regions)
        {
            self.append_application_specific_info(&msg, is_source_little_endian);
        }

        // Field at offset 0x10: signature string pointer
        let signature_ptr = read_u64(0x10);
        if signature_ptr != 0
            && let Some(sig) = self.read_string_from_memory(signature_ptr, mapped_regions)
            && !sig.is_empty()
        {
            self.application_specific_signature_strings.push(sig);
        }

        // Field at offset 0x18: backtrace string pointer
        let backtrace_ptr = read_u64(0x18);
        if backtrace_ptr != 0
            && let Some(bt) = self.read_string_from_memory(backtrace_ptr, mapped_regions)
            && !bt.is_empty()
        {
            self.application_specific_backtraces.push(bt);
        }

        // Version 2+: message2 at offset 0x20
        if version >= 2 {
            let message2_ptr = read_u64(0x20);
            if message2_ptr != 0
                && let Some(msg2) = self.read_string_from_memory(message2_ptr, mapped_regions)
            {
                self.append_application_specific_info(&msg2, is_source_little_endian);
            }
        }

        // Version 3+: abort cause thread_id at offset 0x28
        if version >= 3 {
            let thread_id = read_u64(0x28);
            if thread_id != 0 {
                self.thread_id = Some(thread_id);
            }
        }

        // Version 4+: dialog mode at offset 0x30
        if version >= 4 {
            let dialog_mode_ptr = read_u64(0x30);
            if dialog_mode_ptr != 0
                && let Some(mode) = self.read_string_from_memory(dialog_mode_ptr, mapped_regions)
            {
                self.application_specific_dialog_mode = Some(mode);
            }
        }
    }

    /// Extracts binary image hints from the ___crashreporter_binary_image_hints__ symbol.
    /// Reads the pointer at the symbol, reads the plist string it points to from
    /// pre-mapped memory regions, and stores it in binary_image_hints.
    /// Equivalent to -[CrashReport _extractCrashReporterBinaryImageHintsFromSymbolOwner:withMemory:]
    pub fn extract_crash_reporter_binary_image_hints(
        &mut self,
        memory: &MappedMemory,
        symbol_address: u64,
        mapped_regions: &[MappedMemory],
    ) {
        let ptr = self.read_address_from_memory(memory, symbol_address);
        if ptr == 0 {
            return;
        }
        if let Some(plist_string) = self.read_string_from_memory(ptr, mapped_regions)
            && !plist_string.is_empty()
        {
            self.binary_image_hints.push(plist_string);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crash_rustler::CrashRustler;
    use crate::test_helpers::*;
    use std::collections::HashMap;

    // =========================================================================
    // 7. record_error — Internal error recording
    // =========================================================================
    mod record_error {
        use super::*;

        #[test]
        fn record_internal_error_first_creates() {
            let mut cr = make_test_cr();
            cr.record_internal_error("first error");
            assert_eq!(cr.internal_error, Some("first error".into()));
        }

        #[test]
        fn record_internal_error_appends_with_newline() {
            let mut cr = make_test_cr();
            cr.record_internal_error("first");
            cr.record_internal_error("second");
            assert_eq!(cr.internal_error, Some("first\nsecond".into()));
        }

        #[test]
        fn append_crash_reporter_info_internal_error_with_path() {
            let mut cr = make_test_cr();
            cr.append_crash_reporter_info_internal_error("some error");
            let err = cr.internal_error.as_ref().unwrap();
            assert!(err.starts_with("[/Applications/TestApp.app/Contents/MacOS/TestApp]"));
            assert!(err.contains("some error"));
        }

        #[test]
        fn append_crash_reporter_info_internal_error_no_path() {
            let mut cr = make_test_cr();
            cr.executable_path = None;
            cr.append_crash_reporter_info_internal_error("some error");
            let err = cr.internal_error.as_ref().unwrap();
            assert!(err.starts_with("[notfound]"));
        }

        #[test]
        fn crash_reporter_info_string_ppid_zero() {
            let mut cr = make_test_cr();
            cr.ppid = 0;
            let info = cr.crash_reporter_info_string();
            assert!(info.contains("couldn't determine parent process pid"));
            assert!(info.contains("TestApp"));
            assert!(info.contains("1234"));
        }
    }

    // =========================================================================
    // 8. crash_reporter_info — Info building
    // =========================================================================
    mod crash_reporter_info {
        use super::*;

        #[test]
        fn build_crash_reporter_info_empty() {
            let dict = HashMap::new();
            let errors: Vec<String> = vec![];
            assert_eq!(CrashRustler::build_crash_reporter_info(&dict, &errors), "");
        }

        #[test]
        fn build_crash_reporter_info_with_entries() {
            let mut dict = HashMap::new();
            dict.insert(42, "status for 42".to_string());
            let errors: Vec<String> = vec![];
            let result = CrashRustler::build_crash_reporter_info(&dict, &errors);
            assert_eq!(result, "status for 42");
        }

        #[test]
        fn build_crash_reporter_info_with_errors() {
            let dict = HashMap::new();
            let errors = vec!["err1".to_string(), "err2".to_string()];
            let result = CrashRustler::build_crash_reporter_info(&dict, &errors);
            assert!(result.contains("ReportCrash Internal Errors:"));
            assert!(result.contains("err1"));
            assert!(result.contains("err2"));
        }

        #[test]
        fn crash_reporter_info_string_with_parent() {
            let cr = make_test_cr();
            let info = cr.crash_reporter_info_string();
            assert!(info.contains("parent process launchd"));
            assert!(info.contains("1234"));
            assert!(info.contains(&cr.ppid.to_string()));
        }

        #[test]
        fn append_application_specific_info_empty_noop() {
            let mut cr = make_test_cr();
            cr.append_application_specific_info("", true);
            assert!(cr.application_specific_info.is_none());
            assert!(cr.rosetta_info.is_none());
        }

        #[test]
        fn append_application_specific_info_native_little_endian_to_rosetta() {
            let mut cr = make_test_cr();
            cr.is_native = false; // translated
            cr.append_application_specific_info("rosetta data", true);
            assert!(cr.rosetta_info.is_some());
            assert!(cr.rosetta_info.as_ref().unwrap().contains("rosetta data"));
            assert!(cr.application_specific_info.is_none());
        }

        #[test]
        fn append_application_specific_info_native_to_app_info() {
            let mut cr = make_test_cr();
            cr.is_native = true;
            cr.append_application_specific_info("app data", true);
            assert!(cr.application_specific_info.is_some());
            assert!(
                cr.application_specific_info
                    .as_ref()
                    .unwrap()
                    .contains("app data")
            );
        }

        #[test]
        fn append_application_specific_info_appends_to_existing() {
            let mut cr = make_test_cr();
            cr.application_specific_info = Some("existing\n".into());
            cr.append_application_specific_info("more data", true);
            let info = cr.application_specific_info.as_ref().unwrap();
            assert!(info.contains("existing"));
            assert!(info.contains("more data"));
        }
    }
}

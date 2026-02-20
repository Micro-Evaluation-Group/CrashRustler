use std::collections::BTreeMap;

use crate::crash_rustler::CrashRustler;
use crate::types::*;

impl CrashRustler {
    /// Returns true if the crash was due to a bad memory access.
    /// EXC_BAD_ACCESS (type 1) is a bad memory access UNLESS it's a general
    /// protection fault (code 0xd) with address 0.
    /// Equivalent to -[CrashReport _crashedDueToBadMemoryAccess]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::{CrashRustler, CpuType};
    ///
    /// let mut cr = CrashRustler::default();
    /// cr.exception_type = 1; // EXC_BAD_ACCESS
    /// cr.exception_code = vec![2, 0xdeadbeef];
    /// assert!(cr.crashed_due_to_bad_memory_access());
    ///
    /// // GPF with null address on x86 is NOT a bad memory access
    /// cr.cpu_type = CpuType::X86_64;
    /// cr.exception_code = vec![0xd, 0x0];
    /// assert!(!cr.crashed_due_to_bad_memory_access());
    /// ```
    pub fn crashed_due_to_bad_memory_access(&self) -> bool {
        if self.exception_type != 1 {
            return false;
        }
        // GPF with null address is NOT treated as bad memory access (x86 only)
        if self.is_x86_cpu()
            && self.exception_code.first() == Some(&0xd)
            && self.exception_code.get(1) == Some(&0)
        {
            return false;
        }
        true
    }

    /// Extracts the crashing address from exception codes or exception state.
    /// For bad memory access: uses exception_code\[1\].
    /// For code sign killed: extracts cr2 from exception state registers.
    /// Equivalent to the address extraction in -[CrashReport _extractVMMap]
    pub fn extract_crashing_address(&mut self) {
        if self.crashed_due_to_bad_memory_access() {
            if let Some(&addr) = self.exception_code.get(1) {
                self.crashing_address = addr as u64;
            }
        } else if self.is_code_sign_killed() {
            let state = &self.exception_state.state;
            if self.is_arm_cpu() {
                // ARM64 exception state: FAR (Fault Address Register) at state[0..1] as u64
                if state.len() >= 2 {
                    self.crashing_address = (state[0] as u64) | ((state[1] as u64) << 32);
                }
            } else {
                // x86 exception state: cr2 location depends on sub-flavor
                if !state.is_empty() {
                    if state[0] == 1 {
                        // 32-bit exception state: cr2 at index 4
                        if let Some(&cr2) = state.get(4) {
                            self.crashing_address = cr2 as u64;
                        }
                    } else {
                        // 64-bit exception state: cr2 at indices 4-5
                        if state.len() > 5 {
                            self.crashing_address = (state[4] as u64) | ((state[5] as u64) << 32);
                        }
                    }
                }
            }
        }
    }

    /// Sanitizes a file path by replacing user-specific components.
    /// Replaces /Users/username/ with /Users/USER/ for privacy.
    /// Equivalent to _CRCopySanitizedPath used by -[CrashReport cleansePaths]
    ///
    /// # Examples
    ///
    /// ```
    /// use crashrustler::CrashRustler;
    ///
    /// assert_eq!(
    ///     CrashRustler::sanitize_path("/Users/alice/Library/MyApp"),
    ///     "/Users/USER/Library/MyApp"
    /// );
    /// assert_eq!(
    ///     CrashRustler::sanitize_path("/System/Library/Frameworks/AppKit"),
    ///     "/System/Library/Frameworks/AppKit"
    /// );
    /// ```
    pub fn sanitize_path(path: &str) -> String {
        if let Some(rest) = path.strip_prefix("/Users/")
            && let Some(slash_pos) = rest.find('/')
        {
            return format!("/Users/USER/{}", &rest[slash_pos + 1..]);
        }
        path.to_string()
    }

    /// Sanitizes all file paths in the crash report for privacy.
    /// Preserves original executable path as reopen_path before sanitizing.
    /// Sanitizes: executable_path, all binary image paths, VM map paths.
    /// Equivalent to -[CrashReport cleansePaths]
    pub fn cleanse_paths(&mut self) {
        // Save original path for relaunch
        if self.executable_path.is_some() && self.reopen_path.is_none() {
            self.reopen_path = self.executable_path.clone();
        }

        // Sanitize executable path
        if let Some(ref path) = self.executable_path {
            let sanitized = Self::sanitize_path(path);
            if sanitized != *path {
                self.executable_path = Some(sanitized);
            }
        }

        // Sanitize binary image paths
        for image in &mut self.binary_images {
            image.path = Self::sanitize_path(&image.path);
        }

        // Sanitize VM map paths
        if let Some(ref vm_map) = self.vm_map_string {
            let sanitized_lines: Vec<String> = vm_map
                .lines()
                .map(|line| {
                    if let Some(slash_pos) = line.find('/') {
                        let path = &line[slash_pos..];
                        let sanitized = Self::sanitize_path(path);
                        format!("{}{}", &line[..slash_pos], sanitized)
                    } else {
                        line.to_string()
                    }
                })
                .collect();
            self.vm_map_string = Some(sanitized_lines.join("\n"));
        }
    }

    /// Sets work queue limits from pre-queried sysctl values.
    /// Bit 0 of `flags`: constrained thread limit hit.
    /// Bit 1 of `flags`: total thread limit hit.
    /// The caller (exc_handler) is responsible for querying
    /// `kern.wq_max_constrained_threads` and `kern.wq_max_threads`.
    /// Equivalent to -[CrashReport _extractWorkQueueLimitsFromData:]
    pub fn extract_work_queue_limits_from_flags(
        &mut self,
        flags: u32,
        wq_max_constrained_threads: Option<u32>,
        wq_max_threads: Option<u32>,
    ) {
        if flags & 3 == 0 {
            return;
        }
        let mut limits = WorkQueueLimits {
            min_threads: None,
            max_threads: None,
        };
        if flags & 1 != 0 {
            limits.min_threads = wq_max_constrained_threads;
        }
        if flags & 2 != 0 {
            limits.max_threads = wq_max_threads;
        }
        self.work_queue_limits = Some(limits);
    }

    /// Reads the App Store receipt from the application bundle path.
    /// Sets has_receipt and adam_id if a valid receipt is found.
    /// Equivalent to -[CrashReport _readAppStoreReceipt]
    pub fn set_app_store_receipt(&mut self, adam_id: Option<String>, version_id: Option<String>) {
        if adam_id.is_some() {
            self.has_receipt = true;
            self.adam_id = adam_id;
            self.software_version_external_identifier = version_id;
        }
    }

    // =========================================================================
    // Dictionary/plist and classification methods
    // =========================================================================

    /// Builds the main problem dictionary for crash reporting.
    /// Populates ~40+ keys including app info, exception details, thread state,
    /// binary images, VM map, notes, timestamps, and more.
    /// Equivalent to -[CrashReport problemDictionary]
    pub fn problem_dictionary(&self) -> BTreeMap<String, PlistValue> {
        let mut d = BTreeMap::new();

        if let Some(name) = self.process_name()
            && !name.is_empty()
        {
            d.insert("app_name".into(), PlistValue::String(name.into()));
        }
        if self.pid != 0 {
            d.insert("app_pid".into(), PlistValue::Int(self.pid as i64));
        }
        if let Some(path) = self.executable_path()
            && !path.is_empty()
        {
            d.insert("app_path".into(), PlistValue::String(path.into()));
        }
        if let Some(id) = self.process_identifier()
            && !id.is_empty()
        {
            d.insert("app_bundle_id".into(), PlistValue::String(id.into()));
        }
        let ver = self.app_version();
        if !ver.is_empty() {
            d.insert("app_version".into(), PlistValue::String(ver));
        }
        let build_ver = self.app_build_version();
        if !build_ver.is_empty() {
            d.insert("app_build_version".into(), PlistValue::String(build_ver));
        }

        // Build version dictionary fields
        if let Some(v) = self.build_version_dictionary.get("ProjectName")
            && !v.is_empty()
        {
            d.insert("project_name".into(), PlistValue::String(v.clone()));
        }
        if let Some(v) = self.build_version_dictionary.get("SourceVersion")
            && !v.is_empty()
        {
            d.insert(
                "project_source_version".into(),
                PlistValue::String(v.clone()),
            );
        }
        if let Some(v) = self.build_version_dictionary.get("BuildVersion")
            && !v.is_empty()
        {
            d.insert(
                "project_build_version".into(),
                PlistValue::String(v.clone()),
            );
        }

        d.insert("arch".into(), PlistValue::String(self.short_arch_name()));
        d.insert("arch_translated".into(), PlistValue::Bool(!self.is_native));
        d.insert("arch_64".into(), PlistValue::Bool(self.is_64_bit));

        if let Some(name) = self.parent_process_name()
            && !name.is_empty()
        {
            d.insert("parent_name".into(), PlistValue::String(name.into()));
        }
        if self.ppid != 0 {
            d.insert("parent_pid".into(), PlistValue::Int(self.ppid as i64));
        }
        if self.r_process_pid != -1 {
            if let Some(name) = self.responsible_process_name()
                && !name.is_empty()
            {
                d.insert(
                    "responsible_process_name".into(),
                    PlistValue::String(name.into()),
                );
            }
            d.insert(
                "responsible_process_pid".into(),
                PlistValue::Int(self.r_process_pid as i64),
            );
        }

        if let Some(ref date) = self.date {
            d.insert("date".into(), PlistValue::String(date.clone()));
        }

        // OS version fields
        if let Some(v) = self.os_version_dictionary.get("ProductVersion")
            && !v.is_empty()
        {
            d.insert("os_version".into(), PlistValue::String(v.clone()));
        }
        if let Some(v) = self.os_version_dictionary.get("BuildVersion")
            && !v.is_empty()
        {
            d.insert("os_build".into(), PlistValue::String(v.clone()));
        }
        if let Some(v) = self.os_version_dictionary.get("ProductName")
            && !v.is_empty()
        {
            d.insert("os_product".into(), PlistValue::String(v.clone()));
        }

        d.insert("report_version".into(), PlistValue::String("12".into()));

        if self.awake_system_uptime != 0 {
            d.insert(
                "awake_system_uptime".into(),
                PlistValue::Int(Self::reduce_to_two_sig_figures(self.awake_system_uptime) as i64),
            );
        }

        let sig_name = self.signal_name();
        if !sig_name.is_empty() {
            d.insert("signal_name".into(), PlistValue::String(sig_name));
        }
        if self.crashed_thread_number >= 0 {
            d.insert(
                "crashing_thread_index".into(),
                PlistValue::Int(self.crashed_thread_number as i64),
            );
        }

        let exc_type = self.exception_type_description();
        if !exc_type.is_empty() {
            d.insert("exception_type".into(), PlistValue::String(exc_type));
        }
        let exc_codes = self.exception_codes_description();
        if !exc_codes.is_empty() {
            d.insert("exception_codes".into(), PlistValue::String(exc_codes));
        }

        if self.performing_autopsy {
            d.insert(
                "exception_notes".into(),
                PlistValue::Array(vec![{
                    let mut m = BTreeMap::new();
                    m.insert(
                        "note".into(),
                        PlistValue::String("EXC_CORPSE_NOTIFY".into()),
                    );
                    m
                }]),
            );
        }

        if self.is_code_sign_killed() {
            d.insert("cs_killed".into(), PlistValue::Bool(true));
            if let Some(ref msgs) = self.code_sign_invalid_messages_description {
                d.insert("kernel_messages".into(), PlistValue::String(msgs.clone()));
            }
        }

        d.insert(
            "system_integrity_protection".into(),
            PlistValue::Bool(self.is_rootless_enabled()),
        );

        if let Some(ref info) = self.application_specific_info
            && !info.is_empty()
        {
            d.insert(
                "crash_info_message".into(),
                PlistValue::String(info.clone()),
            );
        }
        if let Some(ref sel) = self.objc_selector_name
            && !sel.is_empty()
        {
            d.insert("objc_selector".into(), PlistValue::String(sel.clone()));
        }
        if !self.application_specific_signature_strings.is_empty() {
            let arr = self
                .application_specific_signature_strings
                .iter()
                .map(|s| {
                    let mut m = BTreeMap::new();
                    m.insert("signature".into(), PlistValue::String(s.clone()));
                    m
                })
                .collect();
            d.insert("crash_info_signatures".into(), PlistValue::Array(arr));
        }
        if !self.application_specific_backtraces.is_empty() {
            let arr = self
                .application_specific_backtraces
                .iter()
                .map(|s| {
                    let mut m = BTreeMap::new();
                    m.insert("backtrace".into(), PlistValue::String(s.clone()));
                    m
                })
                .collect();
            d.insert("crash_info_thread_strings".into(), PlistValue::Array(arr));
        }

        if let Some(ref err) = self.internal_error
            && !err.is_empty()
        {
            d.insert("internal_error".into(), PlistValue::String(err.clone()));
        }
        if let Some(ref err) = self.dyld_error_string
            && !err.is_empty()
        {
            d.insert("dyld_error".into(), PlistValue::String(err.clone()));
        }
        if let Some(ref info) = self.dyld_error_info {
            d.insert("dyld_error_info".into(), PlistValue::String(info.clone()));
        }

        // Thread state
        let ts = self.thread_state_description();
        d.insert("crashing_thread_state".into(), PlistValue::String(ts));

        // VM map
        if let Some(ref vm) = self.vm_map_string
            && !vm.is_empty()
        {
            d.insert("vm_map".into(), PlistValue::String(vm.clone()));
        }
        if let Some(ref vs) = self.vm_summary_string
            && !vs.is_empty()
        {
            d.insert("vm_summary".into(), PlistValue::String(vs.clone()));
        }

        if let Some(ref uuid) = self.sleep_wake_uuid
            && !uuid.is_empty()
        {
            d.insert(
                "sleep_wake_uuid_string".into(),
                PlistValue::String(uuid.clone()),
            );
        }
        if let Some(ref uuid) = self.anon_uuid {
            d.insert("anon_uuid".into(), PlistValue::String(uuid.clone()));
        }
        if !self.ext_mod_info.dictionary.is_empty() {
            let mut ext = BTreeMap::new();
            for (k, v) in &self.ext_mod_info.dictionary {
                ext.insert(k.clone(), PlistValue::String(v.clone()));
            }
            d.insert(
                "external_modification_summary".into(),
                PlistValue::Dict(ext),
            );
        }
        if let Some(ref rosetta) = self.rosetta_info
            && !rosetta.is_empty()
        {
            d.insert(
                "rosetta_threads_string".into(),
                PlistValue::String(rosetta.clone()),
            );
        }

        d
    }

    /// Builds a filtered dictionary for crash signature generation.
    /// Contains a subset of problem dictionary keys needed for signature matching.
    /// Filters thread plists and binary images to only referenced images.
    /// Equivalent to -[CrashReport preSignatureDictionary]
    pub fn pre_signature_dictionary(&self) -> BTreeMap<String, PlistValue> {
        let mut d = BTreeMap::new();

        if let Some(name) = self.process_name()
            && !name.is_empty()
        {
            d.insert("app_name".into(), PlistValue::String(name.into()));
        }
        if let Some(id) = self.process_identifier()
            && !id.is_empty()
        {
            d.insert("app_bundle_id".into(), PlistValue::String(id.into()));
        }
        let build_ver = self.app_build_version();
        if !build_ver.is_empty() {
            d.insert("app_build_version".into(), PlistValue::String(build_ver));
        }
        let ver = self.app_version();
        if !ver.is_empty() {
            d.insert("app_version".into(), PlistValue::String(ver));
        }
        d.insert("arch".into(), PlistValue::String(self.short_arch_name()));

        if let Some(v) = self.os_version_dictionary.get("BuildVersion")
            && !v.is_empty()
        {
            d.insert("os_build".into(), PlistValue::String(v.clone()));
        }

        d.insert("report_version".into(), PlistValue::String("12".into()));

        let sig_name = self.signal_name();
        if !sig_name.is_empty() {
            d.insert("signal_name".into(), PlistValue::String(sig_name));
        }
        let exc_type = self.exception_type_description();
        if !exc_type.is_empty() {
            d.insert("exception_type".into(), PlistValue::String(exc_type));
        }
        if let Some(ref sel) = self.objc_selector_name
            && !sel.is_empty()
        {
            d.insert("objc_selector".into(), PlistValue::String(sel.clone()));
        }
        if !self.application_specific_signature_strings.is_empty() {
            let arr = self
                .application_specific_signature_strings
                .iter()
                .map(|s| {
                    let mut m = BTreeMap::new();
                    m.insert("signature".into(), PlistValue::String(s.clone()));
                    m
                })
                .collect();
            d.insert("crash_info_signatures".into(), PlistValue::Array(arr));
        }
        if let Some(ref err) = self.internal_error
            && !err.is_empty()
        {
            d.insert("internal_error".into(), PlistValue::String(err.clone()));
        }
        if let Some(ref info) = self.dyld_error_info {
            d.insert("dyld_error_info".into(), PlistValue::String(info.clone()));
        }
        if let Some(ref adam) = self.adam_id
            && !adam.is_empty()
        {
            d.insert("mas_adam_id".into(), PlistValue::String(adam.clone()));
        }
        if let Some(ref ext_id) = self.software_version_external_identifier
            && !ext_id.is_empty()
        {
            d.insert("mas_external_id".into(), PlistValue::String(ext_id.clone()));
        }
        if self.work_queue_limits.is_some() {
            let mut wq = BTreeMap::new();
            if let Some(ref limits) = self.work_queue_limits {
                if let Some(min) = limits.min_threads {
                    wq.insert("min_threads".into(), PlistValue::Int(min as i64));
                }
                if let Some(max) = limits.max_threads {
                    wq.insert("max_threads".into(), PlistValue::Int(max as i64));
                }
            }
            d.insert("wq_limits_reached".into(), PlistValue::Dict(wq));
        }

        // Filter crashed thread backtrace for presignature
        if !self.fatal_dyld_error_on_launch
            && self.crashed_thread_number >= 0
            && (self.crashed_thread_number as usize) < self.backtraces.len()
        {
            let bt = &self.backtraces[self.crashed_thread_number as usize];
            let filtered = self.filter_thread_for_presignature(bt);
            d.insert("crashed_thread".into(), PlistValue::Dict(filtered));
        }

        d
    }

    /// Builds a minimal context dictionary with date and sleep/wake UUID.
    /// Equivalent to -[CrashReport contextDictionary]
    pub fn context_dictionary(&self) -> BTreeMap<String, PlistValue> {
        let mut d = BTreeMap::new();
        if let Some(ref date) = self.date {
            d.insert("date".into(), PlistValue::String(date.clone()));
        }
        if let Some(ref uuid) = self.sleep_wake_uuid
            && !uuid.is_empty()
        {
            d.insert(
                "sleep_wake_uuid_string".into(),
                PlistValue::String(uuid.clone()),
            );
        }
        d
    }

    /// Combines problemDictionary, preSignatureDictionary, and contextDictionary
    /// into a single dictionary with keys "report", "presignature", "context".
    /// Equivalent to -[CrashReport descriptionDictionary]
    pub fn description_dictionary(&self) -> BTreeMap<String, PlistValue> {
        let mut d = BTreeMap::new();
        d.insert("report".into(), PlistValue::Dict(self.problem_dictionary()));
        d.insert(
            "presignature".into(),
            PlistValue::Dict(self.pre_signature_dictionary()),
        );
        d.insert(
            "context".into(),
            PlistValue::Dict(self.context_dictionary()),
        );
        d
    }

    /// Filters a thread backtrace for presignature use.
    /// Extracts only symbol, symbol_offset, binary_image_offset,
    /// binary_image_identifier, and binary_image_index per frame.
    /// Equivalent to -[CrashReport filterThreadPlistForPresignature:withBinaryImagesSet:]
    fn filter_thread_for_presignature(&self, bt: &ThreadBacktrace) -> BTreeMap<String, PlistValue> {
        let mut result = BTreeMap::new();
        let mut frames = Vec::new();

        for frame in &bt.frames {
            let mut fd = BTreeMap::new();
            if let Some(ref sym) = frame.symbol_name {
                fd.insert("symbol".into(), PlistValue::String(sym.clone()));
            }
            if frame.symbol_offset != 0 {
                fd.insert(
                    "symbol_offset".into(),
                    PlistValue::Int(frame.symbol_offset as i64),
                );
            }
            if let Some(img) = self.binary_image_for_address(frame.address) {
                let offset = frame.address - img.base_address;
                fd.insert("binary_image_offset".into(), PlistValue::Int(offset as i64));
                if let Some(ref id) = img.identifier {
                    fd.insert(
                        "binary_image_identifier".into(),
                        PlistValue::String(id.clone()),
                    );
                }
            }
            frames.push(fd);
        }

        result.insert("backtrace".into(), PlistValue::Array(frames));
        if let Some(ref name) = bt.thread_name {
            result.insert("thread_name".into(), PlistValue::String(name.clone()));
        }
        result
    }

    /// Filters a binary image for presignature. If UUID exists, returns
    /// just index+uuid. Otherwise returns index + bundle metadata + path.
    /// Equivalent to -[CrashReport filteredBinaryImagePlistForPresignature:]
    pub fn filtered_binary_image_for_presignature(
        &self,
        image: &BinaryImage,
        index: usize,
    ) -> BTreeMap<String, PlistValue> {
        let mut d = BTreeMap::new();
        d.insert("index".into(), PlistValue::Int(index as i64));

        if let Some(ref uuid) = image.uuid {
            d.insert("uuid".into(), PlistValue::String(uuid.clone()));
        } else {
            if let Some(ref ver) = image.version {
                d.insert("bundle_version".into(), PlistValue::String(ver.clone()));
            }
            if let Some(ref id) = image.identifier {
                d.insert("bundle_id".into(), PlistValue::String(id.clone()));
            }
            d.insert("path".into(), PlistValue::String(image.path.clone()));
        }
        d
    }

    /// Converts binary images to plist format array.
    /// Equivalent to -[CrashReport _binaryImagesPlist]
    pub fn binary_images_plist(&self) -> Vec<BTreeMap<String, PlistValue>> {
        self.binary_images
            .iter()
            .enumerate()
            .map(|(i, img)| {
                let mut d = BTreeMap::new();
                d.insert("index".into(), PlistValue::Int(i as i64));
                d.insert(
                    "StartAddress".into(),
                    PlistValue::Int(img.base_address as i64),
                );
                d.insert(
                    "Size".into(),
                    PlistValue::Int((img.end_address - img.base_address) as i64),
                );
                d.insert("path".into(), PlistValue::String(img.path.clone()));
                d.insert("name".into(), PlistValue::String(img.name.clone()));
                if let Some(ref uuid) = img.uuid {
                    d.insert("uuid".into(), PlistValue::String(uuid.clone()));
                }
                if let Some(ref id) = img.identifier {
                    d.insert("bundle_id".into(), PlistValue::String(id.clone()));
                }
                if let Some(ref ver) = img.version {
                    d.insert("bundle_version".into(), PlistValue::String(ver.clone()));
                }
                if let Some(ref arch) = img.arch {
                    d.insert("arch".into(), PlistValue::String(arch.clone()));
                }
                d
            })
            .collect()
    }

    /// Parses rosettaInfo string into plist-compatible thread array.
    /// Splits by newlines, detects Thread headers with Crashed markers,
    /// parses hex address + image path + symbol/offset from each frame.
    /// Equivalent to -[CrashReport _rosettaThreadsPlist]
    pub fn rosetta_threads_plist(&self) -> Vec<BTreeMap<String, PlistValue>> {
        let rosetta = match &self.rosetta_info {
            Some(r) if !r.is_empty() => r,
            _ => return Vec::new(),
        };

        let mut threads: Vec<BTreeMap<String, PlistValue>> = Vec::new();
        let mut current_frames: Vec<BTreeMap<String, PlistValue>> = Vec::new();
        let mut current_thread = BTreeMap::new();
        current_thread.insert("backtrace".into(), PlistValue::Array(Vec::new()));

        for line in rosetta.lines() {
            if line.starts_with("Thread") {
                // Flush previous thread if it had frames
                if (!current_frames.is_empty() || threads.is_empty()) && !current_frames.is_empty()
                {
                    current_thread.insert("backtrace".into(), PlistValue::Array(current_frames));
                    threads.push(current_thread);
                }
                current_frames = Vec::new();
                current_thread = BTreeMap::new();
                if line.contains("Crashed") {
                    current_thread.insert("crashed".into(), PlistValue::Bool(true));
                }
            } else {
                // Parse frame: "0xADDR imagepath symbol + offset"
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                // Try to parse hex address at start
                if let Some(hex_str) = trimmed.strip_prefix("0x") {
                    let addr_end = hex_str
                        .find(|c: char| !c.is_ascii_hexdigit())
                        .unwrap_or(hex_str.len());
                    if let Ok(addr) = u64::from_str_radix(&hex_str[..addr_end], 16) {
                        let mut frame = BTreeMap::new();
                        frame.insert("address".into(), PlistValue::Int(addr as i64));

                        // Parse rest: skip whitespace, get image path, symbol + offset
                        let rest = hex_str[addr_end..].trim_start();
                        if let Some(space_pos) = rest.find(' ') {
                            let image_path = &rest[..space_pos];
                            let after_image = rest[space_pos..].trim_start();

                            if let Some(last_component) = image_path.rsplit('/').next() {
                                frame.insert(
                                    "binary_image_identifier".into(),
                                    PlistValue::String(last_component.into()),
                                );
                            }

                            // Check for "symbol + offset" pattern
                            if let Some(plus_pos) = after_image.rfind(" + ") {
                                let symbol = after_image[..plus_pos].trim();
                                let offset_str = after_image[plus_pos + 3..].trim();
                                if !symbol.is_empty() {
                                    frame
                                        .insert("symbol".into(), PlistValue::String(symbol.into()));
                                    if let Ok(off) = offset_str.parse::<u64>() {
                                        frame.insert(
                                            "symbol_offset".into(),
                                            PlistValue::Int(off as i64),
                                        );
                                    }
                                } else if let Ok(off) = offset_str.parse::<u64>() {
                                    frame.insert(
                                        "binary_image_offset".into(),
                                        PlistValue::Int(off as i64),
                                    );
                                }
                            }
                        }
                        current_frames.push(frame);
                    }
                }
            }
        }

        // Flush last thread
        if !current_frames.is_empty() {
            current_thread.insert("backtrace".into(), PlistValue::Array(current_frames));
            threads.push(current_thread);
        }

        if threads.is_empty() {
            return Vec::new();
        }
        threads
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::*;
    use crate::types::*;

    // =========================================================================
    // 11. crash_analysis — Extraction methods
    // =========================================================================
    mod crash_analysis {
        use super::*;

        #[test]
        fn crashed_due_to_bad_memory_access_not_type1() {
            let mut cr = make_test_cr();
            cr.exception_type = 3; // EXC_ARITHMETIC
            assert!(!cr.crashed_due_to_bad_memory_access());
        }

        #[test]
        fn crashed_due_to_bad_memory_access_type1() {
            let mut cr = make_test_cr();
            cr.exception_type = 1;
            cr.exception_code = vec![2, 0x42];
            assert!(cr.crashed_due_to_bad_memory_access());
        }

        #[test]
        fn crashed_due_to_bad_memory_access_gpf_null_false() {
            let mut cr = make_test_cr();
            cr.exception_type = 1;
            cr.exception_code = vec![0xd, 0]; // GPF with null address
            assert!(!cr.crashed_due_to_bad_memory_access());
        }

        #[test]
        fn extract_crashing_address_bad_memory_access() {
            let mut cr = make_test_cr();
            cr.exception_type = 1;
            cr.exception_code = vec![2, 0xDEAD];
            cr.extract_crashing_address();
            assert_eq!(cr.crashing_address, 0xDEAD);
        }

        #[test]
        fn extract_crashing_address_code_sign_killed_32bit() {
            let mut cr = make_test_cr();
            cr.exception_type = 5; // not bad access
            cr.cs_status = 0x100_0000;
            cr.exception_state = ExceptionState {
                state: vec![1, 0, 0, 0, 0xCAFE, 0], // sub_flavor=1, cr2 at index 4
                count: 6,
            };
            cr.extract_crashing_address();
            assert_eq!(cr.crashing_address, 0xCAFE);
        }

        #[test]
        fn extract_crashing_address_code_sign_killed_64bit() {
            let mut cr = make_test_cr();
            cr.exception_type = 5;
            cr.cs_status = 0x100_0000;
            cr.exception_state = ExceptionState {
                state: vec![4, 0, 0, 0, 0xBEEF, 0x0001], // sub_flavor=4, cr2 at 4-5
                count: 6,
            };
            cr.extract_crashing_address();
            assert_eq!(cr.crashing_address, (0x0001u64 << 32) | 0xBEEF);
        }

        #[test]
        fn crashed_due_to_bad_memory_access_gpf_null_arm64_is_true() {
            // On ARM64, code 0xd with null address is NOT a GPF — it's a real bad access
            let mut cr = make_test_cr_arm64();
            cr.exception_type = 1;
            cr.exception_code = vec![0xd, 0];
            assert!(cr.crashed_due_to_bad_memory_access());
        }

        #[test]
        fn extract_crashing_address_code_sign_killed_arm64() {
            let mut cr = make_test_cr_arm64();
            cr.exception_type = 5;
            cr.cs_status = 0x100_0000;
            // ARM64 exception state: FAR at state[0..1]
            cr.exception_state = ExceptionState {
                state: vec![0xDEAD_0000, 0x0000_FFFF, 0, 0],
                count: 4,
            };
            cr.extract_crashing_address();
            assert_eq!(cr.crashing_address, 0x0000_FFFF_DEAD_0000);
        }

        #[test]
        fn cleanse_paths_sanitizes_executable_path() {
            let mut cr = make_test_cr();
            cr.executable_path = Some("/Users/kurtis/app/bin".into());
            cr.cleanse_paths();
            assert_eq!(cr.executable_path.as_deref(), Some("/Users/USER/app/bin"));
        }

        #[test]
        fn cleanse_paths_preserves_reopen_path() {
            let mut cr = make_test_cr();
            cr.executable_path = Some("/Users/kurtis/app/bin".into());
            cr.reopen_path = None;
            cr.cleanse_paths();
            // reopen_path should be set to original before sanitization
            assert_eq!(cr.reopen_path.as_deref(), Some("/Users/kurtis/app/bin"));
        }

        #[test]
        fn cleanse_paths_sanitizes_binary_image_paths() {
            let mut cr = make_test_cr();
            cr.binary_images.push(BinaryImage {
                name: "libfoo.dylib".into(),
                path: "/Users/kurtis/lib/libfoo.dylib".into(),
                uuid: None,
                base_address: 0x1000,
                end_address: 0x2000,
                arch: None,
                identifier: None,
                version: None,
            });
            cr.cleanse_paths();
            assert_eq!(cr.binary_images[0].path, "/Users/USER/lib/libfoo.dylib");
        }

        #[test]
        fn cleanse_paths_sanitizes_vm_map_lines() {
            let mut cr = make_test_cr();
            cr.vm_map_string =
                Some("region 0x1000 /Users/kurtis/lib/libfoo.dylib\nother line".into());
            cr.cleanse_paths();
            let vm = cr.vm_map_string.as_ref().unwrap();
            assert!(vm.contains("/Users/USER/lib/libfoo.dylib"));
            assert_eq!(vm.lines().nth(1).unwrap(), "other line");
        }

        #[test]
        fn set_app_store_receipt_with_adam_id() {
            let mut cr = make_test_cr();
            cr.set_app_store_receipt(Some("12345".into()), Some("67890".into()));
            assert!(cr.has_receipt);
            assert_eq!(cr.adam_id, Some("12345".into()));
            assert_eq!(
                cr.software_version_external_identifier,
                Some("67890".into())
            );
        }

        #[test]
        fn set_app_store_receipt_without_adam_id() {
            let mut cr = make_test_cr();
            cr.set_app_store_receipt(None, Some("67890".into()));
            assert!(!cr.has_receipt);
            assert!(cr.adam_id.is_none());
        }
    }

    // =========================================================================
    // 12. dictionary_methods — Plist output
    // =========================================================================
    mod dictionary_methods {
        use super::*;

        #[test]
        fn problem_dictionary_has_expected_keys() {
            let cr = make_test_cr();
            let d = cr.problem_dictionary();
            assert!(d.contains_key("app_name"));
            assert!(d.contains_key("app_pid"));
            assert!(d.contains_key("app_path"));
            assert!(d.contains_key("arch"));
            assert!(d.contains_key("arch_translated"));
            assert!(d.contains_key("arch_64"));
            assert!(d.contains_key("report_version"));
            assert!(d.contains_key("system_integrity_protection"));
            assert!(d.contains_key("crashing_thread_state"));
        }

        #[test]
        fn problem_dictionary_values() {
            let cr = make_test_cr();
            let d = cr.problem_dictionary();
            match d.get("app_name") {
                Some(PlistValue::String(s)) => assert_eq!(s, "TestApp"),
                _ => panic!("unexpected app_name type"),
            }
            match d.get("app_pid") {
                Some(PlistValue::Int(n)) => assert_eq!(*n, 1234),
                _ => panic!("unexpected app_pid type"),
            }
        }

        #[test]
        fn pre_signature_dictionary_has_expected_keys() {
            let cr = make_test_cr();
            let d = cr.pre_signature_dictionary();
            assert!(d.contains_key("app_name"));
            assert!(d.contains_key("arch"));
            assert!(d.contains_key("report_version"));
            assert!(d.contains_key("exception_type"));
            assert!(d.contains_key("signal_name"));
        }

        #[test]
        fn pre_signature_dictionary_filtered() {
            let cr = make_test_cr();
            let d = cr.pre_signature_dictionary();
            // Keys that should NOT be in presignature
            assert!(!d.contains_key("app_pid"));
            assert!(!d.contains_key("crashing_thread_state"));
            assert!(!d.contains_key("vm_map"));
        }

        #[test]
        fn context_dictionary_has_date_and_uuid() {
            let mut cr = make_test_cr();
            cr.date = Some("2024-01-01".into());
            cr.sleep_wake_uuid = Some("UUID-123".into());
            let d = cr.context_dictionary();
            assert!(d.contains_key("date"));
            assert!(d.contains_key("sleep_wake_uuid_string"));
            assert_eq!(d.len(), 2);
        }

        #[test]
        fn context_dictionary_date_only() {
            let mut cr = make_test_cr();
            cr.date = Some("2024-01-01".into());
            let d = cr.context_dictionary();
            assert!(d.contains_key("date"));
            assert!(!d.contains_key("sleep_wake_uuid_string"));
        }

        #[test]
        fn description_dictionary_has_three_keys() {
            let cr = make_test_cr();
            let d = cr.description_dictionary();
            assert!(d.contains_key("report"));
            assert!(d.contains_key("presignature"));
            assert!(d.contains_key("context"));
        }

        #[test]
        fn binary_images_plist_empty() {
            let cr = make_test_cr();
            assert!(cr.binary_images_plist().is_empty());
        }

        #[test]
        fn binary_images_plist_populated() {
            let mut cr = make_test_cr();
            cr.binary_images.push(BinaryImage {
                name: "libfoo.dylib".into(),
                path: "/usr/lib/libfoo.dylib".into(),
                uuid: Some("UUID".into()),
                base_address: 0x1000,
                end_address: 0x2000,
                arch: Some("x86_64".into()),
                identifier: Some("libfoo.dylib".into()),
                version: Some("1.0".into()),
            });
            let plist = cr.binary_images_plist();
            assert_eq!(plist.len(), 1);
            assert!(plist[0].contains_key("StartAddress"));
            assert!(plist[0].contains_key("Size"));
            assert!(plist[0].contains_key("uuid"));
            assert!(plist[0].contains_key("bundle_id"));
        }

        #[test]
        fn filtered_binary_image_for_presignature_with_uuid() {
            let cr = make_test_cr();
            let img = BinaryImage {
                name: "libfoo.dylib".into(),
                path: "/usr/lib/libfoo.dylib".into(),
                uuid: Some("UUID-123".into()),
                base_address: 0x1000,
                end_address: 0x2000,
                arch: None,
                identifier: Some("libfoo.dylib".into()),
                version: Some("1.0".into()),
            };
            let d = cr.filtered_binary_image_for_presignature(&img, 0);
            assert!(d.contains_key("uuid"));
            assert!(!d.contains_key("path"));
        }

        #[test]
        fn filtered_binary_image_for_presignature_without_uuid() {
            let cr = make_test_cr();
            let img = BinaryImage {
                name: "libfoo.dylib".into(),
                path: "/usr/lib/libfoo.dylib".into(),
                uuid: None,
                base_address: 0x1000,
                end_address: 0x2000,
                arch: None,
                identifier: Some("libfoo.dylib".into()),
                version: Some("1.0".into()),
            };
            let d = cr.filtered_binary_image_for_presignature(&img, 0);
            assert!(!d.contains_key("uuid"));
            assert!(d.contains_key("path"));
            assert!(d.contains_key("bundle_id"));
            assert!(d.contains_key("bundle_version"));
        }

        #[test]
        fn rosetta_threads_plist_empty() {
            let cr = make_test_cr();
            assert!(cr.rosetta_threads_plist().is_empty());
        }

        #[test]
        fn rosetta_threads_plist_single_thread() {
            let mut cr = make_test_cr();
            cr.rosetta_info = Some("Thread 0:\n0x1000 /usr/lib/libfoo.dylib main + 42\n".into());
            let threads = cr.rosetta_threads_plist();
            assert_eq!(threads.len(), 1);
        }

        #[test]
        fn rosetta_threads_plist_crashed_marker() {
            let mut cr = make_test_cr();
            cr.rosetta_info =
                Some("Thread 0 Crashed:\n0x1000 /usr/lib/libfoo.dylib main + 42\n".into());
            let threads = cr.rosetta_threads_plist();
            assert_eq!(threads.len(), 1);
            assert!(threads[0].contains_key("crashed"));
        }

        #[test]
        fn rosetta_threads_plist_frame_with_symbol_offset() {
            let mut cr = make_test_cr();
            cr.rosetta_info = Some("Thread 0:\n0x1000 /usr/lib/libfoo.dylib main + 42\n".into());
            let threads = cr.rosetta_threads_plist();
            let bt = threads[0].get("backtrace").unwrap();
            if let PlistValue::Array(frames) = bt {
                assert_eq!(frames.len(), 1);
                assert!(frames[0].contains_key("symbol"));
                match frames[0].get("symbol") {
                    Some(PlistValue::String(s)) => assert_eq!(s, "main"),
                    _ => panic!("expected symbol string"),
                }
                match frames[0].get("symbol_offset") {
                    Some(PlistValue::Int(n)) => assert_eq!(*n, 42),
                    _ => panic!("expected symbol_offset int"),
                }
            } else {
                panic!("expected backtrace array");
            }
        }
    }
}

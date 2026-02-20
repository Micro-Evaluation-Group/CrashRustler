use crate::crash_rustler::CrashRustler;
use crate::types::*;

impl CrashRustler {
    /// Adds a binary image to the list. Deduplicates by checking attempted_binary_images.
    /// Sets current_binary_image to "name @ base_address" for tracking.
    /// Returns true if the image was added (not a duplicate).
    /// Equivalent to -[CrashReport _extractBinaryImageInfoFromSymbolOwner:withMemory:]
    pub fn add_binary_image(&mut self, image: BinaryImage) -> bool {
        let key = format!("{} @ 0x{:x}", image.name, image.base_address);
        self.current_binary_image = Some(key.clone());

        if self.attempted_binary_images.contains(&key) {
            return false;
        }
        self.attempted_binary_images.insert(key);
        self.binary_images.push(image);
        true
    }

    /// Post-processes binary images: enriches metadata, sorts by base address,
    /// and assigns sequential indices. Called lazily on first access.
    /// Equivalent to the post-processing logic in -[CrashReport binaryImages]
    pub fn finalize_binary_images(&mut self) {
        if self.binary_image_post_processing_complete {
            return;
        }

        // Enrich images: fill in missing identifiers from path
        for image in &mut self.binary_images {
            if image.identifier.is_none()
                && let Some(last) = image.path.rsplit('/').next()
            {
                image.identifier = Some(last.to_string());
            }
        }

        // Sort by base address
        self.binary_images.sort_by_key(|img| img.base_address);

        // Track max identifier length for formatting
        self.max_binary_identifier_length = self
            .binary_images
            .iter()
            .map(|img| img.identifier.as_deref().unwrap_or("").len() as u32)
            .max()
            .unwrap_or(0);

        self.binary_image_post_processing_complete = true;
    }

    /// Finds the binary image containing the given address.
    /// Linear search: returns first image where base_address <= addr < end_address.
    /// Equivalent to -[CrashReport binaryImageDictionaryForAddress:]
    pub fn binary_image_for_address(&self, address: u64) -> Option<&BinaryImage> {
        self.binary_images
            .iter()
            .find(|img| address >= img.base_address && address < img.end_address)
    }

    /// Finds the binary image with the given executable path.
    /// Equivalent to -[CrashReport binaryImageDictionaryForPath:]
    pub fn binary_image_for_path(&self, path: &str) -> Option<&BinaryImage> {
        self.binary_images.iter().find(|img| img.path == path)
    }

    /// Formats a single binary image line for the crash report.
    /// Format: `startAddr - endAddr [+]identifier version <UUID> path`
    /// Apple images get "+" prefix. 32-bit uses 10-digit hex, 64-bit uses 18-digit.
    /// Equivalent to -[CrashReport _appendToDescription:binaryImageDict:force64BitMode:]
    pub fn format_binary_image_line(&self, image: &BinaryImage, force_64bit: bool) -> String {
        let is_apple = Self::path_is_apple(&image.path)
            || image
                .identifier
                .as_deref()
                .is_some_and(Self::bundle_identifier_is_apple);
        let apple_marker = if is_apple { "+" } else { " " };

        let identifier = image.identifier.as_deref().unwrap_or("???");

        let version_str = match (&image.version, image.identifier.as_deref()) {
            (Some(ver), _) => {
                let sanitized = Self::sanitize_version(Some(ver));
                format!("({sanitized})")
            }
            _ => String::new(),
        };

        let uuid_str = image
            .uuid
            .as_deref()
            .map(|u| format!("<{u}>"))
            .unwrap_or_default();

        let end_addr = if image.end_address > 0 {
            image.end_address - 1
        } else {
            0
        };

        if self.is_64_bit || force_64bit {
            format!(
                "    0x{:018x} - 0x{:018x} {apple_marker}{identifier} {version_str} {uuid_str} {}",
                image.base_address, end_addr, image.path
            )
        } else {
            format!(
                "    0x{:010x} - 0x{:010x} {apple_marker}{identifier} {version_str} {uuid_str} {}",
                image.base_address, end_addr, image.path
            )
        }
    }

    /// Formats all binary images as a human-readable crash report section.
    /// Equivalent to -[CrashReport binaryImagesDescription]
    pub fn binary_images_description(&self) -> String {
        let mut result = String::new();

        if self.binary_images.is_empty() {
            result.push_str("Binary images description not available.\n");
            return result;
        }

        result.push_str("Binary Images:\n");
        for image in &self.binary_images {
            let line = self.format_binary_image_line(image, false);
            result.push_str(&line);
            result.push('\n');
        }
        result
    }

    // =========================================================================
    // Backtrace and thread methods
    // =========================================================================

    /// Adds a thread backtrace from sampled data. Determines crashed thread
    /// by matching thread port or thread ID. Detects special crash patterns:
    /// exec failure (___NEW_PROCESS_COULD_NOT_BE_EXECD___), ObjC messaging
    /// crashes (objc_msgSend*), dyld fatal errors, and SIGABRT in abort/__abort.
    /// Equivalent to -[CrashReport _extractBacktraceInfoUsingSymbolicator:]
    pub fn add_thread_backtrace(&mut self, backtrace: ThreadBacktrace) {
        let thread_idx = self.backtraces.len() as i32;

        // Determine if this is the crashed thread
        if self.crashed_thread_number < 0 {
            if backtrace.is_crashed {
                self.crashed_thread_number = thread_idx;
            } else if let Some(tid) = backtrace.thread_id
                && self.thread_id == Some(tid)
            {
                self.crashed_thread_number = thread_idx;
            }
        }

        // Detect special patterns in frame 0 of crashed thread
        if self.crashed_thread_number == thread_idx
            && let Some(frame) = backtrace.frames.first()
            && let Some(ref sym) = frame.symbol_name
        {
            if sym == "___NEW_PROCESS_COULD_NOT_BE_EXECD___" {
                self.exec_failure_error = Some(String::new());
            } else if sym.starts_with("objc_msgSend") {
                self.objc_selector_name = Some(sym.clone());
            } else if sym.starts_with("dyld_fatal_error") && self.dyld_error_string.is_none() {
                self.extract_legacy_dyld_error_string = true;
            }
            // SIGABRT in abort/__abort → override crashed thread
            if self.signal == 6 && (sym == "abort" || sym == "__abort") {
                self.crashed_thread_number = thread_idx;
            }
        }

        self.backtraces.push(backtrace);
    }

    /// Formats all thread backtraces as human-readable crash report text.
    /// Each thread: "Thread N:" or "Thread N Crashed:". Each frame:
    /// "frameNum  identifier  address  symbolName + offset"
    /// Uses 10-digit hex for 32-bit, 18-digit for 64-bit addresses.
    /// Equivalent to -[CrashReport backtraceDescription]
    pub fn backtrace_description(&self) -> String {
        if self.backtraces.is_empty() {
            return "Backtrace not available\n".to_string();
        }

        let mut result = String::new();

        for (thread_idx, bt) in self.backtraces.iter().enumerate() {
            let crashed_marker = if thread_idx as i32 == self.crashed_thread_number {
                " Crashed"
            } else {
                ""
            };

            result.push_str(&format!("Thread {thread_idx}{crashed_marker}:"));
            if let Some(ref name) = bt.thread_name {
                let clean_name = name.replace('\n', " ");
                result.push_str(&format!(" {clean_name}"));
            }
            result.push('\n');

            for frame in &bt.frames {
                let identifier = if let Some(img) = self.binary_image_for_address(frame.address) {
                    let id = img.identifier.as_deref().unwrap_or("???");
                    if id.len() < 30 {
                        format!("{id:<30}")
                    } else {
                        id.to_string()
                    }
                } else {
                    format!("{:<30}", "???")
                };

                let addr_str = if self.is_64_bit {
                    format!("0x{:018x}", frame.address)
                } else {
                    format!("0x{:010x}", frame.address)
                };

                result.push_str(&format!(
                    "{}  {}  {}",
                    frame.frame_number, identifier, addr_str
                ));

                if let Some(ref sym) = frame.symbol_name {
                    result.push_str(&format!(" {} + 0x{:x}", sym, frame.symbol_offset));
                } else if let Some(img) = self.binary_image_for_address(frame.address) {
                    let offset = frame.address - img.base_address;
                    result.push_str(&format!(" 0x{:x} + {offset}", img.base_address));
                }

                if let Some(ref file) = frame.source_file
                    && let Some(line) = frame.source_line
                {
                    result.push_str(&format!(" ({file}:{line})"));
                }

                result.push('\n');
            }
            result.push('\n');
        }

        result
    }

    /// Formats the crashed thread's register state as human-readable text.
    /// Supports x86_THREAD_STATE (flavor 7) with 32/64-bit sub-flavors,
    /// x86_THREAD_STATE32 (flavor 1 on x86), ARM_THREAD_STATE64 (flavor 6),
    /// and ARM_THREAD_STATE (flavor 1 on ARM with sub-flavor dispatch).
    /// Equivalent to -[CrashReport threadStateDescription]
    pub fn thread_state_description(&self) -> String {
        let thread_label = if self.crashed_thread_number >= 0 {
            format!("Thread {}", self.crashed_thread_number)
        } else {
            "Unknown thread".to_string()
        };

        let regs = &self.thread_state.registers;
        let flavor = self.thread_state.flavor;

        // ARM_THREAD_STATE64 (flavor 6): x0-x28, fp, lr, sp, pc, cpsr
        // 33 registers * 2 u32s each + cpsr(1) + pad(1) = 68 u32s
        if flavor == 6 && regs.len() >= 68 {
            return self.format_arm64_regs(&thread_label, regs, 0);
        }

        // x86_THREAD_STATE (flavor 7) with sub-flavor check
        if flavor == 7 && !regs.is_empty() {
            let sub_flavor = regs[0];
            if sub_flavor == 1 && regs.len() >= 18 {
                // 32-bit: eax, ebx, ecx, edx, edi, esi, ebp, esp, ss, efl, eip, cs, ds, es, fs, gs
                return format!(
                    "{thread_label} crashed with X86 Thread State (32-bit):\n  \
                     eax: 0x{:08x}  ebx: 0x{:08x}  ecx: 0x{:08x}  edx: 0x{:08x}\n  \
                     edi: 0x{:08x}  esi: 0x{:08x}  ebp: 0x{:08x}  esp: 0x{:08x}\n  \
                     ss: 0x{:08x}   efl: 0x{:08x}  eip: 0x{:08x}  cs: 0x{:08x}\n  \
                     ds: 0x{:08x}   es: 0x{:08x}   fs: 0x{:08x}   gs: 0x{:08x}\n",
                    regs[2],
                    regs[3],
                    regs[4],
                    regs[5],
                    regs[6],
                    regs[7],
                    regs[8],
                    regs[9],
                    regs[10],
                    regs[11],
                    regs[12],
                    regs[13],
                    regs[14],
                    regs[15],
                    regs[16],
                    regs[17]
                );
            }
            // 64-bit state (sub_flavor != 1): registers are 64-bit, stored as pairs of u32
            if regs.len() >= 44 {
                let r = |idx: usize| -> u64 {
                    let base = 2 + idx * 2;
                    (regs[base] as u64) | ((regs[base + 1] as u64) << 32)
                };
                return format!(
                    "{thread_label} crashed with X86 Thread State (64-bit):\n  \
                     rax: 0x{:016x}  rbx: 0x{:016x}  rcx: 0x{:016x}  rdx: 0x{:016x}\n  \
                     rdi: 0x{:016x}  rsi: 0x{:016x}  rbp: 0x{:016x}  rsp: 0x{:016x}\n  \
                     r8:  0x{:016x}  r9:  0x{:016x}  r10: 0x{:016x}  r11: 0x{:016x}\n  \
                     r12: 0x{:016x}  r13: 0x{:016x}  r14: 0x{:016x}  r15: 0x{:016x}\n  \
                     rip: 0x{:016x}  rfl: 0x{:016x}\n",
                    r(0),
                    r(1),
                    r(2),
                    r(3),
                    r(4),
                    r(5),
                    r(6),
                    r(7),
                    r(8),
                    r(9),
                    r(10),
                    r(11),
                    r(12),
                    r(13),
                    r(14),
                    r(15),
                    r(16),
                    r(17)
                );
            }
        }

        // Flavor 1 collision: ARM_THREAD_STATE (unified) vs x86_THREAD_STATE32
        if flavor == 1 && !regs.is_empty() {
            if self.is_arm_cpu() {
                let sub_flavor = regs[0];
                if sub_flavor == 2 && regs.len() >= 70 {
                    // ARM_THREAD_STATE sub_flavor=2 (ARM64): 2-word header + 68 ARM64 regs
                    return self.format_arm64_regs(&thread_label, regs, 2);
                }
                if sub_flavor == 1 && regs.len() >= 19 {
                    // ARM_THREAD_STATE sub_flavor=1 (ARM32): r0-r15, cpsr
                    // 2 header words + 17 register words
                    return format!(
                        "{thread_label} crashed with ARM Thread State (32-bit):\n  \
                         r0:  0x{:08x}  r1:  0x{:08x}  r2:  0x{:08x}  r3:  0x{:08x}\n  \
                         r4:  0x{:08x}  r5:  0x{:08x}  r6:  0x{:08x}  r7:  0x{:08x}\n  \
                         r8:  0x{:08x}  r9:  0x{:08x}  r10: 0x{:08x}  r11: 0x{:08x}\n  \
                         r12: 0x{:08x}  sp:  0x{:08x}  lr:  0x{:08x}  pc:  0x{:08x}\n  \
                         cpsr: 0x{:08x}\n",
                        regs[2],
                        regs[3],
                        regs[4],
                        regs[5],
                        regs[6],
                        regs[7],
                        regs[8],
                        regs[9],
                        regs[10],
                        regs[11],
                        regs[12],
                        regs[13],
                        regs[14],
                        regs[15],
                        regs[16],
                        regs[17],
                        regs[18]
                    );
                }
            } else if regs.len() >= 16 {
                // x86_THREAD_STATE32 (flavor 1)
                return format!(
                    "{thread_label} crashed with X86 Thread State (32-bit):\n  \
                     eax: 0x{:08x}  ebx: 0x{:08x}  ecx: 0x{:08x}  edx: 0x{:08x}\n  \
                     edi: 0x{:08x}  esi: 0x{:08x}  ebp: 0x{:08x}  esp: 0x{:08x}\n  \
                     ss: 0x{:08x}   efl: 0x{:08x}  eip: 0x{:08x}  cs: 0x{:08x}\n  \
                     ds: 0x{:08x}   es: 0x{:08x}   fs: 0x{:08x}   gs: 0x{:08x}\n",
                    regs[0],
                    regs[1],
                    regs[2],
                    regs[3],
                    regs[4],
                    regs[5],
                    regs[6],
                    regs[7],
                    regs[8],
                    regs[9],
                    regs[10],
                    regs[11],
                    regs[12],
                    regs[13],
                    regs[14],
                    regs[15]
                );
            }
        }

        format!(
            "{thread_label} crashed with unknown flavor {}, state count {}\n",
            flavor,
            regs.len()
        )
    }

    /// Formats ARM64 register state (x0-x28, fp, lr, sp, pc, cpsr) from a u32 slice.
    /// `offset` is the starting index in `regs` (0 for flavor 6, 2 for flavor 1/sub2).
    fn format_arm64_regs(&self, thread_label: &str, regs: &[u32], offset: usize) -> String {
        let r = |idx: usize| -> u64 {
            let base = offset + idx * 2;
            (regs[base] as u64) | ((regs[base + 1] as u64) << 32)
        };
        let cpsr = regs[offset + 66];
        format!(
            "{thread_label} crashed with ARM Thread State (64-bit):\n  \
             x0:  0x{:016x}  x1:  0x{:016x}  x2:  0x{:016x}  x3:  0x{:016x}\n  \
             x4:  0x{:016x}  x5:  0x{:016x}  x6:  0x{:016x}  x7:  0x{:016x}\n  \
             x8:  0x{:016x}  x9:  0x{:016x}  x10: 0x{:016x}  x11: 0x{:016x}\n  \
             x12: 0x{:016x}  x13: 0x{:016x}  x14: 0x{:016x}  x15: 0x{:016x}\n  \
             x16: 0x{:016x}  x17: 0x{:016x}  x18: 0x{:016x}  x19: 0x{:016x}\n  \
             x20: 0x{:016x}  x21: 0x{:016x}  x22: 0x{:016x}  x23: 0x{:016x}\n  \
             x24: 0x{:016x}  x25: 0x{:016x}  x26: 0x{:016x}  x27: 0x{:016x}\n  \
             x28: 0x{:016x}  fp:  0x{:016x}  lr:  0x{:016x}  sp:  0x{:016x}\n  \
             pc:  0x{:016x}  cpsr: 0x{:08x}\n",
            r(0),
            r(1),
            r(2),
            r(3),
            r(4),
            r(5),
            r(6),
            r(7),
            r(8),
            r(9),
            r(10),
            r(11),
            r(12),
            r(13),
            r(14),
            r(15),
            r(16),
            r(17),
            r(18),
            r(19),
            r(20),
            r(21),
            r(22),
            r(23),
            r(24),
            r(25),
            r(26),
            r(27),
            r(28),
            r(29),
            r(30),
            r(31),
            r(32),
            cpsr
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::test_helpers::*;
    use crate::types::*;

    // =========================================================================
    // 9. binary_images — Image management
    // =========================================================================
    mod binary_images {
        use super::*;

        fn make_image(name: &str, base: u64, end: u64) -> BinaryImage {
            BinaryImage {
                name: name.into(),
                path: format!("/usr/lib/{name}"),
                uuid: Some("AAAA-BBBB-CCCC".into()),
                base_address: base,
                end_address: end,
                arch: Some("x86_64".into()),
                identifier: None,
                version: Some("1.0".into()),
            }
        }

        #[test]
        fn add_binary_image_normal() {
            let mut cr = make_test_cr();
            let img = make_image("libfoo.dylib", 0x1000, 0x2000);
            assert!(cr.add_binary_image(img));
            assert_eq!(cr.binary_images.len(), 1);
        }

        #[test]
        fn add_binary_image_duplicate() {
            let mut cr = make_test_cr();
            let img1 = make_image("libfoo.dylib", 0x1000, 0x2000);
            let img2 = make_image("libfoo.dylib", 0x1000, 0x2000);
            assert!(cr.add_binary_image(img1));
            assert!(!cr.add_binary_image(img2));
            assert_eq!(cr.binary_images.len(), 1);
        }

        #[test]
        fn finalize_binary_images_sorts_by_address() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libB.dylib", 0x3000, 0x4000));
            cr.add_binary_image(make_image("libA.dylib", 0x1000, 0x2000));
            cr.finalize_binary_images();
            assert_eq!(cr.binary_images[0].base_address, 0x1000);
            assert_eq!(cr.binary_images[1].base_address, 0x3000);
        }

        #[test]
        fn finalize_binary_images_fills_identifier_from_path() {
            let mut cr = make_test_cr();
            let mut img = make_image("libfoo.dylib", 0x1000, 0x2000);
            img.identifier = None;
            cr.add_binary_image(img);
            cr.finalize_binary_images();
            assert_eq!(
                cr.binary_images[0].identifier.as_deref(),
                Some("libfoo.dylib")
            );
        }

        #[test]
        fn finalize_binary_images_max_identifier_length() {
            let mut cr = make_test_cr();
            let mut img1 = make_image("short", 0x1000, 0x2000);
            img1.identifier = Some("short".into());
            let mut img2 = make_image("much_longer_name.dylib", 0x3000, 0x4000);
            img2.identifier = Some("much_longer_name.dylib".into());
            cr.add_binary_image(img1);
            cr.add_binary_image(img2);
            cr.finalize_binary_images();
            assert_eq!(cr.max_binary_identifier_length, 22);
        }

        #[test]
        fn finalize_binary_images_idempotent() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libfoo.dylib", 0x1000, 0x2000));
            cr.finalize_binary_images();
            cr.finalize_binary_images(); // second call does nothing
            assert_eq!(cr.binary_images.len(), 1);
        }

        #[test]
        fn binary_image_for_address_found() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libfoo.dylib", 0x1000, 0x2000));
            assert!(cr.binary_image_for_address(0x1500).is_some());
        }

        #[test]
        fn binary_image_for_address_not_found() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libfoo.dylib", 0x1000, 0x2000));
            assert!(cr.binary_image_for_address(0x3000).is_none());
        }

        #[test]
        fn binary_image_for_address_boundaries() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libfoo.dylib", 0x1000, 0x2000));
            // base_address is inclusive
            assert!(cr.binary_image_for_address(0x1000).is_some());
            // end_address is exclusive
            assert!(cr.binary_image_for_address(0x2000).is_none());
            // Just below end
            assert!(cr.binary_image_for_address(0x1FFF).is_some());
        }

        #[test]
        fn binary_image_for_path_found() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libfoo.dylib", 0x1000, 0x2000));
            assert!(cr.binary_image_for_path("/usr/lib/libfoo.dylib").is_some());
        }

        #[test]
        fn binary_image_for_path_not_found() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libfoo.dylib", 0x1000, 0x2000));
            assert!(cr.binary_image_for_path("/usr/lib/libbar.dylib").is_none());
        }

        #[test]
        fn format_binary_image_line_apple() {
            let cr = make_test_cr();
            let mut img = make_image("libSystem.B.dylib", 0x1000, 0x2000);
            img.identifier = Some("libSystem.B.dylib".into());
            let line = cr.format_binary_image_line(&img, false);
            assert!(line.contains("+libSystem.B.dylib"));
        }

        #[test]
        fn format_binary_image_line_non_apple() {
            let cr = make_test_cr();
            let mut img = make_image("libfoo.dylib", 0x1000, 0x2000);
            img.path = "/Applications/Foo.app/Contents/Frameworks/libfoo.dylib".into();
            img.identifier = Some("libfoo.dylib".into());
            let line = cr.format_binary_image_line(&img, false);
            assert!(line.contains(" libfoo.dylib"));
            assert!(!line.contains("+libfoo.dylib"));
        }

        #[test]
        fn format_binary_image_line_32bit() {
            let mut cr = make_test_cr();
            cr.is_64_bit = false;
            let img = make_image("libfoo.dylib", 0x1000, 0x2000);
            let line = cr.format_binary_image_line(&img, false);
            // 32-bit uses 10-digit hex: "0x" + 10 digits
            assert!(line.contains("0x0000001000"));
        }

        #[test]
        fn format_binary_image_line_64bit() {
            let cr = make_test_cr();
            let img = make_image("libfoo.dylib", 0x1000, 0x2000);
            let line = cr.format_binary_image_line(&img, false);
            // 64-bit uses 18-digit hex
            assert!(line.contains("0x000000000000001000"));
        }

        #[test]
        fn format_binary_image_line_missing_uuid() {
            let cr = make_test_cr();
            let mut img = make_image("libfoo.dylib", 0x1000, 0x2000);
            img.uuid = None;
            let line = cr.format_binary_image_line(&img, false);
            assert!(!line.contains('<'));
        }

        #[test]
        fn format_binary_image_line_missing_version() {
            let cr = make_test_cr();
            let mut img = make_image("libfoo.dylib", 0x1000, 0x2000);
            img.version = None;
            let line = cr.format_binary_image_line(&img, false);
            assert!(!line.contains('('));
        }

        #[test]
        fn binary_images_description_empty() {
            let cr = make_test_cr();
            let desc = cr.binary_images_description();
            assert!(desc.contains("not available"));
        }

        #[test]
        fn binary_images_description_populated() {
            let mut cr = make_test_cr();
            cr.add_binary_image(make_image("libfoo.dylib", 0x1000, 0x2000));
            let desc = cr.binary_images_description();
            assert!(desc.starts_with("Binary Images:"));
            assert!(desc.contains("libfoo.dylib"));
        }
    }

    // =========================================================================
    // 10. backtrace_methods — Thread backtrace
    // =========================================================================
    mod backtrace_methods {
        use super::*;

        fn make_frame(num: u32, sym: Option<&str>, addr: u64) -> BacktraceFrame {
            BacktraceFrame {
                frame_number: num,
                image_name: "libfoo.dylib".into(),
                address: addr,
                symbol_name: sym.map(|s| s.into()),
                symbol_offset: 42,
                source_file: None,
                source_line: None,
            }
        }

        fn make_bt(
            thread_num: u32,
            is_crashed: bool,
            frames: Vec<BacktraceFrame>,
        ) -> ThreadBacktrace {
            ThreadBacktrace {
                thread_number: thread_num,
                thread_name: None,
                thread_id: None,
                is_crashed,
                frames,
            }
        }

        #[test]
        fn add_thread_backtrace_sets_crashed_on_is_crashed() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let bt = make_bt(0, true, vec![make_frame(0, Some("main"), 0x1000)]);
            cr.add_thread_backtrace(bt);
            assert_eq!(cr.crashed_thread_number, 0);
        }

        #[test]
        fn add_thread_backtrace_sets_crashed_on_thread_id_match() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            cr.thread_id = Some(999);
            let mut bt = make_bt(0, false, vec![make_frame(0, Some("main"), 0x1000)]);
            bt.thread_id = Some(999);
            cr.add_thread_backtrace(bt);
            assert_eq!(cr.crashed_thread_number, 0);
        }

        #[test]
        fn add_thread_backtrace_exec_failure_pattern() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let bt = make_bt(
                0,
                true,
                vec![make_frame(
                    0,
                    Some("___NEW_PROCESS_COULD_NOT_BE_EXECD___"),
                    0x1000,
                )],
            );
            cr.add_thread_backtrace(bt);
            assert!(cr.exec_failure_error.is_some());
        }

        #[test]
        fn add_thread_backtrace_objc_msgsend_pattern() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let bt = make_bt(0, true, vec![make_frame(0, Some("objc_msgSend"), 0x1000)]);
            cr.add_thread_backtrace(bt);
            assert_eq!(cr.objc_selector_name, Some("objc_msgSend".into()));
        }

        #[test]
        fn add_thread_backtrace_dyld_fatal_error_pattern() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let bt = make_bt(
                0,
                true,
                vec![make_frame(0, Some("dyld_fatal_error"), 0x1000)],
            );
            cr.add_thread_backtrace(bt);
            assert!(cr.extract_legacy_dyld_error_string);
        }

        #[test]
        fn add_thread_backtrace_sigabrt_abort_pattern() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            cr.signal = 6; // SIGABRT
            let bt = make_bt(0, true, vec![make_frame(0, Some("abort"), 0x1000)]);
            cr.add_thread_backtrace(bt);
            assert_eq!(cr.crashed_thread_number, 0);
        }

        #[test]
        fn backtrace_description_empty() {
            let cr = make_test_cr();
            assert!(cr.backtrace_description().contains("not available"));
        }

        #[test]
        fn backtrace_description_single_thread() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let bt = make_bt(0, false, vec![make_frame(0, Some("main"), 0x1000)]);
            cr.add_thread_backtrace(bt);
            let desc = cr.backtrace_description();
            assert!(desc.contains("Thread 0:"));
            assert!(desc.contains("main + 0x2a"));
        }

        #[test]
        fn backtrace_description_crashed_thread_marker() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let bt = make_bt(0, true, vec![make_frame(0, Some("crash_fn"), 0x1000)]);
            cr.add_thread_backtrace(bt);
            let desc = cr.backtrace_description();
            assert!(desc.contains("Thread 0 Crashed:"));
        }

        #[test]
        fn backtrace_description_32bit_addresses() {
            let mut cr = make_test_cr();
            cr.is_64_bit = false;
            cr.crashed_thread_number = -1;
            let bt = make_bt(0, false, vec![make_frame(0, Some("fn"), 0x1000)]);
            cr.add_thread_backtrace(bt);
            let desc = cr.backtrace_description();
            // 32-bit: "0x" + 10 hex digits
            assert!(desc.contains("0x0000001000"));
        }

        #[test]
        fn backtrace_description_64bit_addresses() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let bt = make_bt(0, false, vec![make_frame(0, Some("fn"), 0x1000)]);
            cr.add_thread_backtrace(bt);
            let desc = cr.backtrace_description();
            // 64-bit: "0x" + 18 hex digits
            assert!(desc.contains("0x000000000000001000"));
        }

        #[test]
        fn backtrace_description_source_file_line() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = -1;
            let mut frame = make_frame(0, Some("fn"), 0x1000);
            frame.source_file = Some("main.c".into());
            frame.source_line = Some(42);
            let bt = make_bt(0, false, vec![frame]);
            cr.add_thread_backtrace(bt);
            let desc = cr.backtrace_description();
            assert!(desc.contains("(main.c:42)"));
        }

        #[test]
        fn thread_state_description_flavor7_sub1_32bit() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = 0;
            // flavor 7, sub_flavor 1 (32-bit), need 18 regs total (2 header + 16 regs)
            let mut regs = vec![0u32; 18];
            regs[0] = 1; // sub_flavor
            regs[1] = 0; // padding
            regs[2] = 0xAAAA_AAAA; // eax
            cr.thread_state = ThreadState {
                flavor: 7,
                registers: regs,
            };
            let desc = cr.thread_state_description();
            assert!(desc.contains("32-bit"));
            assert!(desc.contains("eax: 0xaaaaaaaa"));
        }

        #[test]
        fn thread_state_description_flavor7_64bit() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = 0;
            // flavor 7, sub_flavor != 1 (64-bit), need 44 regs
            let mut regs = vec![0u32; 44];
            regs[0] = 4; // sub_flavor (64-bit)
            regs[2] = 0xDEAD_BEEF; // rax low
            regs[3] = 0x0000_0001; // rax high
            cr.thread_state = ThreadState {
                flavor: 7,
                registers: regs,
            };
            let desc = cr.thread_state_description();
            assert!(desc.contains("64-bit"));
            assert!(desc.contains("rax: 0x00000001deadbeef"));
        }

        #[test]
        fn thread_state_description_flavor1() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = 0;
            let mut regs = vec![0u32; 16];
            regs[0] = 0xBBBB_BBBB; // eax
            cr.thread_state = ThreadState {
                flavor: 1,
                registers: regs,
            };
            let desc = cr.thread_state_description();
            assert!(desc.contains("32-bit"));
            assert!(desc.contains("eax: 0xbbbbbbbb"));
        }

        #[test]
        fn thread_state_description_unknown_flavor() {
            let mut cr = make_test_cr();
            cr.crashed_thread_number = 0;
            cr.thread_state = ThreadState {
                flavor: 99,
                registers: vec![],
            };
            let desc = cr.thread_state_description();
            assert!(desc.contains("unknown flavor 99"));
        }

        #[test]
        fn thread_state_description_arm64_flavor6() {
            let mut cr = make_test_cr_arm64();
            cr.crashed_thread_number = 0;
            // ARM_THREAD_STATE64 (flavor 6): 68 u32s
            // 33 registers * 2 + cpsr + pad = 68
            let mut regs = vec![0u32; 68];
            regs[0] = 0xCAFE_BABE; // x0 low
            regs[1] = 0x0000_0001; // x0 high
            regs[64] = 0xDEAD_0000; // pc low
            regs[65] = 0x0000_FFFF; // pc high
            regs[66] = 0x8000_0000; // cpsr
            cr.thread_state = ThreadState {
                flavor: 6,
                registers: regs,
            };
            let desc = cr.thread_state_description();
            assert!(desc.contains("ARM Thread State (64-bit)"));
            assert!(desc.contains("x0:  0x00000001cafebabe"));
            assert!(desc.contains("pc:  0x0000ffffdead0000"));
            assert!(desc.contains("cpsr: 0x80000000"));
        }

        #[test]
        fn thread_state_description_arm_thread_state_sub2() {
            let mut cr = make_test_cr_arm64();
            cr.crashed_thread_number = 0;
            // ARM_THREAD_STATE (flavor 1), sub_flavor=2 (ARM64): 2 header + 68 = 70
            let mut regs = vec![0u32; 70];
            regs[0] = 2; // sub_flavor
            regs[1] = 0; // padding
            regs[2] = 0x1111_2222; // x0 low (offset 2)
            regs[3] = 0x3333_4444; // x0 high
            regs[68] = 0xAAAA_BBBB; // cpsr (offset 2 + 66)
            cr.thread_state = ThreadState {
                flavor: 1,
                registers: regs,
            };
            let desc = cr.thread_state_description();
            assert!(desc.contains("ARM Thread State (64-bit)"));
            assert!(desc.contains("x0:  0x3333444411112222"));
            assert!(desc.contains("cpsr: 0xaaaabbbb"));
        }

        #[test]
        fn thread_state_description_arm32() {
            let mut cr = make_test_cr();
            cr.cpu_type = CpuType::ARM;
            cr.crashed_thread_number = 0;
            // ARM_THREAD_STATE (flavor 1), sub_flavor=1 (ARM32): 2 header + 17 = 19
            let mut regs = vec![0u32; 19];
            regs[0] = 1; // sub_flavor
            regs[1] = 0; // padding
            regs[2] = 0xDEAD_BEEF; // r0
            regs[17] = 0x1234_5678; // pc
            regs[18] = 0x6000_0010; // cpsr
            cr.thread_state = ThreadState {
                flavor: 1,
                registers: regs,
            };
            let desc = cr.thread_state_description();
            assert!(desc.contains("ARM Thread State (32-bit)"));
            assert!(desc.contains("r0:  0xdeadbeef"));
            assert!(desc.contains("pc:  0x12345678"));
            assert!(desc.contains("cpsr: 0x60000010"));
        }
    }
}

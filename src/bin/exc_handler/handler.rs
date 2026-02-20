//! Exception handler callback, disassembly, and crash log writing.
//!
//! Handles the exception data received from Mach messages, gathers
//! additional process info, runs exploitability analysis, and writes
//! the crash log.

use std::io::{Read, Write};

use capstone::prelude::*;
use sha2::{Digest, Sha256};

use crashrustler::ExploitabilityRating;
use crashrustler::exploitability::{
    ClassifyConfig, ExploitabilityResult, StackVerdict, classify_exception, is_stack_suspicious,
};
use crashrustler::unwind::MemoryReader;
use crashrustler::{
    BacktraceFrame, BinaryImage, CpuType, CrashParams, CrashRustler, ExceptionState,
    ThreadBacktrace, ThreadState,
};

use crate::Config;
use crate::ffi;
use crate::image_enum;
use crate::mach_msg::ExceptionData;
use crate::remote_memory;
use crate::thread_enum;

/// Disassembles a single instruction at the given PC from target process memory.
/// Returns the disassembly string, or an empty string on failure.
pub fn disassemble_at_pc(task: ffi::MachPortT, pc: u64) -> String {
    // Read 4 bytes at PC (enough for one ARM64 instruction, or start of x86)
    let bytes = match ffi::read_process_memory(task, pc, 16) {
        Some(b) => b,
        None => return String::new(),
    };

    #[cfg(target_arch = "aarch64")]
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .build();

    #[cfg(target_arch = "x86_64")]
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .build();

    let cs = match cs {
        Ok(cs) => cs,
        Err(_) => return String::new(),
    };

    match cs.disasm_count(&bytes, pc, 1) {
        Ok(insns) => {
            if let Some(insn) = insns.iter().next() {
                let mnemonic = insn.mnemonic().unwrap_or("");
                let op_str = insn.op_str().unwrap_or("");
                if op_str.is_empty() {
                    mnemonic.to_string()
                } else {
                    format!("{mnemonic} {op_str}")
                }
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    }
}

/// Extracts the PC from thread state registers.
fn extract_pc(flavor: i32, state: &[u32]) -> u64 {
    match flavor {
        6 if state.len() >= 66 => {
            // ARM_THREAD_STATE64: pc is at regs[32] (indices 64-65)
            (state[64] as u64) | ((state[65] as u64) << 32)
        }
        7 if state.len() >= 44 => {
            // x86_THREAD_STATE: rip is at regs[16] (64-bit)
            let sub_flavor = state[0];
            if sub_flavor == 1 {
                // 32-bit: eip at index 12
                state[12] as u64
            } else {
                // 64-bit: rip at regs[16] = indices 2+16*2..2+16*2+2
                let base = 2 + 16 * 2;
                (state[base] as u64) | ((state[base + 1] as u64) << 32)
            }
        }
        1 if !state.is_empty() => {
            // Unified state — sub_flavor dispatch
            let sub_flavor = state[0];
            if sub_flavor == 2 && state.len() >= 68 {
                // ARM64: pc at offset 2+32*2 = indices 66-67
                (state[66] as u64) | ((state[67] as u64) << 32)
            } else if sub_flavor == 1 && state.len() >= 19 {
                // ARM32: pc at index 17
                state[17] as u64
            } else if state.len() >= 12 {
                // x86 32-bit: eip at index 10
                state[10] as u64
            } else {
                0
            }
        }
        _ => 0,
    }
}

/// Handles an exception: gathers process data, builds CrashRustler,
/// classifies exploitability, writes crash log.
/// Returns the exit code for the process.
pub fn handle_exception(exc: &ExceptionData, config: &Config) -> i32 {
    let task = exc.task_port;
    let thread = exc.thread_port;

    // Gather process info
    let pid = ffi::pid_from_task(task).unwrap_or(0);
    let (ppid, is_64_bit, uid) = ffi::query_proc_info(pid).unwrap_or((0, true, 0));
    let (executable_path, process_name) = ffi::resolve_process_identity(pid);
    let r_process_pid = ffi::get_responsible_pid(pid);
    let awake_system_uptime = ffi::compute_awake_uptime();
    let date = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S%.3f %z")
        .to_string();

    // Get exception state
    let exception_state = ffi::get_exception_state(thread)
        .map(|(state, count)| ExceptionState { state, count })
        .unwrap_or(ExceptionState {
            state: Vec::new(),
            count: 0,
        });

    // Determine CPU type
    #[cfg(target_arch = "aarch64")]
    let cpu_type = if is_64_bit {
        CpuType::ARM64
    } else {
        CpuType::ARM
    };
    #[cfg(target_arch = "x86_64")]
    let cpu_type = if is_64_bit {
        CpuType::X86_64
    } else {
        CpuType::X86
    };

    // Build CrashParams
    let params = CrashParams {
        task,
        pid,
        ppid,
        uid,
        is_64_bit,
        thread,
        exception_type: exc.exception_type,
        exception_codes: exc.codes.clone(),
        thread_state: ThreadState {
            flavor: exc.flavor as u32,
            registers: exc.state.clone(),
        },
        exception_state,
        process_name: process_name.clone(),
        executable_path: executable_path.clone(),
        r_process_pid,
        date: Some(date),
        awake_system_uptime,
        cpu_type,
    };

    let mut cr = CrashRustler::new(params);

    // Generate thread backtraces and populate binary images
    generate_backtraces(&mut cr, task, thread, exc, is_64_bit, cpu_type);

    // Extract PC and disassemble
    let pc = extract_pc(exc.flavor, &exc.state);
    let disassembly = if pc != 0 {
        disassemble_at_pc(task, pc)
    } else {
        String::new()
    };

    // Classify exploitability
    let classify_config = ClassifyConfig {
        exploitable_reads: config.exploitable_reads,
        exploitable_jit: config.exploitable_jit,
        ignore_frame_pointer: config.ignore_frame_pointer,
    };

    let result = classify_exception(
        cr.exception_type,
        &cr.exception_code,
        &disassembly,
        pc,
        cpu_type,
        &classify_config,
    );

    // Compute SHA256 of the crashing binary
    let sha256 = executable_path.as_deref().and_then(sha256_of_file);

    // Build crash log text
    let crash_log = build_crash_log(&cr, &result, &disassembly, sha256.as_deref());

    // Check backtrace for exploitability override
    let stack_verdict = is_stack_suspicious(
        &crash_log,
        result.access_address,
        cr.exception_type,
        cpu_type,
        &classify_config,
    );

    let final_rating = match stack_verdict {
        StackVerdict::ChangeToExploitable => ExploitabilityRating::Exploitable,
        StackVerdict::ChangeToNotExploitable => ExploitabilityRating::NotExploitable,
        StackVerdict::NoChange => result.rating,
    };

    // Print results
    if !config.quiet {
        let rating_str = match final_rating {
            ExploitabilityRating::Exploitable => "is_exploitable",
            ExploitabilityRating::NotExploitable => "not_exploitable",
            ExploitabilityRating::Unknown => "unknown",
        };

        let name = process_name.as_deref().unwrap_or("unknown");
        eprintln!(
            "exc_handler: {name} ({pid}) {}: signal={}, {}",
            cr.exception_type_description(),
            result.signal,
            rating_str,
        );

        for msg in &result.messages {
            eprintln!("  {msg}");
        }
    }

    // Write crash log
    if !config.no_log {
        write_crash_log(&crash_log, &cr, &final_rating, config);
    }

    // Compute exit code
    let signal = result.signal;
    match final_rating {
        ExploitabilityRating::Exploitable => signal as i32 + 100,
        ExploitabilityRating::NotExploitable | ExploitabilityRating::Unknown => signal as i32,
    }
}

/// Generates thread backtraces and populates binary image info in the crash report.
fn generate_backtraces(
    cr: &mut CrashRustler,
    task: ffi::MachPortT,
    crashed_thread: ffi::MachPortT,
    exc: &ExceptionData,
    is_64_bit: bool,
    cpu_type: CpuType,
) {
    let reader = remote_memory::RemoteMemoryReader { task };

    // Enumerate binary images from dyld_all_image_infos
    let loaded_images = image_enum::enumerate_binary_images(task, &reader, is_64_bit);

    let arch_str = if cpu_type == CpuType::ARM64 {
        "arm64"
    } else if cpu_type == CpuType::X86_64 {
        "x86_64"
    } else if cpu_type == CpuType::ARM {
        "arm"
    } else if cpu_type == CpuType::X86 {
        "x86"
    } else {
        "unknown"
    };

    // Add images to crash report
    for img in &loaded_images {
        let uuid_str = img
            .info
            .uuid
            .map(|bytes| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>());
        cr.add_binary_image(BinaryImage {
            name: img.info.name.clone(),
            path: img.path.clone(),
            uuid: uuid_str,
            base_address: img.info.load_address,
            end_address: img.info.end_address,
            arch: Some(arch_str.to_string()),
            identifier: None,
            version: None,
        });
    }

    // Extract ___crashreporter_info__ from loaded images.
    // Sanitizer runtimes (ASan, etc.) populate this buffer before aborting.
    extract_crash_reporter_info(cr, &reader, &loaded_images, is_64_bit);

    // Build BinaryImageInfo vec for unwinder (symtab refs kept separately)
    let mut unwind_images: Vec<crashrustler::unwind::BinaryImageInfo> =
        loaded_images.iter().map(|img| img.info.clone()).collect();

    // Enumerate all threads
    let threads = thread_enum::enumerate_threads(task);

    // Reorder so the crashed thread is processed first (standard for macOS crash logs)
    let crashed_idx = threads.iter().position(|(port, _)| *port == crashed_thread);
    let mut thread_order: Vec<usize> = Vec::with_capacity(threads.len());
    if let Some(ci) = crashed_idx {
        thread_order.push(ci);
    }
    for i in 0..threads.len() {
        if Some(i) != crashed_idx {
            thread_order.push(i);
        }
    }

    for (thread_number, &orig_idx) in thread_order.iter().enumerate() {
        let (thread_port, thread_state) = &threads[orig_idx];
        let is_crashed = *thread_port == crashed_thread;

        // Use exception message state for crashed thread (captured at exact crash point)
        let state = if is_crashed {
            ThreadState {
                flavor: exc.flavor as u32,
                registers: exc.state.clone(),
            }
        } else {
            thread_state.clone()
        };

        let thread_id = thread_enum::get_thread_id(*thread_port);

        // Unwind the thread
        let frames =
            crashrustler::unwind::unwind_thread(&reader, &state, cpu_type, &mut unwind_images);

        // Convert to BacktraceFrames with symbol resolution
        let bt_frames: Vec<BacktraceFrame> = frames
            .iter()
            .enumerate()
            .map(|(frame_idx, (pc, _regs))| {
                // Find the containing image for name and symbol lookup
                let containing_image = loaded_images.iter().find(|img| img.info.contains(*pc));

                let image_name = containing_image
                    .map(|img| img.info.name.clone())
                    .unwrap_or_else(|| "???".to_string());

                // Resolve symbol from the image's symbol table
                let (symbol_name, symbol_offset) = containing_image
                    .and_then(|img| {
                        let symtab = img.symtab.as_ref()?;
                        image_enum::resolve_symbol(&reader, symtab, *pc, img.info.load_address)
                    })
                    .map(|(name, offset)| (Some(name), offset))
                    .unwrap_or((None, 0));

                BacktraceFrame {
                    frame_number: frame_idx as u32,
                    image_name,
                    address: *pc,
                    symbol_name,
                    symbol_offset,
                    source_file: None,
                    source_line: None,
                }
            })
            .collect();

        cr.add_thread_backtrace(ThreadBacktrace {
            thread_number: thread_number as u32,
            thread_name: None,
            thread_id,
            is_crashed,
            frames: bt_frames,
        });
    }

    cr.finalize_binary_images();
}

/// Extracts crash reporter info from loaded images in the target process.
///
/// Uses two mechanisms to find crash reporter messages:
///
/// 1. **`___crashreporter_info__` symbol** (legacy): Scans nlist symbol tables for
///    the well-known `___crashreporter_info__` symbol (a `const char*`). Used by
///    Rust's sanitizer runtimes.
///
/// 2. **`__DATA,__crash_info` section** (modern): Reads the `crashreporter_annotations_t`
///    struct from the `__crash_info` section. The `message` field (offset 0x08) contains
///    a pointer to the crash reporter string. Used by clang's sanitizer runtimes.
///
/// This captures sanitizer error reports (ASan, UBSan, TSan) that are written
/// before calling `abort()`, as well as any other crash reporter info from
/// system or third-party libraries.
fn extract_crash_reporter_info(
    cr: &mut CrashRustler,
    reader: &remote_memory::RemoteMemoryReader,
    loaded_images: &[image_enum::LoadedImage],
    is_64_bit: bool,
) {
    for img in loaded_images {
        // Method 1: ___crashreporter_info__ nlist symbol (Rust sanitizer runtimes)
        if let Some(symtab) = &img.symtab
            && let Some(ptr_addr) = image_enum::find_symbol_address(
                reader,
                symtab,
                "___crashreporter_info__",
                img.info.load_address,
            )
        {
            let ptr = if is_64_bit {
                match reader.read_u64(ptr_addr) {
                    Some(p) if p != 0 => Some(p),
                    _ => None,
                }
            } else {
                match reader.read_u32(ptr_addr) {
                    Some(p) if p != 0 => Some(p as u64),
                    _ => None,
                }
            };

            if let Some(ptr) = ptr
                && let Some(info) = image_enum::read_large_c_string(reader, ptr)
                && !info.is_empty()
            {
                cr.append_application_specific_info(&info, true);
                continue; // Don't also check __crash_info for same image
            }
        }

        // Method 2: __DATA,__crash_info section (clang sanitizer runtimes)
        // crashreporter_annotations_t layout:
        //   version: u64       (offset 0x00)
        //   message: pointer   (offset 0x08) ← crash reporter message string
        if let Some(crash_info) = img.crash_info_addr {
            let version = reader.read_u64(crash_info).unwrap_or(0);
            if version < 4 {
                continue; // message field not present in older versions
            }
            let msg_ptr = if is_64_bit {
                reader.read_u64(crash_info + 8).unwrap_or(0)
            } else {
                reader.read_u32(crash_info + 4).unwrap_or(0) as u64
            };
            if msg_ptr != 0
                && let Some(info) = image_enum::read_large_c_string(reader, msg_ptr)
                && !info.is_empty()
            {
                cr.append_application_specific_info(&info, true);
            }
        }
    }
}

/// Computes the SHA256 hex digest of the file at `path`.
/// Returns `None` on any I/O error.
fn sha256_of_file(path: &str) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Builds the crash log text.
fn build_crash_log(
    cr: &CrashRustler,
    result: &ExploitabilityResult,
    disassembly: &str,
    sha256: Option<&str>,
) -> String {
    let mut log = String::new();

    // Header
    log.push_str(&format!(
        "Process:         {} [{}]\n",
        cr.process_name.as_deref().unwrap_or("???"),
        cr.pid
    ));
    if let Some(bundle_id) = cr.bundle_identifier() {
        log.push_str(&format!("Identifier:      {bundle_id}\n"));
    }
    if let Some(ref path) = cr.executable_path {
        log.push_str(&format!("Path:            {path}\n"));
    }
    if let Some(hash) = sha256 {
        log.push_str(&format!("SHA256:          {hash}\n"));
    }
    if let Some(cmd) = ffi::resolve_command_line(cr.pid) {
        log.push_str(&format!("Command Line:    {cmd}\n"));
    }
    if let Some(ref date) = cr.date {
        log.push_str(&format!("Date/Time:       {date}\n"));
    }

    log.push('\n');

    // Exception info
    log.push_str(&format!(
        "Exception Type:  {} ({})\n",
        cr.exception_type_description(),
        cr.signal_name()
    ));
    log.push_str(&format!(
        "Exception Codes: {}\n",
        cr.exception_codes_description()
    ));

    if !disassembly.is_empty() {
        log.push_str(&format!(
            "Crashed Thread Instruction: 0x{:x}: {disassembly}\n",
            result.pc
        ));
    }

    log.push('\n');

    // Exploitability
    let rating_str = match result.rating {
        ExploitabilityRating::Exploitable => "EXPLOITABLE",
        ExploitabilityRating::NotExploitable => "NOT_EXPLOITABLE",
        ExploitabilityRating::Unknown => "UNKNOWN",
    };
    log.push_str(&format!("Exploitability:  {rating_str}\n"));
    for msg in &result.messages {
        log.push_str(&format!("  {msg}\n"));
    }

    // Application Specific Information (crash reporter info from loaded libraries)
    if let Some(ref info) = cr.application_specific_info {
        log.push('\n');
        log.push_str("Application Specific Information:\n");
        log.push_str(info);
        if !info.ends_with('\n') {
            log.push('\n');
        }
    }

    log.push('\n');

    // Thread backtraces
    log.push_str(&cr.backtrace_description());

    // Thread state
    log.push_str(&cr.thread_state_description());
    log.push('\n');

    // Binary images
    log.push_str(&cr.binary_images_description());

    log
}

/// Writes the crash log to the appropriate location.
fn write_crash_log(log: &str, cr: &CrashRustler, rating: &ExploitabilityRating, config: &Config) {
    let path: String = if let Some(ref explicit_path) = config.log_path {
        explicit_path.clone()
    } else {
        let name = cr.process_name.as_deref().unwrap_or("unknown");
        let rating_suffix = match rating {
            ExploitabilityRating::Exploitable => ".exploitable",
            ExploitabilityRating::NotExploitable => "",
            ExploitabilityRating::Unknown => ".unknown",
        };

        // Create log directory if it doesn't exist
        let _ = std::fs::create_dir_all(&config.log_dir);

        format!(
            "{}/{}-{}{}.crashlog.txt",
            config.log_dir, name, cr.pid, rating_suffix
        )
    };

    match std::fs::File::create(&path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(log.as_bytes()) {
                eprintln!("exc_handler: failed to write crash log to {path}: {e}");
            }
        }
        Err(e) => {
            eprintln!("exc_handler: failed to create crash log {path}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // extract_pc tests
    // ========================================================================

    #[test]
    fn extract_pc_arm64_flavor6() {
        // ARM_THREAD_STATE64 (flavor 6): pc at indices 64-65
        let mut state = vec![0u32; 68];
        state[64] = 0xDEAD_BEEFu32;
        state[65] = 0x0000_0001;
        assert_eq!(extract_pc(6, &state), 0x0000_0001_DEAD_BEEF);
    }

    #[test]
    fn extract_pc_arm64_flavor6_too_short() {
        let state = vec![0u32; 60]; // too short for ARM64
        assert_eq!(extract_pc(6, &state), 0);
    }

    #[test]
    fn extract_pc_x86_64_flavor7() {
        // x86_THREAD_STATE (flavor 7): sub_flavor != 1 → 64-bit rip
        let mut state = vec![0u32; 50];
        state[0] = 4; // sub_flavor = x86_THREAD_STATE64
        let base = 2 + 16 * 2; // index 34
        state[base] = 0x4141_4141;
        state[base + 1] = 0x0000_7FFF;
        assert_eq!(extract_pc(7, &state), 0x0000_7FFF_4141_4141);
    }

    #[test]
    fn extract_pc_x86_32_flavor7() {
        // x86_THREAD_STATE (flavor 7): sub_flavor=1 → 32-bit eip at index 12
        let mut state = vec![0u32; 50];
        state[0] = 1; // sub_flavor = x86_THREAD_STATE32
        state[12] = 0x0804_8000;
        assert_eq!(extract_pc(7, &state), 0x0804_8000);
    }

    #[test]
    fn extract_pc_unified_arm64() {
        // Unified state (flavor 1): sub_flavor=2 → ARM64 pc at indices 66-67
        let mut state = vec![0u32; 70];
        state[0] = 2; // ARM64 sub_flavor
        state[66] = 0x1234_5678;
        state[67] = 0x0000_0001;
        assert_eq!(extract_pc(1, &state), 0x0000_0001_1234_5678);
    }

    #[test]
    fn extract_pc_unified_arm32() {
        // Unified state (flavor 1): sub_flavor=1 → ARM32 pc at index 17
        let mut state = vec![0u32; 20];
        state[0] = 1; // ARM32 sub_flavor
        state[17] = 0x0001_0000;
        assert_eq!(extract_pc(1, &state), 0x0001_0000);
    }

    #[test]
    fn extract_pc_unknown_flavor() {
        let state = vec![0u32; 100];
        assert_eq!(extract_pc(99, &state), 0);
    }

    #[test]
    fn extract_pc_empty_state() {
        assert_eq!(extract_pc(6, &[]), 0);
        assert_eq!(extract_pc(7, &[]), 0);
        assert_eq!(extract_pc(1, &[]), 0);
    }
}
